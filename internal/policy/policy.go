// Package policy implements the pqseal policy language defined in §6 of the
// challenge spec: short boolean expressions over string-valued claims, with
// a special ordering for the "clearance" identifier.
package policy

import (
	"fmt"
	"strings"
)

// Expr is a parsed policy expression that can be evaluated against a claim set.
type Expr interface {
	Eval(claims map[string]string) bool
}

// clearanceOrder is the §6.3 enumeration. Lower index = less privileged.
var clearanceOrder = map[string]int{
	"UNCLASSIFIED": 0,
	"CUI":          1,
	"CONFIDENTIAL": 2,
	"SECRET":       3,
	"TOP_SECRET":   4,
	"TS_SCI":       5,
}

// Parse parses a policy string into an evaluable Expr.
func Parse(src string) (Expr, error) {
	tokens, err := tokenize(src)
	if err != nil {
		return nil, err
	}
	p := &parser{tokens: tokens}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.peek().kind != tokEOF {
		return nil, fmt.Errorf("policy: unexpected token %q after expression", p.peek().val)
	}
	return expr, nil
}

// --- AST nodes -----------------------------------------------------------

type orExpr struct{ left, right Expr }

func (e *orExpr) Eval(c map[string]string) bool {
	return e.left.Eval(c) || e.right.Eval(c)
}

type andExpr struct{ left, right Expr }

func (e *andExpr) Eval(c map[string]string) bool {
	return e.left.Eval(c) && e.right.Eval(c)
}

type notExpr struct{ inner Expr }

func (e *notExpr) Eval(c map[string]string) bool {
	return !e.inner.Eval(c)
}

type cmpExpr struct {
	ident string
	op    string
	// For scalar ops rhs has exactly one element; for "in" it has one or more.
	rhs []string
}

func (e *cmpExpr) Eval(claims map[string]string) bool {
	left := claims[e.ident] // missing claim → empty string per §6.2

	switch e.op {
	case "==":
		return left == e.rhs[0]
	case "!=":
		return left != e.rhs[0]
	case "in":
		for _, v := range e.rhs {
			if left == v {
				return true
			}
		}
		return false
	case ">", ">=", "<", "<=":
		if e.ident == "clearance" {
			l, lok := clearanceOrder[left]
			r, rok := clearanceOrder[e.rhs[0]]
			if !lok || !rok {
				return false
			}
			switch e.op {
			case ">":
				return l > r
			case ">=":
				return l >= r
			case "<":
				return l < r
			case "<=":
				return l <= r
			}
		}
		switch e.op {
		case ">":
			return left > e.rhs[0]
		case ">=":
			return left >= e.rhs[0]
		case "<":
			return left < e.rhs[0]
		case "<=":
			return left <= e.rhs[0]
		}
	}
	return false
}

// --- Lexer ---------------------------------------------------------------

type tokKind int

const (
	tokEOF tokKind = iota
	tokIdent
	tokString
	tokOp
	tokLParen
	tokRParen
	tokLBracket
	tokRBracket
	tokComma
	tokAnd
	tokOr
	tokNot
	tokIn
)

type token struct {
	kind tokKind
	val  string
}

func isLetter(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}

func isDigit(b byte) bool {
	return b >= '0' && b <= '9'
}

func tokenize(s string) ([]token, error) {
	var out []token
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			out = append(out, token{tokLParen, "("})
			i++
		case c == ')':
			out = append(out, token{tokRParen, ")"})
			i++
		case c == '[':
			out = append(out, token{tokLBracket, "["})
			i++
		case c == ']':
			out = append(out, token{tokRBracket, "]"})
			i++
		case c == ',':
			out = append(out, token{tokComma, ","})
			i++
		case c == '\'':
			j := i + 1
			for j < len(s) && s[j] != '\'' {
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("policy: unterminated string literal at offset %d", i)
			}
			out = append(out, token{tokString, s[i+1 : j]})
			i = j + 1
		case c == '=' && i+1 < len(s) && s[i+1] == '=':
			out = append(out, token{tokOp, "=="})
			i += 2
		case c == '!' && i+1 < len(s) && s[i+1] == '=':
			out = append(out, token{tokOp, "!="})
			i += 2
		case c == '>' && i+1 < len(s) && s[i+1] == '=':
			out = append(out, token{tokOp, ">="})
			i += 2
		case c == '<' && i+1 < len(s) && s[i+1] == '=':
			out = append(out, token{tokOp, "<="})
			i += 2
		case c == '>':
			out = append(out, token{tokOp, ">"})
			i++
		case c == '<':
			out = append(out, token{tokOp, "<"})
			i++
		case isLetter(c):
			j := i
			for j < len(s) && (isLetter(s[j]) || isDigit(s[j]) || s[j] == '_') {
				j++
			}
			word := s[i:j]
			kind := tokIdent
			switch word {
			case "AND":
				kind = tokAnd
			case "OR":
				kind = tokOr
			case "NOT":
				kind = tokNot
			case "in":
				kind = tokIn
			}
			out = append(out, token{kind, word})
			i = j
		default:
			return nil, fmt.Errorf("policy: unexpected character %q at offset %d", c, i)
		}
	}
	out = append(out, token{tokEOF, ""})
	return out, nil
}

// --- Parser --------------------------------------------------------------

type parser struct {
	tokens []token
	pos    int
}

func (p *parser) peek() token {
	return p.tokens[p.pos]
}

func (p *parser) consume() token {
	t := p.tokens[p.pos]
	p.pos++
	return t
}

func (p *parser) parseOr() (Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokOr {
		p.consume()
		right, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		left = &orExpr{left, right}
	}
	return left, nil
}

func (p *parser) parseAnd() (Expr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for p.peek().kind == tokAnd {
		p.consume()
		right, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		left = &andExpr{left, right}
	}
	return left, nil
}

func (p *parser) parseNot() (Expr, error) {
	if p.peek().kind == tokNot {
		p.consume()
		inner, err := p.parsePrimary()
		if err != nil {
			return nil, err
		}
		return &notExpr{inner}, nil
	}
	return p.parsePrimary()
}

func (p *parser) parsePrimary() (Expr, error) {
	if p.peek().kind == tokLParen {
		p.consume()
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		if p.peek().kind != tokRParen {
			return nil, fmt.Errorf("policy: expected ')', got %q", p.peek().val)
		}
		p.consume()
		return expr, nil
	}
	return p.parseComparison()
}

func (p *parser) parseComparison() (Expr, error) {
	t := p.consume()
	if t.kind != tokIdent {
		return nil, fmt.Errorf("policy: expected identifier, got %q", t.val)
	}
	ident := t.val

	opT := p.consume()
	if opT.kind != tokOp && opT.kind != tokIn {
		return nil, fmt.Errorf("policy: expected operator after %q, got %q", ident, opT.val)
	}
	op := opT.val
	if opT.kind == tokIn {
		op = "in"
	}

	if op == "in" {
		if p.peek().kind != tokLBracket {
			return nil, fmt.Errorf("policy: 'in' requires '[' list, got %q", p.peek().val)
		}
		p.consume()
		if p.peek().kind == tokRBracket {
			return nil, fmt.Errorf("policy: empty list after 'in'")
		}
		var vals []string
		for {
			if p.peek().kind != tokString {
				return nil, fmt.Errorf("policy: expected string literal in list, got %q", p.peek().val)
			}
			vals = append(vals, p.consume().val)
			if p.peek().kind == tokComma {
				p.consume()
				continue
			}
			break
		}
		if p.peek().kind != tokRBracket {
			return nil, fmt.Errorf("policy: expected ']', got %q", p.peek().val)
		}
		p.consume()
		return &cmpExpr{ident: ident, op: op, rhs: vals}, nil
	}

	if p.peek().kind != tokString {
		return nil, fmt.Errorf("policy: expected string literal after %q, got %q", op, p.peek().val)
	}
	val := p.consume().val
	return &cmpExpr{ident: ident, op: op, rhs: []string{val}}, nil
}

// String renders the AST back to a canonical form (handy for tests/debugging).
func String(e Expr) string {
	var b strings.Builder
	render(&b, e)
	return b.String()
}

func render(b *strings.Builder, e Expr) {
	switch x := e.(type) {
	case *orExpr:
		b.WriteByte('(')
		render(b, x.left)
		b.WriteString(" OR ")
		render(b, x.right)
		b.WriteByte(')')
	case *andExpr:
		b.WriteByte('(')
		render(b, x.left)
		b.WriteString(" AND ")
		render(b, x.right)
		b.WriteByte(')')
	case *notExpr:
		b.WriteString("NOT ")
		render(b, x.inner)
	case *cmpExpr:
		b.WriteString(x.ident)
		b.WriteByte(' ')
		b.WriteString(x.op)
		b.WriteByte(' ')
		if x.op == "in" {
			b.WriteByte('[')
			for i, v := range x.rhs {
				if i > 0 {
					b.WriteString(", ")
				}
				b.WriteByte('\'')
				b.WriteString(v)
				b.WriteByte('\'')
			}
			b.WriteByte(']')
		} else {
			b.WriteByte('\'')
			b.WriteString(x.rhs[0])
			b.WriteByte('\'')
		}
	}
}
