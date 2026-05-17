package policy

import "testing"

func TestWorkedExamples(t *testing.T) {
	claims := map[string]string{
		"clearance":   "TOP_SECRET",
		"citizenship": "USA",
		"agency":      "DOD",
	}

	cases := []struct {
		src  string
		want bool
	}{
		{"clearance >= 'SECRET' AND citizenship == 'USA'", true},
		{"clearance == 'SECRET'", false},
		{"clearance >= 'SECRET' AND (agency in ['DOE', 'DHS'])", false},
		{"NOT (citizenship == 'PRC') AND clearance >= 'CONFIDENTIAL'", true},
		{"clearance >= 'COSMIC_TOP'", false},
	}
	for _, c := range cases {
		e, err := Parse(c.src)
		if err != nil {
			t.Fatalf("Parse(%q) error: %v", c.src, err)
		}
		got := e.Eval(claims)
		if got != c.want {
			t.Errorf("Eval(%q) = %v, want %v", c.src, got, c.want)
		}
	}
}

func TestPrecedence(t *testing.T) {
	claims := map[string]string{"a": "x", "b": "y", "c": "z"}
	// OR has lowest precedence: a == 'x' OR b == 'wrong' AND c == 'wrong'
	// parses as: (a == 'x') OR ((b == 'wrong') AND (c == 'wrong')) → true
	e, err := Parse("a == 'x' OR b == 'wrong' AND c == 'wrong'")
	if err != nil {
		t.Fatal(err)
	}
	if !e.Eval(claims) {
		t.Errorf("precedence: expected true")
	}
}

func TestMissingClaimIsEmpty(t *testing.T) {
	claims := map[string]string{}
	e, err := Parse("missing == ''")
	if err != nil {
		t.Fatal(err)
	}
	if !e.Eval(claims) {
		t.Errorf("missing claim should compare equal to empty string")
	}
}

func TestClearanceOrdering(t *testing.T) {
	cases := []struct {
		level string
		src   string
		want  bool
	}{
		{"UNCLASSIFIED", "clearance > 'UNCLASSIFIED'", false},
		{"CUI", "clearance > 'UNCLASSIFIED'", true},
		{"TS_SCI", "clearance >= 'TOP_SECRET'", true},
		{"SECRET", "clearance < 'TOP_SECRET'", true},
		{"SECRET", "clearance <= 'SECRET'", true},
		// unknown level on either side → ordering false
		{"SECRET", "clearance > 'BOGUS'", false},
		{"BOGUS", "clearance < 'SECRET'", false},
		// == on clearance is plain string compare
		{"SECRET", "clearance == 'SECRET'", true},
		{"SECRET", "clearance == 'TOP_SECRET'", false},
	}
	for _, c := range cases {
		e, err := Parse(c.src)
		if err != nil {
			t.Fatalf("Parse(%q): %v", c.src, err)
		}
		got := e.Eval(map[string]string{"clearance": c.level})
		if got != c.want {
			t.Errorf("clearance=%q, %q = %v, want %v", c.level, c.src, got, c.want)
		}
	}
}

func TestInOperator(t *testing.T) {
	claims := map[string]string{"agency": "DOD"}
	e, err := Parse("agency in ['DOD', 'DOE', 'DHS']")
	if err != nil {
		t.Fatal(err)
	}
	if !e.Eval(claims) {
		t.Error("expected agency=DOD in list")
	}
	e2, _ := Parse("agency in ['DOE', 'DHS']")
	if e2.Eval(claims) {
		t.Error("expected agency=DOD not in list")
	}
}

func TestParseErrors(t *testing.T) {
	bad := []string{
		"",                              // empty
		"clearance",                     // no operator
		"clearance ==",                  // no rhs
		"clearance == SECRET",           // unquoted rhs
		"clearance >= 'SECRET",          // unterminated string
		"clearance >= 'SECRET' AND",     // dangling AND
		"clearance >= 'SECRET' xyzzy",   // trailing junk
		"agency in []",                  // empty list
		"agency in ('a', 'b')",          // parens not brackets
		"NOT NOT clearance == 'SECRET'", // grammar disallows double NOT
		"$bad == 'x'",                   // bad identifier
	}
	for _, src := range bad {
		if _, err := Parse(src); err == nil {
			t.Errorf("Parse(%q) should have failed", src)
		}
	}
}
