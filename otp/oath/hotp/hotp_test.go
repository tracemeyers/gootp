package hotp

import (
	"encoding/hex"
	"testing"
)

//////////////////////////////////////////////////////////////////////////////
// Generator

func Test_NewGenerator_digitsRange(t *testing.T) {
	valid := []int{6, 7, 8}
	for _, digits := range valid {
		g := NewGenerator(digits)
		if g == nil {
			t.Error("Valid digits (" + string(digits) + ") should not fail")
		}
	}

	invalid := []int{5, 9}

	for _, digits := range invalid {
		g := NewGenerator(digits)
		if g != nil {
			t.Error("Invalid digits (" + string(digits) + ") should fail")
		}
	}
}

//  Count    Hexadecimal    Decimal        HOTP
//  0        4c93cf18       1284755224     755224
//  1        41397eea       1094287082     287082
//  2         82fef30        137359152     359152
//  3        66ef7655       1726969429     969429
//  4        61c5938a       1640338314     338314
//  5        33c083d4        868254676     254676
//  6        7256c032       1918287922     287922
//  7         4e5b397         82162583     162583
//  8        2823443f        673399871     399871
//  9        2679dc69        645520489     520489
func Test_Generate_officialTestValues(t *testing.T) {
	key, _ := hex.DecodeString("3132333435363738393031323334353637383930")
	hotpValues := []string{
		"755224", "287082", "359152", "969429", "338314", "254676", "287922",
		"162583", "399871", "520489",
	}

	gen := NewGenerator(6)
	for counter, hotp := range hotpValues {
		input := NewInput(uint64(counter))
		otp, _ := gen.Generate(input, key)

		if otp.String() != hotp {
			t.Error("Expected " + hotp + ", got " + otp.String())
		}
	}
}

//////////////////////////////////////////////////////////////////////////////
// Input

func Test_Input_Sum(t *testing.T) {
	input := NewInput(0x8000000000000001)

	sum, _ := input.Sum()
	actual := hex.EncodeToString(sum)

	expected := "8000000000000001"
	if actual != expected {
		t.Error("Expected 8000000000000001, got \"" + actual + "\"")
	}
}
