package otp

import (
	"encoding/hex"
	"testing"
)

func Test_OTP_String_6(t *testing.T) {
	// See HOTP 5.4
	value, _ := hex.DecodeString("50ef7f19")
	otp := OTP{Value: value, Digits: 6}

	if otp.String() != "872921" {
		t.Error("Expected 872921, got \"" + otp.String() + "\"")
	}
}

func Test_OTP_String_0(t *testing.T) {
	value, _ := hex.DecodeString("50ef7f19")
	otp := OTP{Value: value, Digits: 0}

	if otp.String() != "1357872921" {
		t.Error("Expected 1357872921, got \"" + otp.String() + "\"")
	}
}

func Test_OTP_String_Hex(t *testing.T) {
	// See HOTP 5.4
	value, _ := hex.DecodeString("0050ef7f19")
	otp := OTP{Value: value, Digits: 0}

	if otp.String() != "0050ef7f19" {
		t.Error("Expected 0050ef7f19, got \"" + otp.String() + "\"")
	}
}
