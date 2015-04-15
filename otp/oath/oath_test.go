package oath

import (
	"crypto/sha1"
	"encoding/hex"
	"github.com/tracemeyers/gootp/otp"
	"testing"
)

type sha1Inputs struct {
	otp.Input
}

func (s *sha1Inputs) Sum() ([]byte, error) {
	return []byte("input"), nil
}

// echo -n "input" | openssl sha1 -hmac "00000000000000000000"
func Test_Generate_sha1(t *testing.T) {
	g := NewGenerator(sha1.New, 0)
	otp, _ := g.Generate(new(sha1Inputs), []byte("00000000000000000000"))

	actual := hex.EncodeToString(otp.Value)
	if actual != "c92f5492209b3ee52062cfeb6010719c49a98906" {
		t.Error("Expected c92f5492209b3ee52062cfeb6010719c49a98906, got \"" +
			actual + "\"")
	}
}

func Test_Generate_sha1_fail_keyTooSmall(t *testing.T) {
	g := NewGenerator(sha1.New, 0)
	_, err := g.Generate(new(sha1Inputs), []byte("000000000000000000"))

	if err == nil {
		t.Error("Expected error")
	}
}

func Test_Generate_sha1_fail_nilInput(t *testing.T) {
	g := NewGenerator(sha1.New, 0)
	_, err := g.Generate(nil, []byte("00000000000000000000"))

	if err == nil {
		t.Error("Expected error")
	}
}

// See HOTP 5.4
func Test_Truncate(t *testing.T) {
	raw, _ := hex.DecodeString("1f8698690e02ca16618550ef7f19da8e945b555a")
	in := otp.OTP{Value: raw}
	out := Truncate(&in, 6)

	actual := hex.EncodeToString(out.Value)
	if actual != "50ef7f19" {
		t.Error("Expected 50ef7f19, got \"" + actual + "\"")
	}

	if out.Digits != 6 {
		t.Error("Expected 6 digits, got \"" + string(out.Digits) + "\"")
	}
}
