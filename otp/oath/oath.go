package oath

import (
	"crypto/hmac"
	"errors"
	"github.com/tracemeyers/gootp/otp"
	"hash"
)

type generator struct {
	hash   func() hash.Hash
	digits int
}

func NewGenerator(hash func() hash.Hash, digits int) otp.Generator {
	hg := new(generator)
	hg.hash = hash
	hg.digits = digits

	return hg
}

func (g *generator) Generate(input otp.Input, key []byte) (*otp.OTP, error) {
	if input == nil {
		return nil, errors.New("variable 'input' required")
	}

	expectedKeySize := g.hash().Size()
	actualKeySize := len(key)
	if actualKeySize < expectedKeySize {
		return nil, errors.New("invalid key size - expected " +
			string(expectedKeySize) + ", actual " + string(actualKeySize))
	}

	message, err := input.Sum()
	if err != nil {
		return nil, err
	}

	hmac := hmac.New(g.hash, key)
	hmac.Write(message)

	return createOtp(hmac.Sum(nil), g.digits), nil
}

func createOtp(hmac []byte, digits int) *otp.OTP {
	fullOtp := &otp.OTP{Value: hmac}
	if digits == 0 {
		return fullOtp
	}
	return Truncate(fullOtp, digits)
}

func Truncate(in *otp.OTP, digits int) *otp.OTP {
	offset := in.Value[len(in.Value)-1] & 0x0F
	p := in.Value[offset : offset+4]
	p[0] &= 0x7F
	return &otp.OTP{Value: p, Digits: digits}
}
