package totp

import (
	"bytes"
	"crypto"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"github.com/tracemeyers/gootp/otp"
	"github.com/tracemeyers/gootp/otp/oath"
	"time"
)

//////////////////////////////////////////////////////////////////////////////
// Usage:
// gen := totp.NewGenerator(6, crypto.SHA1)
// otp, err := gen.Generate(totp.NewInput(), key)
// expiration := otp.ExpirationOrNil

const (
	DIGITS_MIN = 6
	DIGITS_MAX = 8
)

func NewGenerator(digits int, hashID crypto.Hash) otp.Generator {
	if digits < DIGITS_MIN || DIGITS_MAX < digits {
		return nil
	}

	hasher := hashToHashFunc(hashID)
	if hasher == nil {
		return nil
	}

	gen := new(generator)
	gen.subgen = oath.NewGenerator(hasher, digits)
	return gen
}

func hashToHashFunc(hashID crypto.Hash) func() hash.Hash {
	switch hashID {
	default:
		return nil
	case crypto.SHA1:
		return sha1.New
	case crypto.SHA256:
		return sha256.New
	case crypto.SHA512:
		return sha512.New
	}
}

type generator struct {
	subgen otp.Generator
}

func (g *generator) Generate(in otp.Input, key []byte) (*otp.OTP, error) {
	tin, ok := in.(*input)
	if !ok {
		return nil, errors.New("unexpected input type")
	}
	tin = freezeInput(tin)

	totp, err := g.subgen.Generate(tin, key)
	if err != nil {
		return nil, err
	}

	totp.ExpirationOrNil = tin.expiration()
	return totp, nil
}

//////////////////////////////////////////////////////////////////////////////
// Input

type input struct {
	step      int64
	start     int64
	fetchTime func() int64
}

func NewInput() otp.Input {
	return NewInputCustom(30, 0)
}

func NewInputCustom(step, start int64) otp.Input {
	in := new(input)
	in.step = step
	in.start = start
	in.fetchTime = time.Now().Unix
	return in
}

func newInputConst(step, start, time int64) otp.Input {
	in := new(input)
	in.step = step
	in.start = start
	in.fetchTime = func() int64 { return time }
	return in
}

func (i *input) expiration() time.Time {
	return time.Unix((i.fetchTime()/i.step+1)*i.step, 0)
}

func (i *input) t() int64 {
	return (i.fetchTime() - i.start) / i.step
}

func (i *input) Sum() ([]byte, error) {
	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.BigEndian, i.t())
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func freezeInput(i *input) *input {
	var f = new(input)
	*f = *i
	t := i.fetchTime()
	f.fetchTime = func() int64 { return t }
	return f
}
