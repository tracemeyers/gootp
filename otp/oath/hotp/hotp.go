package hotp

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"github.com/tracemeyers/gootp/otp"
	"github.com/tracemeyers/gootp/otp/oath"
)

//////////////////////////////////////////////////////////////////////////////
// Usage:
// gen := hotp.NewGenerator(6)
// otp, err := gen.Generate(hotp.NewInput(counter), key)

//////////////////////////////////////////////////////////////////////////////
// Generator

const (
	DigitsMin = 6
	DigitsMax = 8
)

func NewGenerator(digits int) otp.Generator {
	if digits < DigitsMin || DigitsMax < digits {
		return nil
	}

	return oath.NewGenerator(sha1.New, digits)
}

//////////////////////////////////////////////////////////////////////////////
// Input

type Input interface {
	otp.Input
	Counter() uint64
}

type input struct {
	counter uint64
}

func NewInput(counter uint64) Input {
	in := new(input)
	in.counter = counter

	return in
}

func (i *input) Sum() ([]byte, error) {
	buf := new(bytes.Buffer)

	err := binary.Write(buf, binary.BigEndian, i.counter)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (i *input) Counter() uint64 {
	return i.counter
}
