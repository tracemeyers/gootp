package otp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"time"
)

type OTP struct {
	Value           []byte
	Digits          int
	ExpirationOrNil time.Time
}

func (otp *OTP) String() string {
	if len(otp.Value) <= 4 {
		buf := bytes.NewBuffer(otp.Value)

		var value uint32
		err := binary.Read(buf, binary.BigEndian, &value)
		if err != nil {
			fmt.Printf("err:", err)
		}

		if otp.Digits == 0 {
			return fmt.Sprintf("%d", value)
		} else {
			digits := otp.Digits
			if digits > 10 {
				digits = 10
			}

			decimal := int(value % uint32(math.Pow10(digits)))
			return fmt.Sprintf("%0*d", digits, decimal)
		}
	}

	return hex.EncodeToString(otp.Value)
}

type Input interface {
	Sum() ([]byte, error)
}

type Generator interface {
	Generate(input Input, key []byte) (*OTP, error)
}
