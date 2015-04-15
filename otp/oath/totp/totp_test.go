package totp

import (
	"crypto"
	"encoding/hex"
	"testing"
)

//////////////////////////////////////////////////////////////////////////////
// Generator

func Test_NewGenerator_digitsRange(t *testing.T) {
	valid := []int{6, 7, 8}
	for _, digits := range valid {
		g := NewGenerator(digits, crypto.SHA1)
		if g == nil {
			t.Error("Valid digits (" + string(digits) + ") should not fail")
		}
	}

	invalid := []int{5, 9}

	for _, digits := range invalid {
		g := NewGenerator(digits, crypto.SHA1)
		if g != nil {
			t.Error("Invalid digits (" + string(digits) + ") should fail")
		}
	}
}

// The test token shared secret uses the ASCII string value
// "12345678901234567890".  With Time Step X = 30, and the Unix epoch as
// the initial value to count time steps, where T0 = 0, the TOTP
// algorithm will display the following values for specified modes and
// timestamps.
// +-------------+----------+--------+
// |  Time (sec) |   TOTP   |  Mode  |
// +-------------+----------+--------+
// |      59     | 94287082 |  SHA1  |
// |      59     | 46119246 | SHA256 |
// |      59     | 90693936 | SHA512 |
// |  1111111109 | 07081804 |  SHA1  |
// |  1111111109 | 68084774 | SHA256 |
// |  1111111109 | 25091201 | SHA512 |
// |  1111111111 | 14050471 |  SHA1  |
// |  1111111111 | 67062674 | SHA256 |
// |  1111111111 | 99943326 | SHA512 |
// |  1234567890 | 89005924 |  SHA1  |
// |  1234567890 | 91819424 | SHA256 |
// |  1234567890 | 93441116 | SHA512 |
// |  2000000000 | 69279037 |  SHA1  |
// |  2000000000 | 90698825 | SHA256 |
// |  2000000000 | 38618901 | SHA512 |
// | 20000000000 | 65353130 |  SHA1  |
// | 20000000000 | 77737706 | SHA256 |
// | 20000000000 | 47863826 | SHA512 |
// +-------------+--------------+------------------+----------+--------+
func Test_Generate_sha256_spec(t *testing.T) {
	key, _ := hex.DecodeString("31323334353637383930" +
		"31323334353637383930" +
		"31323334353637383930" +
		"31323334353637383930" +
		"31323334353637383930" +
		"31323334353637383930" +
		"31323334")
	keySize := []int{
		20, 32, 64,
	}
	hashes := []crypto.Hash{
		crypto.SHA1, crypto.SHA256, crypto.SHA512,
	}
	timeValues := []int64{
		59, 1111111109, 1111111111, 1234567890, 2000000000, 20000000000,
	}
	// sha1, sha256, sha512, (repeat using next time value...)
	otps := []string{
		"94287082", "46119246", "90693936", "07081804", "68084774", "25091201",
		"14050471", "67062674", "99943326", "89005924", "91819424", "93441116",
		"69279037", "90698825", "38618901", "65353130", "77737706", "47863826",
	}

	for i, expected := range otps {
		gen := NewGenerator(8, hashes[i%3])
		in := newInputConst(30, 0, timeValues[i/3])
		otp, _ := gen.Generate(in, key[0:keySize[i%3]])

		if otp.String() != expected {
			t.Error("Expected " + expected + ", got " + otp.String())
		}
	}
}

//////////////////////////////////////////////////////////////////////////////
// Input

func Test_Input_Sum(t *testing.T) {
	input := newInputConst(30, 0, 31)

	sum, _ := input.Sum()
	actual := hex.EncodeToString(sum)

	expected := "0000000000000001"
	if actual != expected {
		t.Error("Expected 0000000000000001, got \"" + actual + "\"")
	}
}
