package keygen

import (
	"bytes"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"strconv"
	"testing"

	drbg "github.com/canonical/go-sp800.90a-drbg"
)

func TestHMACDRBG(t *testing.T) {
	for _, entropySize := range []int{16, 24, 31, 32, 64} {
		for _, persSize := range []int{17 /* RSA */, 23 /* ECDSA */} {
			for _, outputSize := range []int{
				(elliptic.P256().Params().N.BitLen() + 7) / 8,
				(elliptic.P384().Params().N.BitLen() + 7) / 8,
				(elliptic.P521().Params().N.BitLen() + 7) / 8,
				2048 / 16,
				(2048 + 16) / 16,
				3072 / 16,
				4096 / 16,
				8192 / 16,
			} {
				name := "entropy=" + strconv.Itoa(entropySize) +
					" pers=" + strconv.Itoa(persSize) +
					" output=" + strconv.Itoa(outputSize)
				t.Run(name, func(t *testing.T) {
					t.Parallel()
					testHMACDRBG(t, entropySize, persSize, outputSize)
				})
			}
		}
	}
}

func testHMACDRBG(t *testing.T, entropySize, persSize, outputSize int) {
	entropy := make([]byte, entropySize)
	rand.Read(entropy)
	personalization := make([]byte, persSize)
	rand.Read(personalization)

	canonicalDRBG, err := drbg.NewHMACWithExternalEntropy(
		crypto.SHA256, entropy, nil, personalization, nil)
	if err != nil {
		t.Fatal(err)
	}
	ourDRBG := hmacDRBG(entropy, personalization)

	for i := range 10 {
		canonical := make([]byte, outputSize)
		our := make([]byte, outputSize)

		if _, err := canonicalDRBG.Read(canonical); err != nil {
			t.Fatal(err)
		}
		if err := ourDRBG(our); err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(canonical, our) {
			t.Errorf("output mismatch on iteration %d", i)
		}
	}
}
