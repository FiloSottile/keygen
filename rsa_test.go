package keygen

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"testing"
)

func TestRSAShortSecret(t *testing.T) {
	_, err := RSA(2048, make([]byte, 15))
	if err == nil {
		t.Error("expected error on short secret")
	}
}

func TestRSAEmptySecret(t *testing.T) {
	_, err := RSA(2048, nil)
	if err == nil {
		t.Error("expected error on empty secret")
	}
}

func TestRSASecretLenghts(t *testing.T) {
	maxSize := 128
	if testing.Short() {
		maxSize = 64
	}
	for l := 16; l < maxSize; l++ {
		t.Run(strconv.Itoa(l), func(t *testing.T) {
			t.Parallel()
			k, err := RSA(2048, make([]byte, l))
			if err != nil {
				t.Fatal(err)
			}
			sig, err := rsa.SignPSS(rand.Reader, k, crypto.SHA256, make([]byte, 32), nil)
			if err != nil {
				t.Error(err)
			}
			if err := rsa.VerifyPSS(&k.PublicKey, crypto.SHA256, make([]byte, 32), sig, nil); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestRSAKeySizeTooSmall(t *testing.T) {
	_, err := RSA(1024, make([]byte, 32))
	if err == nil {
		t.Error("expected error on too small key size")
	}
}

func TestRSAKeySizeTooLarge(t *testing.T) {
	_, err := RSA(65536, make([]byte, 32))
	if err == nil {
		t.Error("expected error on too large key size")
	}
}

func TestRSAKeySizeNotMultipleOf16(t *testing.T) {
	_, err := RSA(2048+8, make([]byte, 32))
	if err == nil {
		t.Error("expected error on key size not multiple of 16")
	}
}

func TestRSAKeySizes(t *testing.T) {
	maxSize := 8192
	if testing.Short() {
		maxSize = 3072
	}
	for bits := 2048; bits <= maxSize; bits += 16 {
		t.Run(strconv.Itoa(bits), func(t *testing.T) {
			t.Parallel()
			k, err := RSA(bits, make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			sig, err := rsa.SignPSS(rand.Reader, k, crypto.SHA256, make([]byte, 32), nil)
			if err != nil {
				t.Error(err)
			}
			if err := rsa.VerifyPSS(&k.PublicKey, crypto.SHA256, make([]byte, 32), sig, nil); err != nil {
				t.Error(err)
			}
		})
	}
}

//go:embed testdata/rsa.json
var rsaVectors []byte

func TestRSAVectors(t *testing.T) {
	var vectors []struct {
		Bits  int    `json:"bits"`
		Seed  []byte `json:"seed"`
		PKCS8 []byte `json:"private_key_pkcs8"`
	}
	if err := json.Unmarshal(rsaVectors, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors {
		t.Run(fmt.Sprintf("%d-%s", v.Bits, hex.EncodeToString(v.Seed)), func(t *testing.T) {
			t.Parallel()
			k, err := RSA(v.Bits, v.Seed)
			if err != nil {
				t.Fatal(err)
			}
			exp, err := x509.ParsePKCS8PrivateKey(v.PKCS8)
			if err != nil {
				t.Fatalf("failed to parse expected PKCS8: %v", err)
			}
			if !k.Equal(exp) {
				t.Errorf("RSA key does not match")
			}
		})
	}
}
