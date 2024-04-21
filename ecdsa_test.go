package keygen

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"filippo.io/bigmod"
	drbg "github.com/canonical/go-sp800.90a-drbg"
	"golang.org/x/crypto/hkdf"
)

func testAllCurves(t *testing.T, f func(*testing.T, elliptic.Curve)) {
	tests := []struct {
		name  string
		curve elliptic.Curve
	}{
		{"P256", elliptic.P256()},
		{"P384", elliptic.P384()},
		{"P521", elliptic.P521()},
	}
	for _, test := range tests {
		curve := test.curve
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			f(t, curve)
		})
	}
}

func TestECDSAShortSecret(t *testing.T) {
	testAllCurves(t, testECDSAShortSecret)
}

func testECDSAShortSecret(t *testing.T, c elliptic.Curve) {
	_, err := ECDSA(c, make([]byte, 15))
	if err == nil {
		t.Error("expected error on short secret")
	}
}

func TestECDSAEmptySecret(t *testing.T) {
	testAllCurves(t, testECDSAEmptySecret)
}

func testECDSAEmptySecret(t *testing.T, c elliptic.Curve) {
	_, err := ECDSA(c, nil)
	if err == nil {
		t.Error("expected error on empty secret")
	}
}

func TestECDSAUnsupportedCurve(t *testing.T) {
	_, err := ECDSA(elliptic.P224(), make([]byte, 16))
	if err == nil {
		t.Error("expected error on unsupported curve")
	}
}

func TestECDSASecretLengths(t *testing.T) {
	testAllCurves(t, testECDSASecretLengths)
}

func testECDSASecretLengths(t *testing.T, c elliptic.Curve) {
	for l := 16; l < 128; l++ {
		l := l
		t.Run(strconv.Itoa(l), func(t *testing.T) {
			t.Parallel()
			k, err := ECDSA(c, make([]byte, l))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := ecdsa.SignASN1(rand.Reader, k, make([]byte, 32)); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestECDSADLength(t *testing.T) {
	testAllCurves(t, testECDSADLength)
}

func testECDSADLength(t *testing.T, c elliptic.Curve) {
	// D might randomly be shorter than N, but it should not be consistently so.
	// This test should catch if we mistakenly truncate D.
	for i := 0; i < 64; i++ {
		secret := make([]byte, 16)
		rand.Read(secret)
		k, err := ECDSA(c, secret)
		if err != nil {
			t.Fatal(err)
		}
		if k.D.Cmp(c.Params().N) >= 0 {
			t.Error("D is greater than N")
		}
		if k.D.BitLen() < c.Params().N.BitLen()-64 {
			t.Error("D is too short")
		}
		if k.D.BitLen() == c.Params().N.BitLen() {
			return
		}
	}
	t.Error("D length never matched N length")
}

func TestECDSARejection(t *testing.T) {
	var rejectionSamplingLooped bool
	testingOnlyRejectionSamplingLooped = func() {
		rejectionSamplingLooped = true
	}
	defer func() { testingOnlyRejectionSamplingLooped = nil }()
	secret, _ := hex.DecodeString("b432f9be30890480298218510559aed7")
	k, err := ECDSA(elliptic.P256(), secret)
	if err != nil {
		t.Fatal(err)
	}
	if !rejectionSamplingLooped {
		t.Error("rejection sampling did not loop")
	}
	if k.D.Cmp(elliptic.P256().Params().N) >= 0 {
		t.Error("D is greater than N")
	}
	if k.D.BitLen() < elliptic.P256().Params().N.BitLen()-64 {
		t.Error("D is too short")
	}
	if _, err := ecdsa.SignASN1(rand.Reader, k, make([]byte, 32)); err != nil {
		t.Error(err)
	}
}

func TestHMACDRBG(t *testing.T) {
	testAllCurves(t, testHMACDRBG)
}

func testHMACDRBG(t *testing.T, c elliptic.Curve) {
	entropy := make([]byte, 16)
	rand.Read(entropy)
	personalization := make([]byte, 6)
	rand.Read(personalization)

	canonicalDRBG, err := drbg.NewHMACWithExternalEntropy(
		crypto.SHA256, entropy, nil, personalization, nil)
	if err != nil {
		t.Fatal(err)
	}
	ourDRBG := hmacDRBG(entropy, personalization)

	N := bigmod.NewModulusFromBig(c.Params().N)
	canonical := make([]byte, N.Size())
	our := make([]byte, N.Size())

	if _, err := canonicalDRBG.Read(canonical); err != nil {
		t.Fatal(err)
	}
	if err := ourDRBG(our); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(canonical, our) {
		t.Error("HMAC_DRBG output does not match")
	}

	if _, err := canonicalDRBG.Read(canonical); err != nil {
		t.Fatal(err)
	}
	if err := ourDRBG(our); err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(canonical, our) {
		t.Error("HMAC_DRBG output does not match")
	}
}

func TestECDSALegacyDLength(t *testing.T) {
	testAllCurves(t, testECDSALegacyDLength)
}

func testECDSALegacyDLength(t *testing.T, c elliptic.Curve) {
	// D might randomly be shorter than N, but it should not be consistently so.
	// This test should catch if we mistakenly truncate D.
	for i := 0; i < 64; i++ {
		k, err := ECDSALegacy(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if k.D.Cmp(c.Params().N) >= 0 {
			t.Error("D is greater than N")
		}
		if k.D.BitLen() < c.Params().N.BitLen()-64 {
			t.Error("D is too short")
		}
		if k.D.BitLen() == c.Params().N.BitLen() {
			return
		}
	}
	t.Error("D length never matched N length")
}

func TestECDSALegacy(t *testing.T) {
	if !strings.HasPrefix(runtime.Version(), "go1.19") {
		t.Skip()
	}
	testAllCurves(t, testECDSALegacy)
}

func testECDSALegacy(t *testing.T, c elliptic.Curve) {
	r := hkdf.New(sha512.New, []byte("test"), nil, nil)
	expected, err := ecdsa.GenerateKey(c, r)
	if err != nil {
		t.Fatal(err)
	}

	r = hkdf.New(sha512.New, []byte("test"), nil, nil)
	got, err := ECDSALegacy(c, r)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, got) {
		t.Error("Go 1.19's GenerateKey disagrees with ECDSALegacy")
	}
}
