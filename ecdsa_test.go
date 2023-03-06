package keygen_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha512"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"filippo.io/keygen"
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
	got, err := keygen.ECDSALegacy(c, r)
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(expected, got) {
		t.Error("Go 1.19's GenerateKey disagrees with ECDSALegacy")
	}
}
