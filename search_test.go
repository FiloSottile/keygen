package keygen

import (
	"crypto/rand"
	"flag"
	"fmt"
	"math"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"filippo.io/bigmod"
)

var searchFlag = flag.String("rsa-search", "", "run specific RSA bruteforce (KEYBITS/SEEDBITS)")
var reportingURL = flag.String("report", "", "report found seeds to this URL via POST")

func TestMain(m *testing.M) {
	flag.Parse()
	if *searchFlag == "" {
		os.Exit(m.Run())
	}

	go func() {
		l, err := net.Listen("tcp", "localhost:")
		if err != nil {
			panic(err)
		}
		fmt.Printf("pprof listening on %s\n", l.Addr().String())
		http.Serve(l, nil)
	}()

	b, s, _ := strings.Cut(*searchFlag, "/")
	bits, err := strconv.Atoi(b)
	if err != nil {
		fmt.Printf("invalid rsa-search value: %v\n", err)
		os.Exit(2)
	}
	size, err := strconv.Atoi(s)
	if err != nil {
		fmt.Printf("invalid rsa-search value: %v\n", err)
		os.Exit(2)
	}
	BruteforceRSACheapSeed(bits, size)
}

func BruteforceRSACheapSeed(bits int, size int) {
	seed := make([]byte, size/8)
	rand.Read(seed)

	var rejectedCandidates int
	var zeroRejections bool
	testingOnlyRejectedCandidates = func(count int) {
		rejectedCandidates += count
		if count == 0 {
			zeroRejections = true
		}
	}

	var gcdBitLen32, gcdBitLenGt32 bool
	testingOnlyGCDBitLen = func(bitLen int) {
		if bitLen == 32 {
			gcdBitLen32 = true
		}
		if bitLen > 32 {
			gcdBitLenGt32 = true
		}
	}

	var cofactorP, cofactorQ, cofactorTwice bool
	testingOnlyNoInverse = func(p, q *bigmod.Modulus) {
		if cofactorP || cofactorQ {
			cofactorTwice = true
			return
		}

		e := bigmod.NewNat().SetUint(65537)
		a, b := p.Nat().SubOne(p), q.Nat().SubOne(q)

		gcd, err := bigmod.NewNat().GCDVarTime(e, a)
		if err != nil {
			panic(err)
		}
		cofactorP = gcd.IsOne() == 0

		gcd, err = bigmod.NewNat().GCDVarTime(e, b)
		if err != nil {
			panic(err)
		}
		cofactorQ = gcd.IsOne() == 0

		if !cofactorP && !cofactorQ {
			panic("neither cofactorP nor cofactorQ set")
		}
	}

	since := time.Now()
	var attempts int64
	var minRejections = math.MaxInt
	for {
		rejectedCandidates = 0
		zeroRejections = false
		gcdBitLen32, gcdBitLenGt32 = false, false
		cofactorP, cofactorQ, cofactorTwice = false, false, false

		k, err := RSA(bits, seed)
		if err != nil {
			fmt.Printf("error generating RSA key: %v\n", err)
			return
		}
		if rejectedCandidates < minRejections {
			minRejections = rejectedCandidates
			fmt.Printf("bits=%d seed=%x rejections=%d zero=%v\n", bits, seed, rejectedCandidates, zeroRejections)
		}
		if gcdBitLen32 {
			fmt.Printf("bits=%d seed=%x GCD BITLEN 32\n", bits, seed)
			reportFound("FOUND RSA seed=%x bits=%d GCD BITLEN 32", seed, bits)
		}
		if gcdBitLenGt32 {
			fmt.Printf("bits=%d seed=%x GCD BITLEN > 32\n", bits, seed)
			reportFound("FOUND RSA seed=%x bits=%d GCD BITLEN > 32", seed, bits)
		}
		if bits == 2048+16 && k.D.BitLen() < 2048 {
			fmt.Printf("bits=%d seed=%x len(d)=%d\n", bits, seed, k.D.BitLen())
		}
		if cofactorP {
			fmt.Printf("bits=%d seed=%x rejections=%d COFACTOR P\n", bits, seed, rejectedCandidates)
		}
		if cofactorQ {
			fmt.Printf("bits=%d seed=%x rejections=%d COFACTOR Q\n", bits, seed, rejectedCandidates)
		}
		if cofactorP && cofactorQ {
			fmt.Printf("bits=%d seed=%x COFACTOR P and Q\n", bits, seed)
			reportFound("FOUND RSA seed=%x bits=%d COFACTOR P and Q", seed, bits)
		}
		if cofactorTwice {
			fmt.Printf("bits=%d seed=%x COFACTOR TWICE\n", bits, seed)
			reportFound("FOUND RSA seed=%x bits=%d COFACTOR TWICE", seed, bits)
		}

		for i := range seed {
			seed[i]++
			if seed[i] != 0 {
				break
			}
		}

		attempts++
		if attempts%(1<<10) == 0 {
			elapsed := time.Since(since)
			estimated := elapsed << (32 - 10)
			fmt.Printf("%d keys in %s (%.2f keys/s), 2^32 estimated in %.2f core-years\n",
				attempts, elapsed, float64(attempts)/elapsed.Seconds(),
				estimated.Hours()/24/365)
			since = time.Now()
			attempts = 0
		}
	}
}

var httpClient = &http.Client{Timeout: 10 * time.Second}

func reportFound(format string, a ...any) {
	if *reportingURL == "" {
		return
	}
	data := fmt.Sprintf(format, a...)
	req, err := http.NewRequest("POST", *reportingURL, strings.NewReader(data))
	if err != nil {
		fmt.Printf("failed to create report request: %v\n", err)
		return
	}
	req.Header.Set("Content-Type", "text/plain")
	resp, err := httpClient.Do(req)
	if err != nil {
		fmt.Printf("failed to send report: %v\n", err)
		return
	}
	resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		fmt.Printf("report returned status %s\n", resp.Status)
	}
}
