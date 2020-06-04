package Tests

import (
	"SecureMPC/SecureMPC"
	"fmt"
	"math/big"
	"testing"
)

func TestPrimeGen(t *testing.T) {
	n, m := SecureMPC.GeneratePrimes(18)
	fmt.Println(n)
	fmt.Println(m)
}

func TestRSAGen(t *testing.T) {
	n, e, d, m := SecureMPC.GenerateRSAKey(512)
	fmt.Println(n)
	fmt.Println(e)
	fmt.Println(d)
	fmt.Println(m)
}

func TestEGCD(t *testing.T) {
	a := big.NewInt(138)
	b := big.NewInt(122)
	gcd, ap, bp := SecureMPC.EGCD(a, b)
	fmt.Println(gcd, ap, bp)
	aa := new(big.Int).Mul(ap, a)
	bb := new(big.Int).Mul(bp, b)
	fmt.Println(new(big.Int).Add(aa, bb))
}
