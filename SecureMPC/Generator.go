package SecureMPC

import (
	"crypto/rand"
	"math/big"
)

func GeneratePrimes(security int) (*big.Int, *big.Int) {
	one := big.NewInt(1)
	two := big.NewInt(2)
	p1, _ := rand.Prime(rand.Reader, security)
	q1, _ := rand.Prime(rand.Reader, security)
	p := new(big.Int).Add(new(big.Int).Mul(p1, two), one)
	q := new(big.Int).Add(new(big.Int).Mul(q1, two), one)
	if p.ProbablyPrime(1) && q.ProbablyPrime(64) {
		return new(big.Int).Mul(p1, q1), new(big.Int).Mul(p, q)
	}
	return GeneratePrimes(security)
}

func GenerateRandomQuadratic(n *big.Int) *big.Int {
	sqrtn := new(big.Int).Sqrt(n)
	v, _ := rand.Int(rand.Reader, sqrtn)
	return new(big.Int).Mul(v, v)
}
