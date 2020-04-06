package SecureMPC

import (
	"crypto/rand"
	"math/big"
)

var One = big.NewInt(1)
var Two = big.NewInt(2)

var PublicExponent = big.NewInt(65537)

func GeneratePrimes(security int) (*big.Int, *big.Int) {
	p1, _ := rand.Prime(rand.Reader, security/2)
	q1, _ := rand.Prime(rand.Reader, security/2)
	p := new(big.Int).Add(new(big.Int).Mul(p1, Two), One)
	q := new(big.Int).Add(new(big.Int).Mul(q1, Two), One)
	if p.ProbablyPrime(8) && q.ProbablyPrime(8) {
		return new(big.Int).Mul(p1, q1), new(big.Int).Mul(p, q)
	}
	return GeneratePrimes(security)
}

func GenerateRandomQuadratic(n *big.Int) *big.Int {
	sqrtn := new(big.Int).Sqrt(n)
	v, _ := rand.Int(rand.Reader, sqrtn)
	return new(big.Int).Mul(v, v)
}

func GenerateRSAKey(security int) (*big.Int, *big.Int, *big.Int, *big.Int) {
	n, m := GeneratePrimes(security)

	// This mod inverse should not be able to fail, as m should be a product of two primes, none of which can be equal to E
	secretKey := new(big.Int).ModInverse(PublicExponent, m)

	return n, PublicExponent, secretKey, m
}

type BigPolynomial struct {
	constant *big.Int
	coefs    []*big.Int
}

func (p *BigPolynomial) eval(x *big.Int, base *big.Int) *big.Int {
	constant := p.constant
	for i := 0; i < len(p.coefs); i++ {
		var exp = big.NewInt(int64(i + 1))
		xpowi := new(big.Int).Exp(x, exp, base)
		mula := (new(big.Int)).Mul(xpowi, p.coefs[i])
		constant.Add(constant, mula)
	}
	return new(big.Int).Mod(constant, base)
}

func GenerateRandomBigPolynomial(zero *big.Int, base *big.Int, degree int) *BigPolynomial {
	coefs := make([]*big.Int, degree)
	for i := 0; i < degree; i++ {
		coefs[i], _ = rand.Int(rand.Reader, base) // Should probably be secure random
	}
	return &BigPolynomial{
		constant: zero,
		coefs:    coefs,
	}
}

func GenerateSecretShares(poly *BigPolynomial, base *big.Int, l int) []*big.Int {
	shares := make([]*big.Int, l+1)
	for i := 1; i <= l; i++ {
		shares[i] = poly.eval(big.NewInt(int64(i)), base)
	}
	return shares
}

func GenerateVerificationKeys(secrets []*big.Int, v *big.Int, n *big.Int) []*big.Int {
	verificationKeys := make([]*big.Int, len(secrets))
	for i := 1; i < len(secrets); i++ {
		verificationKeys[i] = new(big.Int).Exp(v, secrets[i], n)
	}
	return verificationKeys
}
