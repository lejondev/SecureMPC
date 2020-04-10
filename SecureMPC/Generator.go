package SecureMPC

import (
	"crypto/rand"
	"math/big"
	"strconv"
)

var One = big.NewInt(1)
var Two = big.NewInt(2)

// Public exponent is a prime e > l
var e = big.NewInt(65537)

// GeneratePrimes will generate two random primes n=p*q and m=p'*q'
// security is the length of the primes p,q used
func GeneratePrimes(security int) (*big.Int, *big.Int) {
	pprime, _ := rand.Prime(rand.Reader, security-1)
	qprime, _ := rand.Prime(rand.Reader, security-1)
	p := new(big.Int).Add(new(big.Int).Mul(pprime, Two), One)
	q := new(big.Int).Add(new(big.Int).Mul(qprime, Two), One)
	if p.ProbablyPrime(8) && q.ProbablyPrime(8) {
		return new(big.Int).Mul(p, q), new(big.Int).Mul(pprime, qprime)
	}
	return GeneratePrimes(security)
}

func GenerateRandomQuadratic(n *big.Int) *big.Int {
	v, _ := rand.Int(rand.Reader, n)
	return new(big.Int).Mul(v, v)
}

// Generates the parts of the RSA key, where PubKey=(n,e) and SecKey=(n,d)
// n is the RSA modulus
// e is the public exponent
// d is the private exponent
// m is the RSA message to be signed / encrypted
func GenerateRSAKey(security int) (*big.Int, *big.Int, *big.Int, *big.Int) {
	n, m := GeneratePrimes(security)
	// This mod inverse should not be able to fail, as m should be a product of two primes, none of which can be equal to e
	d := new(big.Int).ModInverse(e, m)
	return n, e, d, m
}

type BigPolynomial struct {
	constant *big.Int
	coefs    []*big.Int
}

func (p *BigPolynomial) eval(x *big.Int, base *big.Int) *big.Int {
	constant := p.constant
	for i := 0; i < len(p.coefs); i++ {
		exp := big.NewInt(int64(i + 1))
		xpowi := new(big.Int).Exp(x, exp, base)
		mula := (new(big.Int)).Mul(xpowi, p.coefs[i])
		constant = new(big.Int).Add(constant, mula)
	}
	return new(big.Int).Mod(constant, base)
}

func (p *BigPolynomial) String() string {
	str := p.constant.String()
	for i := 0; i < len(p.coefs); i++ {
		var exp = i + 1
		str = str + " + " + p.coefs[i].String() + "x^" + strconv.Itoa(exp)
	}
	return str
}

// GenerateRandomBigPolynomial creates a random polynomial, such that f(0)=d, where
// d is the secret to be shared (shamir secret sharing)
func GenerateRandomBigPolynomial(zero *big.Int, base *big.Int, degree int) *BigPolynomial {
	coefs := make([]*big.Int, degree)
	for i := 0; i < degree; i++ {
		coefs[i], _ = rand.Int(rand.Reader, base)
	}
	return &BigPolynomial{
		constant: zero,
		coefs:    coefs,
	}
}

// GenerateSecretShares will use a polynomial to generate secret key shares
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
