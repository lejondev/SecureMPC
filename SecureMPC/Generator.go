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

// GeneratePrimes will generate two modulus such that for primes p, q, p', q',
// we have n=p*q and m=p'*q' and p=2p'+1 q=2q' + 1
// security is the length of the RSA Modulus
func GeneratePrimes(security int) (*big.Int, *big.Int) {
	var helper func() (*big.Int, *big.Int)
	certainty := 128
	helper = func() (*big.Int, *big.Int) {
		qprime, _ := rand.Prime(rand.Reader, (security/2)-1)
		q := new(big.Int).Add(new(big.Int).Mul(qprime, Two), One)
		if q.ProbablyPrime(certainty) {
			return q, qprime
		}
		return helper()
	}
	p, pprime := helper()
	q, qprime := helper()
	return new(big.Int).Mul(p, q), new(big.Int).Mul(pprime, qprime)
}

// GenerateRandomQuadratic will create a number v^2, where 0<v<n is uniformly random
func GenerateRandomQuadratic(n *big.Int) *big.Int {
	v, _ := rand.Int(rand.Reader, n)
	return new(big.Int).Mul(v, v)
}

// Generates the parts of the RSA key, where PubKey=(n,e) and SecKey=(n,d)
// n is the RSA modulus
// e is the public exponent
// d is the private exponent
// m is size of the quadratic subgroup
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

// GenerateRandomBigPolynomial creates a random polynomial, such that
//	f(0)=eval_zero
//	s_i = f(i) mod field_base
// where
// eval_zero is the secret to be shared,
// fbase is the modulo base and
// s_i the shares to be distributed
func GenerateRandomBigPolynomial(eval_zero *big.Int, base *big.Int, degree int) *BigPolynomial {
	coefs := make([]*big.Int, degree)
	for i := 0; i < degree; i++ {
		coefs[i], _ = rand.Int(rand.Reader, base)
	}
	return &BigPolynomial{
		constant: eval_zero,
		coefs:    coefs,
	}
}

// GenerateSecretShares will use a polynomial to generate secret key shares for l participants
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

func EGCD(a, b *big.Int) (*big.Int, *big.Int, *big.Int) {
	var c, d *big.Int
	aSmallerThanb := a.Cmp(b) < 0
	if aSmallerThanb {
		c = b
		d = a
	} else {
		c = a
		d = b
	}
	q := new(big.Int).Div(c, d)
	qd := new(big.Int).Mul(q, d)
	r := new(big.Int).Sub(c, qd)
	aprime := big.NewInt(1)
	bprime := new(big.Int).Sub(big.NewInt(0), q)
	apprime := big.NewInt(0)
	bpprime := big.NewInt(1)
	for r.Cmp(big.NewInt(0)) != 0 {
		c = new(big.Int).Set(d)
		d = new(big.Int).Set(r)
		q = new(big.Int).Div(c, d)
		qd = new(big.Int).Mul(q, d)
		r = new(big.Int).Sub(c, qd)
		tmpa := new(big.Int).Set(aprime)
		tmpb := new(big.Int).Set(bprime)
		qa := new(big.Int).Mul(q, aprime)
		qb := new(big.Int).Mul(q, bprime)
		aprime = new(big.Int).Sub(apprime, qa)
		bprime = new(big.Int).Sub(bpprime, qb)
		apprime = new(big.Int).Set(tmpa)
		bpprime = new(big.Int).Set(tmpb)
	}
	if aSmallerThanb {
		return d, bpprime, apprime
	} else {
		return d, apprime, bpprime
	}

}
