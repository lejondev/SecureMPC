package SecureMPC

import (
	"crypto/rand"
	"crypto/sha256"
	"math/big"
)

type SignatureShare struct {
	signature *big.Int
	z         *big.Int
	c         *big.Int
	id        int
}

type ThresholdProtocolData struct {
	l                int      // l is the number of participants
	k                int      // t is the number of adversaries
	n                *big.Int // n is the base of the finite field
	e                *big.Int
	delta            *big.Int
	v                *big.Int
	participants     []*ThresholdPlayer // participants contains the participating players
	verificationKeys []*big.Int
}

// Player contains the information a player has and learns along the way
type ThresholdPlayer struct {
	secretKey       *big.Int                    // secret is the secure info to be shared
	id              int                         // id is the identifier of this player
	knownSignatures map[string]map[int]([]byte) // This is a map from string messages to a map, that maps indices to signatures
	data            *ThresholdProtocolData
}

func ThresholdProtocolSetup(l, k int) *ThresholdProtocolData {
	// n is amount of players, k amount of signatures needed
	n, e, d, m := GenerateRSAKey(511)
	poly := GenerateRandomBigPolynomial(d, m, k-1)
	secrets := GenerateSecretShares(poly, m, l)
	v := GenerateRandomQuadratic(n)
	verificationKeys := GenerateVerificationKeys(secrets, v, n)
	participants := make([]*ThresholdPlayer, l+1)
	emptymap := map[string]map[int][]byte{}

	data := &ThresholdProtocolData{
		l:                l,
		k:                k,
		n:                n,
		e:                e,
		delta:            new(big.Int).MulRange(1, int64(l)), // computes factorial of l
		v:                v,
		participants:     nil,
		verificationKeys: verificationKeys,
	}
	for i := 1; i <= l; i++ {
		participants[i] = &ThresholdPlayer{
			secretKey:       secrets[i],
			id:              i,
			knownSignatures: emptymap,
			data:            data,
		}
	}
	data.participants = participants
	return data
}

func createRecombinationVector(data *ThresholdProtocolData, knownPlayers []int) map[int]*big.Int {
	// Known players is an array of indices of the known players
	recomb := make(map[int]*big.Int, len(knownPlayers))
	// We only compute for the zeroth element, (i = 0 in the paper), as we do not care about the function value at any other point
	for j := range knownPlayers {
		top := 1
		bottom := 1
		for jprime := range knownPlayers {
			if jprime != j {
				top *= -jprime
				bottom *= j - jprime
			}
		}
		deltatop := new(big.Int).Mul(data.delta, big.NewInt(int64(top)))
		lambda0j := new(big.Int).Div(deltatop, big.NewInt(int64(bottom)))
		recomb[j] = lambda0j
	}
	return recomb
}

func (p *ThresholdPlayer) SignHashOfMsg(msg string) *SignatureShare {
	data := p.data
	digest := sha256.Sum256([]byte(msg))
	x := new(big.Int).SetBytes(digest[:])
	twodelta := new(big.Int).Mul(Two, data.delta)
	exponent := new(big.Int).Mul(twodelta, p.secretKey)
	xi := new(big.Int).Exp(x, exponent, data.n)

	// Now we need to construct our proof
	// 512 is bitlength of n, 256 is length of hash output. Division by 8 is to get it in bytes
	securityparam := (512+2*256)/8 + 1
	bytes := make([]byte, securityparam)
	bytes[0] = 1
	// Bytes is equal to exactly 2^1024 when converted to a bigint
	// sets r to be a random number from 0 to 2^(1024)-1
	r, _ := rand.Int(rand.Reader, new(big.Int).SetBytes(bytes))
	vi := data.verificationKeys[p.id]
	// Unsure if below should be modulo n
	fourdelta := new(big.Int).Mul(Two, twodelta)
	xtilde := new(big.Int).Exp(x, fourdelta, data.n)
	xprime := new(big.Int).Exp(xtilde, r, data.n)
	vprime := new(big.Int).Exp(data.v, r, data.n)
	xisquared := new(big.Int).Exp(xi, Two, data.n)
	c := HashSixBigInts(data.v, xtilde, vi, xisquared, vprime, xprime)
	sic := new(big.Int).Mul(p.secretKey, c)
	z := new(big.Int).Add(sic, r)
	signatureShare := &SignatureShare{
		signature: xi,
		z:         z,
		c:         c,
		id:        p.id,
	}
	return signatureShare
}

func HashSixBigInts(v, x, vi, x2, vp, xp *big.Int) *big.Int {
	toHash := v.String() + "|" + x.String() + "|" + vi.String() + "|" + x2.String() + "|" + vp.String() + "|" + xp.String()
	digest := sha256.Sum256([]byte(toHash))
	return new(big.Int).SetBytes(digest[:])
}

func VerifyShare(msg string, signatureShare SignatureShare, data *ThresholdProtocolData) bool {
	digest := sha256.Sum256([]byte(msg))
	x := new(big.Int).SetBytes(digest[:])
	twodelta := new(big.Int).Mul(Two, data.delta)
	fourdelta := new(big.Int).Mul(Two, twodelta)
	xtilde := new(big.Int).Exp(x, fourdelta, data.n)
	id := signatureShare.id
	vi := data.verificationKeys[id]
	xi := signatureShare.signature
	c := signatureShare.c
	z := signatureShare.z
	vpowz := new(big.Int).Exp(data.v, z, data.n)
	negc := new(big.Int).Neg(c)
	vic := new(big.Int).Exp(vi, negc, data.n)
	vprimeNoMod := new(big.Int).Mul(vic, vpowz)
	vprime := new(big.Int).Mod(vprimeNoMod, data.n)
	xtildez := new(big.Int).Exp(xtilde, z, data.n)
	neg2c := new(big.Int).Mul(negc, Two)
	xic := new(big.Int).Exp(xi, neg2c, data.n)
	xprimeNoMod := new(big.Int).Mul(xic, xtildez)
	xprime := new(big.Int).Mod(xprimeNoMod, data.n)
	xisquared := new(big.Int).Exp(xi, Two, data.n)
	cprime := HashSixBigInts(data.v, xtilde, vi, xisquared, vprime, xprime)
	return cprime.Cmp(c) == 0
}
