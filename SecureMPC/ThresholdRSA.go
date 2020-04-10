package SecureMPC

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

type SignatureShare struct {
	signature *big.Int
	z         *big.Int
	c         *big.Int
	id        int
}

type ThresholdProtocolData struct {
	L                int // L is the number of Participants
	K                int
	N                *big.Int // N is the base of the finite field
	E                *big.Int
	Delta            *big.Int
	V                *big.Int
	Participants     []*ThresholdPlayer // Participants contains the participating players
	VerificationKeys []*big.Int
}

// Player contains the information a player has and learns along the way
type ThresholdPlayer struct {
	secretKey       *big.Int                           // secret is the secure info to be shared
	Id              int                                // Id is the identifier of this player
	KnownSignatures map[string]map[int]*SignatureShare // This is a map from string messages to a map, that maps indices to signatures
	Data            *ThresholdProtocolData
}

func ThresholdProtocolSetup(l, k int) *ThresholdProtocolData {
	// N is amount of players, K amount of signatures needed
	n, e, d, m := GenerateRSAKey(257) // Maybe it should be higher but it takes an eternity
	poly := GenerateRandomBigPolynomial(d, m, k-1)
	secrets := GenerateSecretShares(poly, m, l)
	v := GenerateRandomQuadratic(n)
	verificationKeys := GenerateVerificationKeys(secrets, v, n)
	participants := make([]*ThresholdPlayer, l+1)
	emptymap := map[string]map[int]*SignatureShare{}
	data := &ThresholdProtocolData{
		L:                l,
		K:                k,
		N:                n,
		E:                e,
		Delta:            new(big.Int).MulRange(1, int64(l)), // computes factorial of L
		V:                v,
		Participants:     nil,
		VerificationKeys: verificationKeys,
	}
	for i := 1; i <= l; i++ {
		participants[i] = &ThresholdPlayer{
			secretKey:       secrets[i],
			Id:              i,
			KnownSignatures: emptymap,
			Data:            data,
		}
	}
	data.Participants = participants
	return data
}

func (p *ThresholdPlayer) SignHashOfMsg(msg string) *SignatureShare {
	data := p.Data
	digest := sha256.Sum256([]byte(msg))
	x := new(big.Int).SetBytes(digest[:])
	twodelta := new(big.Int).Mul(Two, data.Delta)
	exponent := new(big.Int).Mul(twodelta, p.secretKey)
	xi := new(big.Int).Exp(x, exponent, data.N)
	// Now we need to construct our proof
	// 512 is bitlength of N, 256 is length of hash output. Division by 8 is to get it in bytes
	securityparam := (512+2*256)/8 + 1
	bytes := make([]byte, securityparam)
	bytes[0] = 1
	// Bytes is equal to exactly 2^1024 when converted to a bigint
	// sets r to be a random number from 0 to 2^(1024)-1
	r, _ := rand.Int(rand.Reader, new(big.Int).SetBytes(bytes))
	vi := data.VerificationKeys[p.Id]
	// Unsure if below should be modulo N
	fourdelta := new(big.Int).Mul(Two, twodelta)
	xtilde := new(big.Int).Exp(x, fourdelta, data.N)
	xprime := new(big.Int).Exp(xtilde, r, data.N)
	vprime := new(big.Int).Exp(data.V, r, data.N)
	xisquared := new(big.Int).Exp(xi, Two, data.N)
	c := HashSixBigInts(data.V, xtilde, vi, xisquared, vprime, xprime)
	sic := new(big.Int).Mul(p.secretKey, c)
	z := new(big.Int).Add(sic, r)
	signatureShare := &SignatureShare{
		signature: xi,
		z:         z,
		c:         c,
		id:        p.Id,
	}
	if len(p.KnownSignatures[msg]) == 0 {
		p.KnownSignatures[msg] = map[int]*SignatureShare{}
	}
	p.KnownSignatures[msg][p.Id] = signatureShare
	return signatureShare
}

func HashSixBigInts(v, x, vi, x2, vp, xp *big.Int) *big.Int {
	toHash := v.String() + "|" + x.String() + "|" + vi.String() + "|" + x2.String() + "|" + vp.String() + "|" + xp.String()
	digest := sha256.Sum256([]byte(toHash))
	return new(big.Int).SetBytes(digest[:])
}

func VerifyShare(msg string, signatureShare *SignatureShare, data *ThresholdProtocolData) bool {
	digest := sha256.Sum256([]byte(msg))
	x := new(big.Int).SetBytes(digest[:])
	twodelta := new(big.Int).Mul(Two, data.Delta)
	fourdelta := new(big.Int).Mul(Two, twodelta)
	xtilde := new(big.Int).Exp(x, fourdelta, data.N)
	id := signatureShare.id
	vi := data.VerificationKeys[id]
	xi := signatureShare.signature
	c := signatureShare.c
	z := signatureShare.z
	vpowz := new(big.Int).Exp(data.V, z, data.N)
	negc := new(big.Int).Neg(c)
	vic := new(big.Int).Exp(vi, negc, data.N)
	vprimeNoMod := new(big.Int).Mul(vic, vpowz)
	vprime := new(big.Int).Mod(vprimeNoMod, data.N)
	xtildez := new(big.Int).Exp(xtilde, z, data.N)
	neg2c := new(big.Int).Mul(negc, Two)
	xic := new(big.Int).Exp(xi, neg2c, data.N)
	xprimeNoMod := new(big.Int).Mul(xic, xtildez)
	xprime := new(big.Int).Mod(xprimeNoMod, data.N)
	xisquared := new(big.Int).Exp(xi, Two, data.N)
	cprime := HashSixBigInts(data.V, xtilde, vi, xisquared, vprime, xprime)
	return cprime.Cmp(c) == 0
}

func (p *ThresholdPlayer) AddShare(msg string, signatureShare *SignatureShare) {
	if VerifyShare(msg, signatureShare, p.Data) {
		if len(p.KnownSignatures[msg]) == 0 {
			p.KnownSignatures[msg] = map[int]*SignatureShare{}
		}
		p.KnownSignatures[msg][signatureShare.id] = signatureShare
		return
	}
	fmt.Println("Verification of share failed")
}

func CreateSignature(msg string, data *ThresholdProtocolData, signatureShares map[int]*SignatureShare) (*big.Int, bool) {
	digest := sha256.Sum256([]byte(msg))
	x := new(big.Int).SetBytes(digest[:])
	if len(signatureShares) < data.K {
		fmt.Println("Too few known signature shares")
		return big.NewInt(0), false
	}
	w := big.NewInt(1)
	for i, v := range signatureShares {
		// delta_i(0), because we evaluate h(x) at x=0
		// top/bottom = (0-j)/(i-j)
		top := 1
		bottom := 1
		for j := range signatureShares {
			if j != i {
				top = top * -j
				bottom = bottom * (i - j)
			}
		}
		topB := big.NewInt(int64(top))
		bottomB := big.NewInt(int64(bottom))
		topBDelta := new(big.Int).Mul(topB, data.Delta)
		lambda := new(big.Int).Div(topBDelta, bottomB)
		xipow := new(big.Int).Exp(v.signature, lambda, data.N)
		w.Mul(w, xipow)
		w.Mod(w, data.N) // might not be needed
	}
	w.Exp(w, Two, data.N) // To do essentially mod m, might not strictly be necessary as long as everyone behaves properly
	twodelta := new(big.Int).Mul(data.Delta, Two)
	fourdeltasquared := new(big.Int).Mul(twodelta, twodelta)
	// GCD sets a and b to the correct values we need such that e'a + eb = 1
	// These numbers are actually constant, we could consider throwing them in the Data structure
	a := big.NewInt(0)
	b := big.NewInt(0)
	_ = new(big.Int).GCD(a, b, fourdeltasquared, data.E) // This is actually a constant that is known
	wa := new(big.Int).Exp(w, a, data.N)
	xb := new(big.Int).Exp(x, b, data.N)
	y := new(big.Int).Mul(wa, xb)
	ye := new(big.Int).Exp(y, data.E, data.N)
	return y, ye.Cmp(x) == 0 // At this point x and y^E should be equal
}

func VerifySignature(msg string, y *big.Int, data *ThresholdProtocolData) bool {
	digest := sha256.Sum256([]byte(msg))
	x := new(big.Int).SetBytes(digest[:])
	ye := new(big.Int).Exp(y, data.E, data.N)
	return ye.Cmp(x) == 0
}

func SendSignatureShare(msg string, signatureShare *SignatureShare, receiverID int, data *ThresholdProtocolData) {
	data.Participants[receiverID].OnReceiveSignatureShare(msg, signatureShare)
}

func (p *ThresholdPlayer) OnReceiveSignatureShare(msg string, signatureShare *SignatureShare) {
	p.AddShare(msg, signatureShare)
}

func DistributeSignatureShare(msg string, signatureShare *SignatureShare, data *ThresholdProtocolData) {
	for i := 1; i <= data.L; i++ {
		SendSignatureShare(msg, signatureShare, i, data)
	}
}

func RequestSignatures(msg string, data *ThresholdProtocolData) []*SignatureShare {
	signatures := make([]*SignatureShare, data.L)
	for i := 1; i <= data.L; i++ {
		signatures[i-1] = data.Participants[i].SignHashOfMsg(msg)
	}
	return signatures
}

func FullSignAndDistribute(msg string, data *ThresholdProtocolData) {
	signatures := RequestSignatures(msg, data)
	fmt.Println("Signatures made")
	for _, signature := range signatures {
		DistributeSignatureShare(msg, signature, data)
	}
}
