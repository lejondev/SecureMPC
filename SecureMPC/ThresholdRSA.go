package SecureMPC

import "math/big"

type ThresholdProtocolData struct {
	l                int      // l is the number of participants
	k                int      // t is the number of adversaries
	n                *big.Int // n is the base of the finite field
	e                *big.Int
	participants     []*ThresholdPlayer // participants contains the participating players
	verificationKeys []*big.Int
}

// Player contains the information a player has and learns along the way
type ThresholdPlayer struct {
	secretKey       *big.Int                    // secret is the secure info to be shared
	id              int                         // id is the identifier of this player
	knownSignatures map[string]map[int]([]byte) // This is a map from string messages to a map, that maps indices to signatures
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
	for i := 1; i <= l; i++ {
		participants[i] = &ThresholdPlayer{
			secretKey:       secrets[i],
			id:              i,
			knownSignatures: emptymap,
		}
	}
	return &ThresholdProtocolData{
		l:                l,
		k:                k,
		n:                n,
		e:                e,
		participants:     participants,
		verificationKeys: verificationKeys,
	}
}

func createRecombinationVector(l int, knownPlayers []int) map[int]*big.Int {
	// Known players is an array of indices of the known players
	delta := new(big.Int).MulRange(1, int64(l)) // computes factorial of l
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
		deltatop := new(big.Int).Mul(delta, big.NewInt(int64(top)))
		lambda0j := new(big.Int).Div(deltatop, big.NewInt(int64(bottom)))
		recomb[j] = lambda0j
	}
	return recomb
}
