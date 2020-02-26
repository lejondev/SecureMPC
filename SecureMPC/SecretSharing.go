package SecureMPC

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"strconv"
)

type ProtocolData struct {
	base         int
	n            int
	t            int
	participants []*Player
}

type Player struct {
	secret      int
	id          int
	knownShares map[int]map[int]int // The shares of this players secret will be in [id][i] for shares i = 1...n
	// The known shares of another player pid will be in [pid][i] for shares i that this player knows
	// It is a map, that maps player ID's to a map of known shares.
	// The map maps to a map of known shares for a given pid
	// map[PlayerID] -> map[shareID] -> share
	// It is pretty much a matrix, just with no entries in stead of 0 entries.
}

func (p *ProtocolData) GetPlayer(id int) *Player {
	return p.participants[id]
}
func (p *ProtocolData) GetTolerance() int {
	return p.t
}

func (p *ProtocolData) GetNumberOfParticipants() int {
	return p.n
}

func MakeProtocolData(base, n int) *ProtocolData {
	// The recombination vector and participants array are 1 indexed to make the math easier

	participants := make([]*Player, n+1)
	for i := 1; i <= n; i++ {
		participants[i] = MakePlayer(0, i, n) // Initial secret is just 0
	}
	participants[0] = MakePlayer(0, 0, n)
	return &ProtocolData{
		base:         base,
		n:            n,
		t:            int(math.Floor(float64((n - 1) / 2))),
		participants: participants,
	}
}

func MakePlayer(secret, id int, n int) *Player {
	mapmap := map[int]map[int]int{} // Allocates all the maps for all players. Initially they are empty
	for i := 1; i <= n; i++ {
		mapmap[i] = map[int]int{}
	}
	return &Player{
		secret:      secret,
		id:          id,
		knownShares: mapmap,
	}
}

func (p *Player) AssignSecret(s int) {
	p.secret = s
}

func (p *ProtocolData) makeRecombinationVector(knownShares map[int]int) {
	// Computes recombination vector
	for i, _ := range knownShares {
		var delta_i_0 int // delta_i(0), because we evaluate h(x) at x=0
		// top/bottom = (0-j)/(i-j)
		top := 1
		bottom := 1
		for j, _ := range knownShares {
			if j != i {
				top = top * -j
				bottom = bottom * (i - j)
			}
		}
		// calculate the fraction as whole integer (modulo arithmetic)
		// top/bottom = (0-j)/(i-j) = (0-j)*(i-j)^-1
		base := p.base
		top = mod(top, base)
		bottom = mod(bottom, base)
		delta_i_0 = top * modInverse(bottom, base)
		delta_i_0 = mod(delta_i_0, base)
	}
}

func (p *Player) CreateShares(data ProtocolData) {
	shares := makeShares(p.secret, data)
	p.knownShares[p.id] = shares
}

func (p *Player) DistributeSecretShares(data *ProtocolData) {
	for i := 1; i <= data.n; i++ {
		p.SendShare(p.id, i, data.participants[i])
	}
}

func (p *Player) SendShare(idOfPlayer, idOfShare int, receiver *Player) {
	senderKnown := p.knownShares[idOfPlayer]
	// Should check that the sender knows share idOfShare
	// Should probably check that it is currently unknown for the other player
	receiver.knownShares[idOfPlayer][idOfShare] = senderKnown[idOfShare]
}

func (p *Player) RecomputeSecret(id int, data ProtocolData) int {
	sum := 0
	// Computes recombination vector
	for i, v := range p.knownShares[id] {
		var delta_i_0 int // delta_i(0), because we evaluate h(x) at x=0
		// top/bottom = (0-j)/(i-j)
		top := 1
		bottom := 1
		for j, _ := range p.knownShares[id] {
			if j != i {
				top = top * -j
				bottom = bottom * (i - j)
			}
		}
		// calculate the fraction as whole integer (modulo arithmetic)
		// top/bottom = (0-j)/(i-j) = (0-j)*(i-j)^-1
		base := data.base
		top = mod(top, base)
		bottom = mod(bottom, base)
		delta_i_0 = top * modInverse(bottom, base)
		delta_i_0 = mod(delta_i_0, base)
		sum += v * delta_i_0
	}
	return mod(sum, data.base)
}

func makeShares(s int, data ProtocolData) map[int]int {
	coefs := make([]int, data.t)
	shares := map[int]int{}
	for i := 0; i < data.t; i++ {
		coefs[i] = rand.Intn(100) // Should probably be secure random
	}
	h := Polynomial{s, coefs}
	// Share 0 is not a thing
	for i := 1; i <= data.n; i++ {
		eval := mod(h.eval(i), data.base)
		shares[i] = eval
	}
	return shares
}

func SecureMPC() {
	// finite field F_base
	fmt.Println("Enter prime base for finite field: ")
	var base int
	if _, err := fmt.Scan(&base); err != nil {
		log.Print("Input failed due to:  ", err)
	}

	// secret = secret number to be shared
	fmt.Println("Enter the secret: ")
	var secret int
	if _, err := fmt.Scan(&secret); err != nil {
		log.Print("Input failed due to:  ", err)
	}

	// n = number of parties
	// Their IDs are 1..n for P_1 .. P_n respectively, so C={1,2..n}
	fmt.Println("Enter number of participants: ")
	var n int
	if _, err := fmt.Scan(&n); err != nil {
		log.Print("Input failed due to:  ", err)
	}

	// t = number of corrupt parties we want to tolerate
	// ie <= t parties cannot learn share
	// and need >t parties to learn share
	/*
		println("Enter number of corrupted parties we want to tolerate: ")
		var t int
		if _, err := fmt.Scan(&t); err != nil {
			log.Print("Input failed due to:  ", err)
		}
	*/
	// We can tolerate t < n/2 corruptions
	t := int(math.Floor(float64((n - 1) / 2)))
	// Coefficients
	var coefs []int

	fmt.Println("Use random coefficients? (Y/n)")
	var inputCoeffs string
	if _, err := fmt.Scan(&inputCoeffs); err != nil {
		log.Print("Input failed due to:  ", err)
	}

	if inputCoeffs == "n" {
		for i := 0; i < t; i++ {
			fmt.Printf("Please enter coefficient %d / %d: ", i, t)
			var input int
			if _, err := fmt.Scanf("%d", &input); err != nil {
				log.Print("Input failed due to:  ", err)
			}
			coefs = append(coefs, input)
		}
	} else {
		for i := 0; i < t; i++ {
			coefs = append(coefs, rand.Intn(100))
		}
	}

	// use degree-t polynomial, where f(0)=secret, such that
	// t + 1 data points [ID, share],, will be needed to
	// recreate the polynomial and retrieve the share f(0)=secret

	// h = polynomial
	h := Polynomial{secret, coefs}

	fmt.Println("OK! Polynomial is: h(x)= " + h.toStr())

	fmt.Println("Shares, h(x), for x=1.." + strconv.Itoa(n) + " are: ")

	// compute shares
	var shares = make([]int, n+1)
	for i := 1; i < n+1; i++ {
		eval := h.eval(i)
		shares[i] = int(math.Mod(float64(eval), float64(base)))
		fmt.Printf("%d ", shares[i])
	}
	fmt.Println("----")

	// send the shares securely to each participant P_1 .. P_n respectively
	// -------------------

	// Work with the shares ...
	fmt.Println("\n Now send and work with shares ...\n----")

	// -------------------
	// Now Assume P_3 will recompute the share

	var known_shares = make([]int, 0)
	var ids []int
	fmt.Println("Recompute secret using shares of participants")
	for i := 1; i < t+2; i++ {
		fmt.Printf("Please enter the participant ids: (1..%d) %d of %d: ", n, i, t+1)
		var input int
		if _, err := fmt.Scanf("%d", &input); err != nil {
			log.Print("Input failed due to:  ", err)
		}
		for !(input < n+1 && input > 0) || contains(ids, input) {
			log.Printf("Sorry, range of possible ids is 1..%d and no duplicates allowed, try again: ", n)
			if _, err := fmt.Scanf("%d", &input); err != nil {
				log.Print("Input failed due to:  ", err)
			}
		}
		ids = append(ids, input)
		known_shares = append(known_shares, shares[input])
	}

	fmt.Println("OK! Known shares for the ids  ")
	for i := 0; i < len(ids); i++ {
		fmt.Print(strconv.Itoa(ids[i]) + ", ")
	}
	fmt.Println("are: ")
	for i := 0; i < len(known_shares); i++ {
		fmt.Print(strconv.Itoa(known_shares[i]) + ", ")
	}
	fmt.Println()

	// recombination vector
	var recombination_vector = make([]int, 0)

	fmt.Println("Eval delta_i(0) for every id")

	// evaluate polynomial at x=0
	shares_sum := 0
	for index, i := range ids {

		var delta_i_0 int // delta_i(0), because we evaluate h(x) at x=0

		// top/bottom = (0-j)/(i-j)
		top := 1
		bottom := 1

		for _, j := range ids {
			if j != i {
				top = top * -j
				bottom = bottom * (i - j)
			}
		}

		// calculate the fraction as whole integer (modulo arithmetic)
		// top/bottom = (0-j)/(i-j) = (0-j)*(i-j)^-1

		// make top and bottom positive
		top = mod(top, base)
		bottom = mod(bottom, base)

		delta_i_0 = top * modInverse(bottom, base)

		// calculate the modulo
		delta_i_0 = mod(delta_i_0, base)

		// add to recombination vector
		recombination_vector = append(recombination_vector, delta_i_0)

		fmt.Printf("delta_%d(0) = %d \n", i, delta_i_0)

		// sum all shares
		shares_sum = shares_sum + known_shares[index]*delta_i_0
	}

	fmt.Println("Recombination vector is: ")
	for _, r := range recombination_vector {
		fmt.Printf("%d, ", r)
	}
	fmt.Println("\n")

	fmt.Printf("Shares sum: %d \n", shares_sum)
	fmt.Printf("Secret is: %d\n", mod(shares_sum, base))

}

func mod(num int, base int) int {
	if num < 0 {
		return base - ((-num) % base)
	} else {
		return num % base
	}
}

// A naive method to find modulor
// multiplicative inverse of 'a'
// under modulo 'm'
func modInverse(a int, m int) int {
	a = a % m
	for x := 1; x < m; x++ {
		if (a*x)%m == 1 {
			return x
		}
	}
	return 1
}

/**
 * Simple polynomial of the form
 * const + a_1*x + a_2*x^2 + ... + a_n*x^n
 */
type Polynomial struct {
	constant int
	coefs    []int
}

func (p *Polynomial) toStr() string {
	str := strconv.Itoa(p.constant)
	for i := 0; i < len(p.coefs); i++ {
		var exp = i + 1
		str = str + " + " + strconv.Itoa(p.coefs[i]) + "x^" + strconv.Itoa(exp)
	}
	return str
}

func (p *Polynomial) eval(x int) int {
	constant := p.constant
	for i := 0; i < len(p.coefs); i++ {
		var exp = i + 1
		constant += p.coefs[i] * int(math.Pow(float64(x), float64(exp)))
	}
	return constant
}

func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func (p *Player) GetShares() []int {
	arr := make([]int, 0, len(p.knownShares[p.id]))
	for _, value := range p.knownShares[p.id] {
		arr = append(arr, value)
	}
	return arr
}

func (p *Player) GetSharesOfId(id int) []int {
	arr := make([]int, 0, len(p.knownShares[id]))
	for _, value := range p.knownShares[id] {
		arr = append(arr, value)
	}
	return arr
}

func (p *Player) GetMap() map[int]int {
	return p.knownShares[p.id]
}
func (p *Player) GetMapOfId(id int) map[int]int {
	return p.knownShares[id]
}
