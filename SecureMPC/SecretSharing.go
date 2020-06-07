package SecureMPC

import (
	"fmt"
	"log"
	"math"
	"math/rand"
	"strconv"
)

// ProtocolData contains the configuration and current state of the protocol.
// Its participant field is being worked on under execution.
type ProtocolData struct {
	base         int       // base is the moduo base
	n            int       // N is the number of Participants
	k            int       // k is the number of adversaries
	participants []*Player // Participants contains the participating players
}

// Player contains the information a player has and learns along the way
type Player struct {
	secret               int // secret is the secure info to be shared
	id                   int // Id is the identifier of this player
	recombination_vector []int
	knownShares          map[int]map[int]int // knownShares is a 2D map, that maps player ID's (pid) to a map of known shares
	// of a given player.
	// map[PlayerID] -> map[shareID] -> share
	// The shares of this players secret will be in [Id][i] for shares i = 1..N
	// The learned shares from other players, will be in [pid][i] for shares i which
	// this player has learned.
	// Non existent entries mean that the share is unknown (not learned yet)
}

func (p *ProtocolData) GetPlayer(id int) *Player {
	return p.participants[id]
}
func (p *ProtocolData) GetThreshold() int {
	return p.k
}

func (p *ProtocolData) GetNumberOfParticipants() int {
	return p.n
}

// MakeProtocolData creates a ProtocolData object
func MakeProtocolData(base, n, k int) *ProtocolData {
	participants := make([]*Player, n+1)
	for i := 0; i <= n; i++ {
		participants[i] = MakePlayer(0, i, n)
		// Initial secret is just 0
	}
	return &ProtocolData{
		base:         base,
		n:            n,
		k:            k,
		participants: participants,
	}
}

func MakePlayer(secret, id int, n int) *Player {
	mapmap := map[int]map[int]int{} // Allocates all the maps for all players. Initially they are empty
	for i := 0; i <= n; i++ {
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

func (p *Player) CreateShares(data ProtocolData) {
	shares := makeShares(p.secret, data)
	p.knownShares[p.id] = shares
}

// DistributeSecretShares will send the shares of the secret of the player to all other corresponding Participants
func (p *Player) DistributeSecretShares(data *ProtocolData) {
	for i := 1; i <= data.n; i++ {
		p.SendShare(p.id, i, data.participants[i])
	}
}

// SendShare will "send" a specified share (idOfShare) of this player (p and idOfPlayer) to
// another specified player (receiver)
func (p *Player) SendShare(idOfPlayer, idOfShare int, receiver *Player) {
	theShare := p.knownShares[idOfPlayer][idOfShare]
	receiver.knownShares[idOfPlayer][idOfShare] = theShare
}

func (p *Player) RecomputeSecret(id int, data ProtocolData) int {
	sum := 0
	p.recombination_vector = make([]int, 0)

	// Computes recombination vector
	for i, v := range p.knownShares[id] {
		var delta_i_0 int // delta_i(0), because we evaluate h(x) at x=0
		// top/bottom = (0-j)/(i-j)
		top := 1
		bottom := 1
		for j := range p.knownShares[id] {
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
		fmt.Printf("delta_%d(0) = %d \n", i, delta_i_0)
		p.recombination_vector = append(p.recombination_vector, delta_i_0) // remember recomb. vector
		sum += v * delta_i_0
	}
	return mod(sum, data.base)
}

func makeShares(s int, data ProtocolData) map[int]int {
	coefs := make([]int, data.k)
	shares := map[int]int{}
	for i := 0; i < data.k; i++ {
		coefs[i] = rand.Intn(100) // Should probably be secure random
	}
	// Could also allow custom polynomial here
	h := Polynomial{s, coefs}
	// Share 0 is not a thing
	for i := 1; i <= data.n; i++ {
		eval := mod(h.eval(i), data.base)
		shares[i] = eval
	}
	return shares
}

func PlaySecureMPC() {
	// Phase 0 - Configuration
	fmt.Println("PHASE 0 - Configuration\n")

	// finite field F_base
	fmt.Print("Enter (ideally) a prime base for finite field: ")
	var base int
	if _, err := fmt.Scan(&base); err != nil {
		log.Print("Input failed due to:  ", err)
	}

	// N = number of Participants
	// Their IDs are 1..N for P_1 .. P_n respectively, so C={1,2..N}
	var n int
	fmt.Print("Enter number of Participants (N): ")
	if _, err := fmt.Scan(&n); err != nil {
		log.Print("Input failed due to:  ", err)
	}
	for !(0 < n && n < base) {
		log.Printf("Sorry, N must be smaller than the base (N<base). You chose base=%d, N=%d. Try again.", base, n)
		fmt.Print("Enter number of Participants (N): ")
		if _, err := fmt.Scan(&n); err != nil {
			log.Print("Input failed due to:  ", err)
		}
	}

	// secret = secret number to be shared
	fmt.Print("Enter the secret (secret): ")
	var secret int
	if _, err := fmt.Scan(&secret); err != nil {
		log.Print("Input failed due to:  ", err)
	}

	fmt.Printf("\nOK! base=%d, N=%d, secret=%d\n\n", base, n, secret)

	// Phase 1 - Create and distribute shares
	fmt.Println("PHASE 1 - Create and distribute shares\n")

	// Create the protocol control object
	protocol := MakeProtocolData(base, n, int(math.Floor(float64((n-1)/2))))

	// Create a player (us, ie we are player) and assign the secret
	player := protocol.GetPlayer(1)
	player.AssignSecret(secret)

	// Create polynomial and then, compute shares of the secret
	player.CreateShares(*protocol)

	// Print shares
	var shares = player.GetShares()
	fmt.Println("Shares h(x), for x=1.." + strconv.Itoa(n) + " are: ")
	for i := 0; i < len(shares); i++ {
		fmt.Printf("%d ", shares[i])
	}
	fmt.Println("\n")

	// send the shares securely to each other participant P_1 .. P_n respectively
	player.DistributeSecretShares(protocol)
	fmt.Println("We send our shares to other players")

	// Phase 2 - Work with shares
	fmt.Println("PHASE 2 - Everybody works with shares ... \n---- \n\n", n)

	// Phase 3 - Recomputing!
	fmt.Println("PHASE 3 - Recomputing")

	// Recomputing player
	fmt.Printf("Enter Id of player that should recompute (pid=1..%N): ", n)
	var idOtherPlayer int
	if _, err := fmt.Scan(&idOtherPlayer); err != nil {
		log.Print("Input failed due to:  ", err)
	}

	// Now otherPlayer will recompute the secret
	otherPlayer := protocol.GetPlayer(idOtherPlayer) // Receiving player

	// We can tolerate k < N/2 corruptions
	var k = protocol.GetThreshold()

	// Send shares i=3..c+3 o secret of player, from the respective players, to otherPlayer
	fmt.Printf("Other players send the secret share they got from us to pid=%d\n", idOtherPlayer)
	for i := 1; i <= k+2; {
		if !(i == 1 || i == idOtherPlayer) {
			sendingPlayer := protocol.GetPlayer(i)
			sendingPlayer.SendShare(1, i, otherPlayer) // Sends the share of i=3..7 received from player to otherPlayer
		}
		i++
	}

	fmt.Println("\nEval delta_i(0) for every Id")

	computedSecret := otherPlayer.RecomputeSecret(1, *protocol)

	// recombination vector
	var recombination_vector = otherPlayer.recombination_vector

	fmt.Println("\n Recombination vector is: ")
	for _, r := range recombination_vector {
		fmt.Printf("%d ", r)
	}
	fmt.Println("\n")

	fmt.Printf("Secret is: %d\n", computedSecret)

}

func mod(num int, base int) int {
	if num < 0 {
		return base - ((-num) % base)
	} else {
		return num % base
	}
}

// A naive method to find modulo
// multiplicative inverse of 'a'
// under modulo 'm'
// faster would be EGCD
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
 * const + a_1*x + a_2*x^2 + ... + a_n*x^N
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

// Some functions that might be useful for testing or debugging or whatever

func (p *Player) GetShares() []int {
	arr := make([]int, 0, len(p.knownShares[p.id]))
	for _, value := range p.knownShares[p.id] {
		arr = append(arr, value)
	}
	return arr
}

func (p *Player) GetKnownSharesOfId(id int) []int {
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

func (p *Player) SetShareOfId(playerid, shareid, share int) {
	p.knownShares[playerid][shareid] = share
}
