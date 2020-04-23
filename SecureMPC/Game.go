package SecureMPC

import (
	"bufio"
	"fmt"
	_ "github.com/davecgh/go-spew/spew"
	"log"
	"os"
	"strconv"
	str "strings"
)

func Play() {

	fmt.Println("Welcome!")

	// Players - Number of players (l)
	fmt.Print("Enter amount of players (l): ")
	var l int
	if _, err := fmt.Scan(&l); err != nil {
		log.Print("Input failed due to:  ", err)
	}

	// Adversaries - Number of corrupted players
	//fmt.Print("Enter amount of corrupted players (t): ")
	//var t int
	//if _, err := fmt.Scan(&t); err != nil {
	//	log.Print("Input failed due to:  ", err)
	//}

	// Threshold - Num signature shares needed to obtain a signature (k)
	fmt.Print("Enter amount of signature shares needed to obtain a signature (k): ")
	var k int
	if _, err := fmt.Scan(&k); err != nil {
		log.Print("Input failed due to:  ", err)
	}

	// Validate
	// TODO: validate input

	// Setup
	fmt.Println("Creating data. Please wait ...")
	data := ThresholdProtocolSetup(l, k)
	fmt.Println("Data created")
	fmt.Println("Type 'help' for an overview of commands")

	// Start listening
	listen(data)

	//sigmap := data.Participants[1].KnownSignatures[message]
	//sig, valid := SecureMPC.CreateSignature(message, data, sigmap)
	//if !valid {
	//	fmt.Println("Error")
	//}
	//if SecureMPC.VerifySignature(message, sig, data) {
	//	fmt.Println("Success!")
	//} else {
	//	fmt.Println("Failure!")
	//	t.Errorf("Verification failed")
	//}

}

// defaults to player one
var currentPlayer = 1

//TODO: None of these functions are fully implemented
func listen(data *ThresholdProtocolData) {
	var signatures = make([]*SignatureShare, data.L)
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Printf("Player#%d> ", currentPlayer)
		input, _ := reader.ReadString('\n')
		strings := str.Split(input, " ")
		strings = Map(strings, str.TrimSpace)
		cmd := strings[0]
		args := strings[1:]

		if cmd == "quit" {
			return
		}
		if cmd == "help" || cmd == "commands" {
			fmt.Println("help - Print this list of commands")
			fmt.Println("switchplayer [idOfPlayer] - Select player to switch to")
			fmt.Println("sign")
			fmt.Println("sendsignature")
			fmt.Println("sendsignatures")
			fmt.Print("recombine")
		}
		if cmd == "switchplayer" {
			if len(args) != 1 {
				fmt.Print("Only 1 parameter is expected. Refer to 'help'")
				continue
			}
			playerId, err := strconv.Atoi(args[0])
			if err != nil || !(1 <= playerId && playerId <= data.L) {
				fmt.Printf("Parameter must be integer in range [%d,%d]", 1, data.L)
				continue
			}
			currentPlayer = playerId
			fmt.Printf("You are now player %d of %d", currentPlayer, data.L)
		}
		if cmd == "sign" {
			if len(args) != 1 {
				fmt.Print("Only 1 parameter is expected. Refer to 'help'")
				continue
			}
			var msg = args[0]
			signatures[currentPlayer-1] = data.Participants[currentPlayer].SignHashOfMsg(msg)
			fmt.Print("Message signed")
		}
		if cmd == "sendsignature" { // SignatureShares
			fmt.Print("Select message to send corresponding your own signature")
			msg, _ := reader.ReadString('\n')
			msg = str.TrimSpace(msg)
			fmt.Print("Select player number to receive ")
			receiver, _ := reader.ReadString('\n')
			receiver = str.TrimSpace(receiver)
		}
		if cmd == "sendsignatures" { // SignatureShares
			fmt.Println("Select a receiver to send all known signatures to")
			receiver, _ := reader.ReadString('\n')
			receiver = str.TrimSpace(receiver)
		}
		if cmd == "recombine" { // Recombines actual signature

			fmt.Println("Select a message to try to make the full signature")
			msg, _ := reader.ReadString('\n')
			msg = str.TrimSpace(msg)
		}
		fmt.Println()
	}
}

func Map(vs []string, f func(string) string) []string {
	vsm := make([]string, len(vs))
	for i, v := range vs {
		vsm[i] = f(v)
	}
	return vsm
}
