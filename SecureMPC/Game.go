package SecureMPC

import (
	"bufio"
	"fmt"
	_ "github.com/davecgh/go-spew/spew"
	"log"
	"os"
	"regexp"
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
var message = ""

//TODO: None of these functions are fully implemented
func listen(data *ThresholdProtocolData) {
	var signatures = make([]*SignatureShare, data.L)
	for {
		fmt.Printf("Player#%d> ", currentPlayer)

		// Read and parse the command and arguments
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		cmdAndArgs := str.SplitN(input, " ", 2)
		cmdAndArgs = Map(cmdAndArgs, str.TrimSpace)
		cmd := cmdAndArgs[0] // Command
		args := []string{}   // Default to 0 args

		// Handle whitespace in arguments by encapsulation with quotes, like "" or ''
		if len(cmdAndArgs) == 2 {
			r := regexp.MustCompile(`'.*?'|".*?"|\S+`)
			args = r.FindAllString(cmdAndArgs[1], -1)
			args = Map(args, trimQuote)
		}

		// Commands
		if cmd == "quit" {
			return
		}
		if cmd == "help" || cmd == "commands" {
			fmt.Println("quit - End the program")
			fmt.Println("help - Print this list of commands")
			fmt.Println("switchplayer [idOfPlayer] - Select player to switch to")
			fmt.Println("sign [message] - Sign a message")
			fmt.Println("sendsignature [receivingPlayer]")
			fmt.Println("sendsignatures")
			fmt.Println("recombine")
		}
		if cmd == "switchplayer" {
			if len(args) != 1 {
				fmt.Print("1 parameter is expected. Refer to 'help'\n")
				continue
			}
			playerId, err := strconv.Atoi(args[0])
			if err != nil || !(1 <= playerId && playerId <= data.L) {
				fmt.Printf("Parameter must be integer in range [%d,%d]\n", 1, data.L)
				continue
			}
			currentPlayer = playerId
			fmt.Printf("You are now player %d of %d\n", currentPlayer, data.L)
		}
		if cmd == "sign" {
			if len(args) != 1 {
				fmt.Print("1 parameter is expected. Refer to 'help'")
				continue
			}
			message = args[0]
			signatures[currentPlayer-1] = data.Participants[currentPlayer].SignHashOfMsg(message)
			fmt.Print("Message signed\n")
		}
		if cmd == "sendsignature" { // SignatureShares
			if len(args) != 1 {
				fmt.Print("1 parameter is expected. Refer to 'help'\n")
				continue
			}
			receivingPlayer, err := strconv.Atoi(args[1])
			if err != nil || !(1 <= receivingPlayer && receivingPlayer <= data.L) {
				fmt.Printf("Parameter must be integer in range [%d,%d]\n", 1, data.L)
				continue
			}
			if message == "" {
				fmt.Printf("You need to sign a message first. Refer to 'help'\n")
				continue
			}
			SendSignatureShare(message, signatures[currentPlayer-1], receivingPlayer, data)
			fmt.Printf("Signature share was sent to Player#%d", receivingPlayer)
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
	}
}

func Map(vs []string, f func(string) string) []string {
	vsm := make([]string, len(vs))
	for i, v := range vs {
		vsm[i] = f(v)
	}
	return vsm
}

func trimQuote(s string) string {
	if len(s) > 0 && (s[0] == '"' || s[0] == '\'') {
		s = s[1:]
	}
	if len(s) > 0 && (s[len(s)-1] == '"' || s[0] == '\'') {
		s = s[:len(s)-1]
	}
	return s
}
