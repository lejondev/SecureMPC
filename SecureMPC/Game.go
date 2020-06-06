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
	data := ThresholdProtocolSetup(l, k, 1024)
	fmt.Println("Data created")
	fmt.Println("Type 'help' for an overview of commands")

	// Start listening
	messenger(data)
}

// defaults to player one
var currentPlayer = 1

// messenger will listen and handle console input
func messenger(data *ThresholdProtocolData) {
	running := true
	for running {
		fmt.Printf("Player#%d> ", currentPlayer)

		// Read and parse the command and arguments
		reader := bufio.NewReader(os.Stdin)
		input, _ := reader.ReadString('\n')
		cmdAndArgs := str.SplitN(input, " ", 2)
		cmdAndArgs = Map(cmdAndArgs, str.TrimSpace)
		cmdStr := cmdAndArgs[0] // Command
		args := []string{}      // Default to 0 args

		// Handle whitespace in arguments by encapsulation with quotes, like "" or ''
		if len(cmdAndArgs) == 2 {
			r := regexp.MustCompile(`'.*?'|".*?"|\S+`)
			args = r.FindAllString(cmdAndArgs[1], -1)
			args = Map(args, trimQuote)
		}

		// Execute command
		if cmd, exists := alias[cmdStr]; exists {
			running = cmd.execute(args, data)
		} else if cmd, exists := commands[cmdStr]; exists {
			running = cmd.execute(args, data)
		} else {
			fmt.Println("Unknown command. Refer to 'help'")
		}

	}
}

type Command struct {
	args        []string
	description string
	action      func(args []string, data *ThresholdProtocolData) bool
}

func (command *Command) execute(argsGiven []string, data *ThresholdProtocolData) bool {
	numArgsRequired := len(command.args)
	if len(argsGiven) != numArgsRequired {
		fmt.Printf("Expected %d argument(s): "+command.usage()+"\n", numArgsRequired)
		return true
	}
	return command.action(argsGiven, data)
}
func (command *Command) usage() string {
	usage := ""
	for _, arg := range command.args {
		usage = usage + "[" + arg + "] "
	}
	return usage
}

var alias = map[string]*Command{
	"q":   commands["quit"],
	"h":   commands["help"],
	"sp":  commands["switchplayer"],
	"s":   commands["sign"],
	"ss":  commands["sendsignature"],
	"sss": commands["sendsignatures"],
	"vs":  commands["viewsignatures"],
	"vm":  commands["viewmessages"],
	"r":   commands["recombine"],
}

var commands = map[string]*Command{
	"quit": {
		args:        []string{},
		description: "End the program",
		action: func(args []string, data *ThresholdProtocolData) bool {
			return false
		}},
	"help": {
		args:        []string{},
		description: "Print this list of commands",
		action: func(args []string, data *ThresholdProtocolData) bool {
			fmt.Println("quit\n - End the program")
			fmt.Println("help\n - Print this list of commands")
			fmt.Println("switchplayer [idOfPlayer]\n - Select player to switch to")
			fmt.Println("sign [message]\n - Create the signature share")
			fmt.Println("sendsignature [receivingPlayer] [message]\n - send the signature share of specified message to specified player")
			fmt.Println("sendsignatures [receivingPlayer] [message]\n - Send all known message signature shares to specified player")
			fmt.Println("viewsignatures [message]\n - View all signature shares of specified message known by this player")
			fmt.Println("recombine [message]\n - Try computing the full signature of specified message using known signature shares")
			return true
		}},
	"switchplayer": {
		args:        []string{"iOfPlayer"},
		description: "Select player to switch to",
		action: func(args []string, data *ThresholdProtocolData) bool {
			playerId, err := strconv.Atoi(args[0])
			if err != nil || !(1 <= playerId && playerId <= data.L) {
				fmt.Printf("Parameter must be integer in range [%d,%d]\n", 1, data.L)
				return true
			}
			currentPlayer = playerId
			fmt.Printf("You are now player %d of %d\n", currentPlayer, data.L)
			return true
		}},
	"sign": {
		args:        []string{"mssage"},
		description: "Create the signature share",
		action: func(args []string, data *ThresholdProtocolData) bool {
			message := args[0]
			// Player will sign message and save the signature share in its own object
			data.Participants[currentPlayer].SignHashOfMsg(message)
			fmt.Print("Signature share created\n")
			return true
		}},
	"sendsignature": {
		args:        []string{"rceivingPlayer", "message"},
		description: "Send the signature share of specified message to specified player",
		action: func(args []string, data *ThresholdProtocolData) bool {
			receivingPlayerId, err := strconv.Atoi(args[0])
			if err != nil || !(1 <= receivingPlayerId && receivingPlayerId <= data.L) {
				fmt.Printf("Parameter must be integer in range [%d,%d]\n", 1, data.L)
				return true
			}
			message := args[1]
			// Check if this message has a signature share
			share, msgHasSig := data.Participants[currentPlayer].KnownSignatures[message][currentPlayer]
			if !msgHasSig {
				fmt.Printf("You need to sign this message first. Refer to 'help'\n")
				return true
			}
			SendSignatureShare(message, share, receivingPlayerId, data)
			fmt.Printf("Signature share was sent to Player#%d\n", receivingPlayerId)
			return true
		}},
	"sendsignatures": {
		args:        []string{"rceivingPlayer", "message"},
		description: "Send all known message signature shares to specified player",
		action: func(args []string, data *ThresholdProtocolData) bool {
			return true
		}},
	"viewmessages": {
		args:        []string{},
		description: "View signed and signable messages",
		action: func(args []string, data *ThresholdProtocolData) bool {
			messages := data.Participants[currentPlayer].KnownSignatures
			if len(messages) == 0 {
				fmt.Println("No signed or unsigned messages. Try signing your own!")
				return true
			}
			for msg, playerSignatures := range messages {
				if _, contained := playerSignatures[currentPlayer]; contained {
					fmt.Print("[  signed] ")
				} else {
					fmt.Print("[unsigned] ")
				}
				fmt.Println(msg)
			}
			return true
		}},
	"viewsignatures": {
		args:        []string{"message"},
		description: "View the signature shares for the specified message gotten from different players",
		action: func(args []string, data *ThresholdProtocolData) bool {
			message := args[0]
			// Check if this player has signature shares for this message
			shares, msgHasShares := data.Participants[currentPlayer].KnownSignatures[message]
			if !msgHasShares {
				fmt.Printf("No shares. Nobody has sent you shares and you have not signed this message yourself. \n")
				return true
			}
			fmt.Println("Got shares from players: ")
			// Show ids of other players signature shares
			for share := range shares {
				fmt.Printf("%#v, ", share)
			}
			fmt.Println()
			return true
		}},
	"recombine": {
		args:        []string{"mssage"},
		description: "Try computing the full signature of specified message using known signature shares",
		action: func(args []string, data *ThresholdProtocolData) bool {
			message := args[0]
			sigmap := data.Participants[currentPlayer-1].KnownSignatures[message]
			sig, valid := CreateSignature(message, data, sigmap)
			if !valid {
				fmt.Println("Error")
			}
			if VerifySignature(message, sig, data) {
				fmt.Println("Success!")
			} else {
				fmt.Println("Failure!")
			}
			return true
		}},
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
