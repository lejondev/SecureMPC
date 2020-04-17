package SecureMPC

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// defaults to player one
var currentPlayer = 1

//TODO: None of these functions are fully implemented
func messenger() {
	for {
		reader := bufio.NewReader(os.Stdin)
		fmt.Print("> ")
		text, _ := reader.ReadString('\n')
		text = strings.TrimSpace(text)
		if text == "quit" {
			return
		}
		if text == "switchplayer" {
			fmt.Print("Select player to switch to")
			text, _ := reader.ReadString('\n')
			text = strings.TrimSpace(text)
			//TODO: select player
		}
		if text == "sign" {
			fmt.Print("Enter message to sign")
			text, _ := reader.ReadString('\n')
			text = strings.TrimSpace(text)
		}
		if text == "sendsignature" { // SignatureShares
			fmt.Print("Select message to send corresponding your own signature")
			msg, _ := reader.ReadString('\n')
			msg = strings.TrimSpace(msg)
			fmt.Print("Select player number to receive ")
			receiver, _ := reader.ReadString('\n')
			receiver = strings.TrimSpace(receiver)
		}
		if text == "sendsignatures" { // SignatureShares
			fmt.Println("Select a receiver to send all known signatures to")
			receiver, _ := reader.ReadString('\n')
			receiver = strings.TrimSpace(receiver)
		}
		if text == "recombine" { // Recombines actual signature

			fmt.Println("Select a message to try to make the full signature")
			msg, _ := reader.ReadString('\n')
			msg = strings.TrimSpace(msg)
		}
	}
}
