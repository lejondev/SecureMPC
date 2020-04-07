package Tests

import (
	"SecureMPC/SecureMPC"
	"fmt"
	"testing"
)

func TestThresholdProtocol(t *testing.T) {
	message := "Hi hello"
	data := SecureMPC.ThresholdProtocolSetup(7, 3)
	fmt.Println("Data created")
	SecureMPC.FullSignAndDistribute(message, data)
	fmt.Println("Signing completed created")
	sigmap := data.Participants[1].KnownSignatures[message]
	if SecureMPC.Verify(message, data, sigmap) {
		fmt.Println("Success!")
	} else {
		fmt.Println("Failure!")
		t.Errorf("Verification failed")
	}
	// l - (k - 1) >= k
	// t = k - 1

}
