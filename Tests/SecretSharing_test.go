package Tests

import (
	"SecureMPC/SecureMPC"
	"fmt"
	"math"
	"testing"
)

func TestShares(t *testing.T) {
	protocol := SecureMPC.MakeProtocolData(29, 20, 10)
	fmt.Println(int(math.Floor(float64((29 - 1) / 2))))
	player1 := protocol.GetPlayer(1)
	secret := 5
	player1.AssignSecret(secret)
	player1.CreateShares(*protocol)
	player1.DistributeSecretShares(protocol)
	player2 := protocol.GetPlayer(2) // Receiving player
	c := protocol.GetThreshold()
	for i := 3; i <= c+3; i++ {
		sendingPlayer := protocol.GetPlayer(i)
		sendingPlayer.SendShare(1, i, player2) // Sends the share they received to player2
	}
	got := player2.RecomputeSecret(1, *protocol)
	if got != secret {
		t.Errorf("Expected secret 5, got %d", got)
	}
}
