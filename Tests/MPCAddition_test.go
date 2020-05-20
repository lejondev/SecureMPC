package Tests

import (
	"SecureMPC/SecureMPC"
	"fmt"
	"testing"
)

func TestAddition(t *testing.T) {
	nplayers := 11
	data := SecureMPC.MakeProtocolData(1087, nplayers)
	sum := 0
	for i := 1; i <= nplayers; i++ {
		player := data.GetPlayer(i)
		sum += i + 10
		player.AssignSecret(i + 10)
		player.CreateShares(*data)
		player.DistributeSecretShares(data)
	}
	fmt.Println("Actual sum: ", sum)
	secretsums := make([]int, nplayers+1)
	for i := 1; i <= nplayers; i++ {
		player := data.GetPlayer(i)
		secretsum := 0
		for j := 1; j <= nplayers; j++ {
			shares := player.GetKnownSharesOfId(j)
			if j == i {
				secretsum += player.GetMapOfId(i)[j]
			} else {
				secretsum += shares[0]
			}
		}
		secretsums[i] = secretsum
	}
	for i := 1; i <= data.GetTolerance()+1; i++ {
		player := data.GetPlayer(0)
		player.SetShareOfId(0, i, secretsums[i])
	}
	player := data.GetPlayer(0)
	recompsum := player.RecomputeSecret(0, *data)
	fmt.Println(recompsum)
}
