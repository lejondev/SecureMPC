package Tests

import (
	"SecureMPC/SecureMPC"
	"fmt"
	"testing"
)

func TestPrimeGen(t *testing.T) {
	n, m := SecureMPC.GeneratePrimes(512)
	fmt.Println(n)
	fmt.Println(m)
}
