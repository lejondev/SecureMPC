package Tests

import (
	"SecureMPC/SecureMPC"
	"fmt"
	"testing"
)

func TestPrimeGen(t *testing.T) {
	n, m := SecureMPC.GeneratePrimes(128)
	fmt.Println(n)
	fmt.Println(m)
}
