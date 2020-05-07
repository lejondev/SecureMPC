package Tests

import (
	"SecureMPC/SecureMPC"
	"fmt"
	"testing"
)

func TestPrimeGen(t *testing.T) {
	n, m := SecureMPC.GeneratePrimes(1024)
	fmt.Println(n)
	fmt.Println(m)
}

func TestRSAGen(t *testing.T) {
	n, e, d, m := SecureMPC.GenerateRSAKey(512)
	fmt.Println(n)
	fmt.Println(e)
	fmt.Println(d)
	fmt.Println(m)
}
