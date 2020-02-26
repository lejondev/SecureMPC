package SecureMPC

import (
	"fmt"
	"log"
	"math"
)

func SecureMPC() {

	// finite field F_base
	println("Enter base for finite field: ")
	var base int
	if _, err := fmt.Scan(&base); err != nil {
		log.Print("Input failed due to:  ", err)
	}

	// secret = secret number to be shared
	println("Enter the secret: ")
	var secret int
	if _, err := fmt.Scan(&secret); err != nil {
		log.Print("Input failed due to:  ", err)
	}

	// n = number of parties
	// Their IDs are 1..n for P_1 .. P_n respectively, so C={1,2..n}
	println("Enter number of participants: ")
	var n int
	if _, err := fmt.Scan(&n); err != nil {
		log.Print("Input failed due to:  ", err)
	}

	// t = number of corrupt parties we want to tolerate
	// ie <= t parties cannot learn share
	// and need >t parties to learn share
	println("Enter number of corrupted parties we want to tolerate: ")
	var t int
	if _, err := fmt.Scan(&t); err != nil {
		log.Print("Input failed due to:  ", err)
	}

	// Coefficients
	var coefs []int

	println("Do you want to enter coefficients of the polynomial yourself? (y/N)")
	var inputCoeffs string
	if _, err := fmt.Scan(&inputCoeffs); err != nil {
		log.Print("Input failed due to:  ", err)
	}

	//var
	//if (inputCoeffs == "y")
	//
	//println("Enter t coefficients: ")
	//
	//// Read from std input
	//if _, err := fmt.Scan(&coefs);  err != nil {
	//	log.Print("Reading coefficients failed, due to ", err)
	//	return
	//}

	// use degree-t polynomial, where f(0)=secret, such that
	// t + 1 data points [ID, share],, will be needed to
	// recreate the polynomial and retrieve the share f(0)=secret

	// h = polynomial
	h := Polynomial{secret, coefs}

	println("Shares are")

	// compute shares 1..5
	var shares [6]int
	for i := 1; i < n+1; i++ {
		eval := h.eval(i)
		shares[i] = int(math.Mod(float64(eval), float64(base)))
		fmt.Printf("%d ", shares[i])
	}
	println("\n----")

	// send the shares securely to each participant P_1 .. P_n respectively
	// -------------------

	// Work with the shares ...
	println("send and work with shares ...\n----")

	// -------------------
	// Now Assume P_3 will recompute the share

	// P_3 has kept s_3 and got s_4, s_5 from P_4, P_5 resp.
	// that means we have s_3, s_4, s_5 available
	known_shares := []int{0, 0, 0, shares[3], shares[4], shares[5]}

	println("Recompute secret using shares")
	fmt.Printf("(3,%d), ", known_shares[3])
	fmt.Printf("(4,%d), ", known_shares[4])
	fmt.Printf("(5,%d), \n", known_shares[5])
	println()

	// P_3 finds the secret by computing h(0) using only the "recombination vector" which entries are
	// the constant terms in the delta_i(x) polynomial where i=3..5 from lagrange interpolation

	// delta_i(x) = product_{j=3..5,j!=i}( (x-j)/(i-j) )

	// recombination vector
	var recombination_vector [6]int

	var startC int = 3
	var endC int = 5

	// evaluate polynomial at x=0
	shares_sum := 0
	for i := startC; i <= endC; i++ {

		var delta_i_0 int // delta_i(0), because we evaluate h(x) at x=0

		// top/bottom = (0-j)/(i-j)
		top := 1
		bottom := 1

		for j := startC; j <= endC; j++ {
			if j != i {
				top = top * -j
				bottom = bottom * (i - j)
			}
		}

		// calculate the fraction as whole integer (modulo arithmetic)
		// top/bottom = (0-j)/(i-j) = (0-j)*(i-j)^-1

		// make bottom positive
		if bottom < 0 {
			bottom = base + bottom
		}
		delta_i_0 = top * modInverse(bottom, base)

		// calculate the modulo
		delta_i_0 = mod(delta_i_0, base)

		// add to recombination vector
		recombination_vector[i] = delta_i_0

		fmt.Printf("delta_%d(0) = %d", i, delta_i_0)
		println()

		// sum all shares
		shares_sum = shares_sum + known_shares[i]*delta_i_0
	}

	println("Recombination vector is: ")
	for _, r := range recombination_vector {
		fmt.Printf("%d, ", r)
	}
	println("\n")

	fmt.Printf("Shares sum: %d \n", shares_sum)
	fmt.Printf("Secret is: %d\n", mod(shares_sum, base))

	println()

	println("hehe")
}

func mod(a int, m int) int {
	return int(math.Mod(float64(a), float64(m)))
}

// A naive method to find modulor
// multiplicative inverse of 'a'
// under modulo 'm'
func modInverse(a int, m int) int {
	a = a % m
	for x := 1; x < m; x++ {
		if (a*x)%m == 1 {
			return x
		}
	}
	return 1
}

/**
 * Simple polynomial of the form
 * const + a_1*x + a_2*x^2 + ... + a_n*x^n
 */
type Polynomial struct {
	constant int
	coefs    []int
}

func (p *Polynomial) eval(x int) int {
	constant := p.constant
	for i := 0; i < len(p.coefs); i++ {
		var exp = i + 1
		constant += p.coefs[i] * int(math.Pow(float64(x), float64(exp)))
	}
	return constant
}
