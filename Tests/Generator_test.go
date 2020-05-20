package Tests

import (
	"SecureMPC/SecureMPC"
	"bufio"
	"fmt"
	"os"
	"strconv"
	"testing"
	"time"
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

func TestTime(t *testing.T) {

	f, err := os.Create("C:/Users/SorenAsger/Desktop/Test/TimeTest.txt")
	defer f.Close()
	check(err)
	writer := bufio.NewWriter(f)
	runs := 10
	for i := 0; i < 9; i++ {
		startTime := time.Now()
		keysize := 1024 + 128*i
		for j := 0; j < runs; j++ {
			fmt.Println("Generating key: " + strconv.Itoa(j) + " for key size: " + strconv.Itoa(keysize))
			timeS := time.Now()
			_, _, _, _ = SecureMPC.GenerateRSAKey(keysize)
			fmt.Println("Time passed: " + time.Since(timeS).String())
		}
		avgTimeInSec := time.Since(startTime).Seconds() / float64(runs)
		timeString := fmt.Sprintf("%.2f", avgTimeInSec)
		toWrite := strconv.Itoa(keysize) + "," + timeString + "\n"
		_, err = writer.WriteString(toWrite)
		check(err)
	}
	err = writer.Flush()
	check(err)
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
