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

var keysizes = []int{512, 1024, 2048, 3072}

var path = "PATH GOES HERE"

func TestTimeKeyGen(t *testing.T) {
	f, err := os.Create(path + "keygen.txt")
	defer f.Close()
	check(err)
	writer := bufio.NewWriter(f)
	runs := 20
	for i := 0; i < 4; i++ {
		startTime := time.Now()
		keysize := keysizes[i]
		fmt.Println("Generating keys of size: " + strconv.Itoa(keysize))
		for j := 0; j < runs; j++ {
			timeS := time.Now()
			_, _, _, _ = SecureMPC.GenerateRSAKey(keysize)
			fmt.Println("Keygen, run:" + strconv.Itoa(j) + " Time passed: " + time.Since(timeS).String())
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

func TestTimeAll(t *testing.T) {
	f1, err := os.Create(path + "signingshare.txt")
	f2, err := os.Create(path + "recombine.txt")
	f3, err := os.Create(path + "verify.txt")
	defer f1.Close()
	defer f2.Close()
	defer f3.Close()
	writer1 := bufio.NewWriter(f1)
	writer2 := bufio.NewWriter(f2)
	writer3 := bufio.NewWriter(f3)
	runs := 20
	for i := 0; i < 4; i++ {
		keysize := keysizes[i]
		n, e, d, m := SecureMPC.GenerateRSAKey(keysize)
		for j := 1; j <= 4; j++ {
			k := j * 16
			l := k * 2
			data := SecureMPC.ThresholdProtocolSetupFromKey(l, k, n, e, d, m)

			info := "keysize: " + strconv.Itoa(keysize) + ", k: " + strconv.Itoa(k) + ", l: " + strconv.Itoa(l)

			fmt.Println("New parameters: " + info + " -------------------------------------- ")
			// Single signatureshare signing
			startTime1 := time.Now()
			for a := 0; a < runs; a++ {
				st1 := time.Now()
				message := strconv.Itoa(k) + ", " + strconv.Itoa(keysize) + ", " + strconv.Itoa(a)
				data.Participants[1].SignHashOfMsg(message)
				fmt.Println("Signing " + info + " run: " + strconv.Itoa(a) + ", time passed: " + time.Since(st1).String())
			}

			avgTimeInMs1 := float64(time.Since(startTime1).Nanoseconds()/1000000) / float64(runs)
			timeString1 := fmt.Sprintf("%.2f", avgTimeInMs1)
			toWrite1 := info +
				", time: " + timeString1 + "\n"
			_, err = writer1.WriteString(toWrite1)
			check(err)
			// Single sign done

			// Recombination
			for a := 0; a < runs; a++ {
				message := strconv.Itoa(k) + ", " + strconv.Itoa(keysize) + ", " + strconv.Itoa(a)
				SecureMPC.FullSignAndSendToOne(message, data, 1)
			}
			startTime2 := time.Now()
			for a := 0; a < runs; a++ {
				st1 := time.Now()
				message2 := strconv.Itoa(k) + ", " + strconv.Itoa(keysize) + ", " + strconv.Itoa(a)
				sigmap := data.Participants[1].KnownSignatures[message2]
				sig, _ := SecureMPC.CreateSignature(message2, data, sigmap)
				fmt.Println("Recomb, " + info + " run: " + strconv.Itoa(a) + ", time passed: " + time.Since(st1).String())
				if !SecureMPC.VerifySignature(message2, sig, data) {
					fmt.Println("FAILURE! " + info)
				}
			}
			fmt.Println("Time passed: " + time.Since(startTime2).String() + " " + info)
			avgTimeInMs2 := float64(time.Since(startTime2).Nanoseconds()/1000000) / float64(runs)
			timeString2 := fmt.Sprintf("%.2f", avgTimeInMs2)
			toWrite2 := info +
				", time: " + timeString2 + "\n"
			_, err = writer2.WriteString(toWrite2)
			check(err)

			// Recombination Done

			// Single verification
			signatureShares := make([]*SecureMPC.SignatureShare, runs)
			for a := 0; a < runs; a++ {
				message := strconv.Itoa(k) + ", " + strconv.Itoa(keysize) + ", " + strconv.Itoa(a)
				signatureShares[a] = data.Participants[1].SignHashOfMsg(message)
			}
			startTime3 := time.Now()
			for a := 0; a < runs; a++ {
				st1 := time.Now()
				message := strconv.Itoa(k) + ", " + strconv.Itoa(keysize) + ", " + strconv.Itoa(a)
				if !SecureMPC.VerifyShare(message, signatureShares[a], data) {
					fmt.Println("FAILURE! " + info)
				}
				fmt.Println("Single verification, " + info + " run: " + strconv.Itoa(a) + ", time passed: " + time.Since(st1).String())
			}
			avgTimeInMs3 := float64(time.Since(startTime3).Nanoseconds()/1000000) / float64(runs)
			timeString3 := fmt.Sprintf("%.2f", avgTimeInMs3)
			toWrite3 := info +
				", time: " + timeString3 + "\n"
			_, err = writer3.WriteString(toWrite3)
			check(err)
		}
		err = writer1.Flush()
		err = writer2.Flush()
		err = writer3.Flush()
		check(err)
	}
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}
