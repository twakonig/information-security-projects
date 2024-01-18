package main

import (
	"fmt"
	"strconv"
	//"sort"

	"ethz.ch/netsec/isl/handout/defense/lib"
	"github.com/scionproto/scion/go/lib/slayers"
	spath "github.com/scionproto/scion/go/lib/slayers/path/scion"
)

const (
// Global constants
// put THRESHOLDS HERE
	srcIPthreshold = 40
	srcIAthreshold = 70

)

var (
// Here, you can define variables that keep state for your firewall
	packetsPassed uint64
	counter uint64
	nonce uint64
	// def1
	srcIP string
	srcIPmap map[string]int
	//previous IP
	aIP string
	//before previous IP
	bIP string
	cIP string
	dIP string
	eIP string
	fIP string

	repIPmap map[string]int


	srcIA string
	srcIAmap map[string]int
	// previous IA
	aIA string
	// before previous IA
	bIA string
	repIAmap map[string]int

	// udp
	srcPort string
	srcPortmap map[string]int

	length string
	lengthMap map[string]int

	// try combinations
	// IA + IP
	srcAddr string
	srcAddrmap map[string]int

	payloadStr string
	payloadMap map[string]int

	// tests for nonce:
	n1 []uint64
	n2 []uint64
	n3 []uint64
	n4 []uint64
	n5 []uint64
	n6 []uint64
	n7 []uint64
	n8 []uint64
	n9 []uint64
	
)

// This function receives all packets destined to the customer server.
//
// Your task is to decide whether to forward or drop a packet based on the
// headers and payload.
// References for the given packet types:
// - SCION header
//   https://pkg.go.dev/github.com/scionproto/scion/go/lib/slayers#SCION
// - UDP header
//   https://pkg.go.dev/github.com/scionproto/scion/go/lib/slayers#UDP
//
func filter(scion slayers.SCION, udp slayers.UDP, payload []byte) bool {
	// Print packet contents 
	// TODO: (disable this before submitting your code)
	counter += 1
	//prettyPrintSCION(scion)
	//prettyPrintUDP(udp)
	fmt.Println("REQUEST NR.: ", counter)
	//fmt.Println("Payload: ", string(payload))
	fmt.Println("----------------------------------------")


	
	//------------------SCION header------------------------------------
	fIP = eIP
	eIP = dIP
	dIP = cIP
	cIP = bIP
	bIP = aIP
	aIP = srcIP
	// get RawSrcAddr field from SCION header and convert to string
	bytesIP := scion.RawSrcAddr
	srcIP = "|" + strconv.FormatUint(uint64(bytesIP[0]), 10) + "." + strconv.FormatUint(uint64(bytesIP[1]), 10) + "." + strconv.FormatUint(uint64(bytesIP[2]), 10) + "." + strconv.FormatUint(uint64(bytesIP[3]), 10)


	// get SrcIA field from SCION header and convert to string
	bIA = aIA
	aIA = srcIA
	srcIA = "|" + scion.SrcIA.String()

	// combine IA and IP
	srcAddr = srcIA + srcIP

	//---------------------UDP header-----------------------------------
	// get UDP source port
	srcPort = "|" + strconv.FormatUint(uint64(udp.SrcPort), 10)
	//length = strconv.FormatUint(uint64(udp.Length), 10)




	// put incoming traffic into hashmap. IF NOT YET PRESENT
	// def1: (key: IPaddr = RawSrcAddr, value: numIPrequests)
	srcIPmap[srcIP] += 1
	srcIAmap[srcIA] += 1
	srcPortmap[srcPort] += 1
	srcAddrmap[srcAddr] += 1
	lengthMap[length] += 1


	// DECISIONS
	//------------------DEF1 & DEF2-------------------------------------------
	// test repeated sending of same IP
	if srcIP == aIP || srcIP == bIP || srcIP == cIP || srcIP == dIP || srcIP == eIP || srcIP == fIP {
		repIPmap[srcIP] += 1
		return false
	}
	// def1: filter IPs (too many requests per IP), and AS (unbalanced traffic)
	if srcIPmap[srcIP] > srcIPthreshold {
		return false
	}
	//-----------------------------------------------------------------


/*
	// def2 test
	if srcIA == aIA || srcIA == bIA {
		repIAmap[srcIA] += 1
		fmt.Println("srcIAmap: ", srcIAmap)
		return false
	}
	if srcIAmap[srcIA] > srcIAthreshold {
		return false
	}
*/


	length = strconv.FormatUint(uint64(udp.Length), 10)
	payloadStr = string(payload)
	nonce, _ = strconv.ParseUint((payloadStr[10:len(payloadStr)-1]), 10, 64)
	fmt.Println("Nonce: ", nonce)


	// -------------------Paths DEF3--------------------
	raw := make([]byte, scion.Path.Len())
	scion.Path.SerializeTo(raw)
	path := &spath.Decoded{}
	path.DecodeFromBytes(raw)

	hopString := ""
	for i := range path.HopFields {
		//FILTERING
		if path.HopFields[i].ConsIngress > 6 || path.HopFields[i].ConsEgress > 6 {
			return false
		}
		// keep this to minimize server load
		if i == 0 && path.HopFields[i].ConsIngress == 0 {
			return false
		}

		// format string
		if i > 0 {
			hopString += "->"
		}
		hopString += strconv.FormatUint(uint64(path.HopFields[i].ConsIngress), 10) + "-"
		hopString += strconv.FormatUint(uint64(path.HopFields[i].ConsEgress), 10)
	}

	fmt.Println("HopString: ", hopString)



	// ------------------Nonces-------------------
	// not effective but this is the problematic range, packet length: 29
	// if nonce > 999999999 && nonce < 4000000000 {
	// 	fmt.Println("Length: ", length)
	// 	return false
	// }

	// //SUSPICIOS n1-n3 NOT UNIFORMLY DISTRIBUTED
	// if nonce > 999999999 {
	// 	fmt.Println("Length: ", length)
	// 	if nonce < 2000000000 {
	// 		n1 = append(n1, nonce)
	// 	} else if nonce < 3000000000 {
	// 		n2 = append(n2, nonce)
	// 	} else if nonce < 4000000000 {
	// 		n3 = append(n3, nonce)
	// 	} else if nonce < 5000000000 {
	// 		n4 = append(n4, nonce)
	// 	} else if nonce < 6000000000 {
	// 		n5 = append(n5, nonce)
	// 	} else if nonce < 7000000000 {
	// 		n6 = append(n6, nonce)
	// 	} else if nonce < 8000000000 {
	// 		n7 = append(n7, nonce)
	// 	} else if nonce < 9000000000 {
	// 		n8 = append(n8, nonce)
	// 	} else {
	// 		n9 = append(n9, nonce)
	// 	}
	// }


	// fmt.Println("length of n1: ", len(n1))
	// fmt.Println("length of n2: ", len(n2))
	// fmt.Println("length of n3: ", len(n3))
	// fmt.Println("length of n4: ", len(n4))
	// fmt.Println("length of n5: ", len(n5))
	// fmt.Println("length of n6: ", len(n6))
	// fmt.Println("length of n7: ", len(n7))
	// fmt.Println("length of n8: ", len(n8))
	// fmt.Println("length of n9: ", len(n9))

	// fmt.Println("n4: ", n4)
	// fmt.Println("n5: ", n5)
	//fmt.Println("n1: ", n1)


	// --------PAYLOAD--------
	//payloadStr = string(payload)
	payloadMap[payloadStr] += 1
	/* //fmt.Println("PayloadMap: ", payloadMap)
	// slice and sort keys
	payloadKeys := make([]string, 0, len(payloadMap))
	for k := range payloadMap {
		payloadKeys = append(payloadKeys, k)
	}
	// sort keys
	sort.Strings(payloadKeys)
	for _, k := range payloadKeys {
		fmt.Println(k)
	} */
	
	

	// fmt.Println("srcIPmap: ", srcIPmap)
	// fmt.Println("srcIAmap: ", srcIAmap)
	// fmt.Println("srcPortmap: ", srcPortmap)
	// fmt.Println("srcAddrmap: ", srcAddrmap)
	// fmt.Println("lengthMap: ", lengthMap)
	// fmt.Println("repIPmap: ", repIPmap)
	//fmt.Println("repIAmap: ", repIAmap)

	packetsPassed += 1
	fmt.Println("Number of packets passed: ", packetsPassed)
	fmt.Println("*************************************************************************************")


	// | true  -> forward packet
	// | false -> drop packet
	return true
}

func init() {
	// Perform any initial setup here
	packetsPassed = 0
	counter = 0
	srcIP = ""
	aIP, bIP, cIP, dIP, eIP = "", "", "", "", ""
	srcIA = ""
	aIA = ""
	srcIPmap = make(map[string]int)
	srcIAmap = make(map[string]int)
	srcPortmap = make(map[string]int)
	srcAddrmap = make(map[string]int)
	lengthMap = make(map[string]int)
	repIPmap = make(map[string]int)
	repIAmap = make(map[string]int)
	payloadMap = make(map[string]int)
}

func main() {
	// Start the firewall. Code after this line will not be executed
	lib.RunFirewall(filter)
}
