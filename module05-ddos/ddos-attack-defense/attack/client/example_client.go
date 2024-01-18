package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"
	// "net"
	// "sync"

	"inet.af/netaddr"

	"ethz.ch/netsec/isl/handout/attack/server"
	"github.com/netsec-ethz/scion-apps/pkg/pan"

	// from attack.go
	// "github.com/scionproto/scion/go/lib/snet"
	// "github.com/scionproto/scion/go/lib/addr"
	// "github.com/scionproto/scion/go/lib/daemon"
	// "github.com/scionproto/scion/go/lib/sock/reliable"
	// "github.com/scionproto/scion/go/lib/spath"

)

// Example on how to generate a payload with the public meow API
func GenerateClientPayload() []byte {
	// Choose which request to send
	// var q server.Query = server.Second
	// set flags

	/*
	var flagH = false
	var flagV = true
	var flagM = true
	var flagD = true
	// Use API to build request
	request := server.NewRequest("67534", flagH, flagV, flagM, flagD)
	*/
	zeroArray := []byte{1}
	//request := server.NewRequest(zeroArray)
	// serialize the request with the API Marshal function
	/* d, err := request.MarshalJSON()
	if err != nil {
		fmt.Println(err)
		return make([]byte, 0) // empty paiload on fail
	} */
	return zeroArray
}

// Client is a simple udp-client example which speaks udp over scion through the pan API.
// The payload is sent to the given address exactly once and the answer is printed to
// standard output.

// serverAddr is address and port of meow server
// payload is byte array of the request (above)
func Client(ctx context.Context, serverAddrPort string, payload []byte) (err error) {

	/* Pan is a high level API provided by the scionlab team which facilitates sending and
	receiving scion traffic. The most common use cases are covered, but solving this lab exercise
	will need more fine grained control than pan provides.
	*/
	serverAddr, err := pan.ParseUDPAddr(serverAddrPort)
	if err != nil {
		log.Fatal(err)
	}
	conn, err := pan.DialUDP(ctx, netaddr.IPPort{}, serverAddr, nil, nil)
	if err != nil {
		fmt.Println("CLIENT: Dial produced an error.", err)
		return
	}
	defer conn.Close()
	n, err := conn.Write(payload)
	if err != nil {
		fmt.Println("CLIENT: Write produced an error.", err)
		return
	}

	fmt.Printf("CLIENT: Packet-written: bytes=%d addr=%s\n", n, serverAddr.String())
	buffer := make([]byte, server.MaxBufferSize)

	// Setting a read deadline makes sure the program doesn't get stuck waiting for an
	// answer from the server for too long.
	deadline := time.Now().Add(time.Second * 3)
	err = conn.SetReadDeadline(deadline)
	if err != nil {
		fmt.Println("CLIENT: SetReadDeadline produced an error.", err)
		return
	}

	nRead, _, err := conn.ReadVia(buffer)
	if err != nil {
		fmt.Println("CLIENT: Error reading from connection.", err)
		return
	}

	fmt.Printf("CLIENT: Packet-received: bytes=%d from=%s\n",
		nRead, conn.RemoteAddr())
	var answer string
	json.Unmarshal(buffer[:nRead], &answer)
	fmt.Printf("CLIENT:The answer was: \n%s", answer)

	// try some other stuff
	fmt.Println("Victim_Scion_IA: ", VictimScionIA())
	fmt.Println("Remote_Victim_IP: ", RemoteVictimIP())
	fmt.Println("Victim_Port: ", VictimPort())
	fmt.Println("Local_Victim_IP: ", LocalVictimIP())
	fmt.Println("Meow_IP: ", MeowServerIP())
	fmt.Println("Atack_duration: ", AttackDuration())
	fmt.Println("Attack_secs: ", AttackSeconds())
	fmt.Println("Scion_daemon_address: ", SCIONDAddress())


	return
}
