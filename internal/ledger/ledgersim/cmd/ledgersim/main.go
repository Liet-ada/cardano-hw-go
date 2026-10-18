// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Liet-ada

// Command ledgersim runs the simulated Ledger Cardano app on a TCP port, as
// Speculos serves APDUs, and writes what it receives to a transcript: one
// line per exchange, the APDU and the response in hex. It is for tests.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/Liet-ada/cardano-hw-go/internal/ledger/ledgersim"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:9999", "address to listen on")
	version := flag.String("version", "8.0.0", "app version")
	xs := flag.Bool("xs", false, "the reduced app of the Nano S")
	txHash := flag.String("txhash", "", "transaction body hash to return and sign, in hex")
	transcript := flag.String("transcript", "", "file to write the exchanges to")
	fail := flag.String("fail", "", "N:SW fails the Nth APDU (from 0) with status word SW (hex)")
	flag.Parse()

	var v [4]byte
	parts := strings.Split(*version, ".")
	if len(parts) != 3 {
		log.Fatalf("bad version %q", *version)
	}
	for i, p := range parts {
		n, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			log.Fatalf("bad version %q", *version)
		}
		v[i] = byte(n)
	}
	if *xs {
		v[3] |= 4
	}
	sim, err := ledgersim.New(ledgersim.TestMnemonic, v)
	if err != nil {
		log.Fatal(err)
	}
	if *txHash != "" {
		if sim.TxHash, err = hex.DecodeString(*txHash); err != nil {
			log.Fatal(err)
		}
	}
	var out *os.File
	if *transcript != "" {
		if out, err = os.Create(*transcript); err != nil {
			log.Fatal(err)
		}
	}
	var mu sync.Mutex
	count := 0
	failAt, failSW := -1, uint64(0)
	if *fail != "" {
		n, sw, ok := strings.Cut(*fail, ":")
		a, err1 := strconv.Atoi(n)
		b, err2 := strconv.ParseUint(sw, 16, 16)
		if !ok || err1 != nil || err2 != nil {
			log.Fatalf("bad -fail %q", *fail)
		}
		failAt, failSW = a, b
	}
	sim.Fail = func(apdu []byte) uint16 {
		mu.Lock()
		defer mu.Unlock()
		i := count
		count++
		if i == failAt {
			return uint16(failSW)
		}
		return 0
	}
	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("listening on", l.Addr())
	if out != nil {
		sim.OnExchange = func(e ledgersim.Exchange) {
			fmt.Fprintf(out, "%s %s\n", hex.EncodeToString(e.APDU), hex.EncodeToString(e.Response))
			out.Sync()
		}
	}
	log.Fatal(sim.Serve(l))
}
