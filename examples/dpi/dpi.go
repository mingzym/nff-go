// Copyright 2018 Intel Corporation.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/flier/gohs/hyperscan"
	"github.com/intel-go/nff-go/common"
	"github.com/intel-go/nff-go/flow"
	"github.com/intel-go/nff-go/packet"
)

// Sample input pcap files can be downloaded from http://wiresharkbook.com/studyguide.html
// For example:
// http-cnn2012.pcapng
// http-facebook.pcapng
// http-downloadvideo.pcapng
// google-http.pcapng
//
// Note: only pcap format is supported. Convert pcapng to pcap:
// editcap -F pcap http-facebook.pcapng http-facebook.pcap
//
// Rules file requirements:
// In regexp mode:
//		Rules in file should go in increasing priority.
//		Rules are checked in the order they are in the file.
// 		Each next rule is more specific and refines (or overwrites) result
// 		of previous rules check.
//		Support 'allow'/'disallow' rules.
// In hyperscan mode:
// 		Rules has equal priority and are checked all at once.
//		For match enough at least one match of any pattern.
//		Support only 'allow' rules, 'disallow' rules are skipped.

const (
	// Last flow among totalNumFlows is for dropped packets.
	totalNumFlows uint = 2
	// numFlows=1 is enough to process packets from file.
	numFlows uint = totalNumFlows - 1
)

var (
	infile    string
	outfile   string
	rulesfile string
	nreads    int
	timeout   time.Duration
	useHS     bool

	// Number of allowed packets for each flow
	allowedPktsCount [numFlows]uint64
	// Number of read packets for each flow
	readPktsCount [numFlows]uint64
	// Number of packets blocked by signature for each flow
	blockedPktsCount [numFlows]uint64

	rules []rule

	packetFilter func(*packet.Packet, flow.UserContext) bool

	// Hyperscan block database
	bdb hyperscan.BlockDatabase
	// Each handler require separate scratch
	scratches [numFlows]*hyperscan.Scratch
	// On match callback
	onMatchCallback hyperscan.MatchHandler = onMatch
)

// CheckFatal is an error handling function
func CheckFatal(err error) {
	if err != nil {
		fmt.Printf("checkfatal: %+v\n", err)
		os.Exit(1)
	}
}

func main() {
	flag.StringVar(&infile, "infile", "", "input pcap file")
	flag.StringVar(&outfile, "outfile", "allowed_packets.pcap", "output pcap file with allowed packets")
	flag.StringVar(&rulesfile, "rfile", "test-rules.json", "input JSON file, specifying rules")
	flag.IntVar(&nreads, "nreads", 1, "number pcap file reads")
	flag.DurationVar(&timeout, "timeout", 5*time.Second, "time to run, seconds")
	flag.BoolVar(&useHS, "hs", false, "use Intel Hyperscan library for regex match (default is go regexp)")
	flag.Parse()

	// Initialize NFF-Go library
	config := flow.Config{}
	CheckFatal(flow.SystemInit(&config))

	var err error
	rules, err = getRulesFromFile(rulesfile)
	CheckFatal(err)

	if !useHS {
		packetFilter = filterByRegexp
	} else {
		packetFilter = filterByHS
		setupHyperscan(rules)
	}

	// Receive packets from given PCAP file
	inputFlow := flow.SetReceiverFile(infile, int32(nreads))

	// Split packets into flows by hash of five-tuple
	// Packets without five-tuple are put in last flow and will be dropped
	outputFlows, err := flow.SetSplitter(inputFlow, splitBy5Tuple, totalNumFlows, nil)
	CheckFatal(err)

	// Drop last flow
	CheckFatal(flow.SetStopper(outputFlows[totalNumFlows-1]))

	for i := uint(0); i < numFlows; i++ {
		lc := localCounters{handlerId: i}
		CheckFatal(flow.SetHandlerDrop(outputFlows[i], packetFilter, lc))
	}

	outFlow, err := flow.SetMerger(outputFlows[:numFlows]...)
	CheckFatal(err)

	CheckFatal(flow.SetSenderFile(outFlow, outfile))

	go func() {
		CheckFatal(flow.SystemStart())
	}()

	// Finish by timeout, as cannot verify if file reading finished
	time.Sleep(timeout)

	// Compose info about all handlers
	var read uint64
	var allowed uint64
	var blocked uint64
	fmt.Println("\nHandler statistics")
	for i := uint(0); i < numFlows; i++ {
		fmt.Printf("Handler %d processed %d packets (allowed=%d, blocked by signature=%d)\n",
			i, readPktsCount[i], allowedPktsCount[i], blockedPktsCount[i])
		read += readPktsCount[i]
		allowed += allowedPktsCount[i]
		blocked += blockedPktsCount[i]
	}
	fmt.Println("Total:")
	fmt.Println("read =", read)
	fmt.Println("allowed =", allowed)
	fmt.Println("dropped (read - allowed) =", read-allowed)
	if !useHS {
		fmt.Println("blocked =", blocked)
	}

	if useHS {
		cleanupHyperscan()
	}
}

type localCounters struct {
	handlerId         uint
	allowedCounterPtr *uint64
	readCounterPtr    *uint64
	blockedCounterPtr *uint64
}

// Create new counters for new handler
func (lc localCounters) Copy() interface{} {
	var newlc localCounters
	// Clones has the same id
	id := lc.handlerId
	newlc.handlerId = id
	newlc.allowedCounterPtr = &allowedPktsCount[id]
	newlc.readCounterPtr = &readPktsCount[id]
	newlc.blockedCounterPtr = &blockedPktsCount[id]
	return newlc
}

func (lc localCounters) Delete() {
}

func filterByRegexp(pkt *packet.Packet, context flow.UserContext) bool {
	cnt := context.(localCounters)
	numRead := cnt.readCounterPtr
	numAllowed := cnt.allowedCounterPtr
	numBlocked := cnt.blockedCounterPtr

	atomic.AddUint64(numRead, 1)
	data, err := extractData(pkt)
	if err != nil {
		fmt.Println("WARNING:", err, ", drop packet")
		return false
	}

	accept := false
	block := false
	for _, rule := range rules {
		result := rule.Re.Match(data)
		if !result {
			continue
		}
		if rule.Allow {
			accept = true
		} else {
			accept = false
			block = true
		}
	}
	if accept {
		atomic.AddUint64(numAllowed, 1)
	}
	if !accept && block {
		atomic.AddUint64(numBlocked, 1)
	}
	return accept
}

func splitBy5Tuple(pkt *packet.Packet, context flow.UserContext) uint {
	h := fnv.New64a()
	ip4, ip6, _ := pkt.ParseAllKnownL3()
	if ip4 != nil {
		pkt.ParseL4ForIPv4()
	} else if ip6 != nil {
		pkt.ParseL4ForIPv6()
	} else {
		// Other protocols not supported
		return totalNumFlows - 1
	}
	if ip4 != nil {
		if ip4.NextProtoID != common.TCPNumber && ip4.NextProtoID != common.UDPNumber {
			return totalNumFlows - 1
		}
		h.Write([]byte{ip4.NextProtoID})
		buf := new(bytes.Buffer)
		CheckFatal(binary.Write(buf, binary.LittleEndian, ip4.SrcAddr))
		h.Write(buf.Bytes())
		CheckFatal(binary.Write(buf, binary.LittleEndian, ip4.DstAddr))
		h.Write(buf.Bytes())
	} else if ip6 != nil {
		if ip6.Proto != common.TCPNumber && ip6.Proto != common.UDPNumber {
			return totalNumFlows - 1
		}
		binary.Write(h, binary.BigEndian, ip6.Proto)
		h.Write(ip6.SrcAddr[:])
		h.Write(ip6.DstAddr[:])
	}

	binary.Write(h, binary.BigEndian, pkt.GetTCPNoCheck().SrcPort)
	binary.Write(h, binary.BigEndian, pkt.GetTCPNoCheck().DstPort)

	hash := uint(h.Sum64())
	return hash % numFlows
}

func extractData(pkt *packet.Packet) ([]byte, error) {
	pktLen := pkt.GetPacketSegmentLen()
	pktStartAddr := pkt.StartAtOffset(0)
	pktBytes := (*[1 << 30]byte)(pktStartAddr)[:pktLen]
	ok := pkt.ParseData()
	if ok == -1 {
		return nil, fmt.Errorf("cannot extract packet data")
	}

	hdrsLen := uintptr(pkt.Data) - uintptr(pktStartAddr)
	return pktBytes[hdrsLen:], nil
}

func getRulesFromFile(filename string) ([]rule, error) {
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	rules = make([]rule, 0)
	if err := json.Unmarshal(f, &rules); err != nil {
		return nil, err
	}
	for i := 0; i < len(rules); i++ {
		rules[i].Re = regexp.MustCompile(rules[i].Regexp)
	}
	return rules, nil
}

type rule struct {
	Name   string
	Regexp string
	Re     *regexp.Regexp
	Allow  bool
}

func onMatch(id uint, from, to uint64, flags uint, context interface{}) error {
	isMatch := context.(*bool)
	// Report outside that match was found
	*isMatch = true
	return nil
}

func filterByHS(pkt *packet.Packet, context flow.UserContext) bool {
	cnt := context.(localCounters)
	hid := cnt.handlerId
	numRead := cnt.readCounterPtr
	numAllowed := cnt.allowedCounterPtr

	atomic.AddUint64(numRead, 1)

	data, err := extractData(pkt)
	if err != nil {
		fmt.Println("WARNING:", err, ", drop packet")
		return false
	}

	result := new(bool)
	if err := bdb.Scan(data, scratches[hid], onMatchCallback, result); err != nil {
		return false
	}

	if *result {
		atomic.AddUint64(numAllowed, 1)
	}
	return *result
}

func getAllowPatterns(rules []rule) (ret []string) {
	for _, r := range rules {
		if r.Allow == true {
			ret = append(ret, r.Regexp)
		}
	}
	if len(ret) == 0 {
		fmt.Fprintf(os.Stderr, "ERROR: no 'allow' rules in file. HS mode support only allow rules")
		os.Exit(-1)
	}
	return
}

func parsePatterns(unparsed []string) (patterns []*hyperscan.Pattern) {
	for k, v := range unparsed {
		p, err := hyperscan.ParsePattern(v)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Could not parse pattern: %s", err)
			os.Exit(-1)
		}
		p.Id = k
		patterns = append(patterns, p)
	}
	return
}

// Setup Hyperscan DBs and scratches
func setupHyperscan(rules []rule) {
	unparsed := getAllowPatterns(rules)
	patterns := parsePatterns(unparsed)
	var err error
	bdb, err = hyperscan.NewBlockDatabase(patterns...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Could not compile patterns, %s", err)
		os.Exit(-1)
	}

	// Allocate one scratch per flow
	for i := uint(0); i < numFlows; i++ {
		scratches[i], err = hyperscan.NewScratch(bdb)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ERROR: Could not allocate scratch space i=%d for block db: %s", i, err)
			os.Exit(-1)
		}
	}
}

func cleanupHyperscan() {
	for i := uint(0); i < numFlows; i++ {
		scratches[i].Free()
	}
	bdb.Close()
}
