//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: file:    network.go
//: details: TODO
//: author:  Mehrdad Arshad Rad
//: date:    02/01/2017
//:
//: Licensed under the Apache License, Version 2.0 (the "License");
//: you may not use this file except in compliance with the License.
//: You may obtain a copy of the License at
//:
//:     http://www.apache.org/licenses/LICENSE-2.0
//:
//: Unless required by applicable law or agreed to in writing, software
//: distributed under the License is distributed on an "AS IS" BASIS,
//: WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//: See the License for the specific language governing permissions and
//: limitations under the License.
//: ----------------------------------------------------------------------------

package packet

import (
	"errors"
	"net"
)

// IPv4Header represents an IPv4 header
type IPv4Header struct {
	Version  int    // protocol version
	TOS      int    // type-of-service
	TotalLen int    // packet total length
	ID       int    // identification
	Flags    int    // flags
	FragOff  int    // fragment offset
	TTL      int    // time-to-live
	Protocol int    // next protocol
	Checksum int    // checksum
	Src      string // source address
	Dst      string // destination address
}

// IPv6Header represents an IPv6 header
type IPv6Header struct {
	Version      int    // protocol version
	TrafficClass int    // traffic class
	FlowLabel    int    // flow label
	PayloadLen   int    // payload length
	NextHeader   int    // next header
	HopLimit     int    // hop limit
	Src          string // source address
	Dst          string // destination address
}

const (
	// IPv4HLen is IPv4 header length size
	IPv4HLen = 20

	// IPv6HLen is IPv6 header length size
	IPv6HLen = 40

	// IANAProtoICMP is IANA Internet Control Message number
	IANAProtoICMP = 1

	// IANAProtoIPIP is IANA User Datagram number
	IANAProtoIPIP = 4

	// IANAProtoTCP is IANA Transmission Control number
	IANAProtoTCP = 6

	// IANAProtoUDP is IANA User Datagram number
	IANAProtoUDP = 17

	// IANAProtoIPv6ICMP is IANA Internet Control Message number for IPv6
	IANAProtoIPv6ICMP = 58
)

var (
	errShortIPv4HeaderLength = errors.New("short ipv4 header length")
	errShortIPv6HeaderLength = errors.New("short ipv6 header length")
	errShortEthernetLength   = errors.New("short ethernet header length")
	errUnknownTransportLayer = errors.New("unknown transport layer")
	errUnknownL3Protocol     = errors.New("unknown network layer protocol")
)

func (p *Packet) decodeNextLayer() error {

	var (
		proto int
		len   int
	)

	switch p.L3.(type) {
	case IPv4Header:
		proto = p.L3.(IPv4Header).Protocol
	case IPv6Header:
		proto = p.L3.(IPv6Header).NextHeader
	default:
		return errUnknownL3Protocol
	}

	switch proto {
	case IANAProtoICMP, IANAProtoIPv6ICMP:
		icmp, err := decodeICMP(p.data)
		if err != nil {
			return err
		}

		p.L4 = icmp
		len = 4
	case IANAProtoTCP:
		tcp, err := decodeTCP(p.data)
		if err != nil {
			return err
		}

		p.L4 = tcp
		len = 20
	case IANAProtoUDP:
		udp, err := decodeUDP(p.data)
		if err != nil {
			return err
		}

		p.L4 = udp
		len = 8

	case IANAProtoIPIP:
		ipip, err := decodeIPIP(p.data)
		if err != nil {
			return err
		}

		p.L4 = ipip
		len = 40
	default:
		return errUnknownTransportLayer
	}

	p.data = p.data[len:]

	return nil
}

func (p *Packet) decodeIPv6Header() error {
	if len(p.data) < IPv6HLen {
		return errShortIPv6HeaderLength
	}

	var (
		src net.IP = p.data[8:24]
		dst net.IP = p.data[24:40]
	)

	p.L3 = IPv6Header{
		Version:      int(p.data[0]) >> 4,
		TrafficClass: int(p.data[0]&0x0f)<<4 | int(p.data[1])>>4,
		FlowLabel:    int(p.data[1]&0x0f)<<16 | int(p.data[2])<<8 | int(p.data[3]),
		PayloadLen:   int(uint16(p.data[4])<<8 | uint16(p.data[5])),
		NextHeader:   int(p.data[6]),
		HopLimit:     int(p.data[7]),
		Src:          src.String(),
		Dst:          dst.String(),
	}

	p.data = p.data[IPv6HLen:]

	return nil
}

func (p *Packet) decodeIPv4Header() error {
	if len(p.data) < IPv4HLen {
		return errShortIPv4HeaderLength
	}

	var (
		src net.IP = p.data[12:16]
		dst net.IP = p.data[16:20]
	)

	p.L3 = IPv4Header{
		Version:  int(p.data[0] & 0xf0 >> 4),
		TOS:      int(p.data[1]),
		TotalLen: int(p.data[2])<<8 | int(p.data[3]),
		ID:       int(p.data[4])<<8 | int(p.data[5]),
		Flags:    int(p.data[6] & 0x07),
		TTL:      int(p.data[8]),
		Protocol: int(p.data[9]),
		Checksum: int(p.data[10])<<8 | int(p.data[11]),
		Src:      src.String(),
		Dst:      dst.String(),
	}

	p.data = p.data[IPv4HLen:]

	return nil
}
