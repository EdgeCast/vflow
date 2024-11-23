//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: file:    transport.go
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

// TCPHeader represents TCP header
type TCPHeader struct {
	SrcPort    int
	DstPort    int
	DataOffset int
	Reserved   int
	Flags      int
}

// UDPHeader represents UDP header
type UDPHeader struct {
	SrcPort int
	DstPort int
}

// IPIPHeader represents IPIP header
type IPIPHeader struct {
	InnerVersion  int
	InnerTOS      int
	InnerTotalLen int
	InnerID       int
	InnerFlags    int
	InnerFragOff  int
	InnerTTL      int
	InnerProtocol int
	InnerChecksum int
	InnerSrc      string
	InnerDst      string
	SrcPort       int
	DstPort       int
	DataOffset    int
	Reserved      int
	Flags         int
}

var (
	errShortTCPHeaderLength  = errors.New("short TCP header length")
	errShortUDPHeaderLength  = errors.New("short UDP header length")
	errShortIPIPHeaderLength = errors.New("short IPIP header length")
)

func decodeTCP(b []byte) (TCPHeader, error) {
	if len(b) < 20 {
		return TCPHeader{}, errShortTCPHeaderLength
	}

	return TCPHeader{
		SrcPort:    int(b[0])<<8 | int(b[1]),
		DstPort:    int(b[2])<<8 | int(b[3]),
		DataOffset: int(b[12]) >> 4,
		Reserved:   0,
		Flags:      ((int(b[12])<<8 | int(b[13])) & 0x01ff),
	}, nil
}

func decodeUDP(b []byte) (UDPHeader, error) {
	if len(b) < 8 {
		return UDPHeader{}, errShortUDPHeaderLength
	}

	return UDPHeader{
		SrcPort: int(b[0])<<8 | int(b[1]),
		DstPort: int(b[2])<<8 | int(b[3]),
	}, nil
}

func decodeIPIP(b []byte) (IPIPHeader, error) {
	if len(b) < 40 {
		return IPIPHeader{}, errShortIPIPHeaderLength
	}

	var (
		src net.IP = b[12:16]
		dst net.IP = b[16:20]
	)

	ipipHeader := IPIPHeader{
		InnerVersion:  int(b[0] & 0xf0 >> 4),
		InnerTOS:      int(b[1]),
		InnerTotalLen: int(b[2])<<8 | int(b[3]),
		InnerID:       int(b[4])<<8 | int(b[5]),
		InnerFlags:    int(b[6] & 0x07),
		InnerTTL:      int(b[8]),
		InnerProtocol: int(b[9]),
		InnerChecksum: int(b[10])<<8 | int(b[11]),
		InnerSrc:      src.String(),
		InnerDst:      dst.String(),
		SrcPort:       int(b[20])<<8 | int(b[21]),
		DstPort:       int(b[22])<<8 | int(b[23]),
		DataOffset:    int(b[32]) >> 4,
		Reserved:      0,
		Flags:         ((int(b[32])<<8 | int(b[33])) & 0x01ff),
	}

	return ipipHeader, nil
}
