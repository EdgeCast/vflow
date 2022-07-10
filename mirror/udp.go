//: ----------------------------------------------------------------------------
//: Copyright (C) 2017 Verizon.  All Rights Reserved.
//: All Rights Reserved
//:
//: file:    udp.go
//: details: mirror udp handler
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

package mirror

import "encoding/binary"

// UDP represents UDP header
type UDP struct {
	SrcPort  int
	DstPort  int
	Length   int
	Checksum int
}

// Marshal returns decoded UDP
func (u *UDP) Marshal() []byte {
	b := make([]byte, UDPHLen)

	binary.BigEndian.PutUint16(b[0:], uint16(u.SrcPort))
	binary.BigEndian.PutUint16(b[2:], uint16(u.DstPort))
	binary.BigEndian.PutUint16(b[4:], uint16(UDPHLen+u.Length))
	binary.BigEndian.PutUint16(b[6:], uint16(u.Checksum))

	return b
}

// SetLen sets the payload length
func (u *UDP) SetLen(b []byte, n int) {
	binary.BigEndian.PutUint16(b[4:], uint16(UDPHLen+n))
}

// SetChecksum calculates and sets IPv6 checksum
func (u *UDP) SetChecksum() {
	// TODO
}
