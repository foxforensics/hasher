// Package kermit source: https://github.com/joaojeronimo/go-crc16/blob/master/crc16-kermit.go
package kermit

import (
	"encoding/binary"
	"hash"
)

const (
	size  = 2
	block = 2
)

type Kermit struct {
	sum uint16
}

func New() hash.Hash {
	return new(Kermit)
}

func (h *Kermit) BlockSize() int {
	return block
}

func (h *Kermit) Size() int {
	return size
}

func (h *Kermit) Reset() {
	h.sum = 0
}

func (h *Kermit) Write(b []byte) (n int, err error) {
	v := h.sum

	for i := 0; i < len(b); i++ {
		c := uint16(b[i])
		q := (v ^ c) & 0x0f
		v = (v >> 4) ^ (q * 0x1081)
		q = (v ^ (c >> 4)) & 0xf
		v = (v >> 4) ^ (q * 0x1081)
	}

	h.sum = (v >> 8) ^ (v << 8)

	return len(b), nil
}

func (h *Kermit) Sum(b []byte) []byte {
	sum := make([]byte, size)
	binary.LittleEndian.PutUint16(sum, h.sum)

	return append(b, sum...)
}
