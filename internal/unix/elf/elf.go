// Package elf source: https://en.wikipedia.org/wiki/PJW_hash_function
package elf

import (
	"encoding/binary"
	"hash"
)

type ELF struct {
	sum uint32
}

func New() hash.Hash {
	return new(ELF)
}

func (h *ELF) BlockSize() int {
	return 1
}

func (h *ELF) Size() int {
	return 4
}

func (h *ELF) Reset() {
	h.sum = 0
}

func (h *ELF) Write(b []byte) (n int, err error) {
	var v uint32

	for i := 0; i < len(b); i++ {
		h.sum = (h.sum << 4) + uint32(b[i])

		if v = h.sum & 0xF0000000; v != 0 {
			h.sum ^= v >> 24
		}

		h.sum &= ^v
	}

	return len(b), nil
}

func (h *ELF) Sum(b []byte) []byte {
	if len(b) > 0 {
		_, _ = h.Write(b)
	}

	v := make([]byte, h.Size())
	binary.LittleEndian.PutUint32(v, h.sum)

	return v
}
