// Package sysv
package sysv

import (
	"fmt"
	"hash"
)

type SYSV struct {
	sum uint32
}

func New() hash.Hash {
	return new(SYSV)
}

func (h *SYSV) BlockSize() int {
	return 1
}

func (h *SYSV) Size() int {
	return 2
}

func (h *SYSV) Reset() {
	h.sum = 0
}

func (h *SYSV) Write(b []byte) (n int, err error) {
	for i := 0; i < len(b); i++ {
		h.sum += uint32(b[i])
	}

	return len(b), nil
}

func (h *SYSV) Sum(b []byte) []byte {
	if len(b) > 0 {
		_, _ = h.Write(b)
	}

	var v uint32

	v = (h.sum & 0xFFFF) + (h.sum >> 16)
	v = (h.sum & 0xFFFF) + (h.sum >> 16)

	return []byte(fmt.Sprintf("%05d", v))
}
