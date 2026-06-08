// Package pe source: https://github.com/saferwall/pe/blob/v1.5.7/helper.go#L552
package pe

import (
	"encoding/binary"
	"hash"
)

const (
	size  = 4
	block = 4
)

type PE struct {
	sum uint64
}

func New() hash.Hash {
	return new(PE)
}

func (h *PE) BlockSize() int {
	return block
}

func (h *PE) Size() int {
	return size
}

func (h *PE) Reset() {
	h.sum = 0
}

func (h *PE) Write(b []byte) (n int, err error) {
	var blk uint32

	r := uint32(len(b)) % 4
	l := uint32(len(b))

	if r > 0 {
		l += 4 - r
		b = append(b, make([]byte, 4-r)...)
	}

	for i := uint64(0); i < uint64(l); i += 4 {
		blk = binary.LittleEndian.Uint32(b[i:])
		h.sum = (h.sum & 0xffffffff) + uint64(blk) + (h.sum >> 32)

		if h.sum > 0x100000000 {
			h.sum = (h.sum & 0xffffffff) + (h.sum >> 32)
		}
	}

	h.sum = (h.sum & 0xffff) + (h.sum >> 16)
	h.sum = h.sum + (h.sum >> 16)
	h.sum = h.sum & 0xffff
	h.sum += uint64(l)

	return len(b), nil
}

func (h *PE) Sum(b []byte) []byte {
	if len(b) > 0 {
		_, _ = h.Write(b)
	}

	v := make([]byte, size)
	binary.LittleEndian.PutUint32(v, uint32(h.sum))

	return v
}
