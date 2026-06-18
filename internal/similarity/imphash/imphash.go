// Package imphash based on https://github.com/omarghader/pefile-go/blob/master/pe/pe.go
package imphash

import (
	"crypto/md5"
	"hash"
	"strings"

	"go.foxforensics.eu/hasher/internal/similarity/imports"
)

type ImpHash struct {
	sort bool
	buf  []string
}

func NewSorted() hash.Hash {
	return &ImpHash{sort: true}
}

func NewUnsorted() hash.Hash {
	return &ImpHash{sort: false}
}

func (h *ImpHash) BlockSize() int {
	return md5.BlockSize // from underlying MD5
}

func (h *ImpHash) Size() int {
	return md5.Size
}

func (h *ImpHash) Reset() {
	h.buf = h.buf[:0]
}

func (h *ImpHash) Write(b []byte) (n int, err error) {
	v, err := imports.GetImports(b, h.sort)

	if err != nil {
		return 0, err
	}

	h.buf = append(h.buf, v...)

	return len(b), nil

}

func (h *ImpHash) Sum(b []byte) []byte {
	sum := md5.Sum([]byte(strings.Join(h.buf, ",")))

	return append(b, sum[:]...)
}
