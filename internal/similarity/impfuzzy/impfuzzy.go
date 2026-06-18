package impfuzzy

import (
	"hash"
	"strings"

	"github.com/glaslos/ssdeep"
	"go.foxforensics.eu/hasher/internal/similarity/imports"
)

type ImpFuzzy struct {
	buf []string
}

func New() hash.Hash {
	return new(ImpFuzzy)
}

func (h *ImpFuzzy) BlockSize() int {
	return 3 // minimum block size
}

func (h *ImpFuzzy) Size() int {
	return 64 // spam sum length
}

func (h *ImpFuzzy) Reset() {
	h.buf = h.buf[:0]
}

func (h *ImpFuzzy) Write(b []byte) (n int, err error) {
	v, err := imports.GetImports(b, false)

	if err != nil {
		return 0, err
	}

	h.buf = append(h.buf, v...)

	return len(b), nil
}

func (h *ImpFuzzy) Sum(b []byte) []byte {
	f := ssdeep.Force
	ssdeep.Force = true
	sum, err := ssdeep.FuzzyBytes([]byte(strings.Join(h.buf, ",")))
	ssdeep.Force = f

	if err != nil {
		return nil
	}

	return append(b, sum...)
}
