package impfuzzy

import (
	"hash"
	"log"
	"strings"

	"github.com/glaslos/ssdeep"
	"go.foxforensics.dev/hasher/internal/similarity/imports"
)

type ImpFuzzy struct {
	buf []string
}

func New() hash.Hash {
	return new(ImpFuzzy)
}

func (h *ImpFuzzy) BlockSize() int {
	return h.BlockSize()
}

func (h *ImpFuzzy) Size() int {
	return h.Size()
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

func (h *ImpFuzzy) Sum(_ []byte) []byte {
	sum, err := ssdeep.FuzzyBytes([]byte(strings.Join(h.buf, ",")))

	if err != nil {
		log.Println(err)
	}

	return []byte(sum)
}
