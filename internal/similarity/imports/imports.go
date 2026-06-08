package imports

import (
	"fmt"
	"slices"
	"strings"

	"github.com/saferwall/pe"
)

func Lookup(dll string, ord uint32) string {
	// lookup library imports
	v := pe.OrdLookup(dll, uint64(ord), false)

	if len(v) > 0 {
		return v
	}

	// lookup additional imports
	if m, ok := Ordinals[dll]; ok {
		if v, ok = m[ord]; ok {
			return v
		}
	}

	return fmt.Sprintf("ord%d", ord)
}

func GetImports(b []byte, sort bool) ([]string, error) {
	var file = make([]byte, len(b))
	var imps []string

	copy(file, b)

	f, err := pe.NewBytes(file, &pe.Options{
		DisableCertValidation:      true,
		DisableSignatureValidation: true,
		OmitExportDirectory:        true,
		OmitExceptionDirectory:     true,
		OmitResourceDirectory:      true,
		OmitSecurityDirectory:      true,
		OmitRelocDirectory:         true,
		OmitDebugDirectory:         true,
		OmitArchitectureDirectory:  true,
		OmitGlobalPtrDirectory:     true,
		OmitTLSDirectory:           true,
		OmitLoadConfigDirectory:    true,
		OmitBoundImportDirectory:   true,
		OmitCLRHeaderDirectory:     true,
		OmitCLRMetadata:            true,
	})

	if err != nil {
		return imps, err
	}

	defer func(f *pe.File) {
		_ = f.Close()
	}(f)

	err = f.Parse()

	if err != nil {
		return imps, err
	}

	rep := strings.NewReplacer(".dll", "", ".ocx", "", ".sys", "")

	for _, imp := range f.Imports {
		buf := make([]string, 0, len(imp.Functions))

		dll := rep.Replace(strings.ToLower(imp.Name))

		for _, fn := range imp.Functions {
			name := strings.ToLower(fn.Name)

			if len(fn.Name) == 0 {
				name = Lookup(imp.Name, fn.Ordinal)
			}

			buf = append(buf, fmt.Sprintf("%s.%s", dll, name))
		}

		if sort {
			slices.Sort(buf)
		}

		imps = append(imps, buf...)
	}

	return imps, nil
}
