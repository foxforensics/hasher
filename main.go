// Multi-algorithm hasher supporting cryptographic, performance, perceptual and similarity hashes.
//
// Usage:
//
//	hasher algorithm path
//
// The arguments are:
//
//	algorithm
//		    Hash algorithm to used (required).
//	path
//		    File or folder to hash (required).
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"go.foxforensics.eu/go-mmap"
	"go.foxforensics.eu/hasher/hash"
)

var Usage = `© 2026 Fox Forensics. Licensed under MIT License.
Usage: hasher ALGORITHM PATH

Cryptographic hashes:
  BLAKE2S-256, BLAKE2B-256, BLAKE2B-384, BLAKE2B-512, BLAKE3-256, BLAKE3-512
  GOST2012-256, GOST2012-512, HAS-160, LSH-256, LSH-512, MD2, MD4, MD5, MD6
  RIPEMD-160, SHAKE128, SHAKE256, SHA1, SHA224, SHA256, SHA512, SHA3-224
  SHA3-256, SHA3-384, SHA3-512, Skein-224, Skein-256, Skein-384, Skein-512
  SM3, Whirlpool

Performance hashes:
  DJB2, FNV-1, FNV-1a, Murmur3, RapidHash, SipHash, XXH32, XXH64, XXH3

Perceptual hashes:
  Average, Difference, Median, PHash, WHash, MarrHildreth, BlockMean, PDQ, RASH

Similarity hashes:
  ImpFuzzy, ImpHashO, ImpHashS, sdhash, SSDeep, TLSH

Windows specific:
  LM, NT, PE

Unix specific:
  BSD, ELF, SYSV

Checksums:
  Adler32, Fletcher4, Luhn, CRC16-CCITT, CRC32-C, CRC32-K, CRC32-IEEE
  CRC64-ECMA, CRC64-ISO

Report bugs at: foxforensics.eu/issues`

func main() {
	if len(os.Args) < 3 || os.Args[1] == "--help" {
		_, _ = fmt.Fprintln(os.Stderr, Usage)
		os.Exit(2)
	}

	if !hash.IsSupported(os.Args[1]) {
		_, _ = fmt.Fprintln(os.Stderr, hash.NotSupported.Error())
		os.Exit(1)
	}

	if err := filepath.WalkDir(os.Args[2], func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		path, err = filepath.Abs(path)

		if err != nil {
			return err
		}

		f, err := os.Open(path)

		if err != nil {
			return err
		}

		defer func() {
			_ = f.Close()
		}()

		m, err := mmap.Map(f, mmap.RDONLY, 0)

		if err != nil {
			return err
		}

		defer func() {
			_ = m.Unmap()
		}()

		s, err := hash.Sum(os.Args[1], m)

		if err != nil {
			return err
		}

		_, _ = fmt.Printf("%s  %s\n", s, path)

		return nil
	}); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
