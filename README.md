# hasher
Multi-algorithm hasher supporting cryptographic, performance, perceptual and similarity hashes, as well as different checksums.

```console
go install go.foxforensics.dev/hasher@latest
```

## Usage
```console
$ hasher ALGORITHM PATH
```

## Algorithms
Cryptographic hashes:
> BLAKE2S-256, BLAKE2B-256, BLAKE2B-384, BLAKE2B-512, BLAKE3-256, BLAKE3-512, GOST2012-256, GOST2012-512, HAS-160, LSH-256, LSH-512, MD2, MD4, MD5, MD6, RIPEMD-160, SHAKE128, SHAKE256, SHA1, SHA224, SHA256, SHA512, SHA3, SHA3-224, SHA3-256, SHA3-384, SHA3-512, Skein-224, Skein-256, Skein-384, Skein-512, SM3, Whirlpool

Performance hashes:
> DJB2, FNV-1, FNV-1a, Murmur3, RapidHash, SipHash, XXH32, XXH64, XXH3

Perceptual hashes:
> Average, Difference, Median, PHash, WHash, MarrHildreth, BlockMean, PDQ, RASH

Similarity hashes:
> ImpFuzzy, ImpHashO, ImpHashS, SSDeep, TLSH

Windows hashes:
> LM, NT, PE

Checksums:
> Adler32, Fletcher4, CRC16-CCITT, CRC32-C, CRC32-IEEE, CRC64-ECMA, CRC64-ISO

## License
Released under the [MIT License](LICENSE.md).