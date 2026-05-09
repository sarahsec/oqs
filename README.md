# oqs-lua

A post-quantum CLI tool in Lua. Generate keys, encrypt files, sign them, seal them — all using NIST-standardized algorithms that hold up against a quantum computer.

Think of it as a minimal, no-nonsense OpenSSL for the post-quantum era.

## What it does

| Command  | What happens                                                      |
|----------|-------------------------------------------------------------------|
| `keygen` | Generate a post-quantum keypair (KEM or signature)                |
| `encrypt` | Encrypt a file for a recipient using their public key            |
| `decrypt` | Decrypt it with your private key                                 |
| `sign`   | Sign a file with your private key                                 |
| `verify` | Verify a signature against a public key                           |
| `seal`   | Sign-then-encrypt atomically — the right way to do both at once  |
| `open`   | Decrypt-then-verify atomically — output only written if both pass |

## Algorithms

| Layer | Algorithm   | Standard       |
|-------|-------------|----------------|
| KEM   | ML-KEM-768  | NIST FIPS 203  |
| SIG   | ML-DSA-65   | NIST FIPS 204  |
| SYM   | AES-256-GCM | —              |
| KDF   | HKDF-SHA256 | RFC 5869       |

Built on [liboqs](https://github.com/open-quantum-safe/liboqs) and OpenSSL. Clones and builds its own `liboqs` — no system dependency needed.

## Prerequisites

```
lua  git  cmake  ninja  cc  openssl
```

## Build

```bash
ninja
```

That's it. Clones `liboqs`, builds it, compiles `oqs.so`.

## Usage

```bash
# Generate keys
./oqs keygen kem alice        # alice.pub + alice.priv  [0600]
./oqs keygen sig bob          # bob.pub   + bob.priv    [0600]

# Encrypt and decrypt
./oqs encrypt alice.pub   secret.txt    secret.enc
./oqs decrypt alice.priv  secret.enc   recovered.txt

# Sign and verify
./oqs sign   bob.priv   report.pdf   report.pdf.sig
./oqs verify bob.pub    report.pdf   report.pdf.sig

# Seal and open (sign-then-encrypt, atomic)
./oqs seal bob.priv  alice.pub   secret.txt     secret.sealed
./oqs open alice.priv bob.pub    secret.sealed  secret.txt
```

`seal` signs the plaintext first, then encrypts everything — including the signature. The recipient is the only one who can decrypt it, and the signature proves exactly who sent it. Nobody looking at the file knows either.

`open` only writes output to disk if decryption succeeds *and* the signature verifies. Both or nothing.

## Run, test, prove

```bash
ninja run    # run the demo
ninja test   # 22 assertions across all commands
ninja prove  # programmatic proof of confidentiality, integrity, and authenticity
```

The proof script is worth running once. It doesn't just check that things work — it checks that the wrong things *fail*: tampered ciphertexts, wrong keys, forged signatures, cross-key misuse.

## File formats

Every file has a 4-byte magic header so you can't accidentally mix them up.

| Format         | Magic  | Contents                                    |
|----------------|--------|---------------------------------------------|
| Public key     | `OQKP` | version + type + raw key bytes              |
| Private key    | `OQKS` | version + type + raw key bytes (mode 0600)  |
| Encrypted file | `OQS1` | KEM ciphertext + IV + auth tag + AES-GCM ct |
| Signature file | `OQSS` | signature length + ML-DSA-65 signature      |
| Sealed file    | `OQSL` | KEM ciphertext + IV + auth tag + AES-GCM(sig \|\| plaintext) |
