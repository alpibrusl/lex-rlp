# lex-rlp

**Part of the [Lex](https://lexlang.org) project** — [Manifesto](https://www.lexlang.org/manifesto) · [All packages](https://lexlang.org)

RLP (Recursive Length Prefix) encoding for the Lex language — Ethereum's
canonical wire format for byte strings and nested lists of byte strings,
in pure Lex on top of `std.bytes`.

```
import "lex-rlp/rlp" as rlp

rlp.to_hex(RStr(bytes.from_str("dog")))     # -> "83646f67"
rlp.to_hex(rlp.encode_int(1024))            # -> "820400"
rlp.of_hex("c88363617483646f67")            # -> Ok(RList([RStr("cat"), RStr("dog")]))
```

## Why it exists

[lex-attest](https://github.com/alpibrusl/lex-attest)'s direct-EVM anchor
destination and [lex-x402](https://github.com/alpibrusl/lex-x402)'s
`exact_evm` settlement scheme both need RLP to build an Ethereum
transaction — the crypto primitives (`keccak256`, `secp256k1_sign_digest`,
`hex_encode`) already exist in `std.crypto`, but there was no RLP encoder
anywhere in the ecosystem. This package is exactly that piece, and nothing
more: no transaction structure, no signing, no key handling. Building a
trustworthy EIP-1559 transaction encoder on top of this — and testing it
against a testnet before it ever touches a real key — is separate, larger
work that belongs in the consuming package.

## API

- `type Item = RStr(Bytes) | RList(List[Item])` — an RLP value.
- `encode(item) -> Bytes` / `decode(data) -> Result[Item, Str]` — the wire format.
- `encode_int(n) -> Item` — RLP's integer convention (`0` is the empty byte string).
- `to_hex(item) -> Str` / `of_hex(hex) -> Result[Item, Str]` — hex convenience wrappers over `encode`/`decode`.

A single-byte string whose byte is `< 0x80` encodes as that byte alone, no
prefix — this is canonical RLP, not an optional shortcut (`encode_int(15)`
really is the bare byte `0x0f`). Everything else goes through the
standard length-prefix rule for strings and lists, including the
long-form (`>55` byte) length-of-length prefix.

## Tested against

The canonical vectors from Ethereum's own RLP reference: the empty string,
`"dog"`, `["cat", "dog"]`, the empty list, integers `0`/`15`/`1024`, the
nested "set representation of two" (`[[], [[]], [[], [[]]]]`), and the
long-string branch (a 56-byte string, which needs the length-of-length
prefix). Plus a malformed-input rejection and a round-trip on an
arbitrary nested structure. See `tests/test_rlp.lex`.
