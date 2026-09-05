# lex-rlp -- RLP (Recursive Length Prefix) encoding for the Lex language.
#
# Ethereum's canonical wire format for byte strings and nested lists of
# byte strings. This module only speaks that format: no keccak256, no
# secp256k1, no transaction structure, no signing. lex-attest's EVM
# anchor destination and lex-x402's exact_evm scheme both need this as a
# building block, not the whole path to a signed transaction.
#
# A single-byte string whose byte is < 0x80 encodes as that byte alone,
# no prefix -- not an optional shortcut, canonical RLP requires it (a
# 1-byte string like encode_int(15) is genuinely the bare byte 0x0f, not
# 0x81 0x0f). Every other RStr goes through the length-prefix rule.

import "std.bytes" as bytes

import "std.list" as list

import "std.crypto" as crypto

type Item = RStr(Bytes) | RList(List[Item])

fn empty_bytes() -> Bytes {
  bytes.from_str("")
}

# Minimal big-endian byte representation of a non-negative integer.
# 0 encodes as the empty byte string -- RLP's own integer convention,
# not a general-purpose integer codec (encode_int below is what callers
# should use for integers; this is the shared byte-math primitive).
fn big_endian_bytes(n :: Int) -> Bytes {
  if n == 0 {
    empty_bytes()
  } else {
    bytes.concat_all(list.reverse(be_bytes_rev(n)))
  }
}

fn be_bytes_rev(n :: Int) -> List[Bytes] {
  if n == 0 {
    []
  } else {
    list.cons(bytes.u8(n % 256), be_bytes_rev(n / 256))
  }
}

fn encode_bytes_header(s :: Bytes) -> Bytes {
  let len := bytes.len(s)
  if len == 1 {
    match bytes.u8_at(s, 0) {
      Ok(b) => if b < 128 {
        s
      } else {
        encode_bytes_header_prefixed(s, len)
      },
      Err(_) => encode_bytes_header_prefixed(s, len),
    }
  } else {
    encode_bytes_header_prefixed(s, len)
  }
}

fn encode_bytes_header_prefixed(s :: Bytes, len :: Int) -> Bytes {
  if len <= 55 {
    bytes.concat(bytes.u8(128 + len), s)
  } else {
    let len_bytes := big_endian_bytes(len)
    bytes.concat(bytes.concat(bytes.u8(183 + bytes.len(len_bytes)), len_bytes), s)
  }
}

fn encode_list_header(payload :: Bytes) -> Bytes {
  let len := bytes.len(payload)
  if len <= 55 {
    bytes.concat(bytes.u8(192 + len), payload)
  } else {
    let len_bytes := big_endian_bytes(len)
    bytes.concat(bytes.concat(bytes.u8(247 + bytes.len(len_bytes)), len_bytes), payload)
  }
}

fn encode(item :: Item) -> Bytes {
  match item {
    RStr(s) => encode_bytes_header(s),
    RList(items) => encode_list_header(bytes.concat_all(list.map(items, encode))),
  }
}

# RLP's integer convention: 0 is the empty byte string, any other
# non-negative integer is its minimal big-endian representation (no
# leading zero byte). Negative integers are not RLP-representable and
# are not handled here.
fn encode_int(n :: Int) -> Item {
  RStr(big_endian_bytes(n))
}

fn to_hex(item :: Item) -> Str {
  crypto.hex_encode(encode(item))
}

fn of_hex(hex :: Str) -> Result[Item, Str] {
  match crypto.hex_decode(hex) {
    Err(e) => Err(e),
    Ok(b) => decode(b),
  }
}

fn decode(data :: Bytes) -> Result[Item, Str] {
  match decode_item(data, 0) {
    Err(e) => Err(e),
    Ok(parsed) => match parsed {
      (item, pos) => if pos == bytes.len(data) {
        Ok(item)
      } else {
        Err("trailing bytes after RLP item")
      },
    },
  }
}

# Reads one RLP item starting at `pos`, returning it with the offset just
# past it. `data` is threaded through the whole recursive descent instead
# of re-sliced at each level, so a malicious length field can only ever
# be checked against the true remaining length, never against a shrunk
# view of it.
fn decode_item(data :: Bytes, pos :: Int) -> Result[(Item, Int), Str] {
  if pos >= bytes.len(data) {
    Err("unexpected end of input")
  } else {
    match bytes.u8_at(data, pos) {
      Err(e) => Err(e),
      Ok(prefix) => if prefix <= 183 {
        if prefix < 128 {
          Ok((RStr(bytes.slice(data, pos, pos + 1)), pos + 1))
        } else {
          decode_str_body(data, pos + 1, prefix - 128)
        }
      } else {
        if prefix <= 191 {
          match read_length(data, pos + 1, prefix - 183) {
            Err(e) => Err(e),
            Ok(len) => decode_str_body(data, pos + 1 + (prefix - 183), len),
          }
        } else {
          if prefix <= 247 {
            let len := prefix - 192
            decode_list_body(data, pos + 1, pos + 1 + len)
          } else {
            match read_length(data, pos + 1, prefix - 247) {
              Err(e) => Err(e),
              Ok(len) => decode_list_body(data, pos + 1 + (prefix - 247), pos + 1 + (prefix - 247) + len),
            }
          }
        }
      },
    }
  }
}

fn read_length(data :: Bytes, pos :: Int, n :: Int) -> Result[Int, Str] {
  if pos + n > bytes.len(data) {
    Err("length prefix exceeds available bytes")
  } else {
    read_length_loop(data, pos, n, 0)
  }
}

fn read_length_loop(data :: Bytes, pos :: Int, remaining :: Int, acc :: Int) -> Result[Int, Str] {
  if remaining == 0 {
    Ok(acc)
  } else {
    match bytes.u8_at(data, pos) {
      Err(e) => Err(e),
      Ok(b) => read_length_loop(data, pos + 1, remaining - 1, acc * 256 + b),
    }
  }
}

fn decode_str_body(data :: Bytes, pos :: Int, len :: Int) -> Result[(Item, Int), Str] {
  if pos + len > bytes.len(data) {
    Err("string length exceeds available bytes")
  } else {
    Ok((RStr(bytes.slice(data, pos, pos + len)), pos + len))
  }
}

fn decode_list_body(data :: Bytes, start :: Int, end :: Int) -> Result[(Item, Int), Str] {
  if end > bytes.len(data) {
    Err("list length exceeds available bytes")
  } else {
    match decode_list_items(data, start, end, []) {
      Err(e) => Err(e),
      Ok(items) => Ok((RList(items), end)),
    }
  }
}

fn decode_list_items(data :: Bytes, pos :: Int, end :: Int, acc :: List[Item]) -> Result[List[Item], Str] {
  if pos == end {
    Ok(list.reverse(acc))
  } else {
    if pos > end {
      Err("nested RLP item overruns its list boundary")
    } else {
      match decode_item(data, pos) {
        Err(e) => Err(e),
        Ok(parsed) => match parsed {
          (item, next_pos) => decode_list_items(data, next_pos, end, list.cons(item, acc)),
        },
      }
    }
  }
}

