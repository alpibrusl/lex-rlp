# lex-rlp tests: canonical RLP vectors (empty string, short/long strings,
# lists, nested lists, integers), a malformed-input rejection, and a
# round-trip on a structure beyond the fixed vectors.

import "std.str" as str

import "std.list" as list

import "std.bytes" as bytes

import "../src/rlp" as rlp

fn check_hex(label :: Str, item :: rlp.Item, expected_hex :: Str) -> Result[Unit, Str] {
  let got := rlp.to_hex(item)
  if got == expected_hex {
    match rlp.of_hex(expected_hex) {
      Err(e) => Err(str.concat(label, str.concat(": decode failed: ", e))),
      Ok(back) => if rlp.to_hex(back) == expected_hex {
        Ok(())
      } else {
        Err(str.concat(label, ": decode did not round-trip"))
      },
    }
  } else {
    Err(str.join([label, ": expected ", expected_hex, " got ", got], ""))
  }
}

fn empty_string() -> Result[Unit, Str] {
  check_hex("empty_string", RStr(bytes.from_str("")), "80")
}

fn short_string_dog() -> Result[Unit, Str] {
  check_hex("short_string_dog", RStr(bytes.from_str("dog")), "83646f67")
}

fn list_cat_dog() -> Result[Unit, Str] {
  check_hex("list_cat_dog", RList([RStr(bytes.from_str("cat")), RStr(bytes.from_str("dog"))]), "c88363617483646f67")
}

fn empty_list() -> Result[Unit, Str] {
  check_hex("empty_list", RList([]), "c0")
}

fn int_zero() -> Result[Unit, Str] {
  check_hex("int_zero", rlp.encode_int(0), "80")
}

fn int_fifteen() -> Result[Unit, Str] {
  check_hex("int_fifteen", rlp.encode_int(15), "0f")
}

fn int_1024() -> Result[Unit, Str] {
  check_hex("int_1024", rlp.encode_int(1024), "820400")
}

# The classic "set representation of two" vector: nested empty lists.
fn nested_two() -> Result[Unit, Str] {
  let inner_a := RList([])
  let inner_b := RList([RList([])])
  let inner_c := RList([RList([]), RList([RList([])])])
  check_hex("nested_two", RList([inner_a, inner_b, inner_c]), "c7c0c1c0c3c0c1c0")
}

fn repeat_str(ch :: Str, n :: Int) -> Str {
  if n == 0 {
    ""
  } else {
    str.concat(ch, repeat_str(ch, n - 1))
  }
}

fn repeat_hex(pair :: Str, n :: Int) -> Str {
  if n == 0 {
    ""
  } else {
    str.concat(pair, repeat_hex(pair, n - 1))
  }
}

# The long-string branch: a 56-byte string needs the length-of-length
# prefix (0xb8 = 0xb7 + 1), not the short-string prefix.
fn long_string() -> Result[Unit, Str] {
  let s := repeat_str("a", 56)
  let expected := str.concat("b838", repeat_hex("61", 56))
  check_hex("long_string", RStr(bytes.from_str(s)), expected)
}

fn rejects_truncated_length() -> Result[Unit, Str] {
  match rlp.of_hex("b8ff61") {
    Ok(_) => Err("expected decode to reject a length prefix exceeding available bytes"),
    Err(_) => Ok(()),
  }
}

fn arbitrary_nested_roundtrip() -> Result[Unit, Str] {
  let item := RList([RStr(bytes.from_str("hello")), RList([RStr(bytes.from_str("a")), RStr(bytes.from_str("")), rlp.encode_int(300)]), RStr(bytes.from_str("world"))])
  match rlp.of_hex(rlp.to_hex(item)) {
    Err(e) => Err(str.concat("arbitrary_nested_roundtrip: decode failed: ", e)),
    Ok(back) => if rlp.to_hex(back) == rlp.to_hex(item) {
      Ok(())
    } else {
      Err("arbitrary_nested_roundtrip: did not round-trip")
    },
  }
}

fn run_all() -> Unit {
  let results := [empty_string(), short_string_dog(), list_cat_dog(), empty_list(), int_zero(), int_fifteen(), int_1024(), nested_two(), long_string(), rejects_truncated_length(), arbitrary_nested_roundtrip()]
  let failures := list.fold(results, 0, fn (n :: Int, r :: Result[Unit, Str]) -> Int {
    match r {
      Ok(_) => n,
      Err(_) => n + 1,
    }
  })
  if failures == 0 {
    ()
  } else {
    let __discard := 1 / 0
    ()
  }
}

