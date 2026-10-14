//! Per-line addresses for Hex-Rays pseudocode.
//!
//! Hex-Rays marks the text it generates with hidden `COLOR_ADDR` tags:
//! `COLOR_ON COLOR_ADDR` followed by 16 hex digits. In pseudocode the digits
//! are an anchor (`ctree_anchor_t`), not an address. For a plain ctree item
//! the anchor is the item's index in `cfunc_t::treeitems`, and the item
//! carries the address (`citem_t::ea`) of the instruction it was built from.
//! Anchors can also refer to local variable declarations, item type
//! preciser slots and block comments; those say nothing about the address of
//! the line and are ignored.
//!
//! This module only interprets the tags. Reading the tagged text and
//! resolving an item index to an address needs a decompiled function and is
//! done by the caller.

use crate::error::ToolError;
use crate::ida::types::PseudocodeLine;
use std::collections::BTreeSet;

const COLOR_ON: u8 = 0x01;
const COLOR_ESC: u8 = 0x03;
const COLOR_ADDR: u8 = 0x28;
const COLOR_SEMSPAN: u8 = 0x36;

/// Hex digits after `COLOR_ON COLOR_ADDR` (`COLOR_ADDR_SIZE`, `ea_t` is 64 bits).
const ANCHOR_DIGITS: usize = 16;

// ctree_anchor_t, hexrays.hpp.
const ANCHOR_INDEX: u64 = 0x1FFF_FFFF;
const ANCHOR_MASK: u64 = 0xC000_0000;
const ANCHOR_BLKCMT: u64 = 0x2000_0000;

const BADADDR: u64 = u64::MAX;

/// The raw anchor values (`COLOR_ADDR` payloads) in a tagged line, in text
/// order. A `COLOR_ADDR` tag that is cut short or has a non-hex payload is
/// skipped.
pub fn anchor_values(tagged: &str) -> Vec<u64> {
    let bytes = tagged.as_bytes();
    let mut values = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            // COLOR_ESC quotes the next byte, which may itself be COLOR_ON.
            COLOR_ESC => i += 2,
            COLOR_ON => match bytes.get(i + 1) {
                Some(&COLOR_ADDR) => {
                    let digits = bytes.get(i + 2..i + 2 + ANCHOR_DIGITS);
                    match digits.and_then(parse_hex) {
                        Some(value) => {
                            values.push(value);
                            i += 2 + ANCHOR_DIGITS;
                        }
                        None => i += 2,
                    }
                }
                // COLOR_ON COLOR_SEMSPAN <kind>: the kind byte may be 0x01.
                Some(&COLOR_SEMSPAN) => i += 3,
                _ => i += 2,
            },
            _ => i += 1,
        }
    }
    values
}

fn parse_hex(digits: &[u8]) -> Option<u64> {
    digits.iter().try_fold(0u64, |acc, &b| {
        let digit = char::from(b).to_digit(16)?;
        Some((acc << 4) | u64::from(digit))
    })
}

/// The `cfunc_t::treeitems` index an anchor refers to, for plain ctree item
/// anchors only. `None` for local variable, item type preciser and block
/// comment anchors and for the invalid anchor (`BADADDR`).
fn citem_index(anchor: u64) -> Option<usize> {
    if anchor > u64::from(u32::MAX) || anchor & (ANCHOR_MASK | ANCHOR_BLKCMT) != 0 {
        return None;
    }
    usize::try_from(anchor & ANCHOR_INDEX).ok()
}

/// Addresses of the ctree items anchored on a tagged line.
///
/// `item_address` resolves a `treeitems` index; it returns `None` for an
/// index that is out of range or an item without an address.
pub fn line_addresses(
    tagged: &str,
    mut item_address: impl FnMut(usize) -> Option<u64>,
) -> Vec<u64> {
    anchor_values(tagged)
        .into_iter()
        .filter_map(citem_index)
        .filter_map(&mut item_address)
        .filter(|&ea| ea != BADADDR)
        .collect::<BTreeSet<u64>>()
        .into_iter()
        .collect()
}

/// Pair the plain and tagged form of every line and resolve its addresses.
///
/// Both slices come from the same `get_pseudocode()` result, so a different
/// number of lines means the decompiler output changed between the two reads.
pub fn build_lines(
    plain: Vec<String>,
    tagged: &[String],
    mut item_address: impl FnMut(usize) -> Option<u64>,
) -> Result<Vec<PseudocodeLine>, ToolError> {
    if plain.len() != tagged.len() {
        return Err(ToolError::IdaError(format!(
            "pseudocode has {} plain lines but {} tagged lines",
            plain.len(),
            tagged.len()
        )));
    }
    Ok(plain
        .into_iter()
        .zip(tagged)
        .enumerate()
        .map(|(index, (text, tagged))| PseudocodeLine {
            line: index + 1,
            text,
            addresses: line_addresses(tagged, &mut item_address),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// `COLOR_ON COLOR_ADDR <16 hex digits>` for an anchor value.
    fn tag(anchor: u64) -> String {
        format!("\u{1}\u{28}{anchor:016X}")
    }

    /// Text colored with `color`: `COLOR_ON color text COLOR_OFF color`.
    fn colored(color: u8, text: &str) -> String {
        let c = char::from(color);
        format!("\u{1}{c}{text}\u{2}{c}")
    }

    /// Resolves index `n` to `0x1000 + 4 * n` below 8; anything else is unknown.
    fn items(index: usize) -> Option<u64> {
        (index < 8).then(|| 0x1000 + 4 * index as u64)
    }

    #[test]
    fn single_anchor_is_parsed() {
        let line = format!("{}{}", tag(5), colored(0x07, "x"));
        assert_eq!(anchor_values(&line), vec![5]);
        assert_eq!(line_addresses(&line, items), vec![0x1014]);
    }

    #[test]
    fn adjacent_anchors_are_all_found() {
        let line = format!("{}{}{}", tag(3), tag(1), tag(2));
        assert_eq!(anchor_values(&line), vec![3, 1, 2]);
        // Ascending, whatever the text order was.
        assert_eq!(line_addresses(&line, items), vec![0x1004, 0x1008, 0x100c]);
    }

    #[test]
    fn anchors_between_colored_text_are_found() {
        let line = format!(
            "{}{}{}{}",
            tag(0),
            colored(0x09, "("),
            tag(7),
            colored(0x07, "a1")
        );
        assert_eq!(anchor_values(&line), vec![0, 7]);
        assert_eq!(line_addresses(&line, items), vec![0x1000, 0x101c]);
    }

    #[test]
    fn repeated_anchor_and_shared_address_are_deduplicated() {
        let line = format!("{}{}{}", tag(2), tag(2), tag(3));
        let shared = |index: usize| items(index).map(|_| 0x2000);
        assert_eq!(line_addresses(&line, shared), vec![0x2000]);
        assert_eq!(line_addresses(&line, items), vec![0x1008, 0x100c]);
    }

    #[test]
    fn line_without_anchor_has_no_addresses() {
        let line = format!("{}{}", colored(0x09, "{"), colored(0x09, "}"));
        assert!(anchor_values(&line).is_empty());
        assert!(line_addresses(&line, items).is_empty());
        assert!(line_addresses("", items).is_empty());
        assert!(line_addresses("plain text", items).is_empty());
    }

    #[test]
    fn index_out_of_range_is_dropped() {
        let line = format!("{}{}", tag(2), tag(8));
        assert_eq!(anchor_values(&line), vec![2, 8]);
        assert_eq!(line_addresses(&line, items), vec![0x1008]);
        // Far beyond the tree, but still a plain item anchor.
        assert!(line_addresses(&tag(0x1FFF_FFFF), items).is_empty());
    }

    #[test]
    fn item_without_address_is_dropped() {
        let line = format!("{}{}", tag(1), tag(2));
        let unknown_first = |index: usize| (index != 1).then(|| 0x3000 + index as u64);
        assert_eq!(line_addresses(&line, unknown_first), vec![0x3002]);
        let badaddr = |_: usize| Some(u64::MAX);
        assert!(line_addresses(&line, badaddr).is_empty());
    }

    #[test]
    fn only_plain_item_anchors_count() {
        // lvar declaration, item type preciser, block comment, invalid anchor.
        let line = format!(
            "{}{}{}{}{}",
            tag(0x4000_0001),
            tag(0x8000_0045),
            tag(0x2000_0002),
            tag(u64::MAX),
            tag(0x1_0000_0003),
        );
        assert_eq!(anchor_values(&line).len(), 5);
        let any = |index: usize| Some(0x5000 + index as u64);
        assert!(line_addresses(&line, any).is_empty());
        // The same indices as plain item anchors do resolve.
        let plain = format!("{}{}", tag(1), tag(2));
        assert_eq!(line_addresses(&plain, any), vec![0x5001, 0x5002]);
    }

    #[test]
    fn malformed_anchor_tags_are_skipped() {
        let short = "\u{1}\u{28}0000000000000001"; // 16 digits: ok
        assert_eq!(anchor_values(short), vec![1]);
        let truncated = "\u{1}\u{28}00000000000001";
        assert!(anchor_values(truncated).is_empty());
        let not_hex = "\u{1}\u{28}000000000000000Z";
        assert!(anchor_values(not_hex).is_empty());
        let cut_off = "\u{1}\u{28}";
        assert!(anchor_values(cut_off).is_empty());
        // A good tag after a bad one is still read.
        let mixed = format!("{truncated}{}", tag(4));
        assert_eq!(anchor_values(&mixed), vec![4]);
    }

    #[test]
    fn escaped_color_on_is_not_a_tag() {
        // COLOR_ESC quotes the byte after it, so this is text, not an anchor.
        let escaped = format!("\u{3}\u{1}\u{28}{:016X}", 3);
        assert!(anchor_values(&escaped).is_empty());
        let after = format!("{escaped}{}", tag(6));
        assert_eq!(anchor_values(&after), vec![6]);
    }

    #[test]
    fn semspan_kind_byte_does_not_hide_the_next_anchor() {
        // COLOR_ON COLOR_SEMSPAN COLOR_DEFAULT: the kind byte equals COLOR_ON.
        let line = format!("\u{1}\u{36}\u{1}{}x\u{2}\u{36}", tag(2));
        assert_eq!(anchor_values(&line), vec![2]);
    }

    #[test]
    fn non_ascii_text_does_not_confuse_the_scan() {
        let line = format!("{}{}{}", tag(1), colored(0x07, "名前"), tag(2));
        assert_eq!(anchor_values(&line), vec![1, 2]);
    }

    #[test]
    fn build_lines_numbers_lines_from_one_and_keeps_text() {
        let plain = vec![
            "int f()".to_string(),
            "{".to_string(),
            "  return 1;".to_string(),
        ];
        let tagged = vec![
            format!("{}int f()", tag(0)),
            colored(0x09, "{"),
            format!("{}{}return 1;", tag(2), tag(1)),
        ];
        let lines = build_lines(plain, &tagged, items).expect("lines");
        assert_eq!(
            lines,
            vec![
                PseudocodeLine {
                    line: 1,
                    text: "int f()".into(),
                    addresses: vec![0x1000]
                },
                PseudocodeLine {
                    line: 2,
                    text: "{".into(),
                    addresses: vec![]
                },
                PseudocodeLine {
                    line: 3,
                    text: "  return 1;".into(),
                    addresses: vec![0x1004, 0x1008]
                },
            ]
        );
    }

    #[test]
    fn build_lines_rejects_mismatched_line_counts() {
        let err = build_lines(vec!["a".into(), "b".into()], &["a".to_string()], items)
            .expect_err("mismatch");
        assert!(
            err.to_string().contains("2 plain lines but 1 tagged"),
            "{err}"
        );
    }

    #[test]
    fn lines_serialize_with_hex_string_addresses() {
        let line = PseudocodeLine {
            line: 4,
            text: "x = 1;".into(),
            addresses: vec![0x10, 0xdead_beef_0000_0001],
        };
        assert_eq!(
            serde_json::to_value(&line).expect("serialize"),
            json!({
                "line": 4,
                "text": "x = 1;",
                "addresses": ["0x10", "0xdeadbeef00000001"]
            })
        );
        let empty = PseudocodeLine {
            line: 1,
            text: String::new(),
            addresses: vec![],
        };
        assert_eq!(
            serde_json::to_value(&empty).expect("serialize")["addresses"],
            json!([])
        );
    }
}
