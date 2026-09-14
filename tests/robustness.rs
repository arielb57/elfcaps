//! Property (7): malformed input returns `Ok` or a typed `ElfError`, never a
//! panic. In Rust an out-of-bounds read or an arithmetic overflow in a debug
//! build is a panic, so catching panics covers both.

mod support;

use elfcaps::analysis::analyze;
use elfcaps::elf::{ElfError, ElfFile};
use elfcaps::CapDb;
use std::panic;
use support::writer::{Bits, ElfSpec, Order, SymSpec, Version, STB_GLOBAL, STT_FUNC};
use support::Rng;

fn seeds() -> Vec<Vec<u8>> {
    let rich = |bits, order| {
        let mut spec = ElfSpec::new(bits, order)
            .soname("libseed.so.1")
            .needed("libxcb.so.1")
            .needed("libdl.so.2")
            .rpath("$ORIGIN/../lib")
            .runpath("$ORIGIN")
            .import_versioned("xcb_convert_selection", "libxcb.so.1", "XCB_1.0")
            .import("dlopen")
            .rodata("XRecordEnableContext")
            .rodata("libXtst.so.6")
            .symbol(SymSpec {
                name: "seed_api".into(),
                bind: STB_GLOBAL,
                kind: STT_FUNC,
                defined: true,
                version: Some(Version::Defined("SEED_1".into())),
                hidden: false,
            });
        spec.interp = Some("/lib/ld.so".into());
        spec.build()
    };
    vec![
        rich(Bits::B32, Order::Little),
        rich(Bits::B64, Order::Little),
        rich(Bits::B64, Order::Big),
        ElfSpec::new(Bits::B64, Order::Little).build(),
    ]
}

/// Header fields hold the offsets and counts every later read depends on, so
/// mutations are biased towards the ELF header and the section table.
fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut data = input.to_vec();
    let len = data.len();
    let shoff_region = len.saturating_sub(64 * 12);
    match rng.below(7) {
        0 => {
            for _ in 0..1 + rng.below(8) {
                let i = rng.below(len);
                data[i] ^= 1 << rng.below(8);
            }
        }
        1 => {
            let i = rng.below(64.min(len));
            data[i] = rng.next_u64() as u8;
        }
        2 => {
            let i = shoff_region + rng.below(len - shoff_region);
            let value = rng.next_u64().to_le_bytes();
            let n = (1 + rng.below(8)).min(len - i);
            data[i..i + n].copy_from_slice(&value[..n]);
        }
        3 => data.truncate(rng.below(len)),
        4 => {
            let start = rng.below(len);
            let end = (start + 1 + rng.below(64)).min(len);
            let fill = if rng.chance(2) { 0xff } else { 0x00 };
            data[start..end].iter_mut().for_each(|b| *b = fill);
        }
        5 => {
            // Plausible-looking but hostile values: counts and offsets near limits.
            let i = rng.below(len.saturating_sub(8));
            let hostile = [
                0u64,
                1,
                0x7fff_ffff,
                0xffff_ffff,
                u64::MAX,
                len as u64,
                (len - 1) as u64,
            ];
            let v = hostile[rng.below(hostile.len())].to_le_bytes();
            data[i..i + 8].copy_from_slice(&v);
        }
        _ => {
            for _ in 0..1 + rng.below(32) {
                let i = rng.below(len);
                data[i] = rng.next_u64() as u8;
            }
            if rng.chance(3) {
                data.truncate(rng.below(len));
            }
        }
    }
    data
}

#[test]
fn ten_thousand_seeded_mutations_never_panic() {
    let db = CapDb::builtin();
    let seeds = seeds();
    let mut rng = Rng::new(0x0e1f_ca95);
    let (mut ok, mut errors) = (0usize, 0usize);
    let mut error_kinds = std::collections::HashSet::new();
    for iteration in 0..10_000 {
        let seed = &seeds[iteration % seeds.len()];
        let data = mutate(&mut rng, seed);
        let outcome = panic::catch_unwind(|| {
            ElfFile::parse(&data).map(|elf| {
                // Parsed output must also be safe to analyse.
                let _ = analyze(&elf, &db);
                let _ = elf.is_executable();
            })
        });
        match outcome {
            Ok(Ok(())) => ok += 1,
            Ok(Err(e)) => {
                errors += 1;
                let _ = e.to_string();
                error_kinds.insert(std::mem::discriminant(&e));
            }
            Err(_) => panic!(
                "iteration {iteration} panicked; input ({} bytes): {:02x?}",
                data.len(),
                data
            ),
        }
    }
    // Both outcomes must be common, or the mutations are not reaching the parser.
    assert!(ok > 1_000, "only {ok} mutated files parsed");
    assert!(errors > 1_000, "only {errors} mutated files were rejected");
    assert!(
        error_kinds.len() >= 4,
        "error variety too low: {error_kinds:?}"
    );
}

#[test]
fn every_truncation_of_every_seed_is_handled() {
    for seed in seeds() {
        let full = ElfFile::parse(&seed).expect("seed parses");
        for cut in 0..seed.len() {
            let result = panic::catch_unwind(|| ElfFile::parse(&seed[..cut]));
            match result {
                Ok(Ok(elf)) => assert_ne!(elf, full, "a truncated file cannot parse identically"),
                Ok(Err(_)) => {}
                Err(_) => panic!("truncation at {cut} panicked"),
            }
        }
        // The section table sits at the end, so dropping its last byte must fail.
        assert!(matches!(
            ElfFile::parse(&seed[..seed.len() - 1]),
            Err(ElfError::Truncated { .. })
        ));
    }
}

fn put_u64(data: &mut [u8], at: usize, v: u64) {
    data[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn put_u16(data: &mut [u8], at: usize, v: u16) {
    data[at..at + 2].copy_from_slice(&v.to_le_bytes());
}

#[test]
fn hostile_header_fields_give_specific_errors() {
    let seed = ElfSpec::lib("libh.so").import("XGrabKey").build();

    let mut far_table = seed.clone();
    put_u64(&mut far_table, 40, u64::MAX - 4);
    assert!(matches!(
        ElfFile::parse(&far_table),
        Err(ElfError::Truncated { .. })
    ));

    let mut huge_count = seed.clone();
    put_u16(&mut huge_count, 60, 0xfff0);
    assert!(matches!(
        ElfFile::parse(&huge_count),
        Err(ElfError::Truncated {
            what: "section header table",
            ..
        })
    ));

    let mut tiny_entries = seed.clone();
    put_u16(&mut tiny_entries, 58, 10);
    assert!(matches!(
        ElfFile::parse(&tiny_entries),
        Err(ElfError::BadEntrySize {
            what: "section header",
            ..
        })
    ));

    let mut bad_shstrndx = seed.clone();
    put_u16(&mut bad_shstrndx, 62, 200);
    assert!(matches!(
        ElfFile::parse(&bad_shstrndx),
        Err(ElfError::BadSectionIndex {
            what: "e_shstrndx",
            ..
        })
    ));

    let mut bad_phdrs = seed.clone();
    put_u64(&mut bad_phdrs, 32, seed.len() as u64 - 10);
    assert!(matches!(
        ElfFile::parse(&bad_phdrs),
        Err(ElfError::Truncated {
            what: "program header table",
            ..
        })
    ));
}

#[test]
fn verneed_walk_with_huge_count_and_tiny_steps_is_bounded() {
    let seed = ElfSpec::lib("libv.so")
        .import_versioned("a", "libc.so.6", "V1")
        .import_versioned("b", "libm.so.6", "V2")
        .build();
    let elf = ElfFile::parse(&seed).unwrap();
    let index = elf
        .sections
        .iter()
        .position(|s| s.name == ".gnu.version_r")
        .unwrap();
    let first = elf.sections[index].offset as usize;
    let shoff = u64::from_le_bytes(seed[40..48].try_into().unwrap()) as usize;
    let sh_info = shoff + index * 64 + 44;

    let mut crafted = seed.clone();
    // sh_info claims 4 billion records, vn_cnt claims 65535 aux entries, and
    // vn_next advances one byte at a time through the section.
    crafted[sh_info..sh_info + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    crafted[first + 2..first + 4].copy_from_slice(&u16::MAX.to_le_bytes());
    crafted[first + 12..first + 16].copy_from_slice(&1u32.to_le_bytes());
    let started = std::time::Instant::now();
    let result = panic::catch_unwind(|| ElfFile::parse(&crafted));
    assert!(result.is_ok(), "parser panicked");
    assert!(started.elapsed().as_secs() < 5, "walk was not bounded");
}
