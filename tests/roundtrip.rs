//! Property (1): every symbol the writer emits parses back with the same
//! binding, type, definedness and GNU version, for ELF32 LE, ELF64 LE and
//! ELF64 BE, along with DT_NEEDED, DT_SONAME, DT_RPATH and DT_RUNPATH.

mod support;

use elfcaps::elf::{Binding, Class, ElfFile, Endian, SymbolType};
use support::writer::*;
use support::Rng;

const FORMATS: [(Bits, Order, Class, Endian); 3] = [
    (Bits::B32, Order::Little, Class::Elf32, Endian::Little),
    (Bits::B64, Order::Little, Class::Elf64, Endian::Little),
    (Bits::B64, Order::Big, Class::Elf64, Endian::Big),
];

fn expected_binding(bind: u8) -> Binding {
    match bind {
        STB_LOCAL => Binding::Local,
        STB_GLOBAL => Binding::Global,
        STB_WEAK => Binding::Weak,
        other => panic!("writer test uses unexpected binding {other}"),
    }
}

fn expected_type(kind: u8) -> SymbolType {
    match kind {
        STT_NOTYPE => SymbolType::NoType,
        STT_OBJECT => SymbolType::Object,
        STT_FUNC => SymbolType::Func,
        STT_TLS => SymbolType::Tls,
        STT_GNU_IFUNC => SymbolType::GnuIfunc,
        other => panic!("writer test uses unexpected type {other}"),
    }
}

fn assert_roundtrip(spec: &ElfSpec) {
    let bytes = spec.build();
    let elf = ElfFile::parse(&bytes).unwrap_or_else(|e| panic!("parse failed: {e}"));
    assert_eq!(elf.needed, spec.needed);
    assert_eq!(elf.soname, spec.soname);
    assert_eq!(elf.rpath, spec.rpath);
    assert_eq!(elf.runpath, spec.runpath);
    assert_eq!(elf.machine, spec.machine);
    assert_eq!(elf.interpreter, spec.interp);
    assert_eq!(elf.symbols.len(), spec.symbols.len(), "symbol count");
    for (got, want) in elf.symbols.iter().zip(&spec.symbols) {
        assert_eq!(got.name, want.name);
        assert_eq!(got.binding, expected_binding(want.bind), "{}", want.name);
        assert_eq!(got.kind, expected_type(want.kind), "{}", want.name);
        assert_eq!(got.is_undefined(), !want.defined, "{}", want.name);
        match (&got.version, &want.version) {
            (None, None) => {}
            (Some(v), Some(Version::Needed { file, name })) => {
                assert_eq!(&v.name, name);
                assert_eq!(v.file.as_deref(), Some(file.as_str()));
                assert_eq!(v.hidden, want.hidden);
            }
            (Some(v), Some(Version::Defined(name))) => {
                assert_eq!(&v.name, name);
                assert_eq!(v.file, None);
                assert_eq!(v.hidden, want.hidden);
            }
            (got, want) => panic!(
                "version mismatch for {:?}: {got:?} vs {want:?}",
                elf.symbols
            ),
        }
    }
    let mut rodata = spec.rodata.clone();
    rodata.retain(|s| s.len() >= 4);
    for s in &rodata {
        assert!(elf.rodata_strings.contains(s), "missing rodata string {s}");
    }
}

fn sym(
    name: &str,
    bind: u8,
    kind: u8,
    defined: bool,
    version: Option<Version>,
    hidden: bool,
) -> SymSpec {
    SymSpec {
        name: name.into(),
        bind,
        kind,
        defined,
        version,
        hidden,
    }
}

#[test]
fn handwritten_objects_roundtrip_in_all_formats() {
    for (bits, order, class, endian) in FORMATS {
        let mut spec = ElfSpec::new(bits, order)
            .soname("libQt5XcbQpa.so.5")
            .needed("libxcb.so.1")
            .needed("libc.so.6")
            .rpath("$ORIGIN/../lib:/opt/app/lib")
            .runpath("${ORIGIN}")
            .rodata("libX11.so.6")
            .rodata("XConvertSelection")
            .symbol(sym("local_helper", STB_LOCAL, STT_FUNC, true, None, false))
            .symbol(sym(
                "xcb_convert_selection",
                STB_GLOBAL,
                STT_FUNC,
                false,
                Some(Version::Needed {
                    file: "libxcb.so.1".into(),
                    name: "XCB_1.0".into(),
                }),
                false,
            ))
            .symbol(sym(
                "memcpy",
                STB_GLOBAL,
                STT_FUNC,
                false,
                Some(Version::Needed {
                    file: "libc.so.6".into(),
                    name: "GLIBC_2.14".into(),
                }),
                false,
            ))
            .symbol(sym(
                "stderr",
                STB_GLOBAL,
                STT_OBJECT,
                false,
                Some(Version::Needed {
                    file: "libc.so.6".into(),
                    name: "GLIBC_2.2.5".into(),
                }),
                false,
            ))
            .symbol(sym(
                "__gmon_start__",
                STB_WEAK,
                STT_NOTYPE,
                false,
                None,
                false,
            ))
            .symbol(sym(
                "qt_plugin_instance",
                STB_GLOBAL,
                STT_FUNC,
                true,
                Some(Version::Defined("Qt_5".into())),
                false,
            ))
            .symbol(sym(
                "qt_old_api",
                STB_GLOBAL,
                STT_FUNC,
                true,
                Some(Version::Defined("Qt_5_PRIVATE".into())),
                true,
            ))
            .symbol(sym("tls_state", STB_GLOBAL, STT_TLS, true, None, false))
            .symbol(sym("resolver", STB_WEAK, STT_GNU_IFUNC, true, None, false));
        spec.interp = Some("/lib/ld-linux.so.2".into());
        let elf = ElfFile::parse(&spec.build()).unwrap();
        assert_eq!(elf.class, class);
        assert_eq!(elf.endian, endian);
        assert!(elf.is_executable(), "ET_DYN with PT_INTERP is a PIE");
        assert_roundtrip(&spec);
    }
}

#[test]
fn objects_without_versions_or_dynamic_entries_roundtrip() {
    for (bits, order, _, _) in FORMATS {
        assert_roundtrip(&ElfSpec::new(bits, order));
        assert_roundtrip(&ElfSpec::new(bits, order).import("dlopen").export("main"));
    }
}

fn random_name(rng: &mut Rng) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_0123456789";
    let len = 1 + rng.below(24);
    let mut name: String = (0..len)
        .map(|_| ALPHABET[rng.below(ALPHABET.len())] as char)
        .collect();
    name.insert(0, '_');
    name
}

#[test]
fn randomly_generated_symbol_tables_roundtrip() {
    let bindings = [STB_GLOBAL, STB_WEAK];
    let kinds = [STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_TLS, STT_GNU_IFUNC];
    let files = ["libc.so.6", "libX11.so.6", "libxcb.so.1"];
    let mut rng = Rng::new(0x05ee_de1f);
    for case in 0..300 {
        let (bits, order, _, _) = FORMATS[case % FORMATS.len()];
        let mut spec = ElfSpec::new(bits, order);
        for _ in 0..rng.below(4) {
            spec = spec.needed(&format!("lib{}.so", random_name(&mut rng)));
        }
        if rng.chance(2) {
            spec = spec.soname(&format!("lib{}.so.1", random_name(&mut rng)));
        }
        if rng.chance(3) {
            spec = spec.rpath("$ORIGIN/lib");
        }
        if rng.chance(3) {
            spec = spec.runpath("$ORIGIN/../lib64:/usr/local/lib");
        }
        let locals = rng.below(3);
        for _ in 0..locals {
            let name = random_name(&mut rng);
            spec = spec.symbol(sym(&name, STB_LOCAL, STT_FUNC, true, None, false));
        }
        for _ in 0..rng.below(40) {
            let defined = rng.chance(2);
            let version = match rng.below(3) {
                0 => None,
                1 if defined => Some(Version::Defined(format!("V_{}", rng.below(4)))),
                _ if defined => None,
                _ => Some(Version::Needed {
                    file: files[rng.below(files.len())].into(),
                    name: format!("VER_{}", rng.below(5)),
                }),
            };
            let hidden = version.is_some() && rng.chance(4);
            let name = random_name(&mut rng);
            spec = spec.symbol(sym(
                &name,
                bindings[rng.below(2)],
                kinds[rng.below(kinds.len())],
                defined,
                version,
                hidden,
            ));
        }
        for _ in 0..rng.below(5) {
            spec = spec.rodata(&random_name(&mut rng));
        }
        assert_roundtrip(&spec);
    }
}
