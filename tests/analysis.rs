//! Properties (4) and (5): only undefined imports count, and the indirect
//! pass needs both a dynamic-loader import and a matching read-only string.

mod support;

use elfcaps::analysis::{analyze, Confidence};
use elfcaps::elf::ElfFile;
use elfcaps::CapDb;
use support::writer::{Bits, ElfSpec, Order, SymSpec, Version, STB_WEAK, STT_FUNC};

fn evidence(spec: ElfSpec) -> Vec<(String, String, Confidence)> {
    let elf = ElfFile::parse(&spec.build()).unwrap();
    analyze(&elf, &CapDb::builtin())
        .evidence
        .into_iter()
        .map(|e| (e.capability, e.symbol, e.confidence))
        .collect()
}

fn ev(cap: &str, sym: &str, confidence: Confidence) -> (String, String, Confidence) {
    (cap.to_string(), sym.to_string(), confidence)
}

#[test]
fn defined_symbols_with_capability_names_are_not_flagged() {
    for bits in [Bits::B32, Bits::B64] {
        let spec = ElfSpec::new(bits, Order::Little)
            .soname("libX11.so.6")
            .export("XConvertSelection")
            .export("XGrabKeyboard")
            .symbol(SymSpec {
                name: "XShmGetImage".into(),
                bind: STB_WEAK,
                kind: STT_FUNC,
                defined: true,
                version: Some(Version::Defined("XSHM_1".into())),
                hidden: false,
            });
        assert!(evidence(spec).is_empty());
    }
}

#[test]
fn undefined_imports_are_flagged_with_their_version() {
    let spec = ElfSpec::new(Bits::B64, Order::Big)
        .export("XQueryTree")
        .import("XGrabKeyboard")
        .import_versioned("pw_stream_connect", "libpipewire-0.3.so.0", "PIPEWIRE_0.3")
        .import("printf");
    let elf = ElfFile::parse(&spec.build()).unwrap();
    let analysis = analyze(&elf, &CapDb::builtin());
    let found: Vec<_> = analysis
        .evidence
        .iter()
        .map(|e| {
            (
                e.capability.as_str(),
                e.symbol.as_str(),
                e.version.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        found,
        [
            ("keyboard-grab", "XGrabKeyboard", None),
            ("pipewire-stream", "pw_stream_connect", Some("PIPEWIRE_0.3")),
        ]
    );
    assert!(!analysis.imports_dynamic_loader);
}

#[test]
fn dlopen_plus_symbol_string_is_indirect_and_neither_alone_is() {
    let base = || ElfSpec::lib("libupdater.so").import("fopen");
    assert!(evidence(base()).is_empty());
    assert!(evidence(base().import("dlopen")).is_empty(), "dlopen alone");
    assert!(
        evidence(base().rodata("XConvertSelection")).is_empty(),
        "string alone"
    );
    assert_eq!(
        evidence(base().import("dlopen").rodata("XConvertSelection")),
        [ev(
            "selection-read",
            "XConvertSelection",
            Confidence::Indirect
        )]
    );
    assert_eq!(
        evidence(base().import("dlsym").rodata("XRecordEnableContext")),
        [ev(
            "input-record",
            "XRecordEnableContext",
            Confidence::Indirect
        )]
    );
}

#[test]
fn indirect_pass_needs_an_exact_string_and_an_import_not_a_definition() {
    // A library that *defines* dlopen (a libc) is not a dlopen user.
    assert!(evidence(
        ElfSpec::lib("libc.so.6")
            .export("dlopen")
            .rodata("XConvertSelection")
    )
    .is_empty());
    // Substrings and longer messages do not match.
    assert!(evidence(
        ElfSpec::lib("libx.so")
            .import("dlopen")
            .rodata("cannot resolve XConvertSelection")
            .rodata("XConvertSelectionX")
    )
    .is_empty());
}

#[test]
fn a_direct_import_is_not_repeated_as_indirect() {
    let found = evidence(
        ElfSpec::lib("libqt.so")
            .import("dlopen")
            .import("xcb_convert_selection")
            .rodata("xcb_convert_selection")
            .rodata("xcb_get_image"),
    );
    assert_eq!(
        found,
        [
            ev("screen-capture", "xcb_get_image", Confidence::Indirect),
            ev(
                "selection-read",
                "xcb_convert_selection",
                Confidence::Direct
            ),
        ]
    );
}

#[test]
fn portal_strings_are_indirect_without_dlopen_and_library_names_are_listed() {
    let found = evidence(ElfSpec::lib("libshare.so").rodata("org.freedesktop.portal.ScreenCast"));
    assert_eq!(
        found,
        [ev(
            "portal-screencast",
            "org.freedesktop.portal.ScreenCast",
            Confidence::Indirect
        )]
    );

    let spec = ElfSpec::lib("libloader.so")
        .import("dlopen")
        .rodata("libXtst.so.6")
        .rodata("libX11.so");
    let analysis = analyze(&ElfFile::parse(&spec.build()).unwrap(), &CapDb::builtin());
    assert!(analysis.imports_dynamic_loader);
    assert!(
        analysis.evidence.is_empty(),
        "a library name is not a capability"
    );
    assert_eq!(analysis.dlopen_candidates, ["libX11.so", "libXtst.so.6"]);

    let without_dlopen = ElfSpec::lib("libloader.so").rodata("libXtst.so.6");
    let analysis = analyze(
        &ElfFile::parse(&without_dlopen.build()).unwrap(),
        &CapDb::builtin(),
    );
    assert!(analysis.dlopen_candidates.is_empty());
}

#[test]
fn a_custom_database_changes_what_is_reported() {
    let db = CapDb::parse(
        "[telemetry]\ntitle = Sends telemetry\nrationale = test entry\nsymbols = curl_easy_perform\n",
    )
    .unwrap();
    let spec = ElfSpec::lib("libt.so")
        .import("curl_easy_perform")
        .import("XConvertSelection");
    let elf = ElfFile::parse(&spec.build()).unwrap();
    let found: Vec<_> = analyze(&elf, &db)
        .evidence
        .into_iter()
        .map(|e| e.symbol)
        .collect();
    assert_eq!(found, ["curl_easy_perform"]);
}
