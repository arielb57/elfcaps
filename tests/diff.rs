//! Property (8): diff reports exactly the capabilities that were added or
//! removed, and separates evidence changes inside capabilities kept in both.

mod support;

use elfcaps::analysis::Confidence;
use elfcaps::diff::{diff, EvidenceKey};
use elfcaps::{scan, CapDb, Report};
use support::writer::ElfSpec;
use support::TempDir;

struct Version<'a> {
    main_imports: &'a [&'a str],
    lib_imports: &'a [&'a str],
    lib_path: &'a str,
    lib_rodata: &'a [&'a str],
}

fn build(v: &Version) -> (TempDir, Report) {
    let dir = TempDir::new("diff");
    let mut main = ElfSpec::exe()
        .runpath("$ORIGIN/lib:$ORIGIN/lib/plugins")
        .needed("libcore.so");
    for s in v.main_imports {
        main = main.import(s);
    }
    dir.write("app", &main.build());
    let mut lib = ElfSpec::lib("libcore.so");
    for s in v.lib_imports {
        lib = lib.import(s);
    }
    for s in v.lib_rodata {
        lib = lib.rodata(s);
    }
    dir.write(v.lib_path, &lib.build());
    let report = scan(dir.path(), None, &CapDb::builtin()).unwrap();
    (dir, report)
}

fn ids(changes: &[elfcaps::diff::CapabilityChange]) -> Vec<&str> {
    changes.iter().map(|c| c.capability.as_str()).collect()
}

#[test]
fn reports_exactly_the_added_and_removed_capabilities() {
    let (_a, old) = build(&Version {
        main_imports: &["XConvertSelection", "XQueryTree"],
        lib_imports: &["XRecordEnableContext", "XFixesSelectSelectionNotify"],
        lib_path: "lib/libcore.so",
        lib_rodata: &[],
    });
    let (_b, new) = build(&Version {
        main_imports: &["XConvertSelection", "XQueryTree"],
        lib_imports: &[
            "XFixesSelectSelectionNotify",
            "xcb_shm_get_image",
            "XTestFakeKeyEvent",
        ],
        lib_path: "lib/libcore.so",
        lib_rodata: &[],
    });

    let d = diff(&old, &new);
    assert_eq!(ids(&d.added), ["input-injection", "screen-capture"]);
    assert_eq!(ids(&d.removed), ["input-record"]);
    assert!(d.changed.is_empty(), "{:#?}", d.changed);
    assert_eq!(
        d.added[1].evidence,
        [EvidenceKey {
            object: "lib/libcore.so".into(),
            symbol: "xcb_shm_get_image".into(),
            confidence: Confidence::Direct,
        }]
    );

    let back = diff(&new, &old);
    assert_eq!(ids(&back.added), ["input-record"]);
    assert_eq!(ids(&back.removed), ["input-injection", "screen-capture"]);
}

#[test]
fn identical_scans_have_no_differences_even_in_different_directories() {
    let v = Version {
        main_imports: &["XGrabKeyboard"],
        lib_imports: &["xcb_get_image"],
        lib_path: "lib/libcore.so",
        lib_rodata: &[],
    };
    let (_a, one) = build(&v);
    let (_b, two) = build(&v);
    assert_ne!(one.root, two.root);
    assert!(diff(&one, &two).is_empty());
}

#[test]
fn moved_or_upgraded_evidence_is_a_change_not_an_addition() {
    let (_a, old) = build(&Version {
        main_imports: &[],
        lib_imports: &["dlopen"],
        lib_path: "lib/libcore.so",
        lib_rodata: &["XShmGetImage"],
    });
    let (_b, new) = build(&Version {
        main_imports: &[],
        lib_imports: &["XShmGetImage"],
        lib_path: "lib/plugins/libcore.so",
        lib_rodata: &[],
    });
    assert_eq!(old.findings[0].confidence, Confidence::Indirect);
    let d = diff(&old, &new);
    assert!(d.added.is_empty() && d.removed.is_empty());
    assert_eq!(d.changed.len(), 1);
    let change = &d.changed[0];
    assert_eq!(change.capability, "screen-capture");
    assert_eq!(
        change.added,
        [EvidenceKey {
            object: "lib/plugins/libcore.so".into(),
            symbol: "XShmGetImage".into(),
            confidence: Confidence::Direct,
        }]
    );
    assert_eq!(
        change.removed,
        [EvidenceKey {
            object: "lib/libcore.so".into(),
            symbol: "XShmGetImage".into(),
            confidence: Confidence::Indirect,
        }]
    );
}
