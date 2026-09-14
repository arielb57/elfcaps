//! Properties (2), (3) and (6): crediting through DT_NEEDED chains, ld.so's
//! RPATH/RUNPATH rules, and termination on dependency cycles.

mod support;

use elfcaps::analysis::Confidence;
use elfcaps::scan::{Finding, Report};
use elfcaps::{scan, CapDb};
use support::writer::{Bits, ElfSpec, Order};
use support::TempDir;

fn run(dir: &TempDir) -> Report {
    scan(dir.path(), None, &CapDb::builtin()).expect("scan succeeds")
}

fn needed_of<'a>(report: &'a Report, object: &str, name: &str) -> Option<&'a str> {
    let obj = report
        .objects
        .iter()
        .find(|o| o.path == object)
        .unwrap_or_else(|| panic!("{object} not in report: {:#?}", report.objects));
    obj.needed
        .iter()
        .find(|n| n.name == name)
        .unwrap_or_else(|| panic!("{object} has no DT_NEEDED {name}"))
        .resolved
        .as_deref()
}

fn findings_for<'a>(report: &'a Report, capability: &str) -> Vec<&'a Finding> {
    report
        .findings
        .iter()
        .filter(|f| f.capability == capability)
        .collect()
}

fn chain(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

#[test]
fn capability_is_credited_to_the_importing_library_through_the_chain() {
    let dir = TempDir::new("chain");
    dir.write(
        "bin/main",
        &ElfSpec::exe()
            .runpath("$ORIGIN/../lib")
            .needed("libA.so")
            .import("puts")
            .build(),
    );
    dir.write(
        "lib/libA.so",
        &ElfSpec::lib("libA.so")
            .runpath("$ORIGIN")
            .needed("libB.so")
            .import("malloc")
            .build(),
    );
    dir.write(
        "lib/libB.so",
        &ElfSpec::lib("libB.so")
            .needed("libxcb.so.1")
            .import_versioned("xcb_convert_selection", "libxcb.so.1", "XCB_1.0")
            .build(),
    );

    let report = run(&dir);
    let hits = findings_for(&report, "selection-read");
    assert_eq!(hits.len(), 1, "{:#?}", report.findings);
    let hit = hits[0];
    assert_eq!(hit.object, "lib/libB.so");
    assert_eq!(hit.symbol, "xcb_convert_selection");
    assert_eq!(hit.version.as_deref(), Some("XCB_1.0"));
    assert_eq!(hit.confidence, Confidence::Direct);
    assert_eq!(
        hit.reached_via,
        [chain(&["bin/main", "lib/libA.so", "lib/libB.so"])]
    );
    assert_eq!(
        report.findings.len(),
        1,
        "main and libA import nothing sensitive"
    );
    assert_eq!(
        needed_of(&report, "bin/main", "libA.so"),
        Some("lib/libA.so")
    );
    assert_eq!(needed_of(&report, "lib/libB.so", "libxcb.so.1"), None);
}

#[test]
fn bundled_provider_defining_the_symbol_is_not_flagged() {
    let dir = TempDir::new("provider");
    dir.write(
        "app",
        &ElfSpec::exe()
            .rpath("$ORIGIN/lib")
            .needed("libxcb.so.1")
            .import("xcb_get_image")
            .build(),
    );
    dir.write(
        "lib/libxcb.so.1",
        &ElfSpec::lib("libxcb.so.1")
            .export("xcb_get_image")
            .export("xcb_convert_selection")
            .build(),
    );
    let report = run(&dir);
    assert_eq!(
        needed_of(&report, "app", "libxcb.so.1"),
        Some("lib/libxcb.so.1")
    );
    let objects: Vec<&str> = report.findings.iter().map(|f| f.object.as_str()).collect();
    assert_eq!(objects, ["app"]);
    assert_eq!(report.findings[0].capability, "screen-capture");
    assert_eq!(report.findings[0].reached_via, [chain(&["app"])]);
}

/// bin/main has both RPATH=$ORIGIN/rp and RUNPATH=$ORIGIN/run, and a
/// different libfoo.so sits in each directory.
fn precedence_bundle(with_runpath: bool) -> TempDir {
    let dir = TempDir::new("precedence");
    let mut main = ElfSpec::exe().rpath("$ORIGIN/rp").needed("libfoo.so");
    if with_runpath {
        main = main.runpath("$ORIGIN/run");
    }
    dir.write("bin/main", &main.build());
    dir.write(
        "bin/rp/libfoo.so",
        &ElfSpec::lib("libfoo.so").import("XGrabKeyboard").build(),
    );
    dir.write(
        "bin/run/libfoo.so",
        &ElfSpec::lib("libfoo.so").import("xcb_get_image").build(),
    );
    dir
}

#[test]
fn runpath_takes_precedence_over_rpath() {
    let dir = precedence_bundle(true);
    let report = run(&dir);
    assert_eq!(
        needed_of(&report, "bin/main", "libfoo.so"),
        Some("bin/run/libfoo.so")
    );
    let capture = findings_for(&report, "screen-capture");
    assert_eq!(capture.len(), 1);
    assert_eq!(
        capture[0].reached_via,
        [chain(&["bin/main", "bin/run/libfoo.so"])]
    );
    // The RPATH copy is still scanned, but nothing loads it.
    let grab = findings_for(&report, "keyboard-grab");
    assert_eq!(grab.len(), 1);
    assert_eq!(grab[0].reached_via, [chain(&["bin/rp/libfoo.so"])]);

    let dir = precedence_bundle(false);
    let report = run(&dir);
    assert_eq!(
        needed_of(&report, "bin/main", "libfoo.so"),
        Some("bin/rp/libfoo.so")
    );
}

fn inheritance_bundle(main: ElfSpec, lib_a: ElfSpec) -> TempDir {
    let dir = TempDir::new("inherit");
    dir.write("bin/main", &main.needed("libA.so").build());
    dir.write("deps/libA.so", &lib_a.needed("libB.so").build());
    dir.write(
        "deps/libB.so",
        &ElfSpec::lib("libB.so")
            .import("XRecordEnableContext")
            .build(),
    );
    dir
}

#[test]
fn runpath_is_not_inherited_by_transitive_dependencies() {
    let dir = inheritance_bundle(
        ElfSpec::exe().runpath("$ORIGIN/../deps"),
        ElfSpec::lib("libA.so"),
    );
    let report = run(&dir);
    assert_eq!(
        needed_of(&report, "bin/main", "libA.so"),
        Some("deps/libA.so")
    );
    assert_eq!(needed_of(&report, "deps/libA.so", "libB.so"), None);
    let record = findings_for(&report, "input-record");
    assert_eq!(record[0].reached_via, [chain(&["deps/libB.so"])]);
}

#[test]
fn rpath_is_inherited_by_transitive_dependencies() {
    let dir = inheritance_bundle(
        ElfSpec::exe().rpath("$ORIGIN/../deps"),
        ElfSpec::lib("libA.so"),
    );
    let report = run(&dir);
    assert_eq!(
        needed_of(&report, "deps/libA.so", "libB.so"),
        Some("deps/libB.so")
    );
    let record = findings_for(&report, "input-record");
    assert_eq!(
        record[0].reached_via,
        [chain(&["bin/main", "deps/libA.so", "deps/libB.so"])]
    );
}

#[test]
fn a_runpath_on_the_requester_disables_inherited_rpath() {
    let dir = inheritance_bundle(
        ElfSpec::exe().rpath("$ORIGIN/../deps"),
        ElfSpec::lib("libA.so").runpath("$ORIGIN/nowhere"),
    );
    let report = run(&dir);
    assert_eq!(
        needed_of(&report, "bin/main", "libA.so"),
        Some("deps/libA.so")
    );
    assert_eq!(needed_of(&report, "deps/libA.so", "libB.so"), None);
}

#[test]
fn an_ancestor_with_runpath_contributes_no_rpath() {
    let dir = inheritance_bundle(
        ElfSpec::exe()
            .rpath("$ORIGIN/../deps")
            .runpath("$ORIGIN/../deps"),
        ElfSpec::lib("libA.so"),
    );
    let report = run(&dir);
    assert_eq!(
        needed_of(&report, "bin/main", "libA.so"),
        Some("deps/libA.so")
    );
    assert_eq!(needed_of(&report, "deps/libA.so", "libB.so"), None);
}

#[test]
fn search_skips_objects_of_another_class_or_machine() {
    let dir = TempDir::new("class");
    dir.write(
        "app",
        &ElfSpec::exe()
            .runpath("$ORIGIN/lib32:$ORIGIN/be64:$ORIGIN/lib64")
            .needed("libfoo.so")
            .build(),
    );
    dir.write(
        "lib32/libfoo.so",
        &ElfSpec::new(Bits::B32, Order::Little)
            .soname("libfoo.so")
            .build(),
    );
    dir.write(
        "be64/libfoo.so",
        &ElfSpec::new(Bits::B64, Order::Big)
            .soname("libfoo.so")
            .build(),
    );
    dir.write("lib64/libfoo.so", &ElfSpec::lib("libfoo.so").build());
    let report = run(&dir);
    assert_eq!(
        needed_of(&report, "app", "libfoo.so"),
        Some("lib64/libfoo.so")
    );
}

#[test]
fn search_paths_leaving_the_root_are_treated_as_system() {
    let outside = TempDir::new("outside");
    outside.write(
        "libevil.so",
        &ElfSpec::lib("libevil.so").import("XGrabKey").build(),
    );
    let dir = TempDir::new("inside");
    dir.write(
        "app",
        &ElfSpec::exe()
            .rpath(&format!("{}:$ORIGIN/../..", outside.path().display()))
            .needed("libevil.so")
            .build(),
    );
    let report = run(&dir);
    assert_eq!(needed_of(&report, "app", "libevil.so"), None);
    assert!(report.findings.is_empty());
    assert_eq!(report.objects.len(), 1);
}

#[test]
fn soname_match_reuses_an_already_loaded_object() {
    let dir = TempDir::new("soname");
    dir.write(
        "app",
        &ElfSpec::exe()
            .rpath("$ORIGIN/lib")
            .needed("libcore.so.2")
            .needed("libui.so")
            .build(),
    );
    // Found by file name libcore.so.2 whose SONAME is libcore.so.2.4; libui
    // asks for the SONAME and must get the same object even though no file
    // by that name exists.
    dir.write("lib/libcore.so.2", &ElfSpec::lib("libcore.so.2.4").build());
    dir.write(
        "lib/libui.so",
        &ElfSpec::lib("libui.so").needed("libcore.so.2.4").build(),
    );
    let report = run(&dir);
    assert_eq!(
        needed_of(&report, "lib/libui.so", "libcore.so.2.4"),
        Some("lib/libcore.so.2")
    );
}

#[test]
fn dependency_cycles_terminate_and_load_each_object_once() {
    let dir = TempDir::new("cycle");
    dir.write(
        "bin/app",
        &ElfSpec::exe()
            .rpath("$ORIGIN/../lib")
            .needed("libA.so")
            .build(),
    );
    dir.write(
        "lib/libA.so",
        &ElfSpec::lib("libA.so")
            .needed("libB.so")
            .needed("libA.so")
            .build(),
    );
    dir.write(
        "lib/libB.so",
        &ElfSpec::lib("libB.so")
            .needed("libC.so")
            .needed("libA.so")
            .import("XFixesSelectSelectionNotify")
            .build(),
    );
    dir.write(
        "lib/libC.so",
        &ElfSpec::lib("libC.so")
            .needed("libB.so")
            .needed("libA.so")
            .build(),
    );
    // A cycle nothing links to, which is simulated from its own roots.
    dir.write(
        "plugins/libP.so",
        &ElfSpec::lib("libP.so")
            .runpath("$ORIGIN")
            .needed("libQ.so")
            .build(),
    );
    dir.write(
        "plugins/libQ.so",
        &ElfSpec::lib("libQ.so")
            .runpath("$ORIGIN")
            .needed("libP.so")
            .import("XShmGetImage")
            .build(),
    );
    #[cfg(unix)]
    std::os::unix::fs::symlink("..", dir.path().join("lib/loop")).unwrap();

    let report = run(&dir);
    assert_eq!(report.objects.len(), 6, "{:#?}", report.objects);
    assert_eq!(
        needed_of(&report, "lib/libA.so", "libA.so"),
        Some("lib/libA.so")
    );
    assert_eq!(
        needed_of(&report, "lib/libC.so", "libB.so"),
        Some("lib/libB.so")
    );
    let watch = findings_for(&report, "selection-watch");
    assert_eq!(watch.len(), 1);
    assert_eq!(
        watch[0].reached_via,
        [chain(&["bin/app", "lib/libA.so", "lib/libB.so"])]
    );
    let capture = findings_for(&report, "screen-capture");
    assert_eq!(
        capture[0].reached_via,
        [chain(&["plugins/libP.so", "plugins/libQ.so"])]
    );
    assert_eq!(
        needed_of(&report, "plugins/libQ.so", "libP.so"),
        Some("plugins/libP.so")
    );
}

#[test]
fn corrupt_and_foreign_files_do_not_stop_a_scan() {
    let dir = TempDir::new("corrupt");
    dir.write("app", &ElfSpec::exe().import("XQueryKeymap").build());
    let mut broken = ElfSpec::lib("libbroken.so").build();
    broken.truncate(100);
    dir.write("libbroken.so", &broken);
    dir.write("README.txt", b"not an ELF file");
    dir.write("empty", b"");
    let report = run(&dir);
    assert_eq!(report.objects.len(), 1);
    assert_eq!(report.errors.len(), 1);
    assert_eq!(report.errors[0].path, "libbroken.so");
    assert!(
        report.errors[0].message.contains("out of bounds"),
        "{}",
        report.errors[0].message
    );
    assert_eq!(findings_for(&report, "input-record").len(), 1);
}

#[test]
fn single_binary_scan_resolves_against_its_root() {
    let dir = TempDir::new("single");
    let app = dir.write(
        "opt/app/bin/app",
        &ElfSpec::exe()
            .runpath("$ORIGIN/../lib")
            .needed("libcap.so")
            .build(),
    );
    dir.write(
        "opt/app/lib/libcap.so",
        &ElfSpec::lib("libcap.so")
            .import("XTestFakeKeyEvent")
            .build(),
    );

    let db = CapDb::builtin();
    // Default root is the binary's directory, so the library is out of reach.
    let narrow = scan(&app, None, &db).unwrap();
    assert_eq!(narrow.objects.len(), 1);
    assert!(narrow.findings.is_empty());

    let wide = scan(&app, Some(&dir.path().join("opt/app")), &db).unwrap();
    assert_eq!(wide.findings.len(), 1);
    assert_eq!(wide.findings[0].object, "lib/libcap.so");
    assert_eq!(
        wide.findings[0].reached_via,
        [chain(&["bin/app", "lib/libcap.so"])]
    );

    let err = scan(&app, Some(&dir.path().join("opt/app/lib")), &db).unwrap_err();
    assert!(matches!(err, elfcaps::ScanError::OutsideRoot { .. }));
    let not_elf = dir.write("notes.txt", b"hello");
    assert!(matches!(
        scan(&not_elf, None, &db),
        Err(elfcaps::ScanError::NotElf(_))
    ));
    let mut truncated = ElfSpec::lib("libt.so").build();
    truncated.truncate(80);
    let truncated = dir.write("libt.so", &truncated);
    assert!(matches!(
        scan(&truncated, None, &db),
        Err(elfcaps::ScanError::Parse { .. })
    ));
}
