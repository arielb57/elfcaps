//! End-to-end checks of the `elfcaps` binary: commands, exit codes and output.

mod support;

use std::process::{Command, Output};
use support::writer::ElfSpec;
use support::TempDir;

fn elfcaps(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_elfcaps"))
        .args(args)
        .output()
        .expect("run elfcaps")
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn app(dir: &TempDir, lib_imports: &[&str]) {
    dir.write(
        "bin/app",
        &ElfSpec::exe()
            .runpath("$ORIGIN/../lib")
            .needed("libqpa.so")
            .needed("libc.so.6")
            .build(),
    );
    let mut lib = ElfSpec::lib("libqpa.so");
    for s in lib_imports {
        lib = lib.import(s);
    }
    dir.write("lib/libqpa.so", &lib.build());
}

#[test]
fn scan_prints_a_table_with_the_chain() {
    let dir = TempDir::new("cli-scan");
    app(&dir, &["xcb_convert_selection"]);
    let out = elfcaps(&["scan", dir.path().to_str().unwrap()]);
    assert!(out.status.success(), "{out:?}");
    let text = stdout(&out);
    assert!(
        text.contains("2 ELF objects (1 executable), 1 findings in 1 capabilities"),
        "{text}"
    );
    let row = text
        .lines()
        .find(|l| l.starts_with("selection-read"))
        .unwrap_or_else(|| panic!("{text}"));
    let cells: Vec<&str> = row
        .split("  ")
        .filter(|c| !c.is_empty())
        .map(str::trim)
        .collect();
    assert_eq!(
        cells,
        [
            "selection-read",
            "lib/libqpa.so",
            "xcb_convert_selection",
            "direct",
            "bin/app -> lib/libqpa.so"
        ]
    );
    assert!(text.contains("bin/app: libc.so.6"), "{text}");
}

#[test]
fn scan_json_has_findings_and_resolution() {
    let dir = TempDir::new("cli-json");
    app(&dir, &["XGrabKeyboard"]);
    let out = elfcaps(&["scan", "--json", dir.path().to_str().unwrap()]);
    assert!(out.status.success());
    let json = stdout(&out);
    assert!(json.starts_with("{\"root\":"));
    assert!(json.contains(
        "{\"capability\":\"keyboard-grab\",\"title\":\"Grabs the keyboard or individual key combinations globally\",\"object\":\"lib/libqpa.so\",\"symbol\":\"XGrabKeyboard\",\"version\":null,\"confidence\":\"direct\",\"reached_via\":[[\"bin/app\",\"lib/libqpa.so\"]]}"
    ), "{json}");
    assert!(json.contains("{\"name\":\"libqpa.so\",\"resolved\":\"lib/libqpa.so\"}"));
    assert!(json.contains("{\"name\":\"libc.so.6\",\"resolved\":null}"));
    assert_eq!(json.matches('{').count(), json.matches('}').count());
}

#[test]
fn diff_exit_code_reflects_changes() {
    let old = TempDir::new("cli-old");
    let new = TempDir::new("cli-new");
    let same = TempDir::new("cli-same");
    app(&old, &["XConvertSelection", "XRecordEnableContext"]);
    app(&new, &["XConvertSelection", "XShmGetImage"]);
    app(&same, &["XConvertSelection", "XRecordEnableContext"]);
    let (o, n, s) = (
        old.path().to_str().unwrap(),
        new.path().to_str().unwrap(),
        same.path().to_str().unwrap(),
    );

    let changed = elfcaps(&["diff", o, n]);
    assert_eq!(changed.status.code(), Some(1));
    let text = stdout(&changed);
    assert!(text.contains("+ screen-capture"), "{text}");
    assert!(text.contains("- input-record"), "{text}");
    assert!(!text.contains("selection-read"), "{text}");

    let json = stdout(&elfcaps(&["diff", "--json", o, n]));
    assert!(
        json.starts_with("{\"added\":[{\"capability\":\"screen-capture\""),
        "{json}"
    );
    assert!(
        json.contains("\"removed\":[{\"capability\":\"input-record\""),
        "{json}"
    );
    assert!(json.ends_with("\"changed\":[]}\n"), "{json}");

    let unchanged = elfcaps(&["diff", o, s]);
    assert_eq!(unchanged.status.code(), Some(0));
    assert!(stdout(&unchanged).contains("No capability changes."));
}

#[test]
fn custom_database_and_caps_listing() {
    let dir = TempDir::new("cli-db");
    app(&dir, &["curl_easy_perform"]);
    let db = dir.write(
        "custom.db",
        b"[network]\ntitle = Talks HTTP\nrationale = test\nsymbols = curl_easy_perform\n",
    );
    let out = elfcaps(&[
        "scan",
        dir.path().to_str().unwrap(),
        "--db",
        db.to_str().unwrap(),
    ]);
    assert!(stdout(&out).contains("network"), "{}", stdout(&out));

    let caps = stdout(&elfcaps(&["caps"]));
    assert!(caps.contains("selection-read\n  Reads clipboard"));
    assert!(caps.contains("why: On X11 any client"));

    let bad = dir.write("bad.db", b"[x]\ntitle = t\n");
    let out = elfcaps(&["caps", "--db", bad.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("has no rationale"));
}

#[test]
fn usage_errors_exit_with_two() {
    assert_eq!(elfcaps(&[]).status.code(), Some(2));
    assert_eq!(elfcaps(&["frobnicate"]).status.code(), Some(2));
    assert_eq!(elfcaps(&["scan"]).status.code(), Some(2));
    assert_eq!(elfcaps(&["scan", "x", "--bogus"]).status.code(), Some(2));
    let missing = elfcaps(&["scan", "/definitely/not/here"]);
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("/definitely/not/here"));
    assert!(elfcaps(&["--help"]).status.success());
    assert!(stdout(&elfcaps(&["--version"])).starts_with("elfcaps "));
}
