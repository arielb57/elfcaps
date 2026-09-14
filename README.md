# elfcaps

Static audit of Linux binaries: which privacy-sensitive X11, input and screen-capture APIs they can reach, and which bundled library brings each one in.

## The problem

Closed-source Linux apps such as meeting clients, chat apps and vendor updaters ship big trees of bundled `.so` files, and nobody reads their imports. When one of these apps turns out to read the clipboard in the background, people usually find out by accident while it is running, even though the clipboard calls were sitting in the dynamic symbol tables all along. `nm -D` and `readelf` list symbols but don't tell you what `xcb_convert_selection` means. They also look at one file at a time and don't follow the bundle's `DT_NEEDED`/`RPATH` chain, so they won't show you that the call lives in a vendored `libQt5XcbQpa.so.5` three hops away from the executable.

## How it works

`elfcaps` has four stages. It uses only the Rust standard library.

1. **ELF parsing** (`src/elf.rs`). A zero-dependency reader for ELF32 and ELF64 in both byte orders. It reads the ELF header, program headers, section headers (including the extended `e_shnum`/`e_shstrndx` escapes), `.dynamic` (`DT_NEEDED`, `DT_SONAME`, `DT_RPATH`, `DT_RUNPATH`), `.dynsym`/`.dynstr`, and GNU symbol versioning (`.gnu.version`, `.gnu.version_r`, `.gnu.version_d`, hidden bit included). It also collects NUL-terminated printable strings from read-only, non-executable `PROGBITS` sections. All reads go through one bounds-checked reader that uses checked arithmetic, and table sizes are checked against the file length before anything is allocated. Malformed input produces a typed `ElfError` and never a panic.

2. **Dependency resolution** (`src/loader.rs`). This emulates glibc `ld.so` inside a root directory. It does a breadth-first walk from each executable, in the order ld.so maps dependencies. For each `DT_NEEDED` name:
   - Reuse an already-loaded object whose `SONAME` or earlier request name matches. This is also why cycles terminate.
   - If the requesting object has no `DT_RUNPATH`, search the `DT_RPATH` of the requester, then of its loader, and so on up to the executable. Objects that have a `RUNPATH` contribute no `RPATH`.
   - Search the requester's own `DT_RUNPATH`, which is never inherited.
   - Anything still unresolved, or resolving outside the root, counts as a system library, and the search stops there.

   `$ORIGIN` and `${ORIGIN}` expand to the directory the object was found in. Candidates built for a different class, byte order or `e_machine` are skipped, just as ld.so skips them. Libraries that no executable links (plugins, things loaded with `dlopen`) become roots of their own, so they still get audited.

3. **Capability matching** (`src/analysis.rs`, `caps/capabilities.db`). Only *undefined* dynamic symbols count. A bundled `libX11` that *defines* `XConvertSelection` is a provider, not a user. Each import found in the database is reported with `confidence=direct` and credited to the object that imports it. A second pass handles run-time loading: if an object imports `dlopen`, `dlmopen`, `dlsym` or `dlvsym`, and a read-only string in it is exactly equal to a database symbol, that capability is reported with `confidence=indirect`. Either signal on its own reports nothing. D-Bus portal names such as `org.freedesktop.portal.ScreenCast` are strings by nature, so they are matched without the `dlopen` condition, also at `indirect`.

4. **Reporting and diff** (`src/scan.rs`, `src/diff.rs`). The output is a capability → object → symbol → confidence table, plus every load chain that reaches the object, as text or JSON. `diff` groups findings by capability. A capability with evidence only in the new version is *added*, one with evidence only in the old version is *removed*, and one present in both with different evidence is *changed*. Load chains are left out of the comparison, so moving files around doesn't show up as a new capability.

The database ships as a data file with 11 capabilities: `selection-read`, `selection-watch`, `screen-capture`, `screen-change-tracking`, `pipewire-stream`, `portal-screencast`, `input-record`, `keyboard-grab`, `xi2-event-selection`, `input-injection` and `window-introspection`. Each entry explains why its symbols matter and how noisy the signal is. Run `elfcaps caps` to read it. The file is compiled into the binary, and `--db` replaces it.

### Threat model

**In scope.** A vendor ships an application you can install but not audit at the source level. You want to know, before running it, whether any bundled component *can* read your clipboard, watch selection changes, capture the screen or other windows, record or grab global input, or inject input. You also want to know when an update adds one of those abilities. The adversary here is ordinary commercial software linked in the ordinary way. It doesn't hide from the dynamic linker, because it has no reason to.

**Out of scope.** Software that actively evades static analysis cannot be caught by reading symbol tables: raw X11 protocol over a socket, statically linked or obfuscated code, syscalls, strings built at run time, or a downloaded payload. An import also doesn't prove the code path runs. Most GUI toolkits import `XConvertSelection` so that paste works. The tool reports *reachability through the dynamic linker*, which is a strong reason to look closer. It doesn't show intent, and a clean report doesn't prove anything either.

## Install and usage

You need a stable Rust toolchain (developed and tested with Rust 1.94). There are no runtime dependencies and nothing uses the network.

From a checkout of this repository:

```sh
cargo build --release     # binary at target/release/elfcaps
cargo test
cargo install --path .    # optional: put elfcaps on your PATH
```

```
elfcaps scan <dir-or-binary> [--json] [--root <dir>] [--db <file>]
elfcaps diff <old> <new> [--json] [--db <file>]
elfcaps caps [--db <file>]
```

`scan` exits 0, and `diff` exits 1 when there are changes (like `diff(1)`). Usage and I/O errors exit 2. When you scan a single binary, dependencies are resolved in its own directory unless you pass `--root` (for example `--root /opt/app` for `/opt/app/bin/app`).

### Worked example: a generated app bundle

There are no proprietary binaries in this repository. Instead, an example program uses the test suite's ELF writer to build two versions of a fake chat app. The layout is typical of a vendored Qt application:

```
chatapp-1.0/
  bin/chatapp                   PIE, RUNPATH=$ORIGIN/../lib, NEEDED libchatcore.so libQt5Gui.so.5 libc.so.6
  lib/libchatcore.so            RUNPATH=$ORIGIN, NEEDED libQt5Network.so.5 libupdater.so
  lib/libQt5Gui.so.5            RUNPATH=$ORIGIN, NEEDED libQt5XcbQpa.so.5
  lib/libQt5XcbQpa.so.5         imports xcb_convert_selection@XCB_1.0, xcb_get_image, ...
  lib/libupdater.so             imports dlopen/dlsym, has "libXtst.so.6" in .rodata
  lib/plugins/libscreenshare.so no executable links it (a dlopen plugin)
```

```sh
cargo run --example make_bundle -- demo
cargo run -q -- scan demo/chatapp-1.0
```

```
Scanned demo/chatapp-1.0: 7 ELF objects (1 executable), 6 findings in 5 capabilities.

CAPABILITY              OBJECT                         SYMBOL                              CONFIDENCE  REACHED VIA
selection-read          lib/libQt5XcbQpa.so.5          xcb_convert_selection@XCB_1.0       direct      bin/chatapp -> lib/libQt5Gui.so.5 -> lib/libQt5XcbQpa.so.5 (+1 more)
selection-watch         lib/libQt5XcbQpa.so.5          xcb_xfixes_select_selection_notify  direct      bin/chatapp -> lib/libQt5Gui.so.5 -> lib/libQt5XcbQpa.so.5 (+1 more)
screen-capture          lib/libQt5XcbQpa.so.5          xcb_get_image                       direct      bin/chatapp -> lib/libQt5Gui.so.5 -> lib/libQt5XcbQpa.so.5 (+1 more)
screen-capture          lib/plugins/libscreenshare.so  XShmGetImage                        direct      (not linked from any executable)
screen-change-tracking  lib/plugins/libscreenshare.so  XDamageCreate                       direct      (not linked from any executable)
window-introspection    lib/libQt5XcbQpa.so.5          xcb_query_tree                      direct      bin/chatapp -> lib/libQt5Gui.so.5 -> lib/libQt5XcbQpa.so.5 (+1 more)

Capabilities found:
  selection-read         Reads clipboard or primary-selection contents
  selection-watch        Gets notified whenever any application changes the clipboard
  screen-capture         Reads pixels of the screen or of other windows
  screen-change-tracking Tracks which parts of the screen change
  window-introspection   Enumerates other clients' windows and reads their titles

Library names in objects that import dlopen/dlsym:
  lib/libupdater.so: libXtst.so.6

DT_NEEDED not found in the bundle (left to the system):
  bin/chatapp: libc.so.6
  lib/libQt5XcbQpa.so.5: libxcb.so.1, libxcb-xfixes.so.0
  lib/libupdater.so: libdl.so.2
  lib/plugins/libscreenshare.so: libXext.so.6
```

The clipboard read is credited to `libQt5XcbQpa.so.5`, not the executable. The report also shows the chain that loads it. The `(+1 more)` is the second chain, from the screen-share plugin. In version 1.1 the updater picks up a `"XRecordEnableContext"` string next to its `dlsym` import, plus a ScreenCast portal name, and the Qt platform library starts grabbing the keyboard:

```sh
cargo run -q -- diff demo/chatapp-1.0 demo/chatapp-1.1; echo "exit status: $?"
```

```
Capability diff demo/chatapp-1.0 -> demo/chatapp-1.1

+ input-record  Records keyboard and pointer input of the whole session
    lib/libupdater.so  XRecordEnableContext  indirect
+ keyboard-grab  Grabs the keyboard or individual key combinations globally
    lib/libQt5XcbQpa.so.5  xcb_grab_keyboard  direct
+ portal-screencast  Requests screen capture through xdg-desktop-portal
    lib/libupdater.so  org.freedesktop.portal.ScreenCast  indirect
exit status: 1
```

`--json` output is a single line. Here is one finding from `scan --json demo/chatapp-1.1`, pretty-printed:

```json
{
  "capability": "selection-read",
  "title": "Reads clipboard or primary-selection contents",
  "object": "lib/libQt5XcbQpa.so.5",
  "symbol": "xcb_convert_selection",
  "version": "XCB_1.0",
  "confidence": "direct",
  "reached_via": [
    ["bin/chatapp", "lib/libQt5Gui.so.5", "lib/libQt5XcbQpa.so.5"],
    ["lib/plugins/libscreenshare.so", "lib/libQt5XcbQpa.so.5"]
  ]
}
```

On a real application, point it at the install directory, e.g. `elfcaps scan /opt/zoom` or an extracted `.deb`/AppImage tree.

## Results

This project makes no performance claim and has no benchmark. The correctness claims are backed by the test suite (`cargo test`, 46 tests). Every test builds its ELF files byte by byte with the in-repo writer (`tests/support/writer.rs`), which shares no code with the parser:

| Property | Test file |
|---|---|
| Every written symbol parses back with the same binding, type, definedness and version (needed/defined, hidden bit), for ELF32 LE, ELF64 LE and ELF64 BE, including 300 randomly generated symbol tables | `tests/roundtrip.rs` |
| In main → libA → libB where only libB imports `xcb_convert_selection`, the finding is credited to libB and reached through the chain | `tests/resolution.rs` |
| RUNPATH beats RPATH. RUNPATH is not inherited, RPATH is. A requester's RUNPATH disables inherited RPATH. Mismatched class/machine and paths outside the root are skipped. SONAME reuse works | `tests/resolution.rs` |
| Defined symbols with capability names are never flagged, only undefined imports | `tests/analysis.rs`, `tests/resolution.rs` |
| `dlopen` + the `XConvertSelection` string gives `indirect`, and neither one alone does | `tests/analysis.rs` |
| Dependency cycles (including self-`NEEDED` and unreached cycles) terminate, and each object loads once | `tests/resolution.rs` |
| 10,000 seeded mutations and truncations of valid ELF32/ELF64 files each return `Ok` or a typed error, never a panic, including every possible truncation length and hand-crafted hostile header fields | `tests/robustness.rs` |
| Diff reports exactly the added and removed capabilities, and reports moved or upgraded evidence as a change | `tests/diff.rs`, `tests/cli.rs` |

In a debug build, an out-of-bounds slice index or an integer overflow is a panic, so "never panics" under `catch_unwind` also rules out out-of-bounds reads.

## Design notes

**Credit goes to the importer, not the provider or the executable.** The obvious alternative is to resolve every import to the library that defines it and report "the app uses libxcb". That answers the wrong question, because libxcb is a neutral provider. What matters is which vendored component *calls* it, since that is the code you would ask the vendor about, or delete. Resolving providers would also mean modelling symbol interposition and versioned lookup across the whole global scope, for no gain in what the report says. So findings attach to the object that holds the undefined symbol, and the loader simulation only has to answer "does this object get loaded, and through what?"

**Resolution follows ld.so's actual rules, not a tidy approximation.** Getting RPATH inheritance and RUNPATH non-inheritance right matters for an audit. A tool that treats the executable's RUNPATH as applying to everything would credit a library that ld.so never loads, and it would hide the real one sitting in a different directory. The price is that resolution depends on the load chain, so the same `DT_NEEDED` can resolve differently from two executables. The report keeps every chain that reaches an object, and it keeps the per-object `needed` resolution from the first chain, trying executables before libraries. The indirect pass trades recall for precision on purpose. It needs a `dlopen`/`dlsym` import *and* an exact whole-string match, so it misses names assembled at run time, but it doesn't fire on every error message that happens to mention an X11 function.

## Limitations

- **Symbols come from section headers.** Files whose section headers are stripped (`sstrip`, some packers) parse, but they report no `.dynsym`, `.dynamic` or strings. Falling back to `PT_DYNAMIC` with `DT_HASH`/`DT_GNU_HASH` symbol counting is not implemented.
- **Environment-dependent search paths are not modelled**: `LD_LIBRARY_PATH`, `LD_PRELOAD`, `/etc/ld.so.cache`, `$LIB` and `$PLATFORM` expansion, and relative RPATH entries. Absolute RPATH entries only count if they point inside the root, so a bundle extracted somewhere other than its install prefix may lose those edges. Scan it in place, or pass a `--root` that contains the absolute path.
- **`dlopen` targets are not followed.** Library names found next to `dlopen` are listed, and every ELF file in the tree is scanned anyway, but no load chain is built through `dlopen`.
- **The database covers C-level X11/XCB/XFixes/XRecord/XTest/Composite/Damage/XInput2, PipeWire, libei, and common toolkit clipboard calls.** Wayland protocol requests are inline marshalling functions, not symbols, and mangled C++ toolkit APIs (e.g. `QClipboard`) are not listed. Wayland-native clipboard access is invisible to this tool except through portal strings.
- **XInput2 raw-event selection can't be confirmed statically**, because the event mask is run-time data. `xi2-event-selection` only says that `XISelectEvents` is imported.
- **Strings are matched whole.** A symbol name that the linker tail-merged into a longer string, or built at run time, is not found.
- The test ELF files are synthetic. They follow the specification and are round-tripped through an independent writer, but the suite doesn't include binaries produced by a real toolchain.

## License

MIT. See [LICENSE](LICENSE).
