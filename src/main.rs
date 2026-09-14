use elfcaps::{capdb::CapDb, output, scan};
use std::path::PathBuf;
use std::process::ExitCode;

const USAGE: &str = "\
elfcaps: which privacy-sensitive X11, input and screen APIs Linux binaries can reach

USAGE:
    elfcaps scan <dir-or-binary> [--json] [--root <dir>] [--db <file>]
    elfcaps diff <old> <new> [--json] [--db <file>]
    elfcaps caps [--db <file>]

scan   Report every capability import in a binary or an application directory,
       the bundled object that imports it, and the DT_NEEDED chain that loads it.
       --root sets the directory dependencies are resolved in (default: the
       scanned directory, or the binary's own directory).
diff   Scan two versions of an application and report capabilities that were
       added, removed, or whose evidence changed. Exits 1 when there are changes.
caps   Print the capability database with the rationale for each entry.

Exit status: 0 success, 1 diff found changes, 2 usage or scan error.
";

struct Options {
    positional: Vec<String>,
    json: bool,
    root: Option<PathBuf>,
    db: Option<PathBuf>,
}

fn parse_options(args: &[String]) -> Result<Options, String> {
    let mut opts = Options {
        positional: Vec::new(),
        json: false,
        root: None,
        db: None,
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--json" => opts.json = true,
            "--root" => {
                let value = iter.next().ok_or("--root needs a directory")?;
                opts.root = Some(PathBuf::from(value));
            }
            "--db" => {
                let value = iter.next().ok_or("--db needs a file")?;
                opts.db = Some(PathBuf::from(value));
            }
            flag if flag.starts_with("--") => return Err(format!("unknown option {flag}")),
            _ => opts.positional.push(arg.clone()),
        }
    }
    Ok(opts)
}

fn load_db(opts: &Options) -> Result<CapDb, String> {
    match &opts.db {
        None => Ok(CapDb::builtin()),
        Some(path) => {
            let text =
                std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            CapDb::parse(&text).map_err(|e| format!("{}: {e}", path.display()))
        }
    }
}

fn run(args: &[String]) -> Result<ExitCode, String> {
    let Some(command) = args.first() else {
        return Err("missing command".into());
    };
    let opts = parse_options(&args[1..])?;
    let db = load_db(&opts)?;
    match (command.as_str(), opts.positional.as_slice()) {
        ("scan", [target]) => {
            let report = scan::scan(target.as_ref(), opts.root.as_deref(), &db)
                .map_err(|e| e.to_string())?;
            if opts.json {
                print!("{}", output::report_json(&report));
            } else {
                print!("{}", output::report_text(&report, &db));
            }
            Ok(ExitCode::SUCCESS)
        }
        ("diff", [old, new]) => {
            if opts.root.is_some() {
                return Err("--root is not supported by diff".into());
            }
            let old_report = scan::scan(old.as_ref(), None, &db).map_err(|e| e.to_string())?;
            let new_report = scan::scan(new.as_ref(), None, &db).map_err(|e| e.to_string())?;
            let diff = elfcaps::diff(&old_report, &new_report);
            if opts.json {
                print!("{}", output::diff_json(&diff));
            } else {
                print!("{}", output::diff_text(&diff, old, new));
            }
            Ok(if diff.is_empty() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            })
        }
        ("caps", []) => {
            print!("{}", output::capabilities_text(&db));
            Ok(ExitCode::SUCCESS)
        }
        ("scan" | "diff" | "caps", _) => Err(format!("wrong arguments for {command}")),
        _ => Err(format!("unknown command {command}")),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "-h" || a == "--help") {
        print!("{USAGE}");
        return if args.is_empty() {
            ExitCode::from(2)
        } else {
            ExitCode::SUCCESS
        };
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("elfcaps {}", env!("CARGO_PKG_VERSION"));
        return ExitCode::SUCCESS;
    }
    match run(&args) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("elfcaps: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}
