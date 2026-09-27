use bomdelta::diff::{self, Severity};
use bomdelta::report::Report;
use bomdelta::sbom::{self, Sbom};
use std::process::ExitCode;

const USAGE: &str = "\
usage: bomdelta [--format terminal|json|markdown] [--fail-on high|medium|low|info|none] BEFORE AFTER

  BEFORE, AFTER   CycloneDX JSON SBOMs (spec 1.2 to 1.6)
  --format        output format (default: terminal)
  --fail-on       exit 1 if any change is at or above this severity (default: high)

exit codes: 0 nothing at or above --fail-on, 1 at least one change is, 2 usage or input error";

enum Format {
    Terminal,
    Json,
    Markdown,
}

fn main() -> ExitCode {
    match run(std::env::args().skip(1).collect()) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("bomdelta: {message}\n\n{USAGE}");
            ExitCode::from(2)
        }
    }
}

fn run(args: Vec<String>) -> Result<ExitCode, String> {
    let mut format = Format::Terminal;
    let mut fail_on = Some(Severity::High);
    let mut paths = Vec::new();

    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let (flag, inline) = match arg.split_once('=') {
            Some((f, v)) if f.starts_with("--") => (f.to_string(), Some(v.to_string())),
            _ => (arg.clone(), None),
        };
        let mut value = |name: &str| {
            inline
                .clone()
                .or_else(|| args.next())
                .ok_or(format!("{name} needs a value"))
        };
        match flag.as_str() {
            "-h" | "--help" => {
                println!("{USAGE}");
                return Ok(ExitCode::SUCCESS);
            }
            "-V" | "--version" => {
                println!("bomdelta {}", env!("CARGO_PKG_VERSION"));
                return Ok(ExitCode::SUCCESS);
            }
            "--format" => {
                format = match value("--format")?.as_str() {
                    "terminal" => Format::Terminal,
                    "json" => Format::Json,
                    "markdown" => Format::Markdown,
                    other => return Err(format!("unknown --format {other:?}")),
                }
            }
            "--fail-on" => {
                let v = value("--fail-on")?;
                fail_on = if v == "none" {
                    None
                } else {
                    Some(Severity::parse(&v).ok_or(format!("unknown --fail-on {v:?}"))?)
                };
            }
            f if f.starts_with('-') && f.len() > 1 => return Err(format!("unknown option {f}")),
            _ => paths.push(arg),
        }
    }

    let [before_path, after_path] = <[String; 2]>::try_from(paths)
        .map_err(|p| format!("expected exactly two SBOM files, got {}", p.len()))?;
    let before = load(&before_path)?;
    let after = load(&after_path)?;

    let findings = diff::diff(&before, &after);
    let report = Report {
        before: &before,
        after: &after,
        findings: &findings,
        fail_on,
    };
    print!(
        "{}",
        match format {
            Format::Terminal => report.terminal(),
            Format::Json => report.json(),
            Format::Markdown => report.markdown(),
        }
    );
    Ok(if report.failing() > 0 {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    })
}

fn load(path: &str) -> Result<Sbom, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    sbom::parse(&text).map_err(|e| format!("{path}: {e}"))
}
