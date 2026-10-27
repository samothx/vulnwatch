use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use chrono::Local;
use clap::{Parser, Subcommand};
use opskit::mail::Mailer;
use opskit::truncate;

use vulnwatch::analyze::{self, Options};
use vulnwatch::config::Config;
use vulnwatch::feeds::{self, Fetcher};
use vulnwatch::inventory::Inventory;
use vulnwatch::state::State;
use vulnwatch::{collect, notify, report, summary};

#[derive(Parser)]
#[command(version, about = "Inventory-based vulnerability digest for a handful of hosts")]
struct Cli {
    #[arg(long, global = true, default_value = "/etc/vulnwatch/config.toml")]
    config: PathBuf,
    /// Override general.state_dir (try things without touching the real state).
    #[arg(long, global = true)]
    state_dir: Option<PathBuf>,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build this host's inventory; upload it (collect.upload_url) or write it (--out / collect.out / inbox).
    Collect {
        #[arg(long)]
        out: Option<PathBuf>,
        /// Print a summary of what was collected.
        #[arg(long)]
        print: bool,
        /// Write/upload nothing.
        #[arg(long)]
        dry_run: bool,
    },
    /// Analyze all inventories in the inbox: report, push, mail.
    Run {
        /// Print the report; push, mail and state are left alone.
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        print: bool,
        #[arg(long)]
        no_llm: bool,
        /// Use cached feeds only (no network; OSV/GitHub lookups skipped).
        #[arg(long)]
        offline: bool,
    },
    /// Feed cache: `update` fetches what is stale, `status` shows ages.
    Feeds {
        #[arg(value_parser = ["update", "status"])]
        action: String,
    },
    /// Inventories in the inbox: `list`, or `show <host>`.
    Inventory {
        #[arg(value_parser = ["list", "show"])]
        action: String,
        host: Option<String>,
    },
    /// Validate config and watch.d.
    Config {
        #[arg(value_parser = ["check"])]
        action: String,
    },
    /// Print a stored report (latest or a stamp like 2026-10-03_0730).
    Show {
        #[arg(default_value = "latest")]
        which: String,
    },
    /// Every stored detail of findings whose fingerprint/title/id contains TEXT (latest report).
    Explain { text: String },
    /// Mail a stored report now (tests [email]).
    Mail {
        #[arg(default_value = "latest")]
        which: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match real_main(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("vulnwatch: {e:#}");
            ExitCode::from(1)
        }
    }
}

fn real_main(cli: Cli) -> Result<ExitCode> {
    let mut cfg = Config::load(&cli.config)?;
    if let Some(d) = cli.state_dir {
        cfg.general.state_dir = d;
    }
    let reports_dir = cfg.general.state_dir.join("reports");
    match cli.cmd {
        Cmd::Collect { out, print, dry_run } => cmd_collect(&cfg, out, print, dry_run),
        Cmd::Run { dry_run, print, no_llm, offline } => cmd_run(&cfg, dry_run, print, no_llm, offline),
        Cmd::Feeds { action } => {
            let f = Fetcher::new(cfg.general.state_dir.join("feeds"), cfg.analyze.feeds_max_age_hours, cfg.analyze.http_timeout_secs, false);
            if action == "update" {
                let mut warn = Vec::new();
                for feed in feeds::ALL {
                    match f.get(feed, &mut warn) {
                        Ok(p) => println!("{:<16} ok  {}", feed.name, p.display()),
                        Err(e) => println!("{:<16} ERR {e:#}", feed.name),
                    }
                }
                for w in warn {
                    println!("warning: {w}");
                }
            }
            for (name, age, size) in f.status() {
                let age = age.map(|a| report::human_age(a.as_secs() as i64 / 60)).unwrap_or_else(|| "not cached".into());
                println!("{name:<16} {age:<14} {:>8.1} MiB", size as f64 / 1048576.0);
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Inventory { action, host } => {
            let mut errors = Vec::new();
            let invs = analyze::load_inbox(&cfg, &mut errors);
            for e in &errors {
                eprintln!("warning: {e}");
            }
            if action == "list" {
                for i in &invs {
                    println!("{}", inventory_line(i));
                }
                return Ok(ExitCode::SUCCESS);
            }
            let h = host.context("inventory show <host>")?;
            let i = invs.iter().find(|i| i.host == h).with_context(|| format!("no inventory for {h}"))?;
            print_inventory(i);
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Config { .. } => {
            println!("config OK: {} ({} host(s), {} watch entr(ies))", cfg.path.display(), cfg.hosts.len(), cfg.watch.len());
            println!("this host: {}", cfg.host_name());
            for w in &cfg.watch {
                let how = if w.image.is_empty() { format!("cmd {:?}", w.version_cmd) } else { format!("image {}", w.image) };
                let osv = w.osv.as_ref().map(|o| format!("{}:{}", o.ecosystem, o.name)).unwrap_or_else(|| "-".into());
                println!("  watch {:<14} {how:<40} osv {osv:<36} github {}", w.name, if w.github.is_empty() { "-" } else { &w.github });
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Show { which } => {
            let r = report::load(&reports_dir, &which)?;
            print!("{}", report::markdown(&r, cfg.analyze.report_max_items));
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Explain { text } => {
            let r = report::load(&reports_dir, "latest")?;
            let mut n = 0;
            for f in &r.findings {
                let hit = f.fingerprint.contains(&text) || f.title.contains(&text) || f.vulns.iter().any(|v| v.id == text || v.aliases.contains(&text));
                if hit {
                    n += 1;
                    println!("{}", serde_json::to_string_pretty(f)?);
                }
            }
            if n == 0 {
                bail!("nothing in the latest report matches '{text}'");
            }
            Ok(ExitCode::SUCCESS)
        }
        Cmd::Mail { which } => {
            let r = report::load(&reports_dir, &which)?;
            let md = report::markdown(&r, cfg.analyze.report_max_items);
            let m = mailer(&cfg);
            m.send(&m.build_message(&notify::mail_subject(&r, 0), "Sent by hand (vulnwatch mail).", &md))?;
            println!("mailed {} to {}", which, cfg.email.to.join(", "));
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn cmd_collect(cfg: &Config, out: Option<PathBuf>, print: bool, dry_run: bool) -> Result<ExitCode> {
    let inv = collect::collect(cfg);
    if print || dry_run {
        println!("{}", inventory_line(&inv));
        for e in &inv.errors {
            println!("  problem: {e}");
        }
    }
    if dry_run {
        return Ok(ExitCode::SUCCESS);
    }
    if let Some(p) = out {
        inv.write(&p)?;
        println!("wrote {}", p.display());
    } else if !cfg.collect.upload_url.is_empty() {
        let url = collect::upload::upload(&cfg.collect, &inv.host, &inv.to_gz()?)?;
        println!("uploaded to {url}");
    } else {
        let p = if cfg.collect.out.as_os_str().is_empty() {
            cfg.state_path(&cfg.analyze.inbox).join(format!("{}.json.gz", inv.host))
        } else {
            cfg.resolve(&cfg.collect.out)
        };
        inv.write(&p)?;
        println!("wrote {}", p.display());
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_run(cfg: &Config, dry_run: bool, print: bool, no_llm: bool, offline: bool) -> Result<ExitCode> {
    let state_dir = cfg.general.state_dir.clone();
    let mut state = State::load(&state_dir)?;
    let mut rep = analyze::run(cfg, &Options { offline }, &mut state)?;

    if cfg.llm.enabled && !no_llm && !rep.findings.is_empty() {
        match summary::summarize(cfg, &rep) {
            Ok((s, dropped)) => {
                rep.summary = Some(s);
                rep.notes.extend(dropped);
            }
            Err(e) => rep.errors.push(format!("llm summary: {e:#}")),
        }
    }
    let md = report::markdown(&rep, cfg.analyze.report_max_items);
    let now = Local::now().timestamp();
    let alerts: Vec<String> = notify::select_alerts(&rep, cfg.notify.min_severity).iter().map(|f| f.fingerprint.clone()).collect();
    let mails: Vec<String> = notify::select_mail(&rep, cfg.email.min_severity).iter().map(|f| f.fingerprint.clone()).collect();
    let want_mail = cfg.email.enabled && (!mails.is_empty() || (cfg.email.on_errors && !rep.errors.is_empty()));

    if dry_run {
        if print {
            print!("{md}");
        }
        for f in notify::select_alerts(&rep, cfg.notify.min_severity) {
            eprintln!("  would push: {} {}: {} ({} new)", f.severity, f.host, truncate(&f.title, 160), f.new_count);
        }
        if want_mail {
            eprintln!("  would email to {}: {} finding(s) with new items, {} error(s)", cfg.email.to.join(", "), mails.len(), rep.errors.len());
        }
        return Ok(ExitCode::SUCCESS);
    }

    let path = report::store(&state_dir.join("reports"), &rep, &md, cfg.general.report_retention_days)?;
    let path_s = path.display().to_string();
    if print {
        print!("{md}");
    }
    let mut mailed_to = None;
    if want_mail {
        let intro = format!(
            "{} finding(s) with new items ≥ {}{}. Full report: {path_s}",
            mails.len(),
            cfg.email.min_severity,
            if rep.errors.is_empty() { String::new() } else { format!(", {} error(s)", rep.errors.len()) }
        );
        let m = mailer(cfg);
        match m.send(&m.build_message(&notify::mail_subject(&rep, mails.len()), &intro, &md)) {
            Ok(()) => {
                state.mark_emailed(&mails, now);
                mailed_to = Some(cfg.email.to.join(", "));
            }
            Err(e) => rep.errors.push(format!("mail: {e:#}")),
        }
    }
    if cfg.notify.enabled {
        let alert_refs = notify::select_alerts(&rep, cfg.notify.min_severity);
        if !alert_refs.is_empty() {
            match opskit::notify::emit(&cfg.notify.command, &notify::alert_message(&alert_refs, &path_s)) {
                Ok(()) => state.mark_alerted(&alerts, now),
                Err(e) => eprintln!("push failed: {e:#}"),
            }
        }
        if cfg.notify.digest
            && let Err(e) = opskit::notify::emit(&cfg.notify.command, &notify::digest_message(&rep, &path_s, mailed_to.as_deref()))
        {
            eprintln!("digest push failed: {e:#}");
        }
        if !rep.errors.is_empty() {
            let msg = rep.errors.iter().map(|e| format!("• {}", truncate(e, 300))).collect::<Vec<_>>().join("\n");
            let _ = opskit::notify::emit(&cfg.notify.command, &notify::error_message(&msg));
        }
    }
    state.save(&state_dir)?;
    eprintln!(
        "vulnwatch: {} finding(s), {} new vulnerabilities, {} resolved, {} error(s) → {path_s}",
        rep.findings.len(),
        rep.new_vulns(),
        rep.resolved.len(),
        rep.errors.len()
    );
    for e in &rep.errors {
        eprintln!("  error: {e}");
    }
    Ok(ExitCode::SUCCESS)
}

fn mailer(cfg: &Config) -> Mailer {
    Mailer { app: "vulnwatch".into(), from: cfg.email.from.clone(), to: cfg.email.to.clone(), sendmail: cfg.email.sendmail.clone(), html: cfg.email.html }
}

fn inventory_line(i: &Inventory) -> String {
    let at = i.collected_at.map(|t| t.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "?".into());
    format!(
        "{:<10} {at}  {} · {} {} pkgs · {} images ({} with SBOM) · {} lockfiles ({} deps) · {} watched · {} problem(s)",
        i.host,
        if i.os.pretty_name.is_empty() { &i.os.id } else { &i.os.pretty_name },
        i.packages.len(),
        if i.pkg_manager.is_empty() { "no" } else { &i.pkg_manager },
        i.images.len(),
        i.images.iter().filter(|x| x.sbom.is_some()).count(),
        i.lockfiles.len(),
        i.lockfiles.iter().map(|l| l.packages.len()).sum::<usize>(),
        i.watched.len(),
        i.errors.len()
    )
}

fn print_inventory(i: &Inventory) {
    println!("{}", inventory_line(i));
    println!("kernel {}", i.kernel);
    for img in &i.images {
        let comps = img.sbom.as_ref().and_then(|s| s["components"].as_array()).map(|a| a.len()).unwrap_or(0);
        println!("  image    {:<55} {comps:>5} components  containers: {}", img.reference, img.containers.join(", "));
    }
    for l in &i.lockfiles {
        println!("  lockfile {:<55} {:>5} {} deps", l.path, l.packages.len(), l.ecosystem);
    }
    for w in &i.watched {
        println!("  watched  {:<20} {:<14} ({})", w.name, w.version, w.found_by);
    }
    for e in &i.errors {
        println!("  problem  {e}");
    }
}
