//! Process-level tests of the `pith` binary: every subcommand, the
//! `--json` shapes, the exit-code contract (0 answer · 1 refusal or
//! non-match · 2 usage/io) and the error paths of the argument
//! parser, driven through real fixture files in a temp directory.
//!
//! The library-level behavior is covered by `cli.rs`; this file exists
//! because the thin argument-parsing layer (`src/main.rs`) is part of
//! the shipped surface and its refusals are observable behavior.

use std::path::{Path, PathBuf};
use std::process::Command;

use pith_hash_cli::fixture;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_pith"))
}

/// A private directory with deterministic fixtures written once per test.
struct Sandbox {
    dir: TempDir,
}

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("pith-cli-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp dir");
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, bytes).expect("write fixture");
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn bmp(name_seed: u64, w: u32, h: u32) -> Vec<u8> {
    fixture::bmp24(w, h, &fixture::patterned_pixels(name_seed, w, h))
}

// ---------------------------------------------------------------- help

#[test]
fn help_and_version_answer_zero() {
    for args in [vec!["--help"], vec!["-h"], vec!["help"], vec![]] {
        let out = bin().args(&args).output().expect("spawn");
        assert!(out.status.success(), "{args:?}: {:?}", out.status);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("usage: pith"), "{args:?}: {text}");
        assert!(text.contains("describe"), "{args:?}: {text}");
    }
    let out = bin().arg("--version").output().expect("spawn");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.starts_with("pith "), "{text}");
}

#[test]
fn unknown_command_and_flag_are_usage_errors() {
    let out = bin().arg("teleport").output().expect("spawn");
    assert_eq!(out.status.code(), Some(2));
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("unknown command `teleport`"), "{text}");

    let out = bin().args(["describe", "--nope"]).output().expect("spawn");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unknown flag"));

    let out = bin()
        .args(["dedup", "--threshold"])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("--threshold needs a value"));
}

// ------------------------------------------------------------ describe

#[test]
fn describe_reports_all_modality_shapes() {
    let sb = Sandbox {
        dir: TempDir::new("describe"),
    };
    let bmp = sb.dir.write("a.bmp", &bmp(0xC1, 48, 40));
    let wav = sb
        .dir
        .write("a.wav", &fixture::wav16(44_100, &fixture::tone(0xC2, 0.3)));
    let txt = sb.dir.write("a.txt", fixture::prose(0xC3, 2048).as_bytes());
    let binf = sb
        .dir
        .write("a.bin", &fixture::binary_blob(0xC4, 48 * 1024));
    let mp4 = sb
        .dir
        .write("a.mp4", include_bytes!("../../tests/fixtures/a_64x48.mp4"));

    for (path, modality) in [
        (&bmp, "image"),
        (&wav, "audio"),
        (&txt, "text"),
        (&binf, "binary"),
        (&mp4, "video"),
    ] {
        let out = bin().arg("describe").arg(path).output().expect("spawn");
        assert!(out.status.success(), "{path:?}: {out:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains(&format!("modality: {modality}")), "{text}");
        for tier in ["tier1:", "tier2:", "tier3:"] {
            assert!(text.contains(tier), "{modality}: missing {tier}\n{text}");
        }
    }
}

#[test]
fn describe_json_and_per_command_help() {
    let sb = Sandbox {
        dir: TempDir::new("describe-json"),
    };
    let png = sb.dir.write("a.bmp", &bmp(0xC1, 48, 40));
    let out = bin()
        .args(["describe", "--json"])
        .arg(&png)
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("\"format\": \"bmp\""), "{text}");
    assert!(text.contains("\"tier2\": \"phash:"), "{text}");
    assert!(text.contains("\"facts\""), "{text}");

    for cmd in ["describe", "hash", "match", "dedup", "bench", "calibrate"] {
        let out = bin().args([cmd, "--help"]).output().expect("spawn");
        assert!(out.status.success(), "{cmd}: {out:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains(&format!("usage: pith {cmd}")),
            "{cmd}: {text}"
        );
    }
}

#[test]
fn describe_refusals_exit_by_contract() {
    let sb = Sandbox {
        dir: TempDir::new("refuse"),
    };
    // Missing file → usage/io (2).
    let out = bin()
        .args([
            "describe",
            sb.dir.path().join("missing.bin").to_str().unwrap(),
        ])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));

    // A gutted mp4 is a pipeline refusal (1), with the modality named.
    let mut mp4 = vec![0, 0, 0, 0x20];
    mp4.extend_from_slice(b"ftypisom");
    mp4.extend_from_slice(&[0; 24]);
    let bad = sb.dir.write("bad.mp4", &mp4);
    let out = bin().arg("describe").arg(&bad).output().expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("video:"),
        "stderr names the modality"
    );

    // A corrupt WAV at the wrong rate refuses through the audio lane.
    let bad_wav = sb
        .dir
        .write("bad.wav", &fixture::wav16(22_050, &[0i16; 4096]));
    let out = bin().arg("describe").arg(&bad_wav).output().expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("audio:"));
}

// ---------------------------------------------------------------- hash

#[test]
fn hash_matches_describe_tier1_and_json() {
    let sb = Sandbox {
        dir: TempDir::new("hash"),
    };
    let wav = sb
        .dir
        .write("t.wav", &fixture::wav16(44_100, &fixture::tone(0xC2, 0.3)));

    let out = bin().arg("hash").arg(&wav).output().expect("spawn");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert_eq!(text.trim().len(), 64, "{text}");

    let out = bin()
        .args(["hash", "--json"])
        .arg(&wav)
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"tier1\""), "{json}");

    // Refusal: corrupt container exits 1 with the modality named.
    let bad = sb.dir.write("bad.flac", b"fLaC");
    let out = bin().arg("hash").arg(&bad).output().expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("audio:"));
}

// --------------------------------------------------------------- match

#[test]
fn match_scores_and_exit_codes() {
    let sb = Sandbox {
        dir: TempDir::new("match"),
    };
    let a = sb.dir.write("a.bmp", &bmp(0xA1, 48, 40));
    let a2 = sb.dir.write("a2.bmp", &bmp(0xA1, 48, 40));
    let b = sb.dir.write("b.bmp", &bmp(0xA2, 48, 40));

    // Identical inputs match (0).
    let out = bin()
        .args(["match"])
        .arg(&a)
        .arg(&a2)
        .output()
        .expect("spawn");
    assert!(out.status.success(), "self-match must exit 0");
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("verdict: match"), "{text}");
    assert!(text.contains("hamming=0"), "{text}");
    assert!(text.contains("advisory: hamming <= 10"), "{text}");

    // Distinct bases do not (1), with the distance spelled out.
    let out = bin()
        .args(["match"])
        .arg(&a)
        .arg(&b)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("verdict: no-match"), "{text}");
    assert!(text.contains("distance: "), "{text}");

    // JSON shape carries the same verdict.
    let out = bin()
        .args(["match", "--json"])
        .arg(&a)
        .arg(&a2)
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"matched\": true"), "{json}");
    assert!(json.contains("\"modality\": \"image\""), "{json}");

    // Cross-modality: usage-level refusal (1) with a named error.
    let txt = sb.dir.write("t.txt", fixture::prose(0xC3, 2048).as_bytes());
    let out = bin()
        .args(["match"])
        .arg(&a)
        .arg(&txt)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));

    // Video: mp4 vs its mov remux match.
    let mp4 = sb
        .dir
        .write("a.mp4", include_bytes!("../../tests/fixtures/a_64x48.mp4"));
    let mov = sb
        .dir
        .write("a.mov", include_bytes!("../../tests/fixtures/a_64x48.mov"));
    let out = bin()
        .args(["match", "--json"])
        .arg(&mp4)
        .arg(&mov)
        .output()
        .expect("spawn");
    assert!(out.status.success(), "{out:?}");
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"modality\": \"video\""), "{json}");
    assert!(json.contains("\"matched\": true"), "{json}");
}

// --------------------------------------------------------------- dedup

#[test]
fn dedup_clusters_reports_and_skips() {
    let sb = Sandbox {
        dir: TempDir::new("dedup"),
    };
    sb.dir.write("one.bmp", &bmp(0xB1, 48, 40));
    sb.dir.write("two.bmp", &bmp(0xB1, 48, 40));
    sb.dir.write("three.bmp", &bmp(0xB2, 48, 40));
    // A gutted mp4 lands in skipped, never silently dropped.
    let mut mp4 = vec![0, 0, 0, 0x20];
    mp4.extend_from_slice(b"ftypisom");
    mp4.extend_from_slice(&[0; 24]);
    sb.dir.write("bad.mp4", &mp4);

    let out = bin()
        .arg("dedup")
        .arg(sb.dir.path())
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("group 1 (exact)"), "{text}");
    assert!(text.contains("1 skipped"), "{text}");
    assert!(String::from_utf8_lossy(&out.stderr).contains("skipped:"));

    // --all lists singletons too.
    let out = bin()
        .args(["dedup", "--all"])
        .arg(sb.dir.path())
        .output()
        .expect("spawn");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("single:"));

    // JSON shape.
    let out = bin()
        .args(["dedup", "--json"])
        .arg(sb.dir.path())
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"groups\": ["), "{json}");
    assert!(json.contains("\"skipped\": ["), "{json}");

    // --threshold N replaces the advisory verdict (inclusive bound).
    let sa = pith_hash::signature(&std::fs::read(sb.dir.path().join("one.bmp")).unwrap()).unwrap();
    let sb_sig =
        pith_hash::signature(&std::fs::read(sb.dir.path().join("three.bmp")).unwrap()).unwrap();
    let d = pith_hash_cli::distance(&sa, &sb_sig).unwrap();
    let out = bin()
        .args(["dedup", "--threshold", &d.to_string()])
        .arg(sb.dir.path())
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(
        !text.contains("(exact)"),
        "threshold cluster is perceptual: {text}"
    );
    assert!(text.contains("3 file(s) clustered"), "{text}");

    // Unreadable directory is a usage error (2).
    let out = bin()
        .arg("dedup")
        .arg(sb.dir.path().join("missing-dir"))
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));
}

// --------------------------------------------------------------- bench

#[test]
fn bench_runs_with_one_iteration() {
    let out = bin()
        .args(["bench", "--iters", "1"])
        .output()
        .expect("spawn");
    assert!(out.status.success(), "{out:?}");
    let text = String::from_utf8_lossy(&out.stdout);
    for name in ["image-bmp", "audio-wav", "text", "binary"] {
        assert!(text.contains(name), "{text}");
    }
    assert!(text.contains("release="), "{text}");

    let out = bin()
        .args(["bench", "--iters", "1", "--json"])
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"bench\": ["), "{json}");
    assert!(json.contains("\"mb_per_s\""), "{json}");
}

// ----------------------------------------------------------- calibrate

#[test]
fn calibrate_reports_receipts_and_refuses() {
    let sb = Sandbox {
        dir: TempDir::new("calibrate"),
    };
    // Two near-identical pairs (label 1) and one distinct pair (label 0).
    let a1 = sb.dir.write("a1.bmp", &bmp(0xA1, 48, 40));
    let a2 = sb.dir.write("a2.bmp", &bmp(0xA1, 48, 40));
    let b1 = sb.dir.write("b1.bmp", &bmp(0xA2, 48, 40));
    let b2 = sb.dir.write("b2.bmp", &bmp(0xA2, 48, 40));
    let c1 = sb.dir.write("c1.bmp", &bmp(0xA3, 48, 40));
    let c2 = sb.dir.write("c2.bmp", &bmp(0xA4, 48, 40));
    let csv = sb.dir.write(
        "pairs.csv",
        format!(
            "# receipt dataset\n{},{},1\n{},{},1\n{},{},0\n",
            a1.display(),
            a2.display(),
            b1.display(),
            b2.display(),
            c1.display(),
            c2.display()
        )
        .as_bytes(),
    );

    for profile in ["dedup", "search"] {
        let out = bin()
            .args(["calibrate", "--profile", profile])
            .arg(&csv)
            .output()
            .expect("spawn");
        assert!(out.status.success(), "{profile}: {out:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("threshold:"), "{text}");
        assert!(text.contains("# receipt: measured on"), "{text}");
        assert!(text.contains("counts: tp="), "{text}");
    }

    let out = bin()
        .args(["calibrate", "--profile", "dedup", "--json"])
        .arg(&csv)
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"threshold\":"), "{json}");
    assert!(json.contains("\"profile\": \"Dedup\""), "{json}");

    // Refusals: unknown profile (2), unreadable file (2), bad label (2),
    // wrong cell count (2), modality mismatch (2).
    let out = bin()
        .args(["calibrate", "--profile", "greedy"])
        .arg(&csv)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));

    let out = bin()
        .args(["calibrate", "--profile", "dedup"])
        .arg(sb.dir.path().join("missing.csv"))
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));

    let bad = sb.dir.write("bad.csv", b"a1.bmp,b2.bmp,maybe\n");
    let out = bin()
        .args(["calibrate", "--profile", "dedup"])
        .arg(&bad)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("bad label"));

    let short = sb.dir.write("short.csv", b"a1.bmp,b2.bmp\n");
    let out = bin()
        .args(["calibrate", "--profile", "dedup"])
        .arg(&short)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("expected 3 cells"));

    // Paths that cannot be read are usage errors.
    let unreadable = sb.dir.write("missing-path.csv", b"nope1.bmp,nope2.bmp,1\n");
    let out = bin()
        .args(["calibrate", "--profile", "dedup"])
        .arg(&unreadable)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));

    // Mixed modalities in one set: each line internally consistent, but
    // the set mixes lanes — one-modality-per-dataset refusal (2).
    let t1 = sb
        .dir
        .write("t1.txt", fixture::prose(0xC5, 2048).as_bytes());
    let t2 = sb
        .dir
        .write("t2.txt", fixture::prose(0xC5, 2048).as_bytes());
    let mixed = sb.dir.write(
        "mixed.csv",
        format!(
            "{},{},1\n{},{},0\n",
            a1.display(),
            a2.display(),
            t1.display(),
            t2.display()
        )
        .as_bytes(),
    );
    let out = bin()
        .args(["calibrate", "--profile", "dedup"])
        .arg(&mixed)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("one modality per dataset"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );

    // Empty dataset: calibrate refuses with the named error (1).
    let empty = sb.dir.write("empty.csv", b"# nothing here\n");
    let out = bin()
        .args(["calibrate", "--profile", "dedup"])
        .arg(&empty)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("calibration pairs"),
        "{:?}",
        String::from_utf8_lossy(&out.stderr)
    );
}

// ------------------------------------------------- help pos-arg lanes

#[test]
fn help_pos_arg_works_for_every_command() {
    for cmd in ["describe", "hash", "match", "dedup", "bench", "calibrate"] {
        let out = bin().args([cmd, "help"]).output().expect("spawn");
        assert!(out.status.success(), "{cmd} help: {out:?}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains(&format!("usage: pith {cmd}")),
            "{cmd}: {text}"
        );
    }
}

// --------------------------------------------- describe json variants

#[test]
fn describe_json_covers_audio_text_binary_video() {
    let sb = Sandbox {
        dir: TempDir::new("describe-json-mods"),
    };
    let wav = sb
        .dir
        .write("a.wav", &fixture::wav16(44_100, &fixture::tone(0xC2, 0.3)));
    let txt = sb.dir.write("a.txt", fixture::prose(0xC3, 2048).as_bytes());
    let binf = sb
        .dir
        .write("a.bin", &fixture::binary_blob(0xC4, 48 * 1024));
    let mp4 = sb
        .dir
        .write("a.mp4", include_bytes!("../../tests/fixtures/a_64x48.mp4"));

    let out = bin()
        .args(["describe", "--json"])
        .arg(&wav)
        .output()
        .expect("spawn");
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"tier2\": \"audio-peaks:"), "{json}");
    assert!(json.contains("\"sample_rate\": 44100"), "{json}");
    assert!(json.contains("\"tier3\": \"dtw\""), "{json}");

    let out = bin()
        .args(["describe", "--json"])
        .arg(&txt)
        .output()
        .expect("spawn");
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"tier2\": \"minhash:"), "{json}");
    assert!(json.contains("\"words\":"), "{json}");
    assert!(json.contains("\"tier3\": null"), "{json}");

    let out = bin()
        .args(["describe", "--json"])
        .arg(&binf)
        .output()
        .expect("spawn");
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"tier2\": \"fastcdc:"), "{json}");
    assert!(json.contains("\"chunks\":"), "{json}");

    let out = bin()
        .args(["describe", "--json"])
        .arg(&mp4)
        .output()
        .expect("spawn");
    let json = String::from_utf8_lossy(&out.stdout);
    assert!(json.contains("\"tier2\": \"video:"), "{json}");
    assert!(json.contains("\"duration_s\""), "{json}");
    assert!(json.contains("\"frames_sampled\""), "{json}");
}

// ------------------------------------------------- hash / match edges

#[test]
fn hash_missing_file_is_usage_error() {
    let out = bin()
        .args(["hash", "/definitely/not/here.bin"])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn match_missing_input_and_signature_refusal() {
    let sb = Sandbox {
        dir: TempDir::new("match-edges"),
    };
    let good = sb.dir.write("a.bmp", &bmp(0xA1, 48, 40));
    // One missing side: usage (2) before any signing.
    let out = bin()
        .args(["match"])
        .arg(&good)
        .arg(sb.dir.path().join("missing.bmp"))
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(2));

    // A gutted mp4 signs only far enough to refuse (1), named video.
    let mut mp4 = vec![0, 0, 0, 0x20];
    mp4.extend_from_slice(b"ftypisom");
    mp4.extend_from_slice(&[0; 24]);
    let bad = sb.dir.write("bad.mp4", &mp4);
    let out = bin()
        .args(["match"])
        .arg(&good)
        .arg(&bad)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("video:"));
}

// ------------------------------------------------------- dedup shapes

#[test]
fn dedup_json_lists_many_singles_and_skips() {
    let sb = Sandbox {
        dir: TempDir::new("dedup-json2"),
    };
    sb.dir.write("one.bmp", &bmp(0xB1, 48, 40));
    sb.dir.write("two.bmp", &bmp(0xB1, 48, 40));
    sb.dir.write("s1.bmp", &bmp(0xB2, 48, 40));
    sb.dir.write("s2.bmp", &bmp(0xB3, 48, 40));
    for i in 0..2 {
        let mut mp4 = vec![0, 0, 0, 0x20];
        mp4.extend_from_slice(b"ftypisom");
        mp4.extend_from_slice(&[0; 24]);
        sb.dir.write(&format!("bad{i}.mp4"), &mp4);
    }
    let out = bin()
        .args(["dedup", "--json"])
        .arg(sb.dir.path())
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let json = String::from_utf8_lossy(&out.stdout);
    // Two singles and two skips: the multi-element loops both run.
    assert_eq!(json.matches("bad").count(), 2, "{json}");
    assert!(json.contains("\"exact\": true"), "{json}");
    let singles = json.match_indices("s1").count() + json.match_indices("s2").count();
    assert_eq!(singles, 2, "{json}");
}

// ------------------------------------------------- calibrate variants

#[test]
fn calibrate_accepts_label_word_variants() {
    let sb = Sandbox {
        dir: TempDir::new("calibrate-labels"),
    };
    let a1 = sb.dir.write("a1.bmp", &bmp(0xA1, 48, 40));
    let a2 = sb.dir.write("a2.bmp", &bmp(0xA1, 48, 40));
    let b1 = sb.dir.write("b1.bmp", &bmp(0xA2, 48, 40));
    let b2 = sb.dir.write("b2.bmp", &bmp(0xA2, 48, 40));
    let csv = sb.dir.write(
        "pairs.csv",
        format!(
            "{},{},true\n{},{},yes\n{},{},false\n{},{},no\n",
            a1.display(),
            a2.display(),
            b1.display(),
            b2.display(),
            a1.display(),
            b1.display(),
            a2.display(),
            b2.display()
        )
        .as_bytes(),
    );
    let out = bin()
        .args(["calibrate", "--profile", "dedup"])
        .arg(&csv)
        .output()
        .expect("spawn");
    assert!(out.status.success(), "{out:?}");
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("counts: tp=2"),
        "{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn calibrate_signature_refusal_is_terminal() {
    let sb = Sandbox {
        dir: TempDir::new("calibrate-refuse"),
    };
    let good = sb.dir.write("a.bmp", &bmp(0xA1, 48, 40));
    let mut mp4 = vec![0, 0, 0, 0x20];
    mp4.extend_from_slice(b"ftypisom");
    mp4.extend_from_slice(&[0; 24]);
    let bad = sb.dir.write("bad.mp4", &mp4);
    let csv = sb.dir.write(
        "pairs.csv",
        format!("{},{},1\n", good.display(), bad.display()).as_bytes(),
    );
    let out = bin()
        .args(["calibrate", "--profile", "dedup"])
        .arg(&csv)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("video:"));
}

// ------------------------------------------- argument-parser refusals

#[test]
fn bare_and_misflagged_invocations_are_usage_errors() {
    let cases: &[&[&str]] = &[
        &["describe"],
        &["hash"],
        &["hash", "--nope"],
        &["match"],
        &["match", "only-one"],
        &["match", "--nope", "a", "b"],
        &["dedup"],
        &["bench", "--nope"],
        &["calibrate"],
        &["calibrate", "--nope"],
    ];
    for args in cases {
        let out = bin().args(*args).output().expect("spawn");
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(
            !String::from_utf8_lossy(&out.stderr).is_empty(),
            "{args:?} must explain on stderr"
        );
    }
}

#[test]
fn dedup_ignores_non_file_entries() {
    let sb = Sandbox {
        dir: TempDir::new("dedup-subdir"),
    };
    sb.dir.write("one.bmp", &bmp(0xB1, 48, 40));
    std::fs::create_dir(sb.dir.path().join("subdir")).expect("subdir");
    let out = bin()
        .arg("dedup")
        .arg(sb.dir.path())
        .output()
        .expect("spawn");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("1 single(s)"), "{text}");
}

#[test]
fn calibrate_refuses_on_either_side_of_a_pair() {
    let sb = Sandbox {
        dir: TempDir::new("calibrate-refuse2"),
    };
    let good = sb.dir.write("a.bmp", &bmp(0xA1, 48, 40));
    let mut mp4 = vec![0, 0, 0, 0x20];
    mp4.extend_from_slice(b"ftypisom");
    mp4.extend_from_slice(&[0; 24]);
    let bad = sb.dir.write("bad.mp4", &mp4);
    // Refusal on the FIRST element of the pair.
    let csv = sb.dir.write(
        "p1.csv",
        format!("{},{},1\n", bad.display(), good.display()).as_bytes(),
    );
    let out = bin()
        .args(["calibrate", "--profile", "dedup"])
        .arg(&csv)
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(1));
}
