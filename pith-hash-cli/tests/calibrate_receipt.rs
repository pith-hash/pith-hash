//! The R5-N1 calibrate receipt: `pith calibrate` must reproduce, from
//! the committed dataset (`lab/calibrate-receipt/pairs.csv` + the
//! regenerated BMPs), the exact threshold/receipt lines recorded in
//! `lab/calibrate-receipt/README.md`.
//!
//! - `receipt_dataset_is_reproducible` regenerates the dataset with the
//!   documented fixture recipe and asserts the CSV is byte-identical to
//!   the committed one;
//! - `receipt_output_matches_pinned` runs the real binary against the
//!   committed CSV and diffs both profile runs against the README's
//!   pinned ```receipt blocks.
//!
//! Set `PITH_GEN_RECEIPT=1` to (re)write the committed artifacts from a
//! live run (dataset BMPs land in `lab/calibrate-receipt/dataset/`).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use pith_hash_cli::fixture::{bmp24, patterned_pixels, perturb_pixels};

const SEEDS: [u64; 4] = [0xA1, 0xA2, 0xA3, 0xA4];
const README: &str = include_str!("../../lab/calibrate-receipt/README.md");
const COMMITTED_CSV: &str = include_str!("../../lab/calibrate-receipt/pairs.csv");

/// The receipt blocks pinned in the README, keyed by profile.
fn pinned(profile: &str) -> String {
    let marker = format!("```receipt profile={profile}");
    let start = README
        .find(&marker)
        .unwrap_or_else(|| panic!("README lacks a {marker} block"));
    let rest = &README[start + marker.len()..];
    let end = rest
        .find("```")
        .unwrap_or_else(|| panic!("README {marker} block is unterminated"));
    rest[..end].trim().to_string()
}

/// Regenerates the dataset; writes the files to disk only in GEN mode.
fn dataset(write_out: bool, dir: &Path) -> (Vec<(String, Vec<u8>)>, String) {
    let mut names: Vec<(String, Vec<u8>)> = Vec::new();
    for (i, &seed) in SEEDS.iter().enumerate() {
        let base = patterned_pixels(seed, 48, 40);
        for variant in 0..4u64 {
            let px = if variant == 0 {
                base.clone()
            } else if variant == 3 {
                // Heavy edit: still the same picture (label 1) but far
                // enough from the base to overlap the cross-base
                // distance range, forcing a real threshold trade-off.
                perturb_pixels(&base, seed ^ (variant << 8), 24, 17)
            } else {
                perturb_pixels(&base, seed ^ (variant << 8), 4, 997 + variant)
            };
            names.push((format!("b{}_v{}.bmp", i + 1, variant), bmp24(48, 40, &px)));
        }
    }
    if write_out {
        std::fs::create_dir_all(dir).expect("dataset dir");
        for (name, bytes) in &names {
            std::fs::write(dir.join(name), bytes).expect("write bmp");
        }
    }
    let mut rows: Vec<(String, String, u8)> = Vec::new();
    for (i, _) in SEEDS.iter().enumerate() {
        let b = format!("b{}_v0.bmp", i + 1);
        rows.push((b.clone(), format!("b{}_v1.bmp", i + 1), 1));
        rows.push((b.clone(), format!("b{}_v2.bmp", i + 1), 1));
        rows.push((
            format!("b{}_v1.bmp", i + 1),
            format!("b{}_v2.bmp", i + 1),
            1,
        ));
        rows.push((b, format!("b{}_v3.bmp", i + 1), 1));
    }
    for i in 0..SEEDS.len() {
        for j in (i + 1)..SEEDS.len() {
            rows.push((
                format!("b{}_v0.bmp", i + 1),
                format!("b{}_v0.bmp", j + 1),
                0,
            ));
        }
    }
    let mut csv = String::new();
    csv.push_str("# pith calibrate receipt dataset (R5-N1), image lane, 48x40 BMP\n");
    csv.push_str("# recipe: fixture::patterned_pixels(seed, 48, 40), seeds b1..b4 = 0xA1..0xA4;\n");
    csv.push_str("#   v1 = perturb_pixels(base, seed ^ 0x100, 4, 998)\n");
    csv.push_str("#   v2 = perturb_pixels(base, seed ^ 0x200, 4, 999)\n");
    csv.push_str(
        "#   v3 = perturb_pixels(base, seed ^ 0x300, 24, 17)  (heavy edit, still label 1)\n",
    );
    csv.push_str("# 16 positive pairs (v0/v1, v0/v2, v1/v2, v0/v3 per base), then 6 negatives\n");
    csv.push_str("# (cross-base v0 pairs). paths are relative to the CSV's directory.\n");
    for (a, b, label) in &rows {
        let _ = writeln!(csv, "dataset/{a},dataset/{b},{label}");
    }
    (names, csv)
}

fn run_calibrate(csv: &Path, profile: &str) -> String {
    let out = Command::new(env!("CARGO_BIN_EXE_pith"))
        .args(["calibrate", "--profile", profile])
        .arg("pairs.csv")
        .current_dir(csv.parent().expect("csv has a parent"))
        .output()
        .expect("spawn pith");
    assert!(
        out.status.success(),
        "{profile}: {:?}\n{}",
        out.status,
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

#[test]
fn receipt_dataset_is_reproducible() {
    let write_out = std::env::var("PITH_GEN_RECEIPT").is_ok();
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../lab/calibrate-receipt");
    let (_, csv) = dataset(write_out, &root.join("dataset"));
    if write_out {
        std::fs::write(root.join("pairs.csv"), &csv).expect("write committed csv");
    }
    assert_eq!(
        csv, COMMITTED_CSV,
        "dataset recipe drifted from the committed pairs.csv"
    );
}

#[test]
fn receipt_output_matches_pinned() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../lab/calibrate-receipt");
    let (names, _) = dataset(false, &root.join("dataset"));
    // The CSV's relative paths resolve against its own directory, so the
    // regenerated BMPs must exist there for the binary run.
    std::fs::create_dir_all(root.join("dataset")).expect("dataset dir");
    for (name, bytes) in &names {
        let p = root.join("dataset").join(name);
        if !p.exists() {
            std::fs::write(&p, bytes).expect("write dataset bmp");
        }
    }
    let csv_path = root.join("pairs.csv");
    for profile in ["dedup", "search"] {
        let live = run_calibrate(&csv_path, profile);
        let want = pinned(profile);
        assert_eq!(
            live, want,
            "profile {profile} diverged from the pinned receipt"
        );
    }
}
