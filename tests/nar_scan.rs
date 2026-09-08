use std::{fs, process::Command};

fn string(value: &[u8]) -> Vec<u8> {
    let mut output = (value.len() as u64).to_le_bytes().to_vec();
    output.extend_from_slice(value);
    output.resize(output.len() + (8 - output.len() % 8) % 8, 0);
    output
}

#[test]
fn scanner_emits_streaming_object_offsets_and_nar_digest() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let nar = directory.path().join("sample.nar");
    let list = directory.path().join("inputs.txt");
    let scan = directory.path().join("scan.tsv");
    let content = b"hello";
    let node = [
        string(b"("),
        string(b"type"),
        string(b"regular"),
        string(b"contents"),
        string(content),
        string(b")"),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let bytes = [string(b"nix-archive-1"), node]
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    fs::write(&nar, &bytes).expect("write NAR");
    fs::write(&list, format!("{}\n", nar.display())).expect("write input list");

    let status = Command::new(env!("CARGO_BIN_EXE_nar-scan"))
        .args(["--input-list"])
        .arg(&list)
        .args(["--output"])
        .arg(&scan)
        .status()
        .expect("run scanner");
    assert!(status.success());
    let output = fs::read_to_string(scan).expect("read scan");
    assert!(output.contains("\tfile\t5\t"), "{output}");
    assert!(output.contains("\tregular\t0\t1\t0\n"), "{output}");
}
