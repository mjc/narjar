#[path = "../benches/support/nar_codec_options.rs"]
mod options;

use clap::Parser;
use options::Options;

#[test]
fn fixed_workload_selects_exactly_one_fixture_and_operation() {
    let options = Options::try_parse_from([
        "nar_codec",
        "--bench",
        "--filter",
        "tiny-4096/decode",
        "--iterations",
        "200",
    ])
    .expect("fixed workload options");
    assert!(options.selects("tiny-4096", "decode"));
    assert!(!options.selects("tiny-4096", "encode"));
    assert!(!options.selects("links-4096", "decode"));
    assert_eq!(options.iterations.unwrap().get(), 200);
}

#[test]
fn default_options_run_every_workload_with_adaptive_iterations() {
    let options = Options::try_parse_from(["nar_codec"]).unwrap();
    assert!(options.selects("empty", "decode"));
    assert!(options.selects("native-4096", "collect-sort"));
    assert!(options.iterations.is_none());
}

#[test]
fn a_fixed_iteration_count_cannot_be_zero_or_invalid() {
    for count in ["0", "-1", "no", "4294967296"] {
        assert!(Options::try_parse_from(["nar_codec", "--iterations", count]).is_err());
    }
}
