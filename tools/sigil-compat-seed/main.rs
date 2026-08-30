#![deny(unsafe_code)]

use std::env;
use std::path::Path;

use semver::Version;
use sigil::plugin::store::{PluginStore, RemoteInstall};

fn required_argument(arguments: &mut impl Iterator<Item = String>, name: &str) -> String {
    arguments
        .next()
        .unwrap_or_else(|| panic!("missing {name} argument"))
}

fn main() {
    let mut arguments = env::args().skip(1);
    let data_root = required_argument(&mut arguments, "data-root");
    let archive = required_argument(&mut arguments, "archive");
    let source = required_argument(&mut arguments, "source");
    let plugin = required_argument(&mut arguments, "plugin");
    let version = required_argument(&mut arguments, "version")
        .parse::<Version>()
        .expect("canonical fixture version");
    let release_id = required_argument(&mut arguments, "release-id");
    assert!(arguments.next().is_none(), "unexpected seeder argument");

    let store = PluginStore::new(Path::new(&data_root).join("plugins"));
    store
        .install_remote_inactive(
            Path::new(&archive),
            RemoteInstall {
                source: &source,
                release_id: &release_id,
                plugin: &plugin,
                version: &version,
                verification: "third-party-digest-only",
                tag_target_commit: None,
                official_evidence: None,
            },
        )
        .expect("seed exact remote MySQL conformance package");
}
