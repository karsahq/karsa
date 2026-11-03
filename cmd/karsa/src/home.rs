//! Where a node keeps its files.
//!
//! One directory holds the two files that describe a chain membership and one that
//! holds the data:
//!
//! ```text
//! <home>/
//!   node.toml      what this operator decided locally
//!   genesis.json   what every node of this chain must agree on
//!   data/          the store
//! ```
//!
//! Keeping `node.toml` next to `genesis.json` is deliberate: they are read
//! together, one is meaningless without the other, and a node pointed at the wrong
//! genesis is not a node of this chain at all. A single `--home` therefore replaces
//! two path flags, and the commands that need both cannot be given one without the
//! other.
//!
//! Missing files are written with defaults on first use, so a fresh machine starts
//! rather than complaining. The genesis template it writes is explicitly a template:
//! it carries placeholder keys and says so.

use std::error::Error;
use std::path::{Path, PathBuf};

/// The directory a node runs from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Home {
    dir: PathBuf,
}

/// The files a home holds.
impl Home {
    /// Resolves the home directory: the explicit one, else `$HOME/.karsa`, else
    /// `./.karsa`.
    ///
    /// # Errors
    ///
    /// Returns an error when the directory cannot be created.
    pub fn resolve(explicit: Option<PathBuf>) -> Result<Self, Box<dyn Error>> {
        let dir = match explicit {
            Some(dir) => dir,
            None => match std::env::var_os("HOME") {
                Some(home) => PathBuf::from(home).join(".karsa"),
                None => PathBuf::from(".karsa"),
            },
        };
        std::fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// The directory itself.
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// `node.toml` inside this home.
    #[must_use]
    pub fn node_toml(&self) -> PathBuf {
        self.dir.join("node.toml")
    }

    /// `genesis.json` inside this home.
    #[must_use]
    pub fn genesis_json(&self) -> PathBuf {
        self.dir.join("genesis.json")
    }

    /// `peers.json` inside this home.
    #[must_use]
    pub fn peers_json(&self) -> PathBuf {
        self.dir.join("peers.json")
    }

    /// `keys.json` inside this home.
    ///
    /// Private keys sit beside the public membership they belong to, in the same
    /// directory, but are written `0600` and never hashed.
    #[must_use]
    pub fn keys_json(&self) -> PathBuf {
        self.dir.join("keys.json")
    }

    /// Picks an explicit file when one was given, else the file inside this home.
    #[must_use]
    pub fn file(&self, explicit: Option<PathBuf>, name: &str) -> PathBuf {
        explicit.unwrap_or_else(|| self.dir.join(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_three_paths_sit_side_by_side() {
        let home = Home {
            dir: PathBuf::from("/tmp/example"),
        };
        assert_eq!(home.node_toml(), PathBuf::from("/tmp/example/node.toml"));
        assert_eq!(
            home.genesis_json(),
            PathBuf::from("/tmp/example/genesis.json")
        );
    }

    #[test]
    fn an_explicit_file_wins_over_the_home() {
        let home = Home {
            dir: PathBuf::from("/tmp/example"),
        };
        assert_eq!(
            home.file(Some(PathBuf::from("/elsewhere/node.toml")), "node.toml"),
            PathBuf::from("/elsewhere/node.toml")
        );
        assert_eq!(
            home.file(None, "node.toml"),
            PathBuf::from("/tmp/example/node.toml")
        );
    }
}
