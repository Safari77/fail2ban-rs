//! Dual-form deserialization for [`Backend`].
//!
//! A backend is written either as a bare name (`backend = "ipset"`) or as a
//! settings table (`[jail.sshd.backend.ipset]`). Serde's derived
//! externally-tagged enum cannot do both — a string only maps to a unit variant
//! and a table only to a struct variant — so the bridge is hand-written here.
//! Settings are deserialized through `deny_unknown_fields` structs, keeping the
//! crate-wide posture that a typo'd key fails the load by name.

use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::types::{Backend, default_ipset_chain, default_ipset_maxelem};

/// Backend names accepted in either form, listed in error messages.
const VARIANTS: &[&str] = &["nftables", "iptables", "ipset", "script"];

/// Settings under `[jail.<name>.backend.script]`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ScriptSettings {
    /// Command run to ban an IP.
    ban_cmd: String,
    /// Command run to unban an IP.
    unban_cmd: String,
}

/// Settings under `[jail.<name>.backend.ipset]` — both keys optional.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IpsetSettings {
    /// Maximum number of entries a set can hold.
    #[serde(default = "default_ipset_maxelem")]
    maxelem: u32,
    /// iptables chain the `-m set` DROP rule is inserted into.
    #[serde(default = "default_ipset_chain")]
    chain: String,
}

impl From<ScriptSettings> for Backend {
    fn from(s: ScriptSettings) -> Self {
        Self::Script {
            ban_cmd: s.ban_cmd,
            unban_cmd: s.unban_cmd,
        }
    }
}

impl From<IpsetSettings> for Backend {
    fn from(s: IpsetSettings) -> Self {
        Self::Ipset {
            maxelem: s.maxelem,
            chain: s.chain,
        }
    }
}

/// The ipset backend with every knob left at its default.
fn ipset_defaults() -> Backend {
    Backend::Ipset {
        maxelem: default_ipset_maxelem(),
        chain: default_ipset_chain(),
    }
}

/// Accepts either a backend name or a single-key settings table.
struct BackendVisitor;

impl<'de> Visitor<'de> for BackendVisitor {
    type Value = Backend;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a backend name or a single-key backend settings table")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        match value {
            "nftables" => Ok(Backend::Nftables),
            "iptables" => Ok(Backend::Iptables),
            "ipset" => Ok(ipset_defaults()),
            "script" => Err(de::Error::custom(
                "backend 'script' requires ban_cmd and unban_cmd; use [jail.<name>.backend.script]",
            )),
            other => Err(de::Error::unknown_variant(other, VARIANTS)),
        }
    }

    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Self::Value, M::Error> {
        let Some(key) = map.next_key::<String>()? else {
            return Err(de::Error::custom(format!(
                "empty backend table; expected one of {}",
                VARIANTS.join(", ")
            )));
        };
        // `next_value` carries the settings struct's own errors through, so an
        // unknown key inside the table is reported by name.
        let backend = match key.as_str() {
            "script" => map.next_value::<ScriptSettings>()?.into(),
            "ipset" => map.next_value::<IpsetSettings>()?.into(),
            "nftables" | "iptables" => {
                return Err(de::Error::custom(format!(
                    "backend '{key}' takes no settings; use backend = \"{key}\""
                )));
            }
            other => return Err(de::Error::unknown_variant(other, VARIANTS)),
        };
        if let Some(extra) = map.next_key::<String>()? {
            return Err(de::Error::custom(format!(
                "backend selects one backend; found extra key '{extra}'"
            )));
        }
        Ok(backend)
    }
}

impl<'de> Deserialize<'de> for Backend {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(BackendVisitor)
    }
}

#[cfg(test)]
#[path = "backend_test.rs"]
#[allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::needless_pass_by_value
)]
mod backend_test;
