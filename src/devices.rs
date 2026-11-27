//! Script device naming, suggestions, and Interface aliases (ADR-0009).

use std::collections::HashSet;

use schemars::JsonSchema;
use serde::Serialize;

use crate::{Error, Result, device_target, model::Function};

const MAX_CANDIDATES: usize = 10;

/// The Script device token for a catalog `(source, interface)` pair; the inverse of `device_target`.
pub fn script_device(source: &str, interface: &str) -> String {
    if source == "DLL" {
        format!("DLL{interface}")
    } else {
        interface.to_string()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum MatchedBy {
    ScriptDevice,
    Interface,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, JsonSchema)]
pub struct DeviceMatch {
    pub script_device: String,
    pub matched_by: MatchedBy,
}

/// Distinct `(source, interface)` pairs, sorted.
pub(crate) fn interfaces(functions: &[Function]) -> Vec<(String, String)> {
    let mut pairs: Vec<_> = functions
        .iter()
        .map(|function| (function.source.clone(), function.interface.clone()))
        .collect();
    pairs.sort();
    pairs.dedup();
    pairs
}

pub(crate) fn is_known(device: &str, interfaces: &[(String, String)]) -> bool {
    device_target(device).is_ok_and(|(source, interface)| {
        interfaces
            .iter()
            .any(|(known, name)| known == source && name.eq_ignore_ascii_case(interface))
    })
}

/// Resolves a Script device, accepting an Interface name only when it names exactly one Script device.
pub(crate) fn resolve(device: &str, interfaces: &[(String, String)]) -> Result<DeviceMatch> {
    device_target(device)?;
    if is_known(device, interfaces) {
        return Ok(DeviceMatch {
            script_device: device.to_string(),
            matched_by: MatchedBy::ScriptDevice,
        });
    }
    let mut aliased: Vec<_> = interfaces
        .iter()
        .filter(|(_, interface)| interface.eq_ignore_ascii_case(device))
        .map(|(source, interface)| script_device(source, interface))
        .collect();
    aliased.sort();
    aliased.dedup_by(|left, right| left.eq_ignore_ascii_case(right));
    match aliased.as_slice() {
        [script_device] => Ok(DeviceMatch {
            script_device: script_device.clone(),
            matched_by: MatchedBy::Interface,
        }),
        [] => Err(unknown_device(device, interfaces)),
        _ => Err(Error::UnknownDevice {
            device: device.to_string(),
            candidates: aliased,
        }),
    }
}

pub(crate) fn unknown_device(device: &str, interfaces: &[(String, String)]) -> Error {
    Error::UnknownDevice {
        device: device.to_string(),
        candidates: candidates(device, interfaces),
    }
}

/// Close Script devices: an Interface equal to the token with or without the `DLL` prefix ranks
/// first, then Interfaces containing it (or contained in it).
pub(crate) fn candidates(device: &str, interfaces: &[(String, String)]) -> Vec<String> {
    let query = device
        .split('#')
        .next()
        .unwrap_or(device)
        .to_ascii_uppercase();
    let core = query
        .strip_prefix("DLL")
        .filter(|core| !core.is_empty())
        .unwrap_or(&query);
    if core.is_empty() {
        return Vec::new();
    }
    let mut ranked: Vec<_> = interfaces
        .iter()
        .filter_map(|(source, interface)| {
            let upper = interface.to_ascii_uppercase();
            let rank = if upper == core || upper == query {
                0
            } else if upper.contains(core) || (upper.len() >= 3 && core.contains(&upper)) {
                1
            } else {
                return None;
            };
            Some((rank, script_device(source, interface)))
        })
        .collect();
    ranked.sort();
    let mut seen = HashSet::new();
    ranked
        .into_iter()
        .map(|(_, device)| device)
        .filter(|device| seen.insert(device.to_ascii_uppercase()))
        .take(MAX_CANDIDATES)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interfaces_naming_several_script_devices_are_ambiguous() {
        let interfaces = vec![
            ("DLL".to_string(), "WIFI_TEST".to_string()),
            ("EXTERNAL".to_string(), "WIFI_TEST".to_string()),
        ];
        let error = resolve("WIFI_TEST", &interfaces).err();
        assert_eq!(error.as_ref().map(Error::code), Some("unknown_device"));
        assert_eq!(
            error.as_ref().map(Error::candidates),
            Some(["DLLWIFI_TEST".to_string(), "WIFI_TEST".to_string()].as_slice())
        );
    }
}
