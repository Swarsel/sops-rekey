use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Result};

use crate::manifest::Manifest;

fn deps<'a>(m: &'a Manifest, id: &str) -> &'a [String] {
    m.generator(id)
        .map(|g| g.dependencies.as_slice())
        .unwrap_or(&[])
}

pub fn check_acyclic(m: &Manifest) -> Result<()> {
    #[derive(Clone, Copy, PartialEq)]
    enum Mark {
        Visiting,
        Done,
    }
    fn visit<'a>(
        m: &'a Manifest,
        id: &'a str,
        marks: &mut BTreeMap<&'a str, Mark>,
        stack: &mut Vec<&'a str>,
    ) -> Result<()> {
        match marks.get(id) {
            Some(Mark::Done) => return Ok(()),
            Some(Mark::Visiting) => {
                stack.push(id);
                let start = stack.iter().position(|s| *s == id).unwrap();
                bail!(
                    "generator dependency cycle: {}",
                    stack[start..].join(" -> ")
                );
            }
            None => {}
        }
        marks.insert(id, Mark::Visiting);
        stack.push(id);
        for dep in deps(m, id) {
            visit(m, dep, marks, stack)?;
        }
        stack.pop();
        marks.insert(id, Mark::Done);
        Ok(())
    }
    let mut marks = BTreeMap::new();
    for id in m.secrets.keys() {
        visit(m, id, &mut marks, &mut Vec::new())?;
    }
    Ok(())
}

pub fn with_dependents(m: &Manifest, ids: &BTreeSet<String>) -> BTreeSet<String> {
    let mut out = ids.clone();
    loop {
        let before = out.len();
        for id in m.secrets.keys() {
            if !out.contains(id) && deps(m, id).iter().any(|d| out.contains(d)) {
                out.insert(id.clone());
            }
        }
        if out.len() == before {
            return out;
        }
    }
}

pub fn topo_order(m: &Manifest, ids: &BTreeSet<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut done = BTreeSet::new();
    fn visit(
        m: &Manifest,
        id: &str,
        ids: &BTreeSet<String>,
        done: &mut BTreeSet<String>,
        out: &mut Vec<String>,
    ) {
        if done.contains(id) {
            return;
        }
        done.insert(id.to_string());
        for dep in deps(m, id) {
            if ids.contains(dep) {
                visit(m, dep, ids, done, out);
            }
        }
        out.push(id.to_string());
    }
    for id in ids {
        visit(m, id, ids, &mut done, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(edges: &[(&str, &[&str])]) -> Manifest {
        let mut secrets = serde_json::Map::new();
        for (id, deps) in edges {
            secrets.insert(
                id.to_string(),
                serde_json::json!({
                    "file": "f.yaml", "key": id, "pubFile": "f.pub",
                    "generators": [{ "host": "h", "secret": id, "script": "/s", "dependencies": deps }]
                }),
            );
        }
        serde_json::from_value(serde_json::json!({ "version": 1, "hosts": {}, "secrets": secrets }))
            .unwrap()
    }

    fn set(xs: &[&str]) -> BTreeSet<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn detects_cycle() {
        let m = manifest(&[("a", &["b"]), ("b", &["c"]), ("c", &["a"])]);
        let err = check_acyclic(&m).unwrap_err().to_string();
        assert!(err.contains("cycle"), "{err}");
    }

    #[test]
    fn dependents_are_transitive() {
        let m = manifest(&[("a", &[]), ("b", &["a"]), ("c", &["b"]), ("d", &[])]);
        assert_eq!(with_dependents(&m, &set(&["a"])), set(&["a", "b", "c"]));
    }

    #[test]
    fn topo_puts_dependencies_first() {
        let m = manifest(&[("c", &["b"]), ("b", &["a"]), ("a", &[])]);
        assert_eq!(topo_order(&m, &set(&["a", "b", "c"])), vec!["a", "b", "c"]);
        assert_eq!(topo_order(&m, &set(&["c"])), vec!["c"]);
    }
}
