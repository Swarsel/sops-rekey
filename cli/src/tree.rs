use anyhow::{anyhow, bail, Result};
use serde_json::{Map, Value};

fn components(key: Option<&str>) -> Vec<&str> {
    match key {
        Some(k) => k.split('/').collect(),
        None => vec!["data"],
    }
}

fn display(key: Option<&str>) -> &str {
    key.unwrap_or("<whole file>")
}

pub fn has_key(tree: &Value, key: Option<&str>) -> bool {
    let mut cur = tree;
    for c in components(key) {
        match cur.get(c) {
            Some(v) => cur = v,
            None => return false,
        }
    }
    true
}

pub fn get_leaf(tree: &Value, key: Option<&str>) -> Result<String> {
    let mut cur = tree;
    for c in components(key) {
        cur = cur
            .get(c)
            .ok_or_else(|| anyhow!("key {} not found", display(key)))?;
    }
    match cur {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(b.to_string()),
        Value::Null => Ok(String::new()),
        Value::Object(_) | Value::Array(_) => {
            bail!(
                "key {} is a subtree, but rekeyed secrets must point to a leaf value",
                display(key)
            )
        }
    }
}

pub fn set_leaf(tree: &mut Value, key: Option<&str>, value: String) -> Result<()> {
    insert(tree, &components(key), Value::String(value), true)
        .map_err(|e| anyhow!("cannot set key {}: {e}", display(key)))
}

pub fn insert(tree: &mut Value, path: &[&str], value: Value, overwrite: bool) -> Result<()> {
    if tree.is_null() {
        *tree = Value::Object(Map::new());
    }
    let (last, parents) = path.split_last().ok_or_else(|| anyhow!("empty key"))?;
    let mut cur = tree;
    for (i, c) in parents.iter().enumerate() {
        let obj = cur
            .as_object_mut()
            .ok_or_else(|| anyhow!("{} is not a mapping", path[..i].join("/")))?;
        cur = obj
            .entry(c.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    let obj = cur
        .as_object_mut()
        .ok_or_else(|| anyhow!("{} is not a mapping", parents.join("/")))?;
    if !overwrite && obj.contains_key(*last) {
        bail!("{} is defined twice", path.join("/"));
    }
    obj.insert(last.to_string(), value);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn leaf_access() {
        let t = json!({"db": {"password": "pw", "port": 5432, "tls": true}});
        assert_eq!(get_leaf(&t, Some("db/password")).unwrap(), "pw");
        assert_eq!(get_leaf(&t, Some("db/port")).unwrap(), "5432");
        assert_eq!(get_leaf(&t, Some("db/tls")).unwrap(), "true");
        assert!(get_leaf(&t, Some("db"))
            .unwrap_err()
            .to_string()
            .contains("subtree"));
        assert!(get_leaf(&t, Some("nope")).is_err());
        assert!(has_key(&t, Some("db/port")));
        assert!(!has_key(&t, Some("db/user")));
    }

    #[test]
    fn binary_documents() {
        let t = json!({"data": "raw"});
        assert_eq!(get_leaf(&t, None).unwrap(), "raw");
        let mut empty = Value::Null;
        set_leaf(&mut empty, None, "x".into()).unwrap();
        assert_eq!(empty, json!({"data": "x"}));
    }

    #[test]
    fn set_creates_parents() {
        let mut t = json!({"a": {"x": "1"}});
        set_leaf(&mut t, Some("a/b/c"), "v".into()).unwrap();
        assert_eq!(t, json!({"a": {"x": "1", "b": {"c": "v"}}}));
        assert!(set_leaf(&mut t, Some("a/x/y"), "v".into()).is_err());
    }

    #[test]
    fn insert_rejects_duplicates() {
        let mut t = Value::Null;
        insert(&mut t, &["a", "b"], json!("1"), false).unwrap();
        assert!(insert(&mut t, &["a", "b"], json!("2"), false).is_err());
    }
}
