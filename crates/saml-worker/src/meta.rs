//! Shared helpers for the per-object discovery/description metadata that the
//! `vgi-lint` strict profile expects on **every** function and table.
//!
//! Each function/table surfaces these in its `FunctionMetadata.tags`:
//! - `vgi.title` (VGI124)        — human-friendly display name
//! - `vgi.doc_llm` (VGI112) — concise prose aimed at LLMs
//! - `vgi.doc_md` (VGI113)  — short Markdown description
//! - `vgi.keywords` (VGI126/VGI138) — a JSON array of search terms/synonyms
//!
//! Per-object `vgi.source_url` is intentionally NOT emitted here: `vgi.source_url`
//! belongs on the catalog object only (VGI139). The catalog's `source_url` field
//! already points at the repo.

/// Encode comma-separated keywords as the JSON array of strings that
/// `vgi.keywords` requires (VGI138). Each term is trimmed and empty terms are
/// dropped; the result is e.g. `["units","convert","length"]`.
pub fn keywords_json(keywords: &str) -> String {
    let items: Vec<String> = keywords
        .split(',')
        .map(str::trim)
        .filter(|k| !k.is_empty())
        // JSON-escape each keyword (covers quotes/backslashes) by emitting a
        // one-element array and stripping the surrounding brackets.
        .map(|k| {
            let escaped = k.replace('\\', "\\\\").replace('"', "\\\"");
            format!("\"{escaped}\"")
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// JSON-encode a string into `out`, wrapping it in double quotes and escaping
/// the characters JSON requires.
fn json_string(out: &mut String, s: &str) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Serialize a function's usage examples into the `vgi.example_queries` tag shape
/// (VGI515): a JSON list of `{"description": ..., "sql": ...}` objects.
///
/// Every function ALSO carries the same examples in [`vgi::FunctionMetadata::examples`]
/// (the native `duckdb_functions().examples` column), but that column is a bare
/// `VARCHAR[]` of SQL strings and drops the per-example description. The linter
/// merges the two carriers by SQL, so emitting the identical `sql` here lets the
/// described tag entry win — giving every example a human-readable description
/// without duplicating the query text.
pub fn example_queries_json(examples: &[vgi::FunctionExample]) -> String {
    let mut out = String::from("[");
    for (i, ex) in examples.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"description\":");
        json_string(&mut out, &ex.description);
        out.push_str(",\"sql\":");
        json_string(&mut out, &ex.sql);
        out.push('}');
    }
    out.push(']');
    out
}

/// Build the `vgi.agent_test_tasks` JSON value: a fixed suite of analyst tasks
/// that `vgi-lint simulate` runs. Each `(name, prompt, reference_sql)` triple
/// becomes a task object; the `prompt` is shown to the simulated analyst while
/// `reference_sql` (the canonical solution) is hidden and used to grade — and
/// doubles as few-shot guidance an MCP server can surface.
pub fn agent_test_tasks_json(tasks: &[(&str, &str, &str)]) -> String {
    fn esc(s: &str) -> String {
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('\n', "\\n")
    }
    let items: Vec<String> = tasks
        .iter()
        .map(|(name, prompt, reference_sql)| {
            format!(
                "{{\"name\":\"{}\",\"prompt\":\"{}\",\"reference_sql\":\"{}\"}}",
                esc(name),
                esc(prompt),
                esc(reference_sql)
            )
        })
        .collect();
    format!("[{}]", items.join(","))
}

/// Build the standard per-object discovery/description tags (title, LLM/MD docs,
/// keywords, and the `vgi.category` naming an entry in the schema's registry).
///
/// `relative_path` is the implementing file relative to `units-worker/src`; it is
/// retained for call-site documentation but no longer emitted as a per-object
/// `vgi.source_url` (that tag is catalog-only — VGI139).
pub fn object_tags(
    title: &str,
    description_llm: &str,
    description_md: &str,
    keywords: &str,
    category: &str,
    _relative_path: &str,
) -> Vec<(String, String)> {
    vec![
        ("vgi.title".to_string(), title.to_string()),
        ("vgi.doc_llm".to_string(), description_llm.to_string()),
        ("vgi.doc_md".to_string(), description_md.to_string()),
        ("vgi.keywords".to_string(), keywords_json(keywords)),
        // VGI408/409: name one of the schema's `vgi.categories` registry entries.
        ("vgi.category".to_string(), category.to_string()),
    ]
}
