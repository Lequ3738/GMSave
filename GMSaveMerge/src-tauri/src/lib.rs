// GMSaveMerge — three-way merge UI for GMSave's external-change flow.
//
// The GMSave DLL launches us as:
//     GMSaveMerge.exe --manifest <session>\manifest.json
// The session directory holds base\ local\ remote\ copies of every changed
// file (raw bytes) plus manifest.json (path / kind / status / encoding /
// conflict ranges). We only ever WRITE <session>\decisions.json and
// <session>\decisions\<rel> — the DLL applies them to the project.
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use serde::Deserialize;
use serde_json::Value;

static SESSION: Mutex<Option<PathBuf>> = Mutex::new(None);

fn session() -> Result<PathBuf, String> {
    SESSION
        .lock()
        .unwrap()
        .clone()
        .ok_or_else(|| "no --manifest argument".to_string())
}

/// Session-relative path, refusing anything that could escape the session
/// (absolute paths, .., drive letters).
fn safe_rel(rel: &str) -> Result<PathBuf, String> {
    let normalized = rel.replace('/', "\\");
    let p = Path::new(&normalized);
    if p.is_absolute() {
        return Err(format!("absolute path rejected: {rel}"));
    }
    for c in p.components() {
        match c {
            Component::Normal(_) => {}
            _ => return Err(format!("bad path component rejected: {rel}")),
        }
    }
    Ok(p.to_path_buf())
}

fn decode(bytes: &[u8], enc: &str) -> String {
    if enc == "gbk" {
        let (cow, _, _) = encoding_rs::GBK.decode(bytes);
        cow.into_owned()
    } else {
        match String::from_utf8(bytes.to_vec()) {
            Ok(s) => s,
            Err(e) => String::from_utf8_lossy(e.as_bytes()).into_owned(),
        }
    }
}

fn encode(text: &str, enc: &str) -> Vec<u8> {
    if enc == "gbk" {
        let (cow, _, _) = encoding_rs::GBK.encode(text);
        cow.into_owned()
    } else {
        text.as_bytes().to_vec()
    }
}

/// Encoding of a manifest entry (manifest loaded per call — small file).
fn encoding_of(rel: &str) -> String {
    let sess = match session() {
        Ok(s) => s,
        Err(_) => return "utf-8".into(),
    };
    let Ok(j) = fs::read_to_string(sess.join("manifest.json")) else {
        return "utf-8".into();
    };
    let Ok(v) = serde_json::from_str::<Value>(&j) else {
        return "utf-8".into();
    };
    if let Some(files) = v.get("files").and_then(|f| f.as_array()) {
        for f in files {
            if f.get("path").and_then(|p| p.as_str()) == Some(rel) {
                if let Some(e) = f.get("encoding").and_then(|e| e.as_str()) {
                    return e.to_string();
                }
            }
        }
    }
    "utf-8".into()
}

#[tauri::command]
fn get_manifest() -> Result<Value, String> {
    let sess = session()?;
    let j = fs::read_to_string(sess.join("manifest.json")).map_err(|e| e.to_string())?;
    serde_json::from_str(&j).map_err(|e| e.to_string())
}

#[tauri::command]
fn read_side(side: String, rel: String) -> Result<String, String> {
    let sess = session()?;
    let p = sess.join(&side).join(safe_rel(&rel)?);
    let bytes = fs::read(&p).map_err(|e| format!("read {side}\\{rel}: {e}"))?;
    Ok(decode(&bytes, &encoding_of(&rel)))
}

#[tauri::command]
fn side_exists(side: String, rel: String) -> bool {
    let Ok(sess) = session() else { return false };
    let Ok(r) = safe_rel(&rel) else { return false };
    sess.join(&side).join(r).is_file()
}

#[derive(Deserialize)]
struct DecisionFile {
    path: String,
    action: String, // local | remote | edited
    #[serde(default)]
    content: Option<String>,
}

#[tauri::command]
fn decide(result: String, files: Vec<DecisionFile>) -> Result<(), String> {
    let sess = session()?;
    let decisions_dir = sess.join("decisions");
    for f in &files {
        if f.action == "edited" {
            let Some(content) = &f.content else {
                return Err(format!("edited decision without content: {}", f.path));
            };
            let p = decisions_dir.join(safe_rel(&f.path)?);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::write(&p, encode(content, &encoding_of(&f.path)))
                .map_err(|e| format!("write decisions\\{}: {e}", f.path))?;
        }
    }
    let out = serde_json::json!({
        "result": result,
        "files": files
            .iter()
            .map(|f| serde_json::json!({"path": f.path, "action": f.action}))
            .collect::<Vec<_>>(),
    });
    fs::write(
        sess.join("decisions.json"),
        serde_json::to_vec_pretty(&out).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

#[tauri::command]
fn exit_now(code: i32) {
    std::process::exit(code);
}

pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    let manifest_path = args
        .iter()
        .position(|a| a == "--manifest")
        .and_then(|i| args.get(i + 1))
        .cloned();
    tauri::Builder::default()
        .setup(move |_app| {
            if let Some(mp) = &manifest_path {
                if let Some(parent) = Path::new(mp).parent() {
                    *SESSION.lock().unwrap() = Some(parent.to_path_buf());
                }
            }
            // Debug aid: auto-open devtools in DEBUG builds only, so console
            // errors are visible while driving the UI externally. Release
            // builds keep the devtools feature enabled (press F12 — WebView2
            // opens it on demand) but start clean.
            #[cfg(all(feature = "devtools", debug_assertions))]
            {
                use tauri::Manager;
                if let Some(w) = _app.get_webview_window("main") {
                    w.open_devtools();
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_manifest,
            read_side,
            side_exists,
            decide,
            exit_now
        ])
        .run(tauri::generate_context!())
        .expect("error while running GMSaveMerge");
}
