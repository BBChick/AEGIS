use tauri::{
    menu::{Menu, MenuItem},
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    Manager,
};
use url::Url;

// =====================================================================
// БЕЗОПАСНОЕ ХРАНИЛИЩЕ SECRETS (CWE-312 Fix)
// =====================================================================
use keyring::Entry;

#[tauri::command]
fn secure_store_set(key: String, value: String) -> Result<(), String> {
    if key.len() > 64 || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err("Недопустимый формат ключа".to_string());
    }
    let entry = Entry::new("AegisKernelDiagnostic", &key).map_err(|e| e.to_string())?;
    entry.set_password(&value).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn secure_store_get(key: String) -> Result<String, String> {
    if key.len() > 64 || !key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
        return Err("Недопустимый формат ключа".to_string());
    }
    let entry = Entry::new("AegisKernelDiagnostic", &key).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(pw) => Ok(pw),
        Err(keyring::Error::NoEntry) => Ok(String::new()),
        Err(e) => Err(e.to_string()),
    }
}

// =====================================================================
// СЕТЕВОЙ LLM-МОСТ RUST (Защита от CORS и утечек заголовков)
// =====================================================================
use reqwest::Client;
use serde::{Deserialize, Serialize};

struct HttpState(Client);

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::Arc;
use tokio::sync::Notify;

struct JobStore(Mutex<HashMap<String, Arc<Notify>>>);

#[derive(Deserialize, Serialize, Clone, Debug)]
struct AIAnalysis {
    root_cause: String,
    solution: String,
    severity: String,
}

fn extract_and_parse_json(text: &str) -> AIAnalysis {
    let json_start = text.find('{').unwrap_or(0);
    let json_end = text.rfind('}').map(|i| i + 1).unwrap_or_else(|| text.len());

    let clean_json = if json_start < json_end
        && text.is_char_boundary(json_start)
        && text.is_char_boundary(json_end)
    {
        text.get(json_start..json_end).unwrap_or("{}")
    } else {
        "{}"
    };

    serde_json::from_str(clean_json).unwrap_or_else(|_| AIAnalysis {
        root_cause: "Ошибка парсинга ответа ИИ".to_string(),
        solution: text.to_string(),
        severity: "UNKNOWN".to_string(),
    })
}

async fn safe_read_json(mut res: reqwest::Response) -> Result<serde_json::Value, String> {
    let mut body_bytes = Vec::new();
    while let Some(chunk) = res.chunk().await.map_err(|e| e.to_string())? {
        body_bytes.extend_from_slice(&chunk);
        if body_bytes.len() > 10 * 1024 * 1024 {
            return Err("Превышен лимит размера ответа (10MB)".to_string());
        }
    }
    serde_json::from_slice(&body_bytes).map_err(|e| e.to_string())
}

#[tauri::command]
fn abort_analysis(job_id: String, jobs: tauri::State<'_, JobStore>) {
    let mut guard = match jobs.0.lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    };
    if let Some(notify) = guard.remove(&job_id) {
        notify.notify_one();
    }
}

// [НОВОЕ]: Прямой сетевой Ping из Rust (Обход ограничений Tauri HTTP Capabilities)
#[tauri::command]
async fn ping_ollama(host: String, state: tauri::State<'_, HttpState>) -> Result<bool, String> {
    let client = &state.0;
    let safe_host = host.trim_end_matches('/');
    
    match client.get(safe_host).timeout(std::time::Duration::from_millis(1500)).send().await {
        Ok(res) => Ok(res.status().is_success()),
        Err(_) => Ok(false),
    }
}

#[tauri::command]
async fn analyze_log_bridge(
    job_id: String, provider: String, token: String, model: String,
    prompt: String, locale: String, ollama_host: String,
    state: tauri::State<'_, HttpState>, jobs: tauri::State<'_, JobStore>,
) -> Result<AIAnalysis, String> {
    let client = state.0.clone();
    let notify = Arc::new(Notify::new());

    {
        let mut guard = match jobs.0.lock() { Ok(g) => g, Err(p) => p.into_inner(), };
        guard.insert(job_id.clone(), notify.clone());
    }

    let safe_locale = if locale.len() <= 20 && locale.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        locale
    } else {
        "en-US".to_string()
    };

    let fetch_task = async move {
        if provider == "ollama" {
            let mut resolved_url = "http://127.0.0.1:11434".to_string();
            if let Ok(parsed) = url::Url::parse(&ollama_host) {
                if parsed.scheme() == "http" || parsed.scheme() == "https" {
                    if let Some(host_str) = parsed.host_str() {
                        let port = parsed.port_or_known_default().unwrap_or(11434);
                        let mut final_ip: Option<std::net::IpAddr> = None;
                        
                        if let Ok(resolved_addrs) = tokio::net::lookup_host(format!("{}:{}", host_str, port)).await {
                            for addr in resolved_addrs {
                                let ip = addr.ip();
                                let mut is_safe = true;
                                if ip.is_loopback() {} 
                                else if let std::net::IpAddr::V4(ipv4) = ip { if ipv4.is_link_local() { is_safe = false; } } 
                                else if let std::net::IpAddr::V6(ipv6) = ip { if ipv6.segments()[0] & 0xffc0 == 0xfe80 { is_safe = false; } }
                                
                                if is_safe {
                                    if final_ip.is_none() || ip.is_ipv4() { final_ip = Some(ip); }
                                    if ip.is_ipv4() { break; }
                                }
                            }
                        }

                        if let Some(ip) = final_ip {
                            if ip.is_ipv6() { resolved_url = format!("{}://[{}]:{}", parsed.scheme(), ip, port); } 
                            else { resolved_url = format!("{}://{}:{}", parsed.scheme(), ip, port); }
                        }
                    }
                }
            }

            let payload = serde_json::json!({
                "model": model,
                "prompt": format!("Проанализируй лог на предмет ошибок. ОБЯЗАТЕЛЬНО переведи техническое описание ошибки и решение на язык этой локали {}. Ответь строго в формате JSON: {{ \"root_cause\": \"[Причина ошибки]\", \"solution\": \"[Шаги решения]\", \"severity\": \"LOW|MEDIUM|HIGH|CRITICAL\" }}. Лог: {}", safe_locale, prompt),
                "stream": false
            });

            let mut req = client.post(format!("{}/api/generate", resolved_url));
            if let Ok(parsed) = url::Url::parse(&ollama_host) {
                if let Some(host_str) = parsed.host_str() { req = req.header(reqwest::header::HOST, host_str); }
            }
            
            let res = req.json(&payload).send().await.map_err(|e| format!("Ошибка сети Ollama: {}", e))?;
            if !res.status().is_success() { return Err(format!("Ollama вернула статус: {}", res.status())); }

            let body: serde_json::Value = safe_read_json(res).await?;
            let response_text = body["response"].as_str().unwrap_or("{}");
            return Ok(extract_and_parse_json(response_text));
        }

        if provider == "gemini" {
            let safe_model = "gemini-2.5-flash";
            let gemini_url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent", safe_model);
            let payload = serde_json::json!({
                 "contents":[{ "parts":[{"text": format!("Проанализируй лог. ОБЯЗАТЕЛЬНО переведи техническое объяснение ошибки и шаги по решению на язык этой локали {}. Верни строго JSON: {{ \"root_cause\": \"[Суть ошибки]\", \"solution\": \"[Подробное решение]\", \"severity\": \"LOW|MEDIUM|HIGH|CRITICAL\" }}. Лог: {}", safe_locale, prompt)}] }]
            });

            let res = client.post(&gemini_url).header("x-goog-api-key", token).json(&payload).send().await.map_err(|e| format!("Gemini Network Error: {}", e))?;
            if !res.status().is_success() { return Err(format!("Gemini API Error: {}", res.status())); }
            let body: serde_json::Value = safe_read_json(res).await?;
            let text = body["candidates"][0]["content"]["parts"][0]["text"].as_str().unwrap_or("{}");
            return Ok(extract_and_parse_json(text));
        }

        if provider == "openai" || provider == "deepseek" {
            let endpoint = if provider == "openai" { "https://api.openai.com/v1/chat/completions" } else { "https://api.deepseek.com/chat/completions" };
            let safe_model = if provider == "openai" { "gpt-4o-mini" } else { "deepseek-chat" };

            let payload = serde_json::json!({
                "model": safe_model,
                "messages":[
                    { "role": "system", "content": format!("Ты - системный анализатор логов. Твоя задача: прочесть лог, выявить ошибку и перевести её техническую суть и план решения ИСКЛЮЧИТЕЛЬНО на язык соответствующий локали {}. Отвечай СТРОГО в формате JSON без разметки Markdown: {{ \"root_cause\": \"[Проблема]\", \"solution\": \"[Инструкция по фиксу]\", \"severity\": \"LOW|MEDIUM|HIGH|CRITICAL\" }}", safe_locale) },
                    { "role": "user", "content": format!("Лог: {}", prompt) }
                ],
                "response_format": { "type": "json_object" },
                "temperature": 0.1
            });

            let res = client.post(endpoint).bearer_auth(token).json(&payload).send().await.map_err(|e| format!("Network Error {}: {}", provider, e))?;
            if !res.status().is_success() { return Err(format!("{} API Error: {}", provider, res.status())); }
            let body: serde_json::Value = safe_read_json(res).await?;
            let text = body["choices"][0]["message"]["content"].as_str().unwrap_or("{}");
            return Ok(extract_and_parse_json(text));
        }

        Err(format!("Провайдер {} пока не реализован мостом", provider))
    };

    let result = tokio::select! {
        _ = notify.notified() => { Err("Анализ прерван пользователем (Защита от Dangling Tasks)".to_string()) }
        res = fetch_task => { res }
    };

    {
        let mut guard = match jobs.0.lock() { Ok(g) => g, Err(p) => p.into_inner(), };
        guard.remove(&job_id); 
    }
    result
}

// =====================================================================
// КОНТРОЛЛЕРЫ ОКНА (Log-First Development)
// =====================================================================
#[tauri::command] fn win_minimize(window: tauri::Window) { if let Err(e) = window.minimize() { eprintln!("[ЭГИДА-Window]: Ошибка сворачивания: {}", e); } }
#[tauri::command] fn win_maximize(window: tauri::Window) { match window.is_maximized() { Ok(true) => { if let Err(e) = window.unmaximize() { eprintln!("[ЭГИДА-Window]: {}", e); } } Ok(false) => { if let Err(e) = window.maximize() { eprintln!("[ЭГИДА-Window]: {}", e); } } Err(e) => eprintln!("[ЭГИДА-Window]: {}", e), } }
#[tauri::command] fn win_close(window: tauri::Window) { if let Err(e) = window.close() { eprintln!("[ЭГИДА-Window]: Ошибка закрытия: {}", e); } }
#[tauri::command] fn win_drag(window: tauri::Window) { if let Err(e) = window.start_dragging() { eprintln!("[ЭГИДА-Window]: Ошибка Drag: {}", e); } }

// =====================================================================
// СИСТЕМНЫЕ ВЫЗОВЫ И БЕЗОПАСНОСТЬ (РБПО СТАНДАРТ)
// =====================================================================

#[tauri::command]
fn open_link(app: tauri::AppHandle, target_url: String) {
    let parsed_url = match Url::parse(&target_url) {
        Ok(url) => url,
        Err(_) => { return; }
    };

    if parsed_url.scheme() != "https" { return; }

    use tauri_plugin_opener::OpenerExt;
    let _ = app.opener().open_url(&target_url, None::<&str>);
}

#[tauri::command]
fn check_ollama() -> bool {
    let mut cmd = std::process::Command::new("ollama");
    cmd.arg("--version");
    
    #[cfg(target_os = "windows")]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x08000000); // CREATE_NO_WINDOW
    }
    
    if let Ok(output) = cmd.output() {
        if output.status.success() { return true; }
    }

    //[УЛЬТИМАТИВНЫЙ ФОЛЛБЭК РЕЗОЛВЕР ПУТЕЙ]
    let paths = if cfg!(target_os = "windows") {
        let local_app = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| {
            let user = std::env::var("USERPROFILE").unwrap_or_else(|_| "C:\\Users\\Default".to_string());
            format!("{}\\AppData\\Local", user)
        });
        vec![
            format!("{}\\Programs\\Ollama\\ollama.exe", local_app),
            format!("{}\\Ollama\\ollama.exe", local_app),
            "C:\\Program Files\\Ollama\\ollama.exe".to_string(),
        ]
    } else if cfg!(target_os = "macos") {
        vec![
            "/usr/local/bin/ollama".to_string(), 
            "/opt/homebrew/bin/ollama".to_string(),
            "/Applications/Ollama.app/Contents/Resources/ollama".to_string(),
            std::env::var("HOME").map(|h| format!("{}/.ollama/bin/ollama", h)).unwrap_or_default(),
        ]
    } else {
        vec!["/usr/bin/ollama".to_string(), "/usr/local/bin/ollama".to_string(), "/opt/ollama/ollama".to_string()]
    };

    for p in paths {
        if std::path::Path::new(&p).exists() {
            let mut cmd_fallback = std::process::Command::new(p);
            cmd_fallback.arg("--version");
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                cmd_fallback.creation_flags(0x08000000);
            }
            if let Ok(out) = cmd_fallback.output() {
                if out.status.success() { return true; }
            }
        }
    }
    false
}

// =====================================================================
// ИНИЦИАЛИЗАЦИЯ ЖИЗНЕННОГО ЦИКЛА
// =====================================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(65))
        .build()
        .expect("Failed to build HTTP client");

    tauri::Builder::default()
        .plugin(tauri_plugin_http::init())
        .manage(HttpState(http_client))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init()) 
        .manage(JobStore(Mutex::new(HashMap::new())))
        .invoke_handler(tauri::generate_handler![
            win_minimize, win_maximize, win_close, win_drag, open_link,
            check_ollama, ping_ollama, secure_store_set, secure_store_get,
            analyze_log_bridge, abort_analysis
        ])
        .setup(|app| {
            let quit_i = MenuItem::with_id(app, "quit", "Выход из ЭГИДЫ", true, None::<&str>)?;
            let show_i = MenuItem::with_id(app, "show", "Развернуть терминал", true, None::<&str>)?;
            let hide_i = MenuItem::with_id(app, "hide", "Свернуть в трей", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &hide_i, &quit_i])?;

            //[FIX]: Graceful загрузка иконки. Приложение не упадет, если иконка не собралась.
            let mut tray_builder = TrayIconBuilder::new().menu(&menu);
            if let Some(icon) = app.default_window_icon().cloned() {
                tray_builder = tray_builder.icon(icon);
            }

            let _tray = tray_builder
                .on_menu_event(|app: &tauri::AppHandle, event| match event.id.as_ref() {
                    "quit" => app.exit(0),
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show(); let _ = window.unminimize(); let _ = window.set_focus();
                        }
                    }
                    "hide" => { if let Some(window) = app.get_webview_window("main") { let _ = window.hide(); } }
                    _ => {}
                })
                .on_tray_icon_event(|tray: &tauri::tray::TrayIcon, event| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                        if let Some(window) = tray.app_handle().get_webview_window("main") {
                            if !window.is_visible().unwrap_or(false) {
                                let _ = window.show(); let _ = window.unminimize(); let _ = window.set_focus();
                            } else {
                                let _ = window.hide();
                            }
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("[ЭГИДА-Core]: Фатальный сбой при запуске приложения");
}