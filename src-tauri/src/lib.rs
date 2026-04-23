use std::process::Command;
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
    // Сохраняем API ключ в защищенном OS-хранилище (Windows Credential Manager / macOS Keychain / Linux Secret Service)
    let entry = Entry::new("AegisKernelDiagnostic", &key).map_err(|e| e.to_string())?;
    entry.set_password(&value).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn secure_store_get(key: String) -> Result<String, String> {
    let entry = Entry::new("AegisKernelDiagnostic", &key).map_err(|e| e.to_string())?;
    match entry.get_password() {
        Ok(pw) => Ok(pw),
        Err(keyring::Error::NoEntry) => Ok(String::new()), // Не считаем ошибкой отсутствие ключа
        Err(e) => Err(e.to_string()),
    }
}

// =====================================================================
// СЕТЕВОЙ LLM-МОСТ RUST (Защита от CORS и утечек заголовков)
// =====================================================================
use serde::{Deserialize, Serialize};
use reqwest::Client;

// Глобальный HTTP-клиент, чтобы использовать Connection Pooling (CWE-400 Fix)
struct HttpState(Client);

#[derive(Deserialize, Serialize, Clone)]
struct AIAnalysis {
    root_cause: String,
    solution: String,
    severity: String,
}

// [DRY & Security]: Единый безопасный парсинг JSON ответов от AI для исключения OOB-паник (CWE-248)
fn extract_and_parse_json(text: &str) -> AIAnalysis {
    let json_start = text.find('{').unwrap_or(0);
    let json_end = text.rfind('}').map(|i| i + 1).unwrap_or_else(|| text.len());
    
    let clean_json = if json_start < json_end && text.is_char_boundary(json_start) && text.is_char_boundary(json_end) {
        text.get(json_start..json_end).unwrap_or("{}")
    } else {
        "{}" 
    };

    serde_json::from_str(clean_json).unwrap_or_else(|_| AIAnalysis {
        root_cause: "Ошибка парсинга ответа ИИ".to_string(),
        solution: text.to_string(), // В случае сбоя парсинга возвращаем сырой ответ как решение
        severity: "UNKNOWN".to_string(),
    })
}

#[tauri::command]
async fn analyze_log_bridge(
    provider: String,
    token: String,
    model: String,
    prompt: String,
    locale: String, // Динамическая локаль юзера (например, "ru-RU" или "en-US")
    state: tauri::State<'_, HttpState>, // Инъекция глобального клиента
) -> Result<AIAnalysis, String> {
    let client = &state.0;
    
    // [CWE-20 Fix]: Очистка и санитизация 'locale' для защиты от Prompt Injection и Memory DoS
    let safe_locale = if locale.len() <= 20 && locale.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        locale
    } else {
        "en-US".to_string()
    };

    // Пакетная отправка к Ollama (Подразумевается локально на порту 11434)
    if provider == "ollama" {
        let payload = serde_json::json!({
            "model": model,
            "prompt": format!("Проанализируй лог на предмет ошибок. ОБЯЗАТЕЛЬНО переведи техническое описание ошибки и решение на язык этой локали {}. Ответь строго в формате JSON: {{ \"root_cause\": \"[Причина ошибки]\", \"solution\": \"[Шаги решения]\", \"severity\": \"LOW|MEDIUM|HIGH|CRITICAL\" }}. Лог: {}", safe_locale, prompt),
            "stream": false
        });

        let res = client.post("http://127.0.0.1:11434/api/generate")
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Ошибка сети Ollama: {}", e))?;

        if !res.status().is_success() {
            return Err(format!("Ollama вернула статус: {}", res.status()));
        }

        let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
        let response_text = body["response"].as_str().unwrap_or("{}");
        
        return Ok(extract_and_parse_json(response_text));
    }
    
    // Google Gemini
    if provider == "gemini" {
        // [Logic Fix] Fallback на правильную модель, если в UI выбрана Ollama-модель
        let safe_model = "gemini-2.5-flash"; 
        
        let gemini_url = format!("https://generativelanguage.googleapis.com/v1beta/models/{}:generateContent?key={}", safe_model, token);
        let payload = serde_json::json!({
             "contents": [{
                 "parts": [{"text": format!("Проанализируй лог. ОБЯЗАТЕЛЬНО переведи техническое объяснение ошибки и шаги по решению на язык этой локали {}. Верни строго JSON: {{ \"root_cause\": \"[Суть ошибки]\", \"solution\": \"[Подробное решение]\", \"severity\": \"LOW|MEDIUM|HIGH|CRITICAL\" }}. Лог: {}", safe_locale, prompt)}]
             }]
        });
         
        let res = client.post(&gemini_url).json(&payload).send().await.map_err(|e| format!("Gemini Network Error: {}", e))?;
        if !res.status().is_success() {
            return Err(format!("Gemini API Error: {}", res.status()));
        }
         
        let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
        let text = body["candidates"][0]["content"]["parts"][0]["text"].as_str().unwrap_or("{}");
         
        return Ok(extract_and_parse_json(text));
    }

    // OpenAI & DeepSeek (Совместимые API)
    if provider == "openai" || provider == "deepseek" {
        let endpoint = if provider == "openai" {
            "https://api.openai.com/v1/chat/completions"
        } else {
            "https://api.deepseek.com/chat/completions"
        };
        
        // Подстановка правильной модели (т.к. в интерфейсе сейчас выбираются Ollama-модели)
        let safe_model = if provider == "openai" { "gpt-4o-mini" } else { "deepseek-chat" };

        let payload = serde_json::json!({
            "model": safe_model,
            "messages": [
                {
                    "role": "system",
                    "content": format!("Ты - системный анализатор логов. Твоя задача: прочесть лог, выявить ошибку и перевести её техническую суть и план решения ИСКЛЮЧИТЕЛЬНО на язык соответствующий локали {}. Отвечай СТРОГО в формате JSON без разметки Markdown: {{ \"root_cause\": \"[Проблема]\", \"solution\": \"[Инструкция по фиксу]\", \"severity\": \"LOW|MEDIUM|HIGH|CRITICAL\" }}", safe_locale)
                },
                {
                    "role": "user",
                    "content": format!("Лог: {}", prompt)
                }
            ],
            "response_format": { "type": "json_object" }, // Поддерживается и OpenAI, и свежим Deepseek
            "temperature": 0.1
        });

        let res = client.post(endpoint)
            .bearer_auth(token)
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Network Error {}: {}", provider, e))?;

        if !res.status().is_success() {
            return Err(format!("{} API Error: {}", provider, res.status()));
        }

        let body: serde_json::Value = res.json().await.map_err(|e| e.to_string())?;
        let text = body["choices"][0]["message"]["content"].as_str().unwrap_or("{}");

        return Ok(extract_and_parse_json(text));
    }

    Err(format!("Провайдер {} пока не реализован мостом", provider))
}

// =====================================================================
// КОНТРОЛЛЕРЫ ОКНА (Log-First Development)
// =====================================================================

#[tauri::command]
fn win_minimize(window: tauri::Window) {
    if let Err(e) = window.minimize() {
        eprintln!("[ЭГИДА-Window]: Ошибка сворачивания: {}", e);
    }
}

#[tauri::command]
fn win_maximize(window: tauri::Window) {
    match window.is_maximized() {
        Ok(true) => {
            if let Err(e) = window.unmaximize() {
                eprintln!("[ЭГИДА-Window]: Ошибка unmaximize: {}", e);
            }
        }
        Ok(false) => {
            if let Err(e) = window.maximize() {
                eprintln!("[ЭГИДА-Window]: Ошибка maximize: {}", e);
            }
        }
        Err(e) => eprintln!("[ЭГИДА-Window]: Ошибка проверки состояния окна: {}", e),
    }
}

#[tauri::command]
fn win_close(window: tauri::Window) {
    if let Err(e) = window.close() {
        eprintln!("[ЭГИДА-Window]: Ошибка закрытия окна: {}", e);
    }
}

#[tauri::command]
fn win_drag(window: tauri::Window) {
    if let Err(e) = window.start_dragging() {
        eprintln!("[ЭГИДА-Window]: Ошибка Drag-and-Drop: {}", e);
    }
}

// =====================================================================
// СИСТЕМНЫЕ ВЫЗОВЫ И БЕЗОПАСНОСТЬ (РБПО СТАНДАРТ)
// =====================================================================

#[tauri::command]
fn open_link(app: tauri::AppHandle, target_url: String) {
    // [CWE-20 Fix]: Безопасный парсинг по стандартам RFC 3986 (Разрешает параметры `?os=windows&arch=amd64`)
    let parsed_url = match Url::parse(&target_url) {
        Ok(url) => url,
        Err(_) => {
            eprintln!("[ЭГИДА-Security]: БЛОКИРОВКА УГРОЗЫ. Невалидный URL формат: {}", target_url);
            return;
        }
    };

    if parsed_url.scheme() != "https" {
        eprintln!("[ЭГИДА-Security]: БЛОКИРОВКА УГРОЗЫ. Разрешен только HTTPS: {}", target_url);
        return;
    }

    use tauri_plugin_opener::OpenerExt;
    if let Err(e) = app.opener().open_url(&target_url, None::<&str>) {
        eprintln!("[ЭГИДА-Opener]: Ошибка системного браузера при открытии {}: {}", target_url, e);
    }
}

#[tauri::command]
fn check_ollama() -> bool {
    // Прямой вызов бинарника (Shell Injection невозможен)
    match Command::new("ollama").arg("--version").output() {
        Ok(output) => {
            let is_success = output.status.success();
            if !is_success {
                eprintln!("[ЭГИДА-Ollama]: Процесс найден, но вернул ошибку выполнения.");
            }
            is_success
        }
        Err(e) => {
            eprintln!("[ЭГИДА-Ollama]: Ядро Ollama не отвечает. Причина: {}", e);
            false
        }
    }
}

// =====================================================================
// ИНИЦИАЛИЗАЦИЯ ЖИЗНЕННОГО ЦИКЛА (Tauri Setup)
// =====================================================================

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(65)) // [CWE-400 Fix]: Хард-лимит от утечек Tokio Tasks
        .build()
        .expect("Failed to build HTTP client");

    tauri::Builder::default()
        // Инициализируем глобальный HTTP-пул для предотвращения Socket Exhaustion
        .manage(HttpState(http_client))
        .plugin(tauri_plugin_notification::init())
        .plugin(tauri_plugin_opener::init()) 
        // [CWE-312 Fix]: Удален tauri_plugin_store в пользу OS Keychain (чекрей keyring)
        
        // Регистрация новых безопасных Endpoints (Интеграция с Frontend)
        .invoke_handler(tauri::generate_handler![
            win_minimize,
            win_maximize,
            win_close,
            win_drag,
            open_link,
            check_ollama,
            secure_store_set,
            secure_store_get,
            analyze_log_bridge
        ])
        
        .setup(|app| {
            let quit_i = MenuItem::with_id(app, "quit", "Выход из ЭГИДЫ", true, None::<&str>)?;
            let show_i = MenuItem::with_id(app, "show", "Развернуть терминал", true, None::<&str>)?;
            let hide_i = MenuItem::with_id(app, "hide", "Свернуть в трей", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_i, &hide_i, &quit_i])?;

            // Безопасное извлечение иконки (упадет с понятной ошибкой, если иконки нет)
            let tray_icon = app.default_window_icon()
                .expect("[ЭГИДА-Core]: КРИТИЧЕСКАЯ ОШИБКА. Не найдена иконка приложения в tauri.conf.json")
                .clone();

            let _tray = TrayIconBuilder::new()
                .icon(tray_icon)
                .menu(&menu)
                .on_menu_event(|app: &tauri::AppHandle, event| match event.id.as_ref() {
                    "quit" => app.exit(0), // Graceful shutdown вместо std::process::exit(0)
                    "show" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                    "hide" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.hide();
                        }
                    }
                    _ => {}
                })
                .on_tray_icon_event(|tray: &tauri::tray::TrayIcon, event| {
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        if let Some(window) = tray.app_handle().get_webview_window("main") {
                            if !window.is_visible().unwrap_or(false) {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
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
