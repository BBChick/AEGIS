<div align="center">
  <a href="#english-🇬🇧">English 🇬🇧</a> | <a href="#русский-🇷🇺">Русский 🇷🇺</a>
</div>

---

<h1 id="english-🇬🇧">🛡️ AEGIS // Kernel Diagnostic</h1>

**AEGIS** is a high-performance, secure cross-platform application for intelligent log analysis. It uses local (Ollama) and cloud (Gemini, OpenAI, DeepSeek) LLMs to pinpoint root causes in massive application dumps and server logs.

![AEGIS Architecture](https://img.shields.io/badge/Architecture-Tauri%20%2B%20React-blue) ![Rust](https://img.shields.io/badge/Backend-Rust-orange) ![Tailwind v4](https://img.shields.io/badge/Styling-Tailwind%20v4-38B2AC) ![Security](https://img.shields.io/badge/Security-OS_Keyring_|_DLP_Masking-red)

## 🚀 Features
- **Local-First AI Integration:** Fully supports local execution via **Ollama** (`phi3`, `llama3`, etc.) ensuring absolute privacy.
- **Enterprise-Grade DLP (Data Loss Prevention):** Automatically masks IP addresses, JWT tokens, Emails, and API keys *before* any text reaches memory or is sent over the network.
- **OOM-Safe Stream Processing:** Streams and parses massive log files (up to 50,000 lines) using `AbortController` and chunking. Bypasses standard memory limitations.
- **Hardware-Backed Secrets (CWE-312):** API keys are natively stored within your OS Secure Enclave (Apple Keychain, Windows Credential Manager, Linux Secret Service) using Rust `keyring`.
- **Dynamic Localization:** AI output is automatically translated to match your OS language securely without exposing prompt-injection vulnerabilities (CWE-20).
- **Modern UI Edge:** Fully responsive interface built with Tailwind CSS v4, Framer Motion, and React Virtuoso for buttery-smooth list rendering.

## 🛠️ Tech Stack
**Frontend:** React 19, Vite, Tailwind CSS v4, Framer Motion, Lucide React.  
**Backend:** Tauri, Rust, Reqwest (Connection Pooling), Keyring (Secure Enclave).

## 📦 Installation & Build

1. **Clone the repository & Install dependencies:**
   ```bash
   git clone https://github.com/your-username/aegis-kernel-diagnostic.git
   cd aegis-kernel-diagnostic
   npm install
   ```
2. **Run in Development Mode:**
   ```bash
   npm run tauri dev
   ```
3. **Build for Production (Installer):**
   ```bash
   npm run tauri build
   ```

---

<h1 id="русский-🇷🇺">🛡️ AEGIS // Анализатор Логов</h1>

**AEGIS** — это высокопроизводительное, безопасное кроссплатформенное приложение для интеллектуального анализа логов. Оно использует локальные (Ollama) и облачные (Gemini, OpenAI, DeepSeek) нейросети для поиска причин ошибок в огромных стэктрейсах и логах серверов.

## 🚀 Возможности
- **Локальный ИИ (Local-First):** Полная поддержка оффлайн выполнения через **Ollama** (`phi3`, `llama3` и т.д.), гарантирующая 100% приватность.
- **Корпоративная DLP (Защита от утечек PII):** Автоматическая маскировка IP-адресов, JWT-токенов, Email и API-ключей *до* того, как текст попадет в память или будет отправлен парсеру.
- **Потоковая обработка (Без OOM):** Чтение и парсинг гигантских файлов логов (до 50 000 строк) через стриминг и фрагментирование. Программа никогда не вылетит из-за нехватки RAM.
- **Аппаратное хранение секретов (CWE-312):** API ключи нативно шифруются и хранятся в защищенном менеджере вашей ОС (Apple Keychain, Windows Credential Manager, Linux Secret Service) с помощью Rust `keyring`.
- **Динамическая локализация:** Ответы ИИ автоматически генерируются на языке вашей ОС. Имплементация защищена от уязвимостей типа Prompt Injection (CWE-20).
- **Современный UI:** Киберпанк-минимализм на базе Tailwind CSS v4, Framer Motion и React Virtuoso для максимально плавного рендера DOM.

## 🛠️ Стек технологий
**Фронтенд:** React 19, Vite, Tailwind CSS v4, Framer Motion, Lucide React.  
**Ядро (Бэкенд):** Tauri, Rust, Reqwest (Пулл подключений), Keyring (Аппаратный Vault).

## 📦 Установка и Сборка

1. **Клонирование и зависимости:**
   ```bash
   git clone https://github.com/your-username/aegis-kernel-diagnostic.git
   cd aegis-kernel-diagnostic
   npm install
   ```
2. **Запуск сервера разработки:**
   ```bash
   npm run tauri dev
   ```
3. **Сборка релизного установщика (.exe, .dmg, .AppImage):**
   ```bash
   npm run tauri build
   ```

## 🔒 Архитектура Безопасности (Secure by Design / РБПО)
AEGIS спроектирован с учетом высочайших стандартов безопасности:
- **CWE-400 (Memory Exhaustion DoS):** Rust-клиент реализует Connection Pooling с жесткими таймаутами. Стримы ограничены максимальной длиной строки (`30 000` символов), что спасает от гигантских однострочных JSON и ReDoS атак.
- **CWE-248 (Uncaught Panics):** В парсерах ответов внедрена защита границ памяти (`is_char_boundary`), предотвращающая панику приложения при некорректном парсинге кириллицы/юникода в слайсах.
- **CWE-20 (Improper Input Validation):** Внедрена глубокая санитизация системной локали для предотвращения атак типа LLM Prompt Injection.
- **CWE-79 (XSS):** React автоматически предотвращает DOM-инъекции вредоносного скрипта из логов.

## 📄 Лицензия
MIT License
