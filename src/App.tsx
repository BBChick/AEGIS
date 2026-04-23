import React, { useState, useEffect, useMemo, useCallback, memo, useRef } from 'react';
import {
  Upload, ShieldAlert, Zap, Box, Settings,
  HardDrive, Download, Trash2, Sun, Moon, Lock, Minus, X,
  ExternalLink, Power, AlertTriangle, ShieldCheck, AlertOctagon
} from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { Virtuoso } from 'react-virtuoso';
import { invoke } from '@tauri-apps/api/core';
import { isPermissionGranted, requestPermission, sendNotification } from '@tauri-apps/plugin-notification';

// --- КОНСТАНТЫ И БЕЗОПАСНОСТЬ (РБПО ГОСТ) ---
const OLLAMA_MODELS = [
  { id: 'phi3:mini', name: 'Microsoft Phi-3 Mini', params: '3.8B', desc: 'База. Быстрая, логику тянет нормально.', tag: '⚡ REC' },
  { id: 'qwen2.5:0.5b', name: 'Alibaba Qwen 2.5', params: '0.5B', desc: 'Быстрая, но может галлюцинировать.', tag: '🚀 SPEED' },
  { id: 'llama3.2', name: 'Meta Llama 3.2', params: '3B', desc: 'Тяжелее, зато точнее.', tag: '🧠 ACCURACY' },
  { id: 'deepseek-coder-v2', name: 'DeepSeek Coder', params: '16B', desc: 'Для машин с мощной VRAM.', tag: '💻 DEV' }
];

// Усиленный паттерн: перехват пайпов, сетевых утилит и системных мутаций (DLP / Shell Inject)
const DANGEROUS_REGEX = /(\b(?:rm|mkfs|chmod|chown|dd|wget|curl|nc|netcat|mv|rmdir|eval|exec|sh|bash|zsh|powershell|cmd)\b|[>|&;]\s*\/(?:dev|etc|bin|sbin|usr|var)|\/dev\/(null|random|zero|tcp|udp))/i;

interface LogEntry { id: string; rawLine: string; maskedLine: string; isError: boolean; }
interface AIAnalysis { root_cause: string; solution: string; severity: string; }

// --- СИСТЕМА ЗАЩИТЫ ОТ УТЕЧЕК (DLP) ---
const maskSensitiveData = (text: string) => {
  return text
    .replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, '[REDACTED_IPv4]')
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')
    .replace(/(bearer|token|apikey|password|secret|key)[\s=:]+["']?[a-zA-Z0-9\-_+/=]+["']?/gi, '$1=[REDACTED]')
    .replace(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, '[REDACTED_JWT]');
};

const sanitizeInputTag = (tag: string) => tag.replace(/[^a-zA-Z0-9\-\.\:]/g, ''); // Защита от Injection в Ollama Runtime

const popNotification = async (title: string, body: string) => {
  try {
    let permissionGranted = await isPermissionGranted();
    if (!permissionGranted) permissionGranted = (await requestPermission()) === 'granted';
    if (permissionGranted) sendNotification({ title, body });
  } catch (err) { console.error("[ЭГИДА-Notify]:", err); }
};

// --- СИСТЕМНЫЕ ХУКИ ---
function useSecureStore() {
  const [apiKey, setApiKey] = useState('');

  useEffect(() => {
    async function init() {
      try {
        // Запрос к Rust-бэкенду на получение секрета из системного Keychain (Stronghold)
        const saved = await invoke<string>('secure_store_get', { key: 'SECRET_API_KEY_V2' }).catch(() => '');
        if (saved) setApiKey(saved);
      } catch (err) { console.warn("[ЭГИДА-Store]: Ошибка защищенного хранилища."); }
    }
    init();
  }, []);

  const save = async (val: string) => {
    setApiKey(val);
    try {
      // Сохранение идет в изолированную память Rust (Keyring/Stronghold)
      await invoke('secure_store_set', { key: 'SECRET_API_KEY_V2', value: val });
    } catch (err) {
      console.warn("[ЭГИДА-Store]: Fallback на in-memory (Stronghold недоступен).");
    }
  };
  return { apiKey, save };
}

function useOllamaHealth() {
  const [status, setStatus] = useState<'online' | 'offline' | 'missing' | 'checking'>('checking');
  useEffect(() => {
    const ac = new AbortController();
    async function check() {
      try {
        const res = await fetch('http://127.0.0.1:11434/', { signal: ac.signal });
        if (res.ok) { setStatus('online'); return; }
      } catch (e) { }
      try {
        const isInstalled = await invoke<boolean>('check_ollama');
        setStatus(isInstalled ? 'offline' : 'missing');
      } catch (e) { setStatus('missing'); }
    }
    check();
    const iv = setInterval(check, 5000);
    return () => { clearInterval(iv); ac.abort(); };
  }, []);
  return status;
}

function useLocalModels() {
  const [installed, setInstalled] = useState<string[]>([]);
  const [pulling, setPulling] = useState<string | null>(null);
  const [progress, setProgress] = useState('');
  const [pullController, setPullController] = useState<AbortController | null>(null);

  const fetchInstalled = async () => {
    try {
      const res = await fetch('http://127.0.0.1:11434/api/tags');
      if (!res.ok) throw new Error("API failed");
      const data = await res.json();
      if (!data?.models) throw new Error("Invalid format");
      setInstalled(data.models.map((m: any) => m.name));
    } catch { setInstalled([]); }
  };

  const remove = async (id: string, cb: () => void) => {
    try {
      await fetch('http://127.0.0.1:11434/api/delete', { method: 'DELETE', body: JSON.stringify({ name: id }) });
      await fetchInstalled(); cb();
    } catch (e: any) { alert("[Tauri-Ollama]: Ошибка удаления: " + e.message); }
  };

  const download = async (id: string, cb: () => void) => {
    if (pullController) pullController.abort(); // Отмена старого стрима (СWE-400 Memory Leak Fix)
    const ac = new AbortController();
    setPullController(ac);

    try {
      setPulling(id); setProgress('Инициализация...');
      const res = await fetch('http://127.0.0.1:11434/api/pull', {
        method: 'POST',
        body: JSON.stringify({ name: id }),
        signal: ac.signal
      });
      if (!res.body) throw new Error("Stream error");
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        const chunk = decoder.decode(value, { stream: true });
        const lines = chunk.split('\n');
        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const blob = JSON.parse(line);
            if (blob.total && blob.completed) setProgress(`ЗАГРУЗКА: ${Math.round((blob.completed / blob.total) * 100)}%`);
            else setProgress(blob.status ? blob.status.toUpperCase() : 'СБОРКА...');
          } catch (jsonErr) { }
        }
      }
      await popNotification('ЭГИДА', `Модуль ${id} готов.`);
      fetchInstalled(); setPulling(null); setPullController(null); cb();
    } catch (e: any) {
      if (e.name !== 'AbortError') {
        setProgress(`СБОЙ: ${e.message}`);
        setTimeout(() => setPulling(null), 3000);
      }
    }
  };

  useEffect(() => {
    return () => pullController?.abort();
  }, [pullController]);

  return { installed, pulling, progress, fetchInstalled, remove, download };
}

// --- ВИЗУАЛИЗАЦИЯ И МЕМОИЗАЦИЯ (PREVENT RENDER LAG) ---
const LogItem = memo(({ log, index, report, isActive, localError, onAnalyze }: any) => {
  const isDangerous = report && DANGEROUS_REGEX.test(report.solution);

  return (
    <div className="p-4 border-b border-black/10 dark:border-white/10 hover:bg-black/5 dark:hover:bg-white/5 transition-colors">
      <div className="flex items-start gap-4">
        <span className={`text-[10px] mt-1 font-bold ${log.isError ? 'text-red-500' : 'text-zinc-500'}`}>
          {index.toString().padStart(5, '0')}
        </span>
        <p className={`flex-1 text-sm break-all leading-relaxed font-mono ${log.isError ? 'text-black dark:text-white' : 'text-zinc-500'}`}>
          {log.rawLine}
        </p>
        {log.isError && (
          <button
            onClick={() => onAnalyze(log)}
            disabled={isActive}
            className={`px-6 py-2 border-2 text-[10px] font-bold uppercase transition-all shrink-0 disabled:opacity-20 ${isActive ? 'border-orange-500 text-orange-500' : 'border-black dark:border-white text-black dark:text-white hover:bg-black hover:text-white dark:hover:bg-white dark:hover:text-black'}`}
          >
            {isActive ? 'СКАНИРОВАНИЕ...' : 'РАЗБОР'}
          </button>
        )}
      </div>
      <AnimatePresence>
        {report && (
          <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} className={`mt-4 p-5 border-l-4 ${isDangerous ? 'border-red-500 bg-red-500/10' : 'border-orange-500 bg-black/5 dark:bg-white/5'}`}>
            <div className={`text-[10px] font-bold uppercase mb-2 flex items-center gap-2 ${isDangerous ? 'text-red-500' : 'text-orange-500'}`}>
              {isDangerous ? <AlertOctagon size={14} className="animate-pulse" /> : <ShieldAlert size={14} />}
              ВЕРДИКТ: {report.severity}
            </div>
            <p className="text-sm mb-4 leading-relaxed text-black dark:text-white">{report.root_cause}</p>

            {isDangerous && (
              <div className="mb-2 text-[10px] bg-red-500 text-white p-2 font-bold uppercase flex items-center gap-2">
                <AlertTriangle size={12} /> Внимание! Предложенная команда модифицирует ФС или сеть (DLP/Injection Guard).
              </div>
            )}
            <div className="space-y-2">
              <div className="text-[10px] text-zinc-500 font-bold uppercase">Автоматизированное исправление:</div>
              <pre className={`p-4 bg-black border text-xs overflow-x-auto whitespace-pre-wrap ${isDangerous ? 'border-red-500 text-red-500' : 'border-[#111] text-[#00FF41]'}`}>
                $ {report.solution}
              </pre>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
      {localError && (
        <div className="mt-2 text-[10px] text-red-500 bg-red-500/10 p-2 uppercase font-bold border-l-2 border-red-500">
          СБОЙ ГЕНЕРАЦИИ: {localError}
        </div>
      )}
    </div>
  );
});

// --- ОСНОВНОЙ КОРЕНЬ (ROOT) ---
export default function App() {
  const [themeMode, setThemeMode] = useState<'dark' | 'light'>(() => {
    return (localStorage.getItem('THEME') as 'dark' | 'light') || 'dark';
  });

  useEffect(() => {
    document.documentElement.classList.toggle('dark', themeMode === 'dark');
    localStorage.setItem('THEME', themeMode);
  }, [themeMode]);

  const [rawLogs, setRawLogs] = useState<LogEntry[]>([]);
  const [activeJobs, setActiveJobs] = useState<Record<string, boolean>>({});
  const [reports, setReports] = useState<Record<string, AIAnalysis>>({});
  const [localErrors, setLocalErrors] = useState<Record<string, string>>({});
  const [workingFile, setWorkingFile] = useState<string | null>(null);
  const [configOpen, setConfigOpen] = useState(false);

  const [provider, setProvider] = useState<'gemini' | 'openai' | 'deepseek' | 'ollama'>(() => {
    return (localStorage.getItem('AEGIS_PROVIDER') as any) || 'gemini';
  });
  const [modelHash, setModelHash] = useState(() => localStorage.getItem('OLLAMA_MODEL') || 'phi3:mini');

  useEffect(() => {
    localStorage.setItem('AEGIS_PROVIDER', provider);
  }, [provider]);

  useEffect(() => {
    localStorage.setItem('OLLAMA_MODEL', modelHash);
  }, [modelHash]);

  const { apiKey, save: setApiKey } = useSecureStore();
  const ollamaStatus = useOllamaHealth();
  const engines = useLocalModels();

  // OOM-Save (CWE-400): Stream API Parser для обработки гигантских логов
  const fileReaderController = useRef<AbortController | null>(null);

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setWorkingFile(file.name);

    // Блокировка гонки состояний (Race Condition)
    if (fileReaderController.current) {
      fileReaderController.current.abort();
    }
    const ac = new AbortController();
    fileReaderController.current = ac;

    try {
      const stream = file.stream();
      const reader = stream.getReader();
      const decoder = new TextDecoder();
      let partialLine = '';
      let lineCounter = 0;
      const MAX_LINES = 50000; // Жёсткий лимит защиты V8 RAM
      const MAX_LINE_LENGTH = 30000; // Защита от OOM при отсутствии переносов строк (Огромные DUMP/JSON)
      const newLogs: LogEntry[] = [];

      try {
        while (true) {
          if (ac.signal.aborted) {
            await reader.cancel("User aborted / Race condition");
            break;
          }

          const { done, value } = await reader.read();
          if (done) break;

          const text = decoder.decode(value, { stream: true });
          partialLine += text;

          // Защита от бинарных файлов и бесконечных строк
          if (partialLine.length > MAX_LINE_LENGTH * 2) {
            const chunk = partialLine.substring(0, MAX_LINE_LENGTH);
            partialLine = partialLine.substring(MAX_LINE_LENGTH); // Оставляем хвост

            newLogs.push({
              id: `L${lineCounter++}`,
              rawLine: chunk + '... [TRUNCATED_BY_AEGIS]',
              maskedLine: maskSensitiveData(chunk) + '... [TRUNCATED]',
              isError: /(error|fail|panic|exception|fatal|warn|killed)/i.test(chunk)
            });
          }

          // Парсинг нормальных строк
          if (partialLine.includes('\n')) {
            const lines = partialLine.split('\n');
            partialLine = lines.pop() || ''; // Последний кусок (без \n) оставляем в буфере

            for (const line of lines) {
              const rawLine = line.trim();
              if (rawLine) {
                // Обрезаем чересчур длинную строку ПЕРЕД маскировкой (Защита от ReDoS)
                const safeLine = rawLine.length > MAX_LINE_LENGTH ? rawLine.substring(0, MAX_LINE_LENGTH) + '...[TRUNC]' : rawLine;
                newLogs.push({
                  id: `L${lineCounter++}`,
                  rawLine: safeLine,
                  maskedLine: maskSensitiveData(safeLine),
                  isError: /(error|fail|panic|exception|fatal|warn|killed)/i.test(safeLine)
                });
              }
              if (newLogs.length >= MAX_LINES) {
                await reader.cancel("Security Limit: Max Lines");
                break;
              }
            }
          }
          if (newLogs.length >= MAX_LINES) break;
        }

        // Добиваем хвост
        if (!ac.signal.aborted && partialLine.trim() && newLogs.length < MAX_LINES) {
          const safeLine = partialLine.length > MAX_LINE_LENGTH ? partialLine.substring(0, MAX_LINE_LENGTH) + '...[TRUNC]' : partialLine.trim();
          newLogs.push({
            id: `L${lineCounter++}`,
            rawLine: safeLine,
            maskedLine: maskSensitiveData(safeLine),
            isError: /(error|fail|panic|exception|fatal|warn|killed)/i.test(safeLine)
          });
        }
      } finally {
        reader.releaseLock();
      }

      if (!ac.signal.aborted) {
        setRawLogs(newLogs);
      }
    } catch (err: any) {
      if (err.name !== 'AbortError') console.error("[Tauri-Core]: File read error", err);
    }
  };

  const authState = useRef({ apiKey, provider, modelHash });
  useEffect(() => {
    authState.current = { apiKey, provider, modelHash };
  }, [apiKey, provider, modelHash]);

  const runAnalysis = useCallback(async (log: LogEntry) => {
    const currentAuth = authState.current;

    if (currentAuth.provider !== 'ollama' && !currentAuth.apiKey) {
      setLocalErrors(prev => ({ ...prev, [log.id]: '[Tauri-Auth-Module]: Отсутствует ключ провайдера.' }));
      return;
    }

    setActiveJobs(prev => ({ ...prev, [log.id]: true }));
    setLocalErrors(prev => ({ ...prev, [log.id]: '' }));

    try {
      // IPC Timeout Timeout Guard (Предотвращение бесконечного ожидания ответа AI)
      const invokePromise = invoke<AIAnalysis>('analyze_log_bridge', {
        provider: currentAuth.provider,
        token: currentAuth.apiKey,
        model: currentAuth.modelHash,
        prompt: log.maskedLine,
        locale: navigator.language || 'en-US' // Динамический язык системы
      });

      const timeoutPromise = new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('TIMEOUT_ERROR: Ответ от LLM не получен (превышен лимит 60 сек). Проверьте статус локального узла Ollama или подключение к облаку.')), 60000);
      });

      const result = await Promise.race([invokePromise, timeoutPromise]);
      setReports(prev => ({ ...prev, [log.id]: result }));
    } catch (err: any) {
      setLocalErrors(prev => ({ ...prev, [log.id]: err.toString() }));
    } finally {
      setActiveJobs(prev => ({ ...prev, [log.id]: false }));
    }
  }, []);

  const errorCount = useMemo(() => rawLogs.filter(l => l.isError).length, [rawLogs]);

  useEffect(() => {
    if (configOpen && ollamaStatus === 'online') engines.fetchInstalled();
  }, [configOpen, ollamaStatus]);

  return (
    <div className="h-screen w-screen flex flex-col bg-[#e8e6e1] text-[#111] dark:bg-[#050505] dark:text-[#E0E0E0] font-mono border-4 border-[#111] dark:border-[#1c1c1c] overflow-hidden"
      style={{ backgroundImage: `linear-gradient(rgba(128,128,128,0.15) 1px, transparent 1px), linear-gradient(90deg, rgba(128,128,128,0.15) 1px, transparent 1px)`, backgroundSize: '30px 30px' }}>

      {/* DRAG HEADER */}
      <div onPointerDown={() => invoke('win_drag').catch(() => null)} className="h-10 flex justify-between items-center px-4 border-b-2 border-[#111] dark:border-[#1c1c1c] bg-black/10 cursor-move select-none shrink-0">
        <div className="text-[10px] text-zinc-500 font-bold tracking-widest flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-zinc-400" /> AEGIS // KERNEL_DIAGNOSTIC [SECURE]
        </div>
        <div className="flex gap-4">
          <button onPointerDown={e => e.stopPropagation()} onClick={() => invoke('win_minimize').catch(() => null)} className="hover:text-blue-500"><Minus size={16} /></button>
          <button onPointerDown={e => e.stopPropagation()} onClick={() => invoke('win_close').catch(() => null)} className="hover:text-red-500"><X size={16} /></button>
        </div>
      </div>

      <AnimatePresence>
        {configOpen && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-[100] flex items-center justify-center p-4 bg-black/60 backdrop-blur-md" onClick={() => setConfigOpen(false)}>
            <div onClick={(e) => e.stopPropagation()} className="bg-[#f4f2ee] dark:bg-[#0A0A0A] border-4 border-[#111] dark:border-[#1c1c1c] w-full max-w-4xl max-h-[85vh] flex flex-col shadow-[16px_16px_0_0_rgba(0,0,0,0.6)]">
              {/* Configuration Modal Body */}
              <div className="text-white font-bold p-4 flex justify-between items-center text-sm uppercase bg-orange-500 dark:bg-orange-600">
                <span className="flex items-center gap-2"><HardDrive className="w-5 h-5" /> Управление узлами (OLLAMA_CORE)</span>
                <button onClick={() => setConfigOpen(false)} className="px-3 py-1 bg-black/20 hover:bg-black/50 transition border border-white/20">ЗАКРЫТЬ [X]</button>
              </div>

              <div className="p-6 overflow-y-auto flex flex-col gap-8 font-mono text-sm">
                {/* Local Models Box */}
                <div>
                  <h3 className="font-bold border-b-2 border-black/20 dark:border-white/20 pb-2 mb-4 uppercase flex items-center gap-2">
                    <Lock className="w-4 h-4 text-zinc-500" /> СЕКРЕТНЫЙ АНКЛАВ (ЛОКАЛЬНО)
                  </h3>
                  {engines.installed.length === 0 ? (
                    <div className="text-zinc-500 border-2 border-dashed border-black/20 dark:border-white/20 p-8 text-center bg-black/5">Анклав пуст. Инициализируйте загрузку модуля из реестра.</div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {engines.installed.map((hash: string) => (
                        <div key={hash} className={`p-4 border-2 transition-all ${modelHash === hash ? 'border-orange-500 bg-orange-500/5' : 'border-black/20 dark:border-white/20'}`}>
                          <div className="flex justify-between items-start mb-4">
                            <span className="font-bold uppercase truncate pr-2 flex items-center gap-2">{modelHash === hash && <Zap className="w-4 h-4 text-[#00FF41]" />}{hash}</span>
                            <button onClick={() => engines.remove(hash, () => { if (modelHash === hash) setModelHash('') })} className="text-red-500 hover:bg-red-500 hover:text-white p-1 border border-red-500 transition-colors"><Trash2 className="w-4 h-4" /></button>
                          </div>
                          <button onClick={() => setModelHash(hash)} className={`px-4 py-2 font-bold uppercase border-2 w-full transition-colors ${modelHash === hash ? 'bg-black dark:bg-white text-white dark:text-black border-black dark:border-white' : 'hover:bg-black dark:hover:bg-white hover:text-white dark:hover:text-black border-[#111] dark:border-[#1c1c1c] text-zinc-500'}`}>
                            {modelHash === hash ? 'АКТИВНЫЙ УЗЕЛ' : 'АКТИВИРОВАТЬ'}
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                <div>
                  <h3 className="font-bold border-b-2 border-black/20 dark:border-white/20 pb-2 mb-4 uppercase flex items-center gap-2">
                    <Box className="w-4 h-4 text-zinc-500" /> ГЛОБАЛЬНЫЙ РЕЕСТР
                  </h3>
                  <div className="flex flex-col gap-3">
                    {OLLAMA_MODELS.map(m => {
                      const isLoaded = engines.installed.some((im: string) => im.startsWith(m.id));
                      return (
                        <div key={m.id} className="p-4 flex flex-col md:flex-row justify-between items-start md:items-center border-2 border-black/20 dark:border-white/20 bg-black/5 dark:bg-white/5">
                          <div className="mb-4 md:mb-0">
                            <div className="font-bold uppercase flex items-center gap-2 mb-1">
                              {m.name} <span className="text-[10px] px-2 py-0.5 bg-black dark:bg-white text-[#00FF41] dark:text-black border border-[#00FF41]/30">+{m.params}</span>
                            </div>
                            <div className="text-xs text-zinc-500 dark:text-zinc-400 max-w-sm">{m.desc}</div>
                          </div>
                          <div className="w-full md:w-auto">
                            {engines.pulling === m.id ? (
                              <div className="text-[10px] bg-black text-[#00FF41] p-3 whitespace-pre font-mono border border-[#00FF41]/30 min-w-[200px] shadow-inner">{engines.progress}</div>
                            ) : isLoaded ? (
                              <span className="font-bold text-zinc-500 border-2 border-zinc-500/50 px-4 py-2 text-xs w-full text-center inline-block">УСТАНОВЛЕНО</span>
                            ) : (
                              <button onClick={() => engines.download(m.id, () => setModelHash(m.id))} className="w-full md:w-auto px-6 py-2 border-2 font-bold text-xs uppercase flex items-center justify-center gap-2 transition-all border-black dark:border-white hover:bg-black hover:text-white dark:hover:bg-white dark:hover:text-black">
                                <Download className="w-4 h-4" /> ЗАГРУЗИТЬ
                              </button>
                            )}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>

                {/* Install Panel */}
                <div className="mt-6 flex flex-col gap-2">
                  <input type="text" placeholder="CUSTOM_MODEL:TAG"
                    onChange={e => {
                      e.target.value = sanitizeInputTag(e.target.value);
                    }}
                    className="flex-1 p-3 border-2 border-[#111] dark:border-[#1c1c1c] bg-[#ddd] dark:bg-[#111] text-[#111] dark:text-[#E0E0E0] outline-none font-mono text-xs uppercase focus:border-black dark:focus:border-white transition-colors"
                    id="custom-model-inject" />
                  <button onClick={() => {
                    const val = (document.getElementById('custom-model-inject') as HTMLInputElement)?.value;
                    if (val) engines.download(val, () => setModelHash(val));
                  }} className="px-8 py-3 border-2 font-bold uppercase text-xs transition-colors border-black dark:border-white hover:bg-black dark:hover:bg-white hover:text-white dark:hover:text-black">
                    ИНЪЕКЦИЯ
                  </button>
                </div>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* НОВЫЙ ДИНАМИЧЕСКИЙ АЛЕРТ ПРО OLLAMA */}
      {ollamaStatus !== 'online' && ollamaStatus !== 'checking' && (
        <div className={`shrink-0 border-b-4 p-3 flex justify-between items-center ${ollamaStatus === 'missing' ? 'border-[#FF3333] bg-[#FF3333]/10' : 'border-[#F3A536] bg-[#F3A536]/10'}`}>
          <div className="flex items-center gap-3">
            {ollamaStatus === 'missing' ? <ShieldAlert className="w-5 h-5 text-[#FF3333]" /> : <AlertTriangle className="w-5 h-5 text-[#F3A536]" />}
            <div>
              <h4 className={`font-bold text-xs uppercase ${ollamaStatus === 'missing' ? 'text-[#FF3333]' : 'text-[#F3A536]'}`}>
                {ollamaStatus === 'missing' ? 'ДВИЖОК OLLAMA НЕ НАЙДЕН' : 'ЯДРО OLLAMA СПИТ (АВТОНОМНО)'}
              </h4>
            </div>
          </div>
          {ollamaStatus === 'missing' ? (
            <button onClick={() => invoke('open_link', { url: 'https://ollama.com/download' }).catch(() => null)} className="px-3 py-1 border border-[#FF3333] text-[#FF3333] font-bold text-[10px] uppercase hover:bg-[#FF3333] hover:text-black flex items-center gap-2 transition-colors">
              СКАЧАТЬ ДВИЖОК <ExternalLink className="w-3 h-3" />
            </button>
          ) : (
            <div className="px-3 py-1 border border-[#F3A536] text-[#F3A536] font-bold text-[10px] uppercase flex items-center gap-2">
              ОЖИДАНИЕ ЗАПУСКА <Power className="w-3 h-3 animate-pulse" />
            </div>
          )}
        </div>
      )}

      {/* TOOLBAR */}
      <section className="p-4 border-b-2 border-[#111] dark:border-[#1c1c1c] flex flex-wrap gap-4 items-center bg-black/5 shrink-0 z-10 box-shadow-md">
        <div className="flex gap-2 bg-black p-1 border border-zinc-800">
          {['gemini', 'openai', 'deepseek', 'ollama'].map(p => (
            <button key={p} onClick={() => setProvider(p as any)} className={`px-4 py-1 text-[10px] font-bold uppercase transition-all ${provider === p ? 'bg-white text-black' : 'text-zinc-500 hover:text-white'}`}>
              {p}
            </button>
          ))}
        </div>
        {provider !== 'ollama' && (
          <div className="flex items-center gap-2">
            <Lock className="w-3 h-3 text-zinc-500" />
            <input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)} placeholder={`API KEY: ${provider.toUpperCase()} (SECURE IPC)`} className="text-[10px] p-2 border border-[#111] dark:border-[#1c1c1c] bg-[#ddd] dark:bg-[#111] text-[#111] dark:text-[#E0E0E0] outline-none w-64" />
          </div>
        )}
        <button onClick={() => setConfigOpen(true)} className="ml-auto px-4 py-1.5 text-[10px] font-bold flex items-center gap-2 border border-[#111] dark:border-[#1c1c1c] hover:bg-black dark:hover:bg-white hover:text-white dark:hover:text-black transition-all"><Settings size={14} /> НАСТРОЙКИ УЗЛА</button>
        <button onClick={() => { setThemeMode(themeMode === 'dark' ? 'light' : 'dark'); localStorage.setItem('THEME', themeMode === 'dark' ? 'light' : 'dark'); }} className="p-2 border border-[#111] dark:border-[#1c1c1c] hover:bg-black hover:text-white dark:hover:bg-white dark:hover:text-black transition-all">
          {themeMode === 'dark' ? <Sun size={14} /> : <Moon size={14} />}
        </button>
      </section>

      {/* MAIN VIEW */}
      <main className="flex-1 overflow-hidden relative">
        {rawLogs.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center m-10 border-4 border-dashed border-zinc-500/50 text-zinc-500">
            <Upload className="w-16 h-16 mb-4 opacity-50" />
            <input type="file" id="file" accept=".log,.txt,.json,.csv,.out,.err" title="Load Log" className="hidden" onChange={handleFileUpload} />
            <label htmlFor="file" className="cursor-pointer bg-black text-white dark:bg-white dark:text-black px-10 py-3 font-bold hover:bg-orange-500 hover:text-black transition-all uppercase text-sm">Инициализировать лог</label>
          </div>
        ) : (
          <Virtuoso
            style={{ height: '100%', width: '100%' }}
            totalCount={rawLogs.length}
            itemContent={index => (
              <LogItem
                key={rawLogs[index].id}
                log={rawLogs[index]}
                index={index}
                report={reports[rawLogs[index].id]}
                isActive={activeJobs[rawLogs[index].id]}
                localError={localErrors[rawLogs[index].id]}
                onAnalyze={runAnalysis}
              />
            )}
          />
        )}
      </main>

      <footer className="h-10 border-t-2 border-[#111] dark:border-[#1c1c1c] px-6 flex items-center justify-between text-[10px] font-bold bg-black/20 shrink-0">
        <div className="flex gap-6">
          <span className="opacity-60 uppercase">ФАЙЛ: {workingFile || 'NULL'}</span>
          <span className="text-red-500 uppercase">ОШИБОК: {errorCount}</span>
        </div>
        <div className="flex items-center gap-4">
          <span className="opacity-60 uppercase">СТРОК: {rawLogs.length}</span>
          <div className="flex items-center gap-2">
            <div className={`h-2 w-2 rounded-full ${ollamaStatus === 'online' ? 'bg-green-500' : 'bg-red-600'}`} />
            <span className="opacity-70 uppercase">OLLAMA: {ollamaStatus}</span>
          </div>
        </div>
      </footer>
    </div>
  );
}
