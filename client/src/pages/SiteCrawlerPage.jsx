import { useState, useRef, useEffect } from 'react';
import {
  HardDriveDownload, FileText, Film, Music, Image, Archive,
  Database, Radio, Loader2, Terminal, Download, Package,
  CheckSquare, Square, RefreshCw, FolderOpen, AlertCircle,
  Mail, Phone, Share2, Link2, ExternalLink, Code2, Zap,
  Info, ClipboardList, MessageSquare, Copy, FileJson,
} from 'lucide-react';
import axios from 'axios';
import toast from 'react-hot-toast';

const API = 'http://localhost:8000';
const client = axios.create({ baseURL: API });

const POLL_MS = 1500;

const CAT_CONFIG = {
  video:     { label: 'סרטונים',   icon: Film,             color: 'text-red-600 bg-red-50 border-red-200',     ext: 'mp4 webm mkv avi mov' },
  streaming: { label: 'שידורים',   icon: Radio,            color: 'text-pink-600 bg-pink-50 border-pink-200',  ext: 'm3u8 mpd (HLS/DASH)' },
  audio:     { label: 'שמע',       icon: Music,            color: 'text-purple-600 bg-purple-50 border-purple-200', ext: 'mp3 wav flac aac' },
  document:  { label: 'מסמכים',    icon: FileText,         color: 'text-blue-600 bg-blue-50 border-blue-200',  ext: 'pdf doc docx xls xlsx ppt' },
  archive:   { label: 'ארכיונים',  icon: Archive,          color: 'text-amber-600 bg-amber-50 border-amber-200', ext: 'zip rar 7z tar gz' },
  image:     { label: 'תמונות',    icon: Image,            color: 'text-emerald-600 bg-emerald-50 border-emerald-200', ext: 'jpg png gif webp svg' },
  data:      { label: 'נתונים',    icon: Database,         color: 'text-cyan-600 bg-cyan-50 border-cyan-200',  ext: 'json xml sql yaml csv' },
};

function CategoryToggle({ cat, active, onToggle }) {
  const cfg = CAT_CONFIG[cat];
  const Icon = cfg.icon;
  return (
    <button
      onClick={() => onToggle(cat)}
      className={`flex items-center gap-2 rounded-xl border px-3 py-2.5 text-sm font-semibold transition-all duration-150 ${
        active ? cfg.color + ' ring-2 ring-offset-1 ring-slate-400' : 'border-slate-200 bg-white text-slate-500 hover:border-slate-300'
      }`}
    >
      {active
        ? <CheckSquare size={14} className="shrink-0" />
        : <Square size={14} className="shrink-0" />}
      <Icon size={14} className="shrink-0" />
      <span>{cfg.label}</span>
      <span className="text-xs opacity-60">{cfg.ext}</span>
    </button>
  );
}

function FileRow({ file, siteKey }) {
  const cfg = CAT_CONFIG[file.type] || {};
  const Icon = cfg.icon || FileText;
  const downloadUrl = `${API}/api/v1/crawl/file/${siteKey}/${encodeURIComponent(file.filename)}`;
  return (
    <div className="flex items-center gap-3 rounded-lg border border-slate-100 bg-white px-3 py-2 hover:bg-slate-50 transition">
      <Icon size={15} className={(cfg.color || '').split(' ')[0] || 'text-slate-500'} />
      <div className="flex-1 min-w-0">
        <p className="truncate text-sm font-medium text-slate-800">{file.filename}</p>
        <p className="text-xs text-slate-400 truncate">{file.url}</p>
      </div>
      <span className="shrink-0 text-xs text-slate-400">{file.size_mb} MB</span>
      <a
        href={downloadUrl}
        download={file.filename}
        className="shrink-0 rounded-lg border border-slate-200 p-1.5 text-slate-500 hover:bg-slate-100 transition"
        title="הורד קובץ"
      >
        <Download size={13} />
      </a>
    </div>
  );
}

// ── Intel config ──────────────────────────────────────────────────────────────

const INTEL_CONFIG = {
  emails:         { label: 'אימיילים',          icon: Mail,          color: 'text-blue-600 bg-blue-50 border-blue-200' },
  phones:         { label: 'טלפונים',            icon: Phone,         color: 'text-green-600 bg-green-50 border-green-200' },
  social:         { label: 'רשתות חברתיות',      icon: Share2,        color: 'text-pink-600 bg-pink-50 border-pink-200' },
  links_internal: { label: 'קישורים פנימיים',    icon: Link2,         color: 'text-slate-600 bg-slate-50 border-slate-200' },
  links_external: { label: 'קישורים חיצוניים',   icon: ExternalLink,  color: 'text-orange-600 bg-orange-50 border-orange-200' },
  scripts:        { label: 'JS / CSS',            icon: Code2,         color: 'text-yellow-600 bg-yellow-50 border-yellow-200' },
  api_endpoints:  { label: 'API Endpoints',       icon: Zap,           color: 'text-purple-600 bg-purple-50 border-purple-200' },
  metadata:       { label: 'מטא-דאטה',           icon: Info,          color: 'text-cyan-600 bg-cyan-50 border-cyan-200' },
  forms:          { label: 'טפסים',               icon: ClipboardList, color: 'text-amber-600 bg-amber-50 border-amber-200' },
  comments:       { label: 'תגובות HTML',         icon: MessageSquare, color: 'text-red-600 bg-red-50 border-red-200' },
};

function exportJson(data, filename) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: filename });
  a.click();
}

function copyText(text) {
  navigator.clipboard.writeText(text).catch(() => {});
}

function CopyBtn({ text, className = '' }) {
  const [copied, setCopied] = useState(false);
  function handle() {
    copyText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }
  return (
    <button onClick={handle} title="העתק" className={`shrink-0 rounded p-1 text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition ${className}`}>
      <Copy size={12} className={copied ? 'text-green-500' : ''} />
    </button>
  );
}

function StringRow({ value }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-slate-100 bg-white px-3 py-1.5 hover:bg-slate-50 transition">
      <span className="flex-1 min-w-0 truncate text-sm text-slate-700 font-mono" dir="ltr">{value}</span>
      <CopyBtn text={value} />
    </div>
  );
}

function MetaRow({ item }) {
  return (
    <div className="rounded-lg border border-slate-100 bg-white px-3 py-2 space-y-0.5">
      <div className="flex items-start gap-2">
        <span className="truncate text-sm font-semibold text-slate-800 flex-1" dir="ltr">{item.url}</span>
        <CopyBtn text={item.url} />
      </div>
      {item.title        && <p className="text-xs text-slate-600"><span className="font-semibold">כותרת:</span> {item.title}</p>}
      {item.description  && <p className="text-xs text-slate-500 line-clamp-2"><span className="font-semibold">תיאור:</span> {item.description}</p>}
      {item.keywords     && <p className="text-xs text-slate-400"><span className="font-semibold">מילות מפתח:</span> {item.keywords}</p>}
      {item.og_title     && <p className="text-xs text-slate-400"><span className="font-semibold">OG:</span> {item.og_title}</p>}
    </div>
  );
}

function FormRow({ item }) {
  return (
    <div className="rounded-lg border border-slate-100 bg-white px-3 py-2 space-y-0.5">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs font-bold px-1.5 py-0.5 rounded bg-amber-100 text-amber-700">{item.method}</span>
        <span className="flex-1 truncate text-sm font-mono text-slate-700" dir="ltr">{item.action}</span>
        <CopyBtn text={item.action} />
      </div>
      {item.fields.length > 0 && (
        <p className="text-xs text-slate-400">שדות: {item.fields.join(', ')}</p>
      )}
      <p className="text-xs text-slate-400 truncate" dir="ltr">דף: {item.page}</p>
    </div>
  );
}

function CommentRow({ item }) {
  return (
    <div className="rounded-lg border border-slate-100 bg-white px-3 py-2 space-y-0.5">
      <p className="text-xs text-slate-400 truncate" dir="ltr">{item.url}</p>
      <pre className="text-xs text-slate-700 whitespace-pre-wrap break-all font-mono line-clamp-4">{item.text}</pre>
    </div>
  );
}

function IntelSection({ intel, siteHost }) {
  const [activeKey, setActiveKey] = useState(null);

  const availableTabs = Object.entries(INTEL_CONFIG).filter(([key]) => {
    const d = intel[key];
    return Array.isArray(d) && d.length > 0;
  });

  useEffect(() => {
    if (availableTabs.length > 0 && !activeKey) {
      setActiveKey(availableTabs[0][0]);
    }
  }, [availableTabs.length]);

  if (availableTabs.length === 0) return null;

  const activeData = activeKey ? (intel[activeKey] || []) : [];
  const activeCfg  = activeKey ? INTEL_CONFIG[activeKey] : null;

  function renderItem(item, i) {
    if (activeKey === 'metadata') return <MetaRow key={i} item={item} />;
    if (activeKey === 'forms')    return <FormRow key={i} item={item} />;
    if (activeKey === 'comments') return <CommentRow key={i} item={item} />;
    return <StringRow key={i} value={typeof item === 'string' ? item : JSON.stringify(item)} />;
  }

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
      <div className="mb-4 flex items-center justify-between gap-2 flex-wrap">
        <h2 className="text-base font-black text-slate-900">מודיעין נוסף</h2>
        <button
          onClick={() => exportJson(intel, `intel_${siteHost}.json`)}
          className="flex items-center gap-1.5 rounded-lg border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-50 transition"
        >
          <FileJson size={13} /> ייצוא הכל JSON
        </button>
      </div>

      {/* Tabs */}
      <div className="mb-3 flex flex-wrap gap-1.5">
        {availableTabs.map(([key, cfg]) => {
          const Icon = cfg.icon;
          const count = intel[key]?.length ?? 0;
          return (
            <button
              key={key}
              onClick={() => setActiveKey(key)}
              className={`flex items-center gap-1.5 rounded-xl border px-3 py-1.5 text-xs font-semibold transition ${
                activeKey === key
                  ? cfg.color + ' ring-2 ring-offset-1 ring-slate-300'
                  : 'border-slate-200 bg-white text-slate-500 hover:border-slate-300'
              }`}
            >
              <Icon size={12} />
              {cfg.label}
              <span className="opacity-70">({count})</span>
            </button>
          );
        })}
      </div>

      {/* Content */}
      {activeCfg && (
        <div>
          <div className="mb-2 flex items-center justify-between">
            <span className="text-xs text-slate-400">{activeData.length} פריטים</span>
            <button
              onClick={() => exportJson(activeData, `${activeKey}_${siteHost}.json`)}
              className="flex items-center gap-1 rounded border border-slate-200 px-2 py-1 text-xs text-slate-500 hover:bg-slate-50 transition"
            >
              <FileJson size={11} /> ייצוא
            </button>
          </div>
          <div className="space-y-1.5 max-h-[420px] overflow-y-auto">
            {activeData.map((item, i) => renderItem(item, i))}
          </div>
        </div>
      )}
    </div>
  );
}

export default function SiteCrawlerPage() {
  const [url, setUrl]           = useState('');
  const [maxPages, setMaxPages] = useState(300);
  const [sizeLimitMb, setSizeLimitMb] = useState(500);
  const [categories, setCategories]   = useState(
    new Set(['video', 'streaming', 'audio', 'document', 'archive', 'data'])
  );
  const [status, setStatus]     = useState('idle');   // idle | running | completed | failed
  const [progress, setProgress] = useState([]);
  const [result, setResult]     = useState(null);
  const [jobId, setJobId]       = useState(null);
  const [activeTab, setActiveTab] = useState('all');

  const logRef  = useRef(null);
  const pollRef = useRef(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [progress]);

  useEffect(() => {
    if (!jobId || status !== 'running') return;
    pollRef.current = setInterval(async () => {
      try {
        const { data } = await client.get(`/api/v1/jobs/${jobId}`);
        setProgress(data.progress || []);
        if (data.status === 'completed') {
          clearInterval(pollRef.current);
          setStatus('completed');
          setResult(data.result);
          toast.success(`הושלם! ${data.result?.files_downloaded ?? 0} קבצים הורדו`);
        } else if (data.status === 'failed') {
          clearInterval(pollRef.current);
          setStatus('failed');
          setResult(data.result);
        }
      } catch { /* ignore */ }
    }, POLL_MS);
    return () => clearInterval(pollRef.current);
  }, [jobId, status]);

  function toggleCat(cat) {
    setCategories(prev => {
      const next = new Set(prev);
      next.has(cat) ? next.delete(cat) : next.add(cat);
      return next;
    });
  }

  async function handleStart() {
    if (!url.trim() || status === 'running') return;
    setStatus('running');
    setProgress([]);
    setResult(null);
    setActiveTab('all');
    try {
      const { data } = await client.post('/api/v1/crawl/start', {
        url: url.trim(),
        max_pages: maxPages,
        categories: [...categories],
        include_images: categories.has('image'),
        size_limit_mb: sizeLimitMb,
      });
      setJobId(data.job_id);
    } catch {
      setStatus('failed');
      toast.error('שגיאה בהתחלת הסריקה');
    }
  }

  function reset() {
    clearInterval(pollRef.current);
    setStatus('idle');
    setProgress([]);
    setResult(null);
    setJobId(null);
    setActiveTab('all');
  }

  // Build tab list from results
  const files = result?.files || [];
  const siteKey = result?.site
    ? (new URL(result.site)).hostname.replace(/[^a-zA-Z0-9._-]/g, '_')
    : '';

  const tabs = [{ id: 'all', label: 'הכל', count: files.length }];
  for (const [cat, cfg] of Object.entries(CAT_CONFIG)) {
    const count = files.filter(f => f.type === cat).length;
    if (count > 0) tabs.push({ id: cat, label: cfg.label, count });
  }

  const visibleFiles = activeTab === 'all'
    ? files
    : files.filter(f => f.type === activeTab);

  const isRunning  = status === 'running';
  const isDone     = status === 'completed';
  const isFailed   = status === 'failed';

  return (
    <div className="mx-auto max-w-4xl px-4 pt-20 pb-16" dir="rtl">

      {/* Header */}
      <div className="mb-8 flex items-center gap-3 pt-4">
        <div className="rounded-xl bg-slate-900 p-3 text-white">
          <HardDriveDownload size={22} />
        </div>
        <div>
          <h1 className="text-2xl font-black text-slate-900">סורק וממיר אתרים</h1>
          <p className="text-sm text-slate-500">מצא והורד כל קובץ חבוי באתר — סרטונים, מסמכים, שמע, ארכיונים ועוד</p>
        </div>
      </div>

      {/* Config card */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm space-y-5">

        {/* URL */}
        <div>
          <label className="mb-1.5 block text-xs font-semibold text-slate-500 uppercase tracking-wide">כתובת האתר</label>
          <input
            type="text"
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleStart()}
            placeholder="https://example.com"
            disabled={isRunning}
            dir="ltr"
            className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-900 placeholder:text-slate-400 focus:border-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-100 disabled:opacity-50"
          />
        </div>

        {/* Category toggles */}
        <div>
          <label className="mb-2 block text-xs font-semibold text-slate-500 uppercase tracking-wide">סוגי קבצים להורדה</label>
          <div className="flex flex-wrap gap-2">
            {Object.keys(CAT_CONFIG).map(cat => (
              <CategoryToggle key={cat} cat={cat} active={categories.has(cat)} onToggle={toggleCat} />
            ))}
          </div>
        </div>

        {/* Advanced options */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="mb-1 block text-xs font-semibold text-slate-500">מקסימום דפים לסריקה</label>
            <input
              type="number" min="10" max="1000" value={maxPages}
              onChange={e => setMaxPages(Number(e.target.value))}
              disabled={isRunning}
              className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm focus:outline-none focus:border-slate-400 disabled:opacity-50"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-semibold text-slate-500">גודל מקסימלי לקובץ (MB)</label>
            <input
              type="number" min="1" max="5000" value={sizeLimitMb}
              onChange={e => setSizeLimitMb(Number(e.target.value))}
              disabled={isRunning}
              className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm focus:outline-none focus:border-slate-400 disabled:opacity-50"
            />
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex gap-2">
          <button
            onClick={handleStart}
            disabled={isRunning || !url.trim()}
            className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-slate-900 py-3 text-sm font-bold text-white transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {isRunning
              ? <><Loader2 size={15} className="animate-spin" /> סורק ומוריד...</>
              : <><HardDriveDownload size={15} /> סרוק והורד הכל</>}
          </button>
          {(isDone || isFailed) && (
            <button onClick={reset} className="rounded-xl border border-slate-200 p-3 text-slate-500 hover:bg-slate-50">
              <RefreshCw size={15} />
            </button>
          )}
        </div>
      </div>

      {/* Progress log */}
      {progress.length > 0 && (
        <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950 p-4">
          <div className="mb-2 flex items-center gap-2">
            <Terminal size={13} className="text-slate-400" />
            <span className="text-xs font-semibold uppercase tracking-widest text-slate-400">לוג</span>
            {isRunning && <Loader2 size={11} className="animate-spin text-slate-500" />}
          </div>
          <div ref={logRef} className="max-h-56 overflow-y-auto space-y-0.5" dir="ltr">
            {progress.map((line, i) => (
              <p key={i} className="font-mono text-xs text-green-400 break-all">{line}</p>
            ))}
          </div>
        </div>
      )}

      {/* Error */}
      {isFailed && (
        <div className="mt-4 flex items-start gap-2 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          <AlertCircle size={16} className="mt-0.5 shrink-0" />
          <span>{result?.error || 'הסריקה נכשלה'}</span>
        </div>
      )}

      {/* Results */}
      {isDone && result && (
        <div className="mt-5 space-y-4">

          {/* Stats */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: 'דפים נסרקו',   value: result.pages_crawled },
              { label: 'קבצים נמצאו',  value: result.files_found },
              { label: 'קבצים הורדו',  value: result.files_downloaded },
            ].map(s => (
              <div key={s.label} className="rounded-xl border border-slate-200 bg-white p-4 text-center">
                <p className="text-2xl font-black text-slate-900">{s.value}</p>
                <p className="text-xs text-slate-500">{s.label}</p>
              </div>
            ))}
          </div>

          {/* Category summary pills */}
          {result.categories && Object.keys(result.categories).length > 0 && (
            <div className="flex flex-wrap gap-2">
              {Object.entries(result.categories).map(([cat, count]) => {
                const cfg = CAT_CONFIG[cat] || {};
                const Icon = cfg.icon || FileText;
                return (
                  <div key={cat} className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold ${cfg.color || 'text-slate-600 bg-slate-50 border-slate-200'}`}>
                    <Icon size={11} />
                    {cfg.label || cat}: {count}
                  </div>
                );
              })}
            </div>
          )}

          {/* Download all as ZIP */}
          {files.length > 0 && siteKey && (
            <div className="flex gap-2">
              <a
                href={`${API}/api/v1/crawl/zip/${siteKey}`}
                className="flex items-center gap-2 rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-bold text-white hover:bg-slate-700 transition"
                download
              >
                <Package size={14} /> הורד הכל כ-ZIP ({files.length} קבצים)
              </a>
              <div className="flex items-center gap-1.5 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-500">
                <FolderOpen size={13} />
                {result.download_dir}
              </div>
            </div>
          )}

          {/* Files list with tabs */}
          {files.length > 0 && (
            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4">
              {/* Tabs */}
              <div className="mb-3 flex flex-wrap gap-1">
                {tabs.map(t => (
                  <button
                    key={t.id}
                    onClick={() => setActiveTab(t.id)}
                    className={`rounded-lg px-3 py-1.5 text-xs font-semibold transition ${
                      activeTab === t.id
                        ? 'bg-white text-slate-900 shadow-sm ring-1 ring-slate-200'
                        : 'text-slate-500 hover:text-slate-700'
                    }`}
                  >
                    {t.label} ({t.count})
                  </button>
                ))}
              </div>

              {/* File rows */}
              <div className="space-y-1.5 max-h-[500px] overflow-y-auto">
                {visibleFiles.map((f, i) => (
                  <FileRow key={i} file={f} siteKey={siteKey} />
                ))}
              </div>
            </div>
          )}

          {/* Intel summary pills */}
          {result.intel && (() => {
            const intelPills = Object.entries(INTEL_CONFIG)
              .map(([key, cfg]) => ({ key, cfg, count: result.intel[key]?.length ?? 0 }))
              .filter(({ count }) => count > 0);
            if (intelPills.length === 0) return null;
            return (
              <div className="flex flex-wrap gap-2">
                {intelPills.map(({ key, cfg, count }) => {
                  const Icon = cfg.icon;
                  return (
                    <div key={key} className={`flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-semibold ${cfg.color}`}>
                      <Icon size={11} />
                      {cfg.label}: {count}
                    </div>
                  );
                })}
              </div>
            );
          })()}

          {/* Errors */}
          {result.errors?.length > 0 && (
            <details className="rounded-xl border border-red-100 bg-red-50 p-3">
              <summary className="cursor-pointer text-xs font-semibold text-red-600">
                שגיאות ({result.errors.length})
              </summary>
              <div className="mt-2 space-y-1">
                {result.errors.map((e, i) => (
                  <p key={i} className="font-mono text-xs text-red-700 break-all">{e}</p>
                ))}
              </div>
            </details>
          )}

          {/* Intel section */}
          {result.intel && (
            <IntelSection intel={result.intel} siteHost={siteKey} />
          )}
        </div>
      )}

    </div>
  );
}
