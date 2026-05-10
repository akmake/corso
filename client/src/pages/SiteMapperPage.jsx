import { useState, useRef, useEffect } from 'react';
import {
  Map, Loader2, Terminal, RefreshCw, AlertCircle,
  CheckCircle2, XCircle, Globe, Archive, Code2,
  FileSearch, List, Zap, Copy, FileJson, FileText,
  ChevronDown, ChevronUp, Filter,
} from 'lucide-react';
import axios from 'axios';
import toast from 'react-hot-toast';

const API    = 'http://localhost:8000';
const client = axios.create({ baseURL: API });
const POLL_MS = 1500;

const SOURCE_CONFIG = {
  crawl:     { label: 'BFS Crawl',       color: 'bg-blue-100 text-blue-700',    icon: Globe },
  sitemap:   { label: 'Sitemap',          color: 'bg-green-100 text-green-700',  icon: List },
  robots:    { label: 'robots.txt',       color: 'bg-yellow-100 text-yellow-700',icon: FileSearch },
  wayback:   { label: 'Wayback Machine',  color: 'bg-purple-100 text-purple-700',icon: Archive },
  js_routes: { label: 'JS Routes',        color: 'bg-pink-100 text-pink-700',    icon: Code2 },
  wordlist:  { label: 'Wordlist',         color: 'bg-orange-100 text-orange-700',icon: Zap },
  unknown:   { label: 'אחר',              color: 'bg-slate-100 text-slate-600',  icon: Globe },
};

const STATUS_COLOR = {
  200: 'text-green-600',
  201: 'text-green-600',
  301: 'text-blue-500',
  302: 'text-blue-500',
  307: 'text-blue-500',
  308: 'text-blue-500',
  403: 'text-amber-600',
  404: 'text-red-400',
  500: 'text-red-600',
  0:   'text-slate-400',
};

function statusColor(code) {
  return STATUS_COLOR[code] || 'text-slate-500';
}

function statusLabel(code) {
  if (code === 0)   return '—';
  if (code === 200) return '200 OK';
  if (code === 403) return '403 Forbidden';
  if (code >= 300 && code < 400) return `${code} Redirect`;
  if (code === 404) return '404 Not Found';
  if (code >= 500) return `${code} Error`;
  return String(code);
}

function SourceBadge({ src }) {
  const cfg = SOURCE_CONFIG[src] || SOURCE_CONFIG.unknown;
  return (
    <span className={`inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-semibold ${cfg.color}`}>
      {cfg.label}
    </span>
  );
}

function OptionToggle({ label, checked, onChange, description }) {
  return (
    <label className="flex cursor-pointer items-start gap-3 rounded-xl border border-slate-200 bg-white p-3 hover:border-slate-300 transition">
      <input
        type="checkbox"
        checked={checked}
        onChange={e => onChange(e.target.checked)}
        className="mt-0.5 h-4 w-4 rounded accent-slate-800"
      />
      <div>
        <p className="text-sm font-semibold text-slate-800">{label}</p>
        {description && <p className="text-xs text-slate-400 mt-0.5">{description}</p>}
      </div>
    </label>
  );
}

function copyText(text) {
  navigator.clipboard.writeText(text).catch(() => {});
}

function exportFile(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const a = Object.assign(document.createElement('a'), {
    href: URL.createObjectURL(blob), download: filename,
  });
  a.click();
}

export default function SiteMapperPage() {
  const [url, setUrl]             = useState('');
  const [maxPages, setMaxPages]   = useState(200);
  const [useWayback, setUseWayback]     = useState(true);
  const [useWordlist, setUseWordlist]   = useState(true);
  const [useJsRoutes, setUseJsRoutes]   = useState(true);
  const [verifyAll, setVerifyAll]       = useState(true);
  const [status, setStatus]       = useState('idle');
  const [progress, setProgress]   = useState([]);
  const [result, setResult]       = useState(null);
  const [jobId, setJobId]         = useState(null);

  // Filters
  const [filterSource, setFilterSource] = useState('all');
  const [filterStatus, setFilterStatus] = useState('alive');
  const [filterText, setFilterText]     = useState('');
  const [showLog, setShowLog]           = useState(false);

  const logRef  = useRef(null);
  const pollRef = useRef(null);

  useEffect(() => {
    if (logRef.current && showLog) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [progress, showLog]);

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
          toast.success(`הושלם! ${data.result?.total ?? 0} URLs נמצאו`);
        } else if (data.status === 'failed') {
          clearInterval(pollRef.current);
          setStatus('failed');
          setResult(data.result);
        }
      } catch { /* ignore */ }
    }, POLL_MS);
    return () => clearInterval(pollRef.current);
  }, [jobId, status]);

  async function handleStart() {
    if (!url.trim() || status === 'running') return;
    setStatus('running');
    setProgress([]);
    setResult(null);
    setFilterSource('all');
    setFilterStatus('alive');
    setFilterText('');
    try {
      const { data } = await client.post('/api/v1/sitemap/start', {
        url: url.trim(),
        max_crawl_pages: maxPages,
        use_wayback: useWayback,
        use_wordlist: useWordlist,
        use_js_routes: useJsRoutes,
        verify_all: verifyAll,
      });
      setJobId(data.job_id);
    } catch {
      setStatus('failed');
      toast.error('שגיאה בהתחלת המיפוי');
    }
  }

  function reset() {
    clearInterval(pollRef.current);
    setStatus('idle');
    setProgress([]);
    setResult(null);
    setJobId(null);
  }

  const isRunning = status === 'running';
  const isDone    = status === 'completed';
  const isFailed  = status === 'failed';

  // Filter pages
  const pages = result?.pages || [];
  const filteredPages = pages.filter(p => {
    if (filterSource !== 'all' && !p.sources.includes(filterSource)) return false;
    if (filterStatus === 'alive' && ![200,201,301,302,307,308,403].includes(p.status)) return false;
    if (filterStatus === 'dead'  && [200,201,301,302,307,308,403].includes(p.status)) return false;
    if (filterStatus === '200'   && p.status !== 200) return false;
    if (filterStatus === '403'   && p.status !== 403) return false;
    if (filterText && !p.url.toLowerCase().includes(filterText.toLowerCase())) return false;
    return true;
  });

  function handleExportTxt() {
    exportFile(filteredPages.map(p => p.url).join('\n'), 'pages.txt', 'text/plain');
  }
  function handleExportJson() {
    exportFile(JSON.stringify(filteredPages, null, 2), 'pages.json', 'application/json');
  }
  function handleExportCsv() {
    const rows = ['URL,Status,Sources', ...filteredPages.map(p =>
      `"${p.url}",${p.status},"${p.sources.join('|')}"`
    )];
    exportFile(rows.join('\n'), 'pages.csv', 'text/csv');
  }

  const availableSources = result
    ? Object.keys(result.by_source || {}).filter(k => (result.by_source[k] || 0) > 0)
    : [];

  return (
    <div className="mx-auto max-w-5xl px-4 pt-20 pb-16" dir="rtl">

      {/* Header */}
      <div className="mb-8 flex items-center gap-3 pt-4">
        <div className="rounded-xl bg-slate-900 p-3 text-white">
          <Map size={22} />
        </div>
        <div>
          <h1 className="text-2xl font-black text-slate-900">מיפוי דפי אתר</h1>
          <p className="text-sm text-slate-500">מוצא כמה שיותר דפים בדומיין — crawl, sitemap, robots, Wayback Machine, JS routes, wordlist</p>
        </div>
      </div>

      {/* Config */}
      <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm space-y-5">

        {/* URL */}
        <div>
          <label className="mb-1.5 block text-xs font-semibold uppercase tracking-wide text-slate-500">כתובת האתר</label>
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

        {/* Methods */}
        <div>
          <label className="mb-2 block text-xs font-semibold uppercase tracking-wide text-slate-500">שיטות גילוי</label>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            <OptionToggle label="BFS Crawl" checked={true} onChange={() => {}}
              description="עוקב אחרי קישורים (תמיד פעיל)" />
            <OptionToggle label="Sitemap" checked={true} onChange={() => {}}
              description="sitemap.xml רקורסיבי" />
            <OptionToggle label="robots.txt" checked={true} onChange={() => {}}
              description="Disallow/Allow paths" />
            <OptionToggle label="Wayback Machine" checked={useWayback} onChange={setUseWayback}
              description="כל URL שנארכב אי פעם" />
            <OptionToggle label="JS Routes" checked={useJsRoutes} onChange={setUseJsRoutes}
              description="Routes מתוך bundle.js" />
            <OptionToggle label="Wordlist Fuzzing" checked={useWordlist} onChange={setUseWordlist}
              description="600+ paths נפוצים" />
          </div>
        </div>

        {/* Options row */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="mb-1 block text-xs font-semibold text-slate-500">מקסימום דפים ל-Crawl</label>
            <input
              type="number" min="10" max="2000" value={maxPages}
              onChange={e => setMaxPages(Number(e.target.value))}
              disabled={isRunning}
              className="w-full rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm focus:outline-none focus:border-slate-400 disabled:opacity-50"
            />
          </div>
          <div className="flex items-end">
            <OptionToggle label="בדוק סטטוס HTTP לכל URL" checked={verifyAll} onChange={setVerifyAll}
              description="HEAD request לכל כתובת שנמצאה" />
          </div>
        </div>

        {/* Actions */}
        <div className="flex gap-2">
          <button
            onClick={handleStart}
            disabled={isRunning || !url.trim()}
            className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-slate-900 py-3 text-sm font-bold text-white transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {isRunning
              ? <><Loader2 size={15} className="animate-spin" /> ממפה...</>
              : <><Map size={15} /> התחל מיפוי</>}
          </button>
          {(isDone || isFailed) && (
            <button onClick={reset} className="rounded-xl border border-slate-200 p-3 text-slate-500 hover:bg-slate-50">
              <RefreshCw size={15} />
            </button>
          )}
        </div>
      </div>

      {/* Log */}
      {progress.length > 0 && (
        <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950 p-4">
          <button
            onClick={() => setShowLog(v => !v)}
            className="mb-2 flex w-full items-center gap-2 text-left"
          >
            <Terminal size={13} className="text-slate-400" />
            <span className="flex-1 text-xs font-semibold uppercase tracking-widest text-slate-400">לוג</span>
            {isRunning && <Loader2 size={11} className="animate-spin text-slate-500" />}
            {showLog ? <ChevronUp size={13} className="text-slate-500" /> : <ChevronDown size={13} className="text-slate-500" />}
          </button>
          {showLog && (
            <div ref={logRef} className="max-h-56 overflow-y-auto space-y-0.5" dir="ltr">
              {progress.map((line, i) => (
                <p key={i} className="font-mono text-xs text-green-400 break-all">{line}</p>
              ))}
            </div>
          )}
          {!showLog && (
            <p className="font-mono text-xs text-green-400 truncate" dir="ltr">
              {progress[progress.length - 1] || ''}
            </p>
          )}
        </div>
      )}

      {/* Error */}
      {isFailed && (
        <div className="mt-4 flex items-start gap-2 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          <AlertCircle size={16} className="mt-0.5 shrink-0" />
          <span>{result?.error || 'המיפוי נכשל'}</span>
        </div>
      )}

      {/* Results */}
      {isDone && result && (
        <div className="mt-5 space-y-4">

          {/* Stats */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label: 'סה"כ URLs',    value: result.total,                 icon: Globe,         color: 'text-slate-900' },
              { label: 'דפים חיים',    value: result.alive,                 icon: CheckCircle2,  color: 'text-green-600' },
              { label: 'לא מגיבים',   value: result.total - result.alive,  icon: XCircle,       color: 'text-red-500'   },
            ].map(s => (
              <div key={s.label} className="rounded-xl border border-slate-200 bg-white p-4 text-center">
                <s.icon size={18} className={`mx-auto mb-1 ${s.color}`} />
                <p className={`text-2xl font-black ${s.color}`}>{s.value}</p>
                <p className="text-xs text-slate-500">{s.label}</p>
              </div>
            ))}
            {/* By source */}
            <div className="rounded-xl border border-slate-200 bg-white p-3">
              <p className="mb-1.5 text-xs font-semibold text-slate-500">לפי מקור</p>
              <div className="space-y-1">
                {Object.entries(result.by_source || {}).map(([src, count]) => (
                  count > 0 && (
                    <div key={src} className="flex items-center justify-between">
                      <SourceBadge src={src} />
                      <span className="text-xs font-bold text-slate-700">{count}</span>
                    </div>
                  )
                ))}
              </div>
            </div>
          </div>

          {/* Table */}
          <div className="rounded-2xl border border-slate-200 bg-white shadow-sm">

            {/* Toolbar */}
            <div className="flex flex-wrap items-center gap-2 border-b border-slate-100 p-4">
              <Filter size={14} className="text-slate-400" />

              {/* Status filter */}
              <select
                value={filterStatus}
                onChange={e => setFilterStatus(e.target.value)}
                className="rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-xs font-semibold text-slate-700 focus:outline-none"
              >
                <option value="all">כל הסטטוסים</option>
                <option value="alive">חיים בלבד</option>
                <option value="dead">לא מגיבים</option>
                <option value="200">200 OK</option>
                <option value="403">403 Forbidden</option>
              </select>

              {/* Source filter */}
              <select
                value={filterSource}
                onChange={e => setFilterSource(e.target.value)}
                className="rounded-lg border border-slate-200 bg-white px-2 py-1.5 text-xs font-semibold text-slate-700 focus:outline-none"
              >
                <option value="all">כל המקורות</option>
                {availableSources.map(s => (
                  <option key={s} value={s}>{SOURCE_CONFIG[s]?.label || s}</option>
                ))}
              </select>

              {/* Text search */}
              <input
                type="text"
                placeholder="חיפוש URL..."
                value={filterText}
                onChange={e => setFilterText(e.target.value)}
                dir="ltr"
                className="flex-1 min-w-[140px] rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 text-xs focus:outline-none focus:border-slate-400"
              />

              <span className="text-xs text-slate-400 ml-auto">{filteredPages.length} תוצאות</span>

              {/* Copy all */}
              <button
                onClick={() => copyText(filteredPages.map(p => p.url).join('\n'))}
                className="flex items-center gap-1.5 rounded-lg border border-slate-200 px-2 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-50 transition"
              >
                <Copy size={12} /> העתק הכל
              </button>

              {/* Export */}
              <div className="flex gap-1">
                <button onClick={handleExportTxt}
                  className="flex items-center gap-1 rounded-lg border border-slate-200 px-2 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-50 transition">
                  <FileText size={12} /> TXT
                </button>
                <button onClick={handleExportCsv}
                  className="flex items-center gap-1 rounded-lg border border-slate-200 px-2 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-50 transition">
                  <FileText size={12} /> CSV
                </button>
                <button onClick={handleExportJson}
                  className="flex items-center gap-1 rounded-lg border border-slate-200 px-2 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-50 transition">
                  <FileJson size={12} /> JSON
                </button>
              </div>
            </div>

            {/* Rows */}
            <div className="divide-y divide-slate-50 max-h-[600px] overflow-y-auto">
              {filteredPages.length === 0 ? (
                <p className="py-8 text-center text-sm text-slate-400">אין תוצאות</p>
              ) : filteredPages.map((page, i) => (
                <div key={i} className="flex items-center gap-3 px-4 py-2 hover:bg-slate-50 transition group">
                  <span className={`shrink-0 w-16 text-center text-xs font-bold font-mono ${statusColor(page.status)}`}>
                    {statusLabel(page.status)}
                  </span>
                  <a
                    href={page.url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex-1 min-w-0 truncate text-sm text-slate-700 font-mono hover:text-blue-600 hover:underline"
                    dir="ltr"
                  >
                    {page.url}
                  </a>
                  <div className="shrink-0 flex gap-1 flex-wrap justify-end">
                    {page.sources.map(s => <SourceBadge key={s} src={s} />)}
                  </div>
                  <button
                    onClick={() => copyText(page.url)}
                    className="shrink-0 opacity-0 group-hover:opacity-100 rounded p-1 text-slate-400 hover:text-slate-700 hover:bg-slate-100 transition"
                  >
                    <Copy size={12} />
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
