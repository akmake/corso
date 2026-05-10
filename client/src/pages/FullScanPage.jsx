import { useState, useRef, useEffect, useCallback } from 'react';
import {
  ScanSearch, Globe, Shield, Bug, Mail, Phone, Key, Folder,
  ChevronDown, ChevronUp, Loader2, CheckCircle2, XCircle,
  AlertTriangle, AlertCircle, Info, Download, Terminal,
  Map, Layers, Cpu, Server, Lock, ShoppingCart, Search,
  Crosshair, FolderSearch, ExternalLink, Copy, RefreshCw,
} from 'lucide-react';
import { startScan, getJob } from '../utils/webintApi';
import toast from 'react-hot-toast';

// ── Severity helpers ────────────────────────────────────────────────────────────
const SEV = {
  critical: { label: 'קריטי',  bg: 'bg-red-100',    text: 'text-red-700',    border: 'border-red-300',    dot: 'bg-red-500'    },
  high:     { label: 'גבוה',   bg: 'bg-orange-100', text: 'text-orange-700', border: 'border-orange-300', dot: 'bg-orange-500' },
  medium:   { label: 'בינוני', bg: 'bg-yellow-100', text: 'text-yellow-700', border: 'border-yellow-300', dot: 'bg-yellow-500' },
  low:      { label: 'נמוך',   bg: 'bg-blue-100',   text: 'text-blue-700',   border: 'border-blue-300',   dot: 'bg-blue-500'   },
  info:     { label: 'מידע',   bg: 'bg-slate-100',  text: 'text-slate-600',  border: 'border-slate-200',  dot: 'bg-slate-400'  },
};

function SevBadge({ sev }) {
  const s = SEV[sev] || SEV.info;
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold ${s.bg} ${s.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  );
}

// ── Collapsible Section ─────────────────────────────────────────────────────────
function Section({ icon: Icon, title, badge, badgeColor = 'bg-slate-200 text-slate-700', children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-xl border border-slate-200 bg-white shadow-sm overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-5 py-4 text-right hover:bg-slate-50 transition-colors"
      >
        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-slate-100 text-slate-600 shrink-0">
          <Icon size={16} strokeWidth={2} />
        </span>
        <span className="flex-1 font-semibold text-slate-800 text-sm">{title}</span>
        {badge != null && (
          <span className={`rounded-full px-2.5 py-0.5 text-xs font-bold ${badgeColor}`}>{badge}</span>
        )}
        {open ? <ChevronUp size={16} className="text-slate-400" /> : <ChevronDown size={16} className="text-slate-400" />}
      </button>
      {open && <div className="border-t border-slate-100 px-5 py-4">{children}</div>}
    </div>
  );
}

// ── Finding Card ────────────────────────────────────────────────────────────────
function FindingCard({ f }) {
  const [open, setOpen] = useState(false);
  const s = SEV[f.severity] || SEV.info;
  return (
    <div className={`rounded-lg border ${s.border} overflow-hidden mb-2`}>
      <button
        onClick={() => setOpen(o => !o)}
        className={`w-full flex items-center gap-3 px-4 py-3 text-right ${s.bg} hover:brightness-95 transition`}
      >
        <SevBadge sev={f.severity} />
        <span className={`flex-1 font-medium text-sm ${s.text}`}>{f.title}</span>
        {open ? <ChevronUp size={14} className="text-slate-400" /> : <ChevronDown size={14} className="text-slate-400" />}
      </button>
      {open && (
        <div className="bg-white px-4 py-3 space-y-2 text-sm">
          {f.description && <p className="text-slate-600">{f.description}</p>}
          {f.url && (
            <p className="font-mono text-xs bg-slate-50 rounded p-2 break-all text-slate-500">{f.url}</p>
          )}
          {Array.isArray(f.evidence) && f.evidence.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-1">עדות</p>
              {f.evidence.map((e, i) => (
                <div key={i} className="font-mono text-xs bg-slate-900 text-green-400 rounded p-2 mb-1 break-all whitespace-pre-wrap">{e}</div>
              ))}
            </div>
          )}
          {f.recommendation && (
            <div className="bg-green-50 border border-green-200 rounded-lg p-3">
              <p className="text-xs font-semibold text-green-700 mb-1">המלצה</p>
              <p className="text-green-700 text-sm whitespace-pre-wrap">{f.recommendation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── KV Row ──────────────────────────────────────────────────────────────────────
function KV({ label, value }) {
  if (!value || (Array.isArray(value) && value.length === 0)) return null;
  const display = Array.isArray(value) ? value.join(', ') : String(value);
  return (
    <div className="flex gap-3 py-1.5 border-b border-slate-50 last:border-0 text-sm">
      <span className="text-slate-400 font-medium w-32 shrink-0 text-right">{label}</span>
      <span className="text-slate-800 break-all">{display}</span>
    </div>
  );
}

// ── Pill list ───────────────────────────────────────────────────────────────────
function PillList({ items, color = 'bg-slate-100 text-slate-700' }) {
  if (!items?.length) return <span className="text-slate-400 text-sm">לא נמצא</span>;
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((item, i) => (
        <span key={i} className={`rounded-full px-3 py-1 text-xs font-medium ${color}`}>{item}</span>
      ))}
    </div>
  );
}

// ── Summary Stats ───────────────────────────────────────────────────────────────
function SummaryBar({ result }) {
  const stats = [
    { label: 'Subdomains',  value: result.subdomains?.length ?? 0,   color: 'text-indigo-600',  bg: 'bg-indigo-50'  },
    { label: 'מיילים',      value: result.emails?.length ?? 0,        color: 'text-sky-600',     bg: 'bg-sky-50'     },
    { label: 'טלפונים',     value: result.phones?.length ?? 0,        color: 'text-teal-600',    bg: 'bg-teal-50'    },
    { label: 'Dorks',       value: result.dorks_total ?? 0,           color: 'text-violet-600',  bg: 'bg-violet-50'  },
    { label: 'Secrets',     value: result.secrets_count ?? 0,         color: 'text-rose-600',    bg: 'bg-rose-50'    },
    { label: 'קריטיים',     value: result.summary?.critical ?? 0,     color: 'text-red-600',     bg: 'bg-red-50'     },
    { label: 'גבוהים',      value: result.summary?.high ?? 0,         color: 'text-orange-600',  bg: 'bg-orange-50'  },
    { label: 'בינוניים',    value: result.summary?.medium ?? 0,       color: 'text-yellow-600',  bg: 'bg-yellow-50'  },
  ];
  return (
    <div className="grid grid-cols-4 gap-3 sm:grid-cols-8">
      {stats.map(s => (
        <div key={s.label} className={`rounded-xl ${s.bg} p-3 text-center`}>
          <div className={`text-2xl font-black ${s.color}`}>{s.value}</div>
          <div className={`text-xs font-medium ${s.color} opacity-80`}>{s.label}</div>
        </div>
      ))}
    </div>
  );
}

// ── Export HTML report ──────────────────────────────────────────────────────────
function exportHtml(result) {
  const esc = s => String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
  const allFindings = [
    ...(result.dir_fuzzing || []),
    ...(result.idor || []),
    ...(result.ssrf || []),
    ...(result.auth || []),
    ...(result.biz_logic || []),
    ...(result.audit_findings || []),
  ].filter(f => f.severity !== 'info');

  const SEV_COLOR = { critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', info:'#6b7280' };
  const SEV_HEB   = { critical:'קריטי', high:'גבוה', medium:'בינוני', low:'נמוך', info:'מידע' };

  const findingRows = allFindings.map(f => {
    const c = SEV_COLOR[f.severity] || '#6b7280';
    const ev = (f.evidence || []).map(e =>
      `<div style="background:#111;color:#4ade80;font-family:monospace;font-size:12px;padding:6px 10px;border-radius:4px;margin:3px 0;word-break:break-all;">${esc(e)}</div>`
    ).join('');
    return `
    <div style="border:1px solid ${c}44;border-radius:10px;margin:10px 0;overflow:hidden;">
      <div style="background:${c}18;padding:12px 16px;display:flex;align-items:center;gap:10px;">
        <span style="background:${c};color:#fff;font-size:11px;font-weight:700;padding:2px 8px;border-radius:20px;">${esc(SEV_HEB[f.severity]||f.severity)}</span>
        <b style="color:${c};font-size:14px;">${esc(f.title)}</b>
      </div>
      <div style="background:#fff;padding:12px 16px;">
        <p style="color:#374151;font-size:13px;margin:0 0 6px;">${esc(f.description)}</p>
        ${ev}
        ${f.recommendation ? `<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:8px 12px;margin-top:8px;"><b style="color:#166534;">המלצה:</b><p style="color:#166534;font-size:13px;margin:4px 0 0;white-space:pre-wrap;">${esc(f.recommendation)}</p></div>` : ''}
      </div>
    </div>`;
  }).join('');

  const subList = (result.subdomains || []).map(s => `<li style="font-family:monospace;font-size:13px;">${esc(s)}</li>`).join('');
  const emailList = (result.emails || []).map(e => `<li>${esc(e)}</li>`).join('');

  const html = `<!DOCTYPE html>
<html dir="rtl" lang="he">
<head>
  <meta charset="UTF-8">
  <title>Full Scan — ${esc(result.domain)}</title>
  <style>*{box-sizing:border-box}body{font-family:Arial,'Segoe UI',sans-serif;background:#f8fafc;color:#1e293b;max-width:960px;margin:0 auto;padding:30px 20px;}</style>
</head>
<body>
  <div style="border-bottom:3px solid #0f172a;padding-bottom:20px;margin-bottom:24px;">
    <h1 style="margin:0 0 6px;font-size:26px;color:#0f172a;">Full Scan Report</h1>
    <p style="margin:0;color:#64748b;font-size:14px;">${esc(result.target)} &nbsp;|&nbsp; ${new Date().toLocaleString('he-IL')}</p>
  </div>

  <h2 style="font-size:18px;color:#0f172a;margin-bottom:12px;">סיכום ממצאים</h2>
  <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:24px;">
    ${Object.entries(SEV_HEB).map(([k,l]) => {
      const cnt = allFindings.filter(f=>f.severity===k).length;
      const c = SEV_COLOR[k];
      return `<div style="border:1px solid ${c}44;background:${c}11;border-radius:8px;padding:12px 20px;text-align:center;"><div style="font-size:28px;font-weight:900;color:${c};">${cnt}</div><div style="font-size:12px;color:${c};">${l}</div></div>`;
    }).join('')}
  </div>

  <h2 style="font-size:18px;color:#0f172a;margin-bottom:8px;">OSINT</h2>
  <table style="width:100%;border-collapse:collapse;margin-bottom:24px;font-size:13px;">
    ${[
      ['דומיין', result.domain],
      ['IP', result.dns?.a?.[0]],
      ['מדינה', result.geolocation?.country],
      ['ארגון', result.geolocation?.org || result.whois?.org],
      ['SSL נפוג', result.ssl?.not_after],
    ].filter(([,v])=>v).map(([k,v])=>`<tr><td style="padding:6px 12px;background:#f1f5f9;font-weight:600;width:160px;">${esc(k)}</td><td style="padding:6px 12px;border-bottom:1px solid #e2e8f0;">${esc(v)}</td></tr>`).join('')}
  </table>

  ${subList ? `<h2 style="font-size:18px;color:#0f172a;margin-bottom:8px;">Subdomains (${result.subdomains.length})</h2><ul style="column-count:3;margin-bottom:24px;">${subList}</ul>` : ''}
  ${emailList ? `<h2 style="font-size:18px;color:#0f172a;margin-bottom:8px;">מיילים (${result.emails.length})</h2><ul style="margin-bottom:24px;">${emailList}</ul>` : ''}

  <h2 style="font-size:18px;color:#0f172a;margin-bottom:12px;">ממצאי אבטחה (${allFindings.length})</h2>
  ${findingRows || '<p style="color:#64748b;">לא נמצאו ממצאים משמעותיים</p>'}
</body>
</html>`;

  const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `fullscan_${result.domain}_${Date.now()}.html`;
  a.click();
}

// ═══════════════════════════════════════════════════════════════════════════════
export default function FullScanPage() {
  const [url, setUrl]         = useState('');
  const [jobId, setJobId]     = useState(null);
  const [status, setStatus]   = useState('idle'); // idle | running | completed | failed
  const [progress, setProgress] = useState([]);
  const [result, setResult]   = useState(null);
  const [elapsed, setElapsed] = useState(0);

  const pollRef    = useRef(null);
  const timerRef   = useRef(null);
  const logEndRef  = useRef(null);
  const wsRef      = useRef(null);

  // ── auto-scroll log ──
  useEffect(() => { logEndRef.current?.scrollIntoView({ behavior: 'smooth' }); }, [progress]);

  // ── elapsed timer ──
  useEffect(() => {
    if (status === 'running') {
      timerRef.current = setInterval(() => setElapsed(e => e + 1), 1000);
    } else {
      clearInterval(timerRef.current);
    }
    return () => clearInterval(timerRef.current);
  }, [status]);

  // ── WebSocket live log ──
  useEffect(() => {
    wsRef.current = new WebSocket('ws://localhost:8000/ws/jobs');
    wsRef.current.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.job_id === jobId) {
          setProgress(p => [...p, msg.msg]);
        }
      } catch {}
    };
    return () => wsRef.current?.close();
  }, [jobId]);

  // ── Poll job ──
  const pollJob = useCallback((id) => {
    pollRef.current = setInterval(async () => {
      try {
        const { data } = await getJob(id);
        if (data.status === 'completed') {
          clearInterval(pollRef.current);
          setStatus('completed');
          setResult(data.result);
          setProgress(data.progress || []);
          toast.success('הסריקה הושלמה!');
        } else if (data.status === 'failed') {
          clearInterval(pollRef.current);
          setStatus('failed');
          toast.error('הסריקה נכשלה');
        } else {
          setProgress(data.progress || []);
        }
      } catch {}
    }, 2000);
  }, []);

  useEffect(() => () => clearInterval(pollRef.current), []);

  const handleScan = async () => {
    if (!url.trim()) return toast.error('הכנס כתובת אתר');
    setStatus('running');
    setProgress([]);
    setResult(null);
    setElapsed(0);
    try {
      const { data } = await startScan.fullscan(url.trim());
      setJobId(data.job_id);
      pollJob(data.job_id);
    } catch {
      setStatus('failed');
      toast.error('שגיאה בהתחלת הסריקה');
    }
  };

  const handleKeyDown = (e) => { if (e.key === 'Enter') handleScan(); };

  const fmtElapsed = (s) => `${Math.floor(s/60).toString().padStart(2,'0')}:${(s%60).toString().padStart(2,'0')}`;

  // ── filter findings helper ──
  const nonInfo = (arr) => (arr || []).filter(f => f.severity !== 'info');

  return (
    <div className="min-h-screen bg-slate-50 pb-16 pt-24">
      <div className="mx-auto max-w-4xl px-4 sm:px-6">

        {/* ── Header ── */}
        <div className="mb-8 text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-900 text-white shadow-lg">
            <ScanSearch size={26} strokeWidth={2} />
          </div>
          <h1 className="text-3xl font-black tracking-tight text-slate-900">Full Scan</h1>
          <p className="mt-1 text-slate-500 text-sm">הכנס כתובת אתר — כל הכלים רצים אוטומטית</p>
        </div>

        {/* ── Input ── */}
        <div className="mb-6 flex gap-2">
          <input
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="https://example.com  או  example.com"
            disabled={status === 'running'}
            className="flex-1 rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm shadow-sm
                       placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-900
                       disabled:opacity-60 font-mono"
          />
          <button
            onClick={handleScan}
            disabled={status === 'running' || !url.trim()}
            className="flex items-center gap-2 rounded-xl bg-slate-900 px-5 py-3 text-sm font-semibold
                       text-white shadow-sm hover:bg-slate-700 transition disabled:opacity-50"
          >
            {status === 'running'
              ? <><Loader2 size={16} className="animate-spin" /> סורק...</>
              : <><ScanSearch size={16} /> סרוק הכל</>}
          </button>
        </div>

        {/* ── Scan covers ── */}
        {status === 'idle' && (
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 mb-8">
            {[
              { icon: Globe,      label: 'Domain Intel',   sub: 'DNS · WHOIS · SSL · Subs' },
              { icon: Search,     label: 'OSINT & Dorks',  sub: 'Playwright · Harvester' },
              { icon: Key,        label: 'Secrets',        sub: 'API keys · Tokens' },
              { icon: Shield,     label: 'Audit',          sub: 'Headers · Files' },
              { icon: FolderSearch,label: 'Dir Fuzz',      sub: '500+ נתיבים' },
              { icon: Bug,        label: 'IDOR',           sub: '35+ endpoints' },
              { icon: Crosshair,  label: 'SSRF',           sub: 'URL params' },
              { icon: Lock,       label: 'Auth & BizLogic',sub: 'Rate limit · Logic' },
            ].map(({ icon: Icon, label, sub }) => (
              <div key={label} className="rounded-xl border border-slate-200 bg-white p-4 text-center shadow-sm">
                <div className="mx-auto mb-2 flex h-8 w-8 items-center justify-center rounded-lg bg-slate-100">
                  <Icon size={15} className="text-slate-600" strokeWidth={2} />
                </div>
                <p className="font-semibold text-slate-800 text-xs">{label}</p>
                <p className="text-slate-400 text-xs mt-0.5">{sub}</p>
              </div>
            ))}
          </div>
        )}

        {/* ── Progress Log ── */}
        {(status === 'running' || progress.length > 0) && (
          <div className="mb-6 rounded-xl border border-slate-200 bg-slate-900 overflow-hidden shadow-lg">
            <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-700">
              <div className="flex items-center gap-2">
                <Terminal size={14} className="text-slate-400" />
                <span className="text-xs font-semibold text-slate-300">לוג סריקה חי</span>
              </div>
              <div className="flex items-center gap-3">
                {status === 'running' && (
                  <>
                    <span className="text-xs text-slate-400 font-mono">{fmtElapsed(elapsed)}</span>
                    <span className="flex items-center gap-1 text-xs text-emerald-400">
                      <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                      רץ
                    </span>
                  </>
                )}
                {status === 'completed' && (
                  <span className="flex items-center gap-1 text-xs text-emerald-400">
                    <CheckCircle2 size={12} /> הושלם ב-{fmtElapsed(elapsed)}
                  </span>
                )}
                {status === 'failed' && (
                  <span className="flex items-center gap-1 text-xs text-red-400">
                    <XCircle size={12} /> נכשל
                  </span>
                )}
              </div>
            </div>
            <div className="h-52 overflow-y-auto p-4 space-y-1 font-mono text-xs">
              {progress.map((line, i) => (
                <div key={i} className="text-emerald-300 leading-relaxed">
                  <span className="text-slate-500 select-none">{String(i+1).padStart(3,'0')}  </span>
                  {line}
                </div>
              ))}
              {status === 'running' && (
                <div className="text-slate-500 flex items-center gap-2">
                  <Loader2 size={10} className="animate-spin" /> ממתין לנתונים...
                </div>
              )}
              <div ref={logEndRef} />
            </div>
          </div>
        )}

        {/* ── Results ── */}
        {result && (
          <div className="space-y-4">

            {/* Summary bar */}
            <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="font-black text-lg text-slate-900">{result.domain}</h2>
                  <p className="text-slate-500 text-xs font-mono">{result.target}</p>
                  {result.page_title && <p className="text-slate-500 text-xs mt-0.5">{result.page_title}</p>}
                </div>
                <button
                  onClick={() => exportHtml(result)}
                  className="flex items-center gap-2 rounded-lg border border-slate-200 px-3 py-2
                             text-xs font-semibold text-slate-600 hover:bg-slate-50 transition"
                >
                  <Download size={13} /> יצוא HTML
                </button>
              </div>
              <SummaryBar result={result} />
            </div>

            {/* Domain / OSINT */}
            <Section icon={Globe} title="Domain Intelligence" badge={result.subdomains?.length} defaultOpen>
              <div className="space-y-1 mb-4">
                <KV label="IP"         value={result.dns?.a?.[0]} />
                <KV label="MX"         value={result.dns?.mx} />
                <KV label="NS"         value={result.dns?.ns} />
                <KV label="WHOIS Org"  value={result.whois?.org || result.whois?.registrant_org} />
                <KV label="Registrar"  value={result.whois?.registrar} />
                <KV label="Created"    value={result.whois?.creation_date} />
                <KV label="SSL נפוג"   value={result.ssl?.not_after} />
                <KV label="SSL Issuer" value={result.ssl?.issuer} />
                <KV label="מדינה"      value={result.geolocation?.country} />
                <KV label="עיר"        value={result.geolocation?.city} />
                <KV label="ISP"        value={result.geolocation?.isp || result.geolocation?.org} />
                <KV label="Shodan"     value={result.shodan?.ports?.join(', ')} />
              </div>
              {result.subdomains?.length > 0 && (
                <>
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">
                    Subdomains ({result.subdomains.length})
                  </p>
                  <div className="grid grid-cols-2 gap-1 sm:grid-cols-3">
                    {result.subdomains.map((s, i) => (
                      <span key={i} className="rounded-md bg-slate-50 border border-slate-100 px-2 py-1 font-mono text-xs text-slate-600 truncate">
                        {s}
                      </span>
                    ))}
                  </div>
                </>
              )}
            </Section>

            {/* Contacts */}
            <Section
              icon={Mail}
              title="מיילים, טלפונים וטכנולוגיות"
              badge={(result.emails?.length || 0) + (result.phones?.length || 0)}
            >
              {result.emails?.length > 0 && (
                <div className="mb-4">
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">מיילים ({result.emails.length})</p>
                  <PillList items={result.emails} color="bg-sky-50 text-sky-700" />
                </div>
              )}
              {result.phones?.length > 0 && (
                <div className="mb-4">
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">טלפונים ({result.phones.length})</p>
                  <PillList items={result.phones} color="bg-teal-50 text-teal-700" />
                </div>
              )}
              {result.technologies?.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2">טכנולוגיות</p>
                  <PillList items={result.technologies} color="bg-violet-50 text-violet-700" />
                </div>
              )}
              {!result.emails?.length && !result.phones?.length && !result.technologies?.length && (
                <p className="text-slate-400 text-sm">לא נמצא מידע</p>
              )}
            </Section>

            {/* Dorks */}
            <Section
              icon={Search}
              title="Google Dorks"
              badge={result.dorks_total}
              badgeColor="bg-violet-100 text-violet-700"
            >
              {result.dorks_data?.length > 0 ? (
                <div className="space-y-2">
                  {result.dorks_data.map((d, i) => (
                    <div key={i} className="rounded-lg bg-slate-50 border border-slate-100 p-3 text-sm">
                      <p className="font-medium text-slate-700">{d.query || d.title || d.url}</p>
                      {d.url && d.url !== d.query && (
                        <p className="font-mono text-xs text-slate-400 mt-1 truncate">{d.url}</p>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-slate-400 text-sm">לא נמצאו תוצאות</p>
              )}
            </Section>

            {/* Secrets */}
            <Section
              icon={Key}
              title="Secrets חשופים"
              badge={result.secrets_count}
              badgeColor={result.secrets_count > 0 ? 'bg-rose-100 text-rose-700' : 'bg-slate-100 text-slate-500'}
            >
              {result.secrets_count > 0 ? (
                <div className="space-y-2">
                  {Object.entries(result.secrets || {}).map(([type, items]) =>
                    Array.isArray(items) && items.length > 0 ? (
                      <div key={type}>
                        <p className="text-xs font-semibold text-slate-500 uppercase mb-1">{type} ({items.length})</p>
                        {items.slice(0, 5).map((item, i) => (
                          <div key={i} className="font-mono text-xs bg-slate-900 text-rose-300 rounded p-2 mb-1 break-all">{String(item)}</div>
                        ))}
                        {items.length > 5 && <p className="text-xs text-slate-400">ועוד {items.length - 5}...</p>}
                      </div>
                    ) : null
                  )}
                </div>
              ) : (
                <p className="text-slate-400 text-sm">לא נמצאו secrets חשופים</p>
              )}
            </Section>

            {/* Audit */}
            <Section
              icon={Shield}
              title="Security Audit"
              badge={nonInfo(result.audit_findings).length}
              badgeColor={nonInfo(result.audit_findings).length > 0 ? 'bg-orange-100 text-orange-700' : 'bg-slate-100 text-slate-500'}
            >
              {nonInfo(result.audit_findings).length > 0 ? (
                nonInfo(result.audit_findings).map((f, i) => <FindingCard key={i} f={f} />)
              ) : (
                <p className="text-slate-400 text-sm">לא נמצאו ממצאים משמעותיים</p>
              )}
            </Section>

            {/* Dir Fuzzing */}
            <Section
              icon={FolderSearch}
              title="Directory Fuzzing"
              badge={nonInfo(result.dir_fuzzing).length}
              badgeColor={nonInfo(result.dir_fuzzing).length > 0 ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-500'}
            >
              {nonInfo(result.dir_fuzzing).length > 0 ? (
                nonInfo(result.dir_fuzzing).map((f, i) => <FindingCard key={i} f={f} />)
              ) : (
                <p className="text-slate-400 text-sm">לא נמצאו נתיבים חשופים</p>
              )}
            </Section>

            {/* IDOR */}
            <Section
              icon={Bug}
              title="IDOR Vulnerabilities"
              badge={nonInfo(result.idor).length}
              badgeColor={nonInfo(result.idor).length > 0 ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500'}
            >
              {nonInfo(result.idor).length > 0 ? (
                nonInfo(result.idor).map((f, i) => <FindingCard key={i} f={f} />)
              ) : (
                <p className="text-slate-400 text-sm">לא נמצאו ממצאי IDOR</p>
              )}
            </Section>

            {/* SSRF */}
            <Section
              icon={Crosshair}
              title="SSRF Vulnerabilities"
              badge={nonInfo(result.ssrf).length}
              badgeColor={nonInfo(result.ssrf).length > 0 ? 'bg-red-100 text-red-700' : 'bg-slate-100 text-slate-500'}
            >
              {nonInfo(result.ssrf).length > 0 ? (
                nonInfo(result.ssrf).map((f, i) => <FindingCard key={i} f={f} />)
              ) : (
                <p className="text-slate-400 text-sm">לא נמצאו ממצאי SSRF</p>
              )}
            </Section>

            {/* Auth */}
            <Section
              icon={Lock}
              title="Authentication & Rate Limiting"
              badge={nonInfo(result.auth).length}
              badgeColor={nonInfo(result.auth).length > 0 ? 'bg-orange-100 text-orange-700' : 'bg-slate-100 text-slate-500'}
            >
              {nonInfo(result.auth).length > 0 ? (
                nonInfo(result.auth).map((f, i) => <FindingCard key={i} f={f} />)
              ) : (
                <p className="text-slate-400 text-sm">לא נמצאו ממצאי auth</p>
              )}
            </Section>

            {/* Biz Logic */}
            <Section
              icon={ShoppingCart}
              title="Business Logic"
              badge={nonInfo(result.biz_logic).length}
              badgeColor={nonInfo(result.biz_logic).length > 0 ? 'bg-orange-100 text-orange-700' : 'bg-slate-100 text-slate-500'}
            >
              {nonInfo(result.biz_logic).length > 0 ? (
                nonInfo(result.biz_logic).map((f, i) => <FindingCard key={i} f={f} />)
              ) : (
                <p className="text-slate-400 text-sm">לא נמצאו ממצאי Business Logic</p>
              )}
            </Section>

          </div>
        )}
      </div>
    </div>
  );
}
