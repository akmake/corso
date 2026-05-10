import { useState, useRef, useEffect } from 'react';
import {
  ShieldCheck, Globe, Rocket, Search, Zap, Radio, Eye,
  Loader2, ChevronDown, ChevronUp, RefreshCw,
  AlertTriangle, AlertCircle, Info, CheckCircle2, XCircle,
  Terminal, Wifi, Download, FileText,
  FolderSearch, Users, Server, Lock, ShoppingCart, Crosshair, Cloud
} from 'lucide-react';
import { startScan, getJob, getToolsStatus } from '../utils/webintApi';
import toast from 'react-hot-toast';

// ── Report generation ──────────────────────────────────────────────────────────
function buildHtmlReport(toolLabel, result) {
  const now = new Date().toLocaleString('he-IL');
  const target = result?.target || result?.domain || result?.host || '—';
  const findings = result?.findings || [];
  const summary  = result?.summary  || {};

  const SEV_HEB = { critical:'קריטי', high:'גבוה', medium:'בינוני', low:'נמוך', info:'מידע' };
  const SEV_COLOR = {
    critical:'#ef4444', high:'#f97316', medium:'#eab308', low:'#3b82f6', info:'#6b7280',
  };

  const escHtml = s => String(s ?? '')
    .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

  const findingRows = findings.map(f => {
    const color = SEV_COLOR[f.severity] || '#6b7280';
    const evRows = (f.evidence || []).map(e =>
      `<div style="background:#111;color:#4ade80;font-family:monospace;font-size:12px;
        padding:6px 10px;border-radius:4px;margin:3px 0;word-break:break-all;white-space:pre-wrap;">${escHtml(e)}</div>`
    ).join('');
    const rec = f.recommendation
      ? `<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:8px 12px;margin-top:8px;">
           <b style="color:#166534;">המלצה:</b>
           <div style="color:#166534;font-size:13px;margin-top:4px;white-space:pre-wrap;">${escHtml(f.recommendation)}</div>
         </div>`
      : '';
    return `
      <div style="border:1px solid ${color}33;border-radius:10px;margin:8px 0;overflow:hidden;">
        <div style="background:${color}18;padding:12px 16px;display:flex;align-items:center;gap:10px;">
          <span style="background:${color};color:#fff;font-size:11px;font-weight:700;
            padding:2px 8px;border-radius:20px;">${escHtml(SEV_HEB[f.severity] || f.severity)}</span>
          <b style="color:${color};font-size:14px;">${escHtml(f.title)}</b>
        </div>
        <div style="background:#fff;padding:12px 16px;">
          <p style="color:#374151;font-size:13px;margin:0 0 8px;">${escHtml(f.description)}</p>
          ${evRows ? `<div style="margin:6px 0;"><b style="color:#6b7280;font-size:11px;text-transform:uppercase;letter-spacing:.05em;">עדות</b>${evRows}</div>` : ''}
          ${rec}
        </div>
      </div>`;
  }).join('');

  const summaryBadges = Object.entries(SEV_HEB).map(([k, label]) => {
    const count = summary[k] || 0;
    const color = SEV_COLOR[k];
    return `<div style="border:1px solid ${color}55;background:${color}11;border-radius:8px;
      padding:12px;text-align:center;min-width:80px;">
      <div style="font-size:28px;font-weight:900;color:${color};">${count}</div>
      <div style="font-size:12px;color:${color};">${label}</div>
    </div>`;
  }).join('');

  return `<!DOCTYPE html>
<html dir="rtl" lang="he">
<head>
  <meta charset="UTF-8">
  <title>דוח אבטחה — ${escHtml(target)}</title>
  <style>
    * { box-sizing: border-box; }
    body { font-family: Arial, 'Segoe UI', sans-serif; background:#f8fafc; color:#1e293b;
           max-width:900px; margin:0 auto; padding:30px 20px; }
    @media print { body { background: white; } }
  </style>
</head>
<body>
  <div style="border-bottom:3px solid #0f172a;padding-bottom:20px;margin-bottom:24px;">
    <h1 style="margin:0 0 6px;font-size:26px;color:#0f172a;">דוח ביקורת אבטחה</h1>
    <p style="margin:0;color:#64748b;font-size:14px;">
      כלי: ${escHtml(toolLabel)} &nbsp;|&nbsp;
      יעד: <b>${escHtml(target)}</b> &nbsp;|&nbsp;
      תאריך: ${now} &nbsp;|&nbsp;
      סה"כ ממצאים: <b>${findings.length}</b>
    </p>
  </div>

  <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:28px;">${summaryBadges}</div>

  ${findings.length
    ? `<h2 style="font-size:16px;color:#374151;margin-bottom:12px;">ממצאים</h2>${findingRows}`
    : `<div style="background:#f0fdf4;border:1px solid #bbf7d0;border-radius:10px;padding:20px;color:#166534;text-align:center;">
         <b>לא נמצאו ממצאים — האתר נראה תקין</b></div>`
  }

  <div style="margin-top:30px;border-top:1px solid #e2e8f0;padding-top:12px;
    color:#94a3b8;font-size:12px;text-align:center;">
    נוצר ע"י WEBINT Security Platform
  </div>
</body>
</html>`;
}

function downloadReport(toolLabel, result) {
  try {
    const html = buildHtmlReport(toolLabel, result);
    const target = (result?.target || result?.domain || 'report').replace(/[^a-zA-Z0-9.-]/g, '_');
    const date = new Date().toISOString().split('T')[0];
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `security-report_${target}_${date}.html`;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch {
    toast.error('שגיאה בהורדת הדוח');
  }
}

function downloadJson(toolLabel, result) {
  try {
    const target = (result?.target || result?.domain || 'report').replace(/[^a-zA-Z0-9.-]/g, '_');
    const date = new Date().toISOString().split('T')[0];
    const blob = new Blob(
      [JSON.stringify({ tool: toolLabel, generated: new Date().toISOString(), ...result }, null, 2)],
      { type: 'application/json' }
    );
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `report_${target}_${date}.json`;
    a.click();
    URL.revokeObjectURL(a.href);
  } catch {
    toast.error('שגיאה בהורדת הדוח');
  }
}

const POLL_MS = 1500;

// ── Tool → external-tools mapping ──────────────────────────────────────────────
const TOOL_DEPS = {
  audit:       ['nuclei','nikto','sqlmap','dalfox','testssl','commix','wafw00f','arjun'],
  domain:      ['subfinder','amass','httpx'],
  deep_domain: ['subfinder','amass','httpx','theHarvester','trufflehog'],
  dirfuzz:     ['ffuf','feroxbuster'],
  rustscan:    ['rustscan'],
  masscan:     ['masscan'],
  pentest:     ['nuclei','nikto','sqlmap','dalfox','testssl','commix','wafw00f','arjun','ffuf','feroxbuster'],
};

const MODE_STYLE = {
  docker: { dot: 'bg-violet-500', label: 'Docker',  ring: 'ring-violet-300' },
  python: { dot: 'bg-emerald-500', label: 'Python', ring: 'ring-emerald-300' },
  native: { dot: 'bg-sky-500',    label: 'Native',  ring: 'ring-sky-300' },
};

// ── Tool definitions ───────────────────────────────────────────────────────────
const TOOLS = [
  {
    id: 'audit',
    label: 'ביקורת אבטחה',
    icon: ShieldCheck,
    color: 'text-red-600 bg-red-50 border-red-200',
    placeholder: 'https://example.com',
    description: 'SQLi, XSS, TLS, headers, WAF, Nikto, Nuclei, SQLmap, Dalfox, Commix, Arjun',
  },
  {
    id: 'domain',
    label: 'מודיעין דומיין',
    icon: Globe,
    color: 'text-blue-600 bg-blue-50 border-blue-200',
    placeholder: 'example.com',
    description: 'DNS, WHOIS, SSL, תת-דומיינים (Subfinder+Amass), httpx probe',
  },
  {
    id: 'deep_domain',
    label: 'סריקת דומיין מעמיקה',
    icon: Rocket,
    color: 'text-purple-600 bg-purple-50 border-purple-200',
    placeholder: 'example.com',
    description: 'Dorking, Playwright, theHarvester, Amass, httpx, TruffleHog',
  },
  {
    id: 'web',
    label: 'חילוץ מאתר',
    icon: Search,
    color: 'text-emerald-600 bg-emerald-50 border-emerald-200',
    placeholder: 'https://example.com',
    description: 'חילוץ מיילים, טלפונים, טכנולוגיות',
  },
  {
    id: 'quick',
    label: 'בדיקת פורטים',
    icon: Zap,
    color: 'text-amber-600 bg-amber-50 border-amber-200',
    placeholder: '192.168.1.1 או domain.com',
    description: 'בדיקת פורטים נפוצים (HTTP, SSH, RDP, DB...)',
  },
  {
    id: 'rustscan',
    label: 'RustScan — 65K פורטים',
    icon: Rocket,
    color: 'text-orange-600 bg-orange-50 border-orange-200',
    placeholder: '192.168.1.1 או domain.com',
    description: 'סריקת כל 65,535 פורטים תוך שניות (Docker)',
  },
  {
    id: 'masscan',
    label: 'Masscan — סריקה מסיבית',
    icon: Radio,
    color: 'text-red-600 bg-red-50 border-red-200',
    placeholder: '10.0.0.0/24 או IP',
    description: 'סריקת טווח IP/פורטים ב-10M packets/sec (Docker)',
  },
  {
    id: 'network',
    label: 'סריקת רשת LAN',
    icon: Radio,
    color: 'text-cyan-600 bg-cyan-50 border-cyan-200',
    placeholder: '',
    description: 'כל המכשירים ברשת המקומית (דורש nmap)',
    noInput: true,
  },
  {
    id: 'torSearch',
    label: 'Dark Web',
    icon: Eye,
    color: 'text-slate-600 bg-slate-100 border-slate-300',
    placeholder: 'מונח חיפוש...',
    description: 'חיפוש ב-.onion דרך Ahmia',
  },
  {
    id: 'dirfuzz',
    label: 'Directory Fuzzing',
    icon: FolderSearch,
    color: 'text-violet-600 bg-violet-50 border-violet-200',
    placeholder: 'https://example.com',
    description: 'ffuf + feroxbuster — admin, .env, backup, .git, recursive',
  },
  {
    id: 'idor',
    label: 'IDOR',
    icon: Users,
    color: 'text-pink-600 bg-pink-50 border-pink-200',
    placeholder: 'https://example.com',
    description: 'גישה לנתוני משתמשים אחרים דרך מניפולציית ID',
  },
  {
    id: 'ssrf',
    label: 'SSRF',
    icon: Server,
    color: 'text-teal-600 bg-teal-50 border-teal-200',
    placeholder: 'https://example.com',
    description: 'גרימת השרת לפנות לכתובות פנימיות / cloud metadata',
  },
  {
    id: 'authtest',
    label: 'Auth & Rate Limiting',
    icon: Lock,
    color: 'text-rose-600 bg-rose-50 border-rose-200',
    placeholder: 'https://example.com',
    description: 'ברירות מחדל, SQL bypass, brute force, JWT',
  },
  {
    id: 'bizlogic',
    label: 'Business Logic',
    icon: ShoppingCart,
    color: 'text-lime-600 bg-lime-50 border-lime-200',
    placeholder: 'https://example.com',
    description: 'מחיר שלילי, כמות שלילית, עקיפת תשלום',
  },
  {
    id: 'baas',
    label: 'BaaS Scanner',
    icon: Cloud,
    color: 'text-indigo-600 bg-indigo-50 border-indigo-200',
    placeholder: 'https://example.com',
    description: 'Supabase / Firebase — RLS, Edge Functions, הרשמות, upload, storage',
  },
  {
    id: 'pentest',
    label: 'Pentest מלא',
    icon: Crosshair,
    color: 'text-white bg-slate-900 border-slate-700',
    placeholder: 'https://example.com',
    description: 'כל 5 הבדיקות יחד — דוח מלא',
  },
];

// ── Severity config ────────────────────────────────────────────────────────────
const SEV = {
  critical: { label: 'קריטי',  bg: 'bg-red-100',    text: 'text-red-800',    border: 'border-red-300',    icon: XCircle,        dot: 'bg-red-500'    },
  high:     { label: 'גבוה',   bg: 'bg-orange-100', text: 'text-orange-800', border: 'border-orange-300', icon: AlertTriangle,  dot: 'bg-orange-500' },
  medium:   { label: 'בינוני', bg: 'bg-yellow-100', text: 'text-yellow-800', border: 'border-yellow-300', icon: AlertCircle,    dot: 'bg-yellow-500' },
  low:      { label: 'נמוך',   bg: 'bg-blue-50',    text: 'text-blue-800',   border: 'border-blue-200',   icon: Info,           dot: 'bg-blue-400'   },
  info:     { label: 'מידע',   bg: 'bg-slate-50',   text: 'text-slate-700',  border: 'border-slate-200',  icon: Info,           dot: 'bg-slate-400'  },
};

// ── Small components ───────────────────────────────────────────────────────────
function SeverityBadge({ sev }) {
  const s = SEV[sev] || SEV.info;
  return (
    <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-bold ${s.bg} ${s.text}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} />
      {s.label}
    </span>
  );
}

function FindingCard({ f }) {
  const [open, setOpen] = useState(false);
  const s = SEV[f.severity] || SEV.info;
  const Icon = s.icon;
  return (
    <div className={`rounded-xl border ${s.border} overflow-hidden`}>
      <button
        onClick={() => setOpen(o => !o)}
        className={`flex w-full items-start gap-3 px-4 py-3 text-right ${s.bg} hover:brightness-95 transition`}
      >
        <Icon size={16} className={`mt-0.5 shrink-0 ${s.text}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <SeverityBadge sev={f.severity} />
            <span className={`text-sm font-semibold ${s.text}`}>{f.title}</span>
          </div>
          {!open && <p className="mt-0.5 line-clamp-1 text-xs opacity-70">{f.description}</p>}
        </div>
        {open ? <ChevronUp size={14} className="shrink-0 mt-1 opacity-50" /> : <ChevronDown size={14} className="shrink-0 mt-1 opacity-50" />}
      </button>
      {open && (
        <div className="border-t border-current border-opacity-10 bg-white px-4 py-3 space-y-2">
          <p className="text-sm text-slate-700">{f.description}</p>
          {f.evidence?.length > 0 && (
            <div>
              <p className="mb-1 text-xs font-semibold text-slate-500 uppercase tracking-wide">עדות</p>
              <div className="space-y-1">
                {f.evidence.map((e, i) => {
                  const isHeader = e.startsWith('---') && e.endsWith('---');
                  const isBody = i > 0 && f.evidence[i - 1]?.startsWith('---');
                  if (isHeader) return (
                    <p key={i} className="text-xs font-bold text-slate-400 uppercase tracking-wide mt-2">{e}</p>
                  );
                  if (isBody) return (
                    <pre key={i} className="rounded bg-slate-900 px-3 py-2 font-mono text-xs text-green-300 break-all whitespace-pre-wrap max-h-64 overflow-y-auto">{e}</pre>
                  );
                  return (
                    <p key={i} className="rounded bg-slate-900 px-3 py-1.5 font-mono text-xs text-green-400 break-all">{e}</p>
                  );
                })}
              </div>
            </div>
          )}
          {f.recommendation && (
            <div className="rounded-lg bg-emerald-50 border border-emerald-200 px-3 py-2">
              <p className="text-xs font-semibold text-emerald-700 mb-0.5">המלצה</p>
              <p className="text-xs text-emerald-800">{f.recommendation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AuditResults({ data }) {
  const { summary, findings = [] } = data;
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const grouped = order.reduce((acc, s) => {
    acc[s] = findings.filter(f => f.severity === s);
    return acc;
  }, {});

  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="grid grid-cols-5 gap-2">
        {order.map(s => {
          const cfg = SEV[s];
          const count = summary?.[s] || 0;
          return (
            <div key={s} className={`rounded-xl border ${cfg.border} ${cfg.bg} px-3 py-2 text-center`}>
              <p className={`text-xl font-black ${cfg.text}`}>{count}</p>
              <p className={`text-xs font-medium ${cfg.text} opacity-75`}>{cfg.label}</p>
            </div>
          );
        })}
      </div>

      {/* Findings by severity */}
      {order.map(s => grouped[s].length > 0 && (
        <div key={s}>
          <p className="mb-2 text-xs font-bold uppercase tracking-widest text-slate-400">
            {SEV[s].label} ({grouped[s].length})
          </p>
          <div className="space-y-2">
            {grouped[s].map((f, i) => <FindingCard key={i} f={f} />)}
          </div>
        </div>
      ))}

      {findings.length === 0 && (
        <div className="flex items-center gap-2 rounded-xl bg-emerald-50 p-4 text-emerald-700">
          <CheckCircle2 size={18} />
          <span className="font-semibold">לא נמצאו ממצאים — האתר נראה תקין</span>
        </div>
      )}
    </div>
  );
}

function GenericResults({ data }) {
  if (!data || typeof data !== 'object') return null;
  const render = (val, depth = 0) => {
    if (val === null || val === undefined) return <span className="text-slate-400">—</span>;
    if (typeof val === 'boolean') return <span className={val ? 'text-emerald-600' : 'text-red-500'}>{val ? 'כן' : 'לא'}</span>;
    if (typeof val !== 'object') return <span className="font-mono text-xs break-all">{String(val)}</span>;
    if (Array.isArray(val)) {
      if (!val.length) return <span className="text-slate-400 text-xs">ריק</span>;
      if (typeof val[0] !== 'object') return (
        <div className="flex flex-wrap gap-1 mt-1">
          {val.slice(0, 30).map((v, i) => (
            <span key={i} className="rounded bg-slate-100 px-2 py-0.5 font-mono text-xs text-slate-700">{String(v)}</span>
          ))}
          {val.length > 30 && <span className="text-xs text-slate-400">+{val.length - 30} נוספים</span>}
        </div>
      );
      return <div className="space-y-1 mt-1">{val.slice(0, 10).map((v, i) => <div key={i} className="rounded border border-slate-100 bg-slate-50 p-2">{render(v, depth + 1)}</div>)}</div>;
    }
    return (
      <table className="w-full text-sm mt-1">
        <tbody>
          {Object.entries(val).filter(([, v]) => v !== null && v !== undefined && v !== '').map(([k, v]) => (
            <tr key={k} className="border-b border-slate-100 last:border-0">
              <td className="py-1.5 pr-3 font-medium text-slate-500 whitespace-nowrap align-top w-36 text-xs">{k}</td>
              <td className="py-1.5 align-top">{render(v, depth + 1)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  };
  return <div className="rounded-xl border border-slate-200 bg-white p-4">{render(data)}</div>;
}

// ── Findings-only results (for dirfuzz / idor / ssrf / authtest / bizlogic) ───
function FindingsResults({ data }) {
  const findings = data?.findings || [];
  const order = ['critical', 'high', 'medium', 'low', 'info'];

  // Compute summary from findings array
  const summary = order.reduce((acc, s) => {
    acc[s] = findings.filter(f => f.severity === s).length;
    return acc;
  }, {});

  const grouped = order.reduce((acc, s) => {
    acc[s] = findings.filter(f => f.severity === s);
    return acc;
  }, {});

  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="grid grid-cols-5 gap-2">
        {order.map(s => {
          const cfg = SEV[s];
          return (
            <div key={s} className={`rounded-xl border ${cfg.border} ${cfg.bg} px-3 py-2 text-center`}>
              <p className={`text-xl font-black ${cfg.text}`}>{summary[s] || 0}</p>
              <p className={`text-xs font-medium ${cfg.text} opacity-75`}>{cfg.label}</p>
            </div>
          );
        })}
      </div>

      {order.map(s => grouped[s].length > 0 && (
        <div key={s}>
          <p className="mb-2 text-xs font-bold uppercase tracking-widest text-slate-400">
            {SEV[s].label} ({grouped[s].length})
          </p>
          <div className="space-y-2">
            {grouped[s].map((f, i) => <FindingCard key={i} f={f} />)}
          </div>
        </div>
      ))}

      {findings.length === 0 && (
        <div className="flex items-center gap-2 rounded-xl bg-emerald-50 p-4 text-emerald-700">
          <CheckCircle2 size={18} />
          <span className="font-semibold">לא נמצאו ממצאים</span>
        </div>
      )}
    </div>
  );
}

// ── Pentest full results ───────────────────────────────────────────────────────
const PENTEST_SECTIONS = [
  { key: 'dir_fuzzing', label: 'Directory Fuzzing', icon: FolderSearch, color: 'text-violet-600' },
  { key: 'idor',        label: 'IDOR',              icon: Users,         color: 'text-pink-600'   },
  { key: 'ssrf',        label: 'SSRF',              icon: Server,        color: 'text-teal-600'   },
  { key: 'auth',        label: 'Auth & Rate Limit', icon: Lock,          color: 'text-rose-600'   },
  { key: 'biz_logic',   label: 'Business Logic',    icon: ShoppingCart,  color: 'text-lime-600'   },
];

function PentestResults({ data }) {
  const { summary = {}, target } = data;
  const order = ['critical', 'high', 'medium', 'low'];

  return (
    <div className="space-y-6">
      {/* Overall summary */}
      <div className="rounded-2xl border border-slate-200 bg-white p-4">
        <p className="mb-3 text-xs font-bold uppercase tracking-widest text-slate-400">סיכום כללי — {target}</p>
        <div className="grid grid-cols-4 gap-2">
          {order.map(s => {
            const cfg = SEV[s];
            return (
              <div key={s} className={`rounded-xl border ${cfg.border} ${cfg.bg} px-3 py-3 text-center`}>
                <p className={`text-2xl font-black ${cfg.text}`}>{summary[s] || 0}</p>
                <p className={`text-xs font-medium ${cfg.text} opacity-75`}>{cfg.label}</p>
              </div>
            );
          })}
        </div>
      </div>

      {/* Per-section findings */}
      {PENTEST_SECTIONS.map(({ key, label, icon: Icon, color }) => {
        const findings = data[key] || [];
        const vulns = findings.filter(f => f.severity !== 'info');
        if (findings.length === 0) return null;

        return (
          <div key={key} className="rounded-2xl border border-slate-200 bg-white overflow-hidden">
            <div className="flex items-center gap-2 border-b border-slate-100 bg-slate-50 px-4 py-3">
              <Icon size={15} className={color} />
              <span className="font-bold text-slate-800 text-sm">{label}</span>
              {vulns.length > 0 && (
                <span className="mr-auto rounded-full bg-red-100 px-2 py-0.5 text-xs font-bold text-red-700">
                  {vulns.length} ממצאים
                </span>
              )}
            </div>
            <div className="p-3 space-y-2">
              {findings.map((f, i) => <FindingCard key={i} f={f} />)}
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────────
export default function SecurityPage() {
  const [selected, setSelected] = useState(null);
  const [input, setInput]       = useState('');
  const [status, setStatus]     = useState('idle');
  const [progress, setProgress] = useState([]);
  const [result, setResult]     = useState(null);
  const [jobId, setJobId]       = useState(null);
  const [toolsStatus, setToolsStatus] = useState({});

  const logRef  = useRef(null);
  const pollRef = useRef(null);

  useEffect(() => {
    getToolsStatus().then(r => setToolsStatus(r.data?.tools || {})).catch(() => {});
  }, []);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [progress]);

  useEffect(() => {
    if (!jobId || status !== 'running') return;
    pollRef.current = setInterval(async () => {
      try {
        const { data } = await getJob(jobId);
        setProgress(data.progress || []);
        if (data.status === 'completed') {
          clearInterval(pollRef.current);
          setStatus('completed');
          setResult(data.result);
          toast.success('הסריקה הושלמה');
        } else if (data.status === 'failed') {
          clearInterval(pollRef.current);
          setStatus('failed');
          setResult(data.result);
        }
      } catch { /* ignore */ }
    }, POLL_MS);
    return () => clearInterval(pollRef.current);
  }, [jobId, status]);

  function selectTool(tool) {
    setSelected(tool);
    setInput('');
    setStatus('idle');
    setProgress([]);
    setResult(null);
    setJobId(null);
    clearInterval(pollRef.current);
  }

  async function handleScan() {
    if (!selected || (status === 'running')) return;
    if (!selected.noInput && !input.trim()) return;
    setStatus('running');
    setProgress([]);
    setResult(null);
    try {
      const { data } = await startScan[selected.id](input.trim());
      setJobId(data.job_id);
    } catch {
      setStatus('failed');
      toast.error('שגיאה בהתחלת הסריקה');
    }
  }

  const isRunning  = status === 'running';
  const isDone     = status === 'completed';
  const isFailed   = status === 'failed';

  return (
    <div className="mx-auto max-w-4xl px-4 pt-20 pb-16" dir="rtl">

      {/* Header */}
      <div className="mb-8 flex items-center gap-3 pt-4">
        <div className="rounded-xl bg-slate-900 p-3 text-white">
          <ShieldCheck size={22} />
        </div>
        <div>
          <h1 className="text-2xl font-black text-slate-900">אבטחה ורשת</h1>
          <p className="text-sm text-slate-500">בדיקות אבטחה, מודיעין דומיינים, סריקת רשת</p>
        </div>
      </div>

      {/* Tool grid */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-4">
        {TOOLS.map(tool => {
          const Icon = tool.icon;
          const active = selected?.id === tool.id;
          return (
            <button
              key={tool.id}
              onClick={() => selectTool(tool)}
              disabled={isRunning}
              className={`rounded-2xl border p-4 text-right transition-all duration-150 disabled:opacity-50 ${
                active
                  ? `${tool.color} ring-2 ring-offset-1 ring-slate-900 shadow-sm`
                  : 'border-slate-200 bg-white hover:border-slate-300 hover:shadow-sm'
              }`}
            >
              <div className={`mb-2 inline-flex rounded-lg border p-2 ${active ? tool.color : 'border-slate-100 bg-slate-50 text-slate-500'}`}>
                <Icon size={16} strokeWidth={2} />
              </div>
              <p className={`text-sm font-bold ${active ? '' : 'text-slate-800'}`}>{tool.label}</p>
              <p className={`mt-0.5 text-xs leading-snug ${active ? 'opacity-70' : 'text-slate-400'}`}>{tool.description}</p>
              {/* Tool availability dots */}
              {TOOL_DEPS[tool.id] && Object.keys(toolsStatus).length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1">
                  {TOOL_DEPS[tool.id].map(t => {
                    const info = toolsStatus[t];
                    const avail = info?.available;
                    const ms = MODE_STYLE[info?.mode] || null;
                    return (
                      <span
                        key={t}
                        title={`${t}: ${avail ? (info.mode || 'available') : 'לא זמין'}`}
                        className={`inline-flex items-center gap-1 rounded-full border px-1.5 py-0.5 text-[10px] font-medium leading-none ${
                          avail
                            ? ms
                              ? `${ms.dot.replace('bg-','text-')} bg-white border-slate-200`
                              : 'text-emerald-600 bg-white border-slate-200'
                            : 'text-red-400 bg-white border-red-200 line-through'
                        }`}
                      >
                        <span className={`h-1.5 w-1.5 rounded-full ${avail ? (ms?.dot || 'bg-emerald-500') : 'bg-red-400'}`} />
                        {t}
                      </span>
                    );
                  })}
                </div>
              )}
            </button>
          );
        })}
      </div>

      {/* Input + Run */}
      {selected && (
        <div className="mt-5 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
          <div className="mb-3 flex items-center gap-2">
            <selected.icon size={15} className="text-slate-500" />
            <span className="font-semibold text-slate-800">{selected.label}</span>
          </div>

          {!selected.noInput && (
            <div className="mb-3">
              <input
                type="text"
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && !isRunning && handleScan()}
                placeholder={selected.placeholder}
                disabled={isRunning}
                className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-900 placeholder:text-slate-400 focus:border-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-100 disabled:opacity-50"
                dir="ltr"
              />
            </div>
          )}

          <div className="flex gap-2">
            <button
              onClick={handleScan}
              disabled={isRunning || (!selected.noInput && !input.trim())}
              className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-slate-900 py-3 text-sm font-bold text-white transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
            >
              {isRunning
                ? <><Loader2 size={15} className="animate-spin" /> סורק...</>
                : <><ShieldCheck size={15} /> הפעל סריקה</>}
            </button>
            {(isDone || isFailed) && (
              <button
                onClick={() => selectTool(selected)}
                className="rounded-xl border border-slate-200 p-3 text-slate-500 hover:bg-slate-50"
                title="נקה"
              >
                <RefreshCw size={15} />
              </button>
            )}
          </div>
        </div>
      )}

      {/* Progress log */}
      {progress.length > 0 && (
        <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950 p-4">
          <div className="mb-2 flex items-center gap-2">
            <Terminal size={13} className="text-slate-400" />
            <span className="text-xs font-semibold uppercase tracking-widest text-slate-400">לוג</span>
            {isRunning && <Loader2 size={11} className="animate-spin text-slate-500" />}
          </div>
          <div ref={logRef} className="max-h-48 overflow-y-auto space-y-0.5" dir="ltr">
            {progress.map((line, i) => (
              <p key={i} className="font-mono text-xs text-green-400 break-all">{line}</p>
            ))}
          </div>
        </div>
      )}

      {/* Results */}
      {isDone && result && !result.error && (
        <div className="mt-5">
          <div className="mb-3 flex items-center justify-between">
            <p className="text-xs font-bold uppercase tracking-widest text-slate-400">תוצאות</p>
            <div className="flex gap-2">
              <button
                onClick={() => downloadReport(selected?.label || 'Scan', result)}
                className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition"
                title="הורד דוח HTML"
              >
                <FileText size={13} /> הורד דוח HTML
              </button>
              <button
                onClick={() => downloadJson(selected?.label || 'Scan', result)}
                className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition"
                title="הורד JSON"
              >
                <Download size={13} /> JSON
              </button>
            </div>
          </div>
          {selected?.id === 'pentest'
            ? <PentestResults data={result} />
            : ['audit'].includes(selected?.id)
            ? <AuditResults data={result} />
            : ['dirfuzz', 'idor', 'ssrf', 'authtest', 'bizlogic', 'baas'].includes(selected?.id)
            ? <FindingsResults data={result} />
            : <GenericResults data={result} />}
        </div>
      )}

      {(isFailed || result?.error) && (
        <div className="mt-4 flex items-start gap-2 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          <XCircle size={16} className="mt-0.5 shrink-0" />
          <span>{result?.error || 'הסריקה נכשלה'}</span>
        </div>
      )}

    </div>
  );
}
