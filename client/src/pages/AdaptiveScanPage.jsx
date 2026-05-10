import { useState, useRef, useEffect, useCallback } from 'react';
import { startScan, getJob } from '../utils/webintApi';
import {
  Brain, Play, ChevronDown, ChevronRight, AlertTriangle, Shield, Info,
  Zap, Target, GitBranch, Link2, CheckCircle, XCircle, Clock, Layers,
  Download, Terminal, Eye
} from 'lucide-react';

// ── Severity helpers ───────────────────────────────────────────────────────────

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const SEV_STYLES = {
  critical: {
    bg: 'bg-red-50', border: 'border-red-200', badge: 'bg-red-600 text-white',
    dot: 'bg-red-500', icon: XCircle, label: 'קריטי', text: 'text-red-700',
  },
  high: {
    bg: 'bg-orange-50', border: 'border-orange-200', badge: 'bg-orange-500 text-white',
    dot: 'bg-orange-500', icon: AlertTriangle, label: 'גבוה', text: 'text-orange-700',
  },
  medium: {
    bg: 'bg-yellow-50', border: 'border-yellow-200', badge: 'bg-yellow-500 text-white',
    dot: 'bg-yellow-500', icon: AlertTriangle, label: 'בינוני', text: 'text-yellow-700',
  },
  low: {
    bg: 'bg-blue-50', border: 'border-blue-200', badge: 'bg-blue-500 text-white',
    dot: 'bg-blue-400', icon: Info, label: 'נמוך', text: 'text-blue-700',
  },
  info: {
    bg: 'bg-slate-50', border: 'border-slate-200', badge: 'bg-slate-400 text-white',
    dot: 'bg-slate-400', icon: Info, label: 'מידע', text: 'text-slate-600',
  },
};

const sev = (s) => SEV_STYLES[s] || SEV_STYLES.info;

// ── Phase indicator ────────────────────────────────────────────────────────────

const PHASES = [
  { id: 1, label: 'טביעת אצבע', icon: Eye,       desc: 'headers, paths, SSL, DNS, tech stack' },
  { id: 2, label: 'בדיקות ממוקדות', icon: Target,    desc: 'מבוסס על מה שנמצא בשלב 1' },
  { id: 3, label: 'ניצול מעמיק', icon: Zap,       desc: 'SQLi עמוק, XSS advanced, CORS chains' },
  { id: 4, label: 'שרשראות תקיפה', icon: GitBranch, desc: 'ניתוח שילובי ממצאים' },
];

function PhaseBar({ currentPhase, status }) {
  return (
    <div className="flex items-center gap-1 mb-6">
      {PHASES.map((p, i) => {
        const done = currentPhase > p.id || status === 'completed';
        const active = currentPhase === p.id && status === 'running';
        const Icon = p.icon;
        return (
          <div key={p.id} className="flex items-center flex-1">
            <div className={`flex-1 rounded-lg px-3 py-2 border transition-all ${
              done    ? 'bg-green-50 border-green-200' :
              active  ? 'bg-blue-50 border-blue-300 ring-1 ring-blue-300' :
                        'bg-slate-50 border-slate-200 opacity-50'
            }`}>
              <div className="flex items-center gap-2">
                {done ? (
                  <CheckCircle size={14} className="text-green-500 flex-shrink-0" />
                ) : active ? (
                  <div className="w-3.5 h-3.5 rounded-full border-2 border-blue-500 border-t-transparent animate-spin flex-shrink-0" />
                ) : (
                  <Icon size={14} className="text-slate-400 flex-shrink-0" />
                )}
                <div className="min-w-0">
                  <div className={`text-xs font-semibold truncate ${
                    done ? 'text-green-700' : active ? 'text-blue-700' : 'text-slate-400'
                  }`}>{p.label}</div>
                  <div className="text-[10px] text-slate-400 truncate hidden sm:block">{p.desc}</div>
                </div>
              </div>
            </div>
            {i < PHASES.length - 1 && (
              <ChevronRight size={14} className="text-slate-300 flex-shrink-0 mx-0.5" />
            )}
          </div>
        );
      })}
    </div>
  );
}

// ── Decision log (what adaptive choices were made) ─────────────────────────────

function DecisionLog({ decisions }) {
  if (!decisions?.length) return null;
  return (
    <div className="mb-6 rounded-xl border border-blue-200 bg-blue-50 p-4">
      <div className="flex items-center gap-2 mb-3">
        <Brain size={16} className="text-blue-600" />
        <span className="text-sm font-semibold text-blue-800">החלטות אלגוריתמיות — למה נבחרו הבדיקות האלה</span>
      </div>
      <ul className="space-y-1.5">
        {decisions.map((d, i) => (
          <li key={i} className="flex items-start gap-2 text-sm text-blue-700">
            <Zap size={12} className="mt-0.5 flex-shrink-0 text-blue-500" />
            {d}
          </li>
        ))}
      </ul>
    </div>
  );
}

// ── Attack chain card ──────────────────────────────────────────────────────────

function ChainCard({ chain }) {
  const [open, setOpen] = useState(false);
  const style = sev(chain.severity);
  return (
    <div className={`rounded-xl border ${style.border} ${style.bg} overflow-hidden`}>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-start gap-3 p-4 text-left"
      >
        <GitBranch size={16} className={`mt-0.5 flex-shrink-0 ${style.text}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-sm text-slate-800">{chain.title}</span>
            <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${style.badge}`}>
              {style.label}
            </span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5">{chain.description}</p>
        </div>
        {open ? <ChevronDown size={14} className="text-slate-400 mt-1" /> : <ChevronRight size={14} className="text-slate-400 mt-1" />}
      </button>
      {open && (
        <div className="px-4 pb-4">
          <ol className="space-y-2">
            {chain.steps.map((step, i) => (
              <li key={i} className="flex items-start gap-2 text-sm text-slate-700">
                <span className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold flex-shrink-0 ${style.badge}`}>
                  {i + 1}
                </span>
                {step}
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}

// ── Finding card ───────────────────────────────────────────────────────────────

function FindingCard({ finding }) {
  const [open, setOpen] = useState(false);
  const style = sev(finding.severity);
  const Icon = style.icon;

  return (
    <div className={`rounded-xl border ${style.border} ${style.bg} overflow-hidden`}>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-start gap-3 p-3.5 text-left hover:brightness-98 transition-all"
      >
        <Icon size={15} className={`mt-0.5 flex-shrink-0 ${style.text}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-semibold text-sm text-slate-800">{finding.title}</span>
            <span className={`text-[10px] font-semibold px-2 py-0.5 rounded-full ${style.badge}`}>
              {style.label}
            </span>
            <span className="text-[10px] text-slate-400 font-medium px-1.5 py-0.5 bg-slate-100 rounded-md">
              {finding.category}
            </span>
            <span className="text-[10px] text-slate-400">שלב {finding.phase}</span>
          </div>
          <p className="text-xs text-slate-500 mt-0.5 line-clamp-2">{finding.description}</p>
        </div>
        {open ? <ChevronDown size={13} className="text-slate-400 mt-0.5" /> : <ChevronRight size={13} className="text-slate-400 mt-0.5" />}
      </button>
      {open && (
        <div className="px-4 pb-4 space-y-3 border-t border-current/10">
          {finding.evidence?.length > 0 && (
            <div>
              <div className="text-xs font-semibold text-slate-500 mb-1 mt-3">עדויות</div>
              <div className="space-y-1">
                {finding.evidence.map((e, i) => (
                  <div key={i} className="font-mono text-xs bg-slate-900 text-green-400 rounded-lg px-3 py-1.5 break-all">
                    {e}
                  </div>
                ))}
              </div>
            </div>
          )}
          {finding.recommendation && (
            <div>
              <div className="text-xs font-semibold text-slate-500 mb-1">המלצה</div>
              <div className="text-sm text-slate-700 bg-white rounded-lg px-3 py-2 border border-slate-200">
                {finding.recommendation}
              </div>
            </div>
          )}
          {finding.tags?.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {finding.tags.map(tag => (
                <span key={tag} className="text-[10px] px-2 py-0.5 bg-slate-200 text-slate-600 rounded-full">
                  #{tag}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Summary bar ────────────────────────────────────────────────────────────────

function SummaryBar({ summary }) {
  if (!summary) return null;
  const items = [
    { key: 'critical', label: 'קריטי', color: 'bg-red-600' },
    { key: 'high',     label: 'גבוה',  color: 'bg-orange-500' },
    { key: 'medium',   label: 'בינוני', color: 'bg-yellow-500' },
    { key: 'low',      label: 'נמוך',  color: 'bg-blue-500' },
    { key: 'info',     label: 'מידע',  color: 'bg-slate-400' },
  ];
  return (
    <div className="flex flex-wrap gap-2 mb-6 p-4 bg-slate-50 rounded-xl border border-slate-200">
      <div className="flex items-center gap-1.5 mr-2">
        <Shield size={15} className="text-slate-600" />
        <span className="text-sm font-semibold text-slate-700">סיכום: {summary.total} ממצאים</span>
      </div>
      {items.map(({ key, label, color }) => (
        summary[key] > 0 && (
          <div key={key} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-full ${color} text-white text-xs font-semibold`}>
            {summary[key]} {label}
          </div>
        )
      ))}
    </div>
  );
}

// ── Attack surface panel ───────────────────────────────────────────────────────

function SurfacePanel({ surface }) {
  const [open, setOpen] = useState(false);
  if (!surface || Object.keys(surface).length === 0) return null;

  const items = [
    { key: 'technologies',  label: 'טכנולוגיות', render: v => v.join(', ') },
    { key: 'cms',           label: 'CMS',         render: v => v },
    { key: 'backend',       label: 'Backend',     render: v => v },
    { key: 'baas',          label: 'BaaS',        render: v => v },
    { key: 'server_version',label: 'שרת',         render: v => v },
    { key: 'ips',           label: 'IP',          render: v => v.join(', ') },
    { key: 'ssl_days_left', label: 'SSL (ימים)',  render: v => `${v} ימים` },
    { key: 'wp_version',    label: 'WP גרסה',    render: v => v },
    { key: 'wp_plugins',    label: 'WP Plugins',  render: v => v.join(', ') },
    { key: 'login_pages',   label: 'Login pages', render: v => `${v.length} נמצאו` },
    { key: 'api_endpoints', label: 'API endpoints',render: v => `${v.length} נמצאו` },
    { key: 'forms',         label: 'טפסים',       render: v => `${v.length} נמצאו` },
    { key: 'secrets_found', label: 'Secrets',     render: v => `${v} ממצאים` },
    { key: 'cors_wildcard', label: 'CORS Wildcard', render: () => 'כן ⚠️' },
    { key: 'spa',           label: 'SPA',         render: () => 'כן' },
    { key: 'git_exposed',   label: 'Git חשוף',   render: () => 'כן 🚨' },
  ].filter(({ key }) => {
    const v = surface[key];
    return v !== undefined && v !== null && v !== false && !(Array.isArray(v) && v.length === 0);
  });

  return (
    <div className="mb-6 rounded-xl border border-slate-200 overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 bg-slate-50 hover:bg-slate-100 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Layers size={15} className="text-slate-600" />
          <span className="text-sm font-semibold text-slate-700">פני שטח מותקפים שנמפו</span>
          <span className="text-xs bg-slate-200 text-slate-600 px-2 py-0.5 rounded-full">{items.length} פריטים</span>
        </div>
        {open ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
      </button>
      {open && (
        <div className="grid grid-cols-2 md:grid-cols-3 gap-px bg-slate-200">
          {items.map(({ key, label, render }) => (
            <div key={key} className="bg-white px-3 py-2">
              <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wide">{label}</div>
              <div className="text-sm text-slate-800 font-medium mt-0.5 break-all">{render(surface[key])}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Live terminal ──────────────────────────────────────────────────────────────

function LiveTerminal({ logs }) {
  const bottomRef = useRef(null);
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  return (
    <div className="bg-slate-900 rounded-xl p-4 font-mono text-xs h-48 overflow-y-auto border border-slate-700">
      {logs.map((line, i) => {
        const isPhase = line.startsWith('▶') || line.startsWith('✔');
        const isDecision = line.includes('⚡');
        const isError = line.toLowerCase().includes('error') || line.includes('❌');
        return (
          <div key={i} className={`leading-6 ${
            isPhase    ? 'text-cyan-400 font-bold' :
            isDecision ? 'text-yellow-400' :
            isError    ? 'text-red-400' :
                         'text-green-400'
          }`}>
            <span className="text-slate-600 select-none">{String(i + 1).padStart(3, ' ')} </span>
            {line}
          </div>
        );
      })}
      <div ref={bottomRef} />
    </div>
  );
}

// ── Export ─────────────────────────────────────────────────────────────────────

function buildHtmlReport(url, result) {
  const { findings = [], chains = [], summary = {}, attack_surface = {}, decision_log = [] } = result;
  const sorted = [...findings].sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));

  const escHtml = s => String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

  const findingsHtml = sorted.map(f => `
    <div class="finding sev-${f.severity}">
      <div class="finding-header">
        <span class="badge ${f.severity}">${escHtml(SEV_STYLES[f.severity]?.label || f.severity)}</span>
        <strong>${escHtml(f.title)}</strong>
        <span class="cat">${escHtml(f.category)}</span>
        <span class="phase">שלב ${f.phase}</span>
      </div>
      <p>${escHtml(f.description)}</p>
      ${f.evidence?.length ? `<div class="evidence">${f.evidence.map(e => `<code>${escHtml(e)}</code>`).join('')}</div>` : ''}
      ${f.recommendation ? `<div class="rec">💡 ${escHtml(f.recommendation)}</div>` : ''}
    </div>
  `).join('');

  const chainsHtml = chains.map(c => `
    <div class="chain sev-${c.severity}">
      <strong>${escHtml(c.title)}</strong>
      <p>${escHtml(c.description)}</p>
      <ol>${c.steps.map(s => `<li>${escHtml(s)}</li>`).join('')}</ol>
    </div>
  `).join('');

  return `<!DOCTYPE html><html dir="rtl" lang="he"><head><meta charset="utf-8">
<title>דוח אבטחה אדפטיבי — ${escHtml(url)}</title>
<style>
  body{font-family:Arial,sans-serif;background:#f8fafc;color:#1e293b;margin:0;padding:24px;direction:rtl}
  h1{color:#0f172a;border-bottom:2px solid #3b82f6;padding-bottom:8px}
  h2{color:#1e40af;margin-top:32px}
  .summary{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
  .summary span{padding:4px 12px;border-radius:20px;color:#fff;font-weight:700;font-size:13px}
  .critical-c{background:#dc2626}.high-c{background:#f97316}.medium-c{background:#eab308}
  .low-c{background:#3b82f6}.info-c{background:#94a3b8}
  .finding{border-radius:8px;padding:12px 16px;margin:8px 0;border:1px solid}
  .sev-critical{background:#fef2f2;border-color:#fca5a5}
  .sev-high{background:#fff7ed;border-color:#fdba74}
  .sev-medium{background:#fefce8;border-color:#fde047}
  .sev-low{background:#eff6ff;border-color:#93c5fd}
  .sev-info{background:#f8fafc;border-color:#cbd5e1}
  .finding-header{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:4px}
  .badge{padding:2px 8px;border-radius:10px;font-size:11px;font-weight:700;color:#fff}
  .badge.critical{background:#dc2626}.badge.high{background:#f97316}
  .badge.medium{background:#eab308;color:#000}.badge.low{background:#3b82f6}
  .badge.info{background:#94a3b8}
  .cat{font-size:11px;background:#e2e8f0;padding:2px 8px;border-radius:8px;color:#475569}
  .phase{font-size:11px;color:#94a3b8}
  .evidence{background:#0f172a;border-radius:6px;padding:8px 12px;margin:8px 0}
  .evidence code{display:block;color:#4ade80;font-size:11px;white-space:pre-wrap;word-break:break-all;margin:2px 0}
  .rec{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:8px 12px;font-size:13px;margin-top:8px}
  .chain{border-radius:8px;padding:12px 16px;margin:8px 0;border:1px solid #c7d2fe;background:#eef2ff}
  .chain ol{margin:8px 0;padding-right:20px}
  .decision{background:#eff6ff;border:1px solid #bfdbfe;padding:6px 12px;border-radius:6px;font-size:12px;margin:4px 0}
  @media print{body{padding:0}}
</style></head><body>
<h1>🛡️ דוח אבטחה אדפטיבי</h1>
<p><strong>יעד:</strong> ${escHtml(url)}</p>
<p><strong>תאריך:</strong> ${new Date().toLocaleString('he-IL')}</p>

<div class="summary">
  ${summary.critical ? `<span class="critical-c">${summary.critical} קריטי</span>` : ''}
  ${summary.high ? `<span class="high-c">${summary.high} גבוה</span>` : ''}
  ${summary.medium ? `<span class="medium-c" style="color:#000">${summary.medium} בינוני</span>` : ''}
  ${summary.low ? `<span class="low-c">${summary.low} נמוך</span>` : ''}
  ${summary.info ? `<span class="info-c">${summary.info} מידע</span>` : ''}
  <span style="background:#475569;padding:4px 12px;border-radius:20px;color:#fff;font-weight:700;font-size:13px">סה"כ ${summary.total}</span>
</div>

${decision_log.length ? `<h2>🧠 החלטות אלגוריתמיות</h2>${decision_log.map(d => `<div class="decision">⚡ ${escHtml(d)}</div>`).join('')}` : ''}

${chains.length ? `<h2>🔗 שרשראות תקיפה (${chains.length})</h2>${chainsHtml}` : ''}

<h2>📋 כל הממצאים (${findings.length})</h2>
${findingsHtml}
</body></html>`;
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function AdaptiveScanPage() {
  const [url, setUrl] = useState('');
  const [jobId, setJobId] = useState(null);
  const [status, setStatus] = useState('idle'); // idle | running | completed | failed
  const [logs, setLogs] = useState([]);
  const [result, setResult] = useState(null);
  const [currentPhase, setCurrentPhase] = useState(0);
  const [elapsed, setElapsed] = useState(0);
  const [activeTab, setActiveTab] = useState('findings');
  const [filterSev, setFilterSev] = useState('all');
  const pollRef = useRef(null);
  const timerRef = useRef(null);
  const startTimeRef = useRef(null);

  const detectPhase = useCallback((logLines) => {
    const last = [...logLines].reverse().find(l =>
      l.includes('שלב 1/4') || l.includes('שלב 2/4') || l.includes('שלב 3/4') || l.includes('שלב 4/4')
    );
    if (!last) return 1;
    if (last.includes('4/4')) return 4;
    if (last.includes('3/4')) return 3;
    if (last.includes('2/4')) return 2;
    return 1;
  }, []);

  const stopPolling = useCallback(() => {
    clearInterval(pollRef.current);
    clearInterval(timerRef.current);
    pollRef.current = null;
    timerRef.current = null;
  }, []);

  const handleScan = async () => {
    if (!url.trim() || status === 'running') return;
    setStatus('running');
    setLogs([]);
    setResult(null);
    setCurrentPhase(1);
    setElapsed(0);

    try {
      const res = await startScan.adaptive(url.trim());
      const id = res.data.job_id;
      setJobId(id);
      startTimeRef.current = Date.now();

      timerRef.current = setInterval(() => {
        setElapsed(Math.floor((Date.now() - startTimeRef.current) / 1000));
      }, 1000);

      pollRef.current = setInterval(async () => {
        try {
          const job = await getJob(id);
          const { status: s, progress, result: r } = job.data;
          setLogs(progress || []);
          setCurrentPhase(detectPhase(progress || []));
          if (s === 'completed') {
            stopPolling();
            setStatus('completed');
            setResult(r);
            setCurrentPhase(5);
          } else if (s === 'failed') {
            stopPolling();
            setStatus('failed');
          }
        } catch {
          // transient error — keep polling
        }
      }, 1500);
    } catch (err) {
      setStatus('failed');
      setLogs([`שגיאה: ${err.message}`]);
    }
  };

  useEffect(() => () => stopPolling(), [stopPolling]);

  const findings = result?.findings || [];
  const chains = result?.chains || [];

  const filteredFindings = findings
    .filter(f => filterSev === 'all' || f.severity === filterSev)
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9));

  const handleExport = () => {
    const html = buildHtmlReport(url, result);
    const blob = new Blob([html], { type: 'text/html;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `adaptive-scan-${url.replace(/[^a-z0-9]/gi, '_')}.html`;
    a.click();
  };

  const formatElapsed = (s) => {
    const m = Math.floor(s / 60), sec = s % 60;
    return m > 0 ? `${m}:${String(sec).padStart(2, '0')}` : `${sec}s`;
  };

  return (
    <div className="max-w-4xl mx-auto px-4 py-10" dir="rtl">

      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-2">
          <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-600 to-blue-600 shadow-md">
            <Brain size={20} className="text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-black text-slate-900 tracking-tight">סריקה אדפטיבית</h1>
            <p className="text-sm text-slate-500">אלגוריתם שיטתי — כל שלב לומד מהקודם ומתאים את הבדיקות</p>
          </div>
        </div>
      </div>

      {/* Input */}
      <div className="flex gap-2 mb-6">
        <input
          type="text"
          value={url}
          onChange={e => setUrl(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleScan()}
          placeholder="https://example.com"
          disabled={status === 'running'}
          className="flex-1 rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm font-mono text-slate-800 placeholder-slate-400 shadow-sm focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-60"
          dir="ltr"
        />
        <button
          onClick={handleScan}
          disabled={!url.trim() || status === 'running'}
          className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-violet-600 to-blue-600 px-6 py-3 text-sm font-bold text-white shadow-md hover:opacity-90 disabled:opacity-50 transition-all"
        >
          {status === 'running' ? (
            <>
              <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
              {formatElapsed(elapsed)}
            </>
          ) : (
            <>
              <Play size={14} strokeWidth={2.5} />
              סרוק
            </>
          )}
        </button>
      </div>

      {/* Phase bar — show when active */}
      {status !== 'idle' && (
        <PhaseBar currentPhase={currentPhase} status={status} />
      )}

      {/* Live terminal — while running */}
      {status === 'running' && (
        <div className="mb-6">
          <div className="flex items-center gap-2 mb-2">
            <Terminal size={13} className="text-slate-400" />
            <span className="text-xs text-slate-500 font-semibold">לוג חי</span>
          </div>
          <LiveTerminal logs={logs} />
        </div>
      )}

      {/* Error state */}
      {status === 'failed' && (
        <div className="rounded-xl border border-red-200 bg-red-50 p-4 mb-6 text-sm text-red-700">
          הסריקה נכשלה. בדוק שהשרת רץ ושה-URL נכון.
        </div>
      )}

      {/* Results */}
      {result && status === 'completed' && (
        <div>
          {/* Summary */}
          <SummaryBar summary={result.summary} />

          {/* Decision log */}
          <DecisionLog decisions={result.decision_log} />

          {/* Attack surface */}
          <SurfacePanel surface={result.attack_surface} />

          {/* Tabs */}
          <div className="flex items-center justify-between mb-4">
            <div className="flex gap-1 bg-slate-100 p-1 rounded-xl">
              {[
                { id: 'findings', label: `ממצאים (${findings.length})` },
                { id: 'chains',   label: `שרשראות (${chains.length})` },
                { id: 'logs',     label: 'לוג' },
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`px-4 py-2 rounded-lg text-xs font-semibold transition-all ${
                    activeTab === tab.id
                      ? 'bg-white text-slate-900 shadow-sm ring-1 ring-slate-200'
                      : 'text-slate-500 hover:text-slate-800'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
            <button
              onClick={handleExport}
              className="flex items-center gap-1.5 text-xs font-semibold text-slate-600 hover:text-slate-900 bg-white border border-slate-200 rounded-lg px-3 py-2 hover:bg-slate-50 transition-all"
            >
              <Download size={13} />
              ייצא HTML
            </button>
          </div>

          {/* Findings tab */}
          {activeTab === 'findings' && (
            <div>
              {/* Severity filter */}
              <div className="flex flex-wrap gap-1.5 mb-4">
                {['all', 'critical', 'high', 'medium', 'low', 'info'].map(s => {
                  const count = s === 'all' ? findings.length : findings.filter(f => f.severity === s).length;
                  if (s !== 'all' && count === 0) return null;
                  return (
                    <button
                      key={s}
                      onClick={() => setFilterSev(s)}
                      className={`text-xs font-semibold px-3 py-1.5 rounded-full transition-all ${
                        filterSev === s
                          ? (s === 'all' ? 'bg-slate-800 text-white' : `${SEV_STYLES[s]?.badge} ring-2 ring-offset-1 ring-current`)
                          : 'bg-slate-100 text-slate-600 hover:bg-slate-200'
                      }`}
                    >
                      {s === 'all' ? `הכל (${count})` : `${SEV_STYLES[s]?.label} (${count})`}
                    </button>
                  );
                })}
              </div>
              <div className="space-y-2">
                {filteredFindings.length === 0 ? (
                  <div className="text-center py-12 text-slate-400">
                    <CheckCircle size={40} className="mx-auto mb-3 text-green-400" />
                    <p className="font-semibold">לא נמצאו ממצאים בחומרה זו</p>
                  </div>
                ) : (
                  filteredFindings.map((f, i) => <FindingCard key={i} finding={f} />)
                )}
              </div>
            </div>
          )}

          {/* Chains tab */}
          {activeTab === 'chains' && (
            <div className="space-y-3">
              {chains.length === 0 ? (
                <div className="text-center py-12 text-slate-400">
                  <Link2 size={36} className="mx-auto mb-3" />
                  <p className="font-semibold">לא זוהו שרשראות תקיפה</p>
                  <p className="text-sm mt-1">שרשראות נוצרות כשיש שילוב של חולשות</p>
                </div>
              ) : (
                chains.map((c, i) => <ChainCard key={i} chain={c} />)
              )}
            </div>
          )}

          {/* Logs tab */}
          {activeTab === 'logs' && (
            <LiveTerminal logs={logs} />
          )}
        </div>
      )}
    </div>
  );
}
