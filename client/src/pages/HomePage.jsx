import { useState, useEffect, useRef } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import {
  Search, Globe, Wifi, Zap, Radio, Loader2,
  ChevronDown, ChevronUp, ExternalLink, User, Eye, ShieldAlert, UserSearch, Network,
  Flag, Rocket, Building2
} from 'lucide-react';
import { startScan, getJob, getTorStatus } from '../utils/webintApi';

// ── Scan types ────────────────────────────────────────────────────────────────
const SCAN_TYPES = [
  {
    id: 'deep_domain',
    label: 'סריקת דומיין מעמיקה',
    icon: Rocket,
    placeholder: 'example.com',
    description: 'קלט: שם דומיין · מוצא קבצים חשופים, ספריות פתוחות, SSL · מחלץ מיילים עם דפדפן',
    inputType: 'דומיין',
    enhanced: 'docker',  // subfinder + nuclei + ffuf
  },
  {
    id: 'domain',
    label: 'מודיעין דומיין',
    icon: Globe,
    placeholder: 'example.com',
    description: 'קלט: שם דומיין · DNS, WHOIS, תעודת SSL, תת-דומיינים',
    inputType: 'דומיין',
    enhanced: 'docker',  // subfinder
  },
  {
    id: 'web',
    label: 'חילוץ מאתר',
    icon: Search,
    placeholder: 'https://example.com',
    description: 'קלט: כתובת URL · מחלץ מיילים, טלפונים וטכנולוגיות מהאתר',
    inputType: 'URL',
  },
  {
    id: 'username',
    label: 'חיפוש שם משתמש',
    icon: User,
    placeholder: 'username',
    description: 'קלט: שם משתמש · בודק קיום בפייסבוק, אינסטגרם, גיטהאב, טיקטוק ו-40+ פלטפורמות',
    inputType: 'שם משתמש',
    enhanced: 'docker', // maigret via Docker
  },
  {
    id: 'quick',
    label: 'בדיקת פורטים',
    icon: Zap,
    placeholder: '192.168.1.1 או domain.com',
    description: 'קלט: IP או דומיין · בודק פורטים נפוצים ללא nmap',
    inputType: 'IP / דומיין',
  },
  {
    id: 'network',
    label: 'סריקת רשת מקומית',
    icon: Radio,
    placeholder: '',
    description: 'ללא קלט · סורק את כל המכשירים ברשת ה-LAN המקומית (דורש nmap)',
    noInput: true,
    inputType: 'ללא',
  },
  {
    id: 'torSearch',
    label: 'חיפוש Dark Web',
    icon: Eye,
    placeholder: 'מונח לחיפוש...',
    description: 'קלט: מונח חיפוש · מוצא קישורי .onion דרך אינדקס Ahmia',
    inputType: 'מונח חיפוש',
  },
  {
    id: 'audit',
    label: 'ביקורת אבטחה',
    icon: ShieldAlert,
    placeholder: 'https://example.com',
    description: 'קלט: כתובת URL · בודק דליפות, קבצים חשופים, Headers חסרים, סודות ב-JS',
    inputType: 'URL',
    enhanced: 'docker',  // nuclei
  },
  {
    id: 'dossier',
    label: 'תיק אדם',
    icon: UserSearch,
    placeholder: 'שם מלא (עברית / אנגלית)',
    description: 'קלט: שם אדם · חיפוש רשת → חילוץ מיילים → GitHub → SOCMINT → מאגרים ישראליים',
    dossierFields: true,
    inputType: 'שם אדם',
    enhanced: 'python',  // holehe
  },
  {
    id: 'graph',
    label: 'מפת קשרים',
    icon: Network,
    placeholder: 'אימייל / שם / דומיין',
    description: 'קלט: כל מזהה · בונה גרף ויזואלי של קשרים בין ישויות',
    inputType: 'מזהה כלשהו',
  },
  {
    id: 'siteSearch',
    label: 'חיפוש שם באתר',
    icon: Search,
    placeholder: 'guidestar.org.il',
    description: 'קלט: אתר + שם · סורק את כל דפי האתר ומוצא כל הופעה של השם',
    extraField: { placeholder: 'שם לחיפוש (עברית / אנגלית)' },
    inputType: 'אתר + שם',
  },
  {
    id: 'israeli',
    label: 'מאגרים ישראליים',
    icon: Flag,
    placeholder: 'שם אדם / חברה / עמותה',
    description: 'קלט: שם · מחפש ב-data.gov.il, רשם העמותות, רשם החברות, כנסת',
    inputType: 'שם',
  },
  {
    id: 'guidestar',
    label: 'Guidestar עמותות',
    icon: Building2,
    placeholder: 'שם אדם לחיפוש',
    description: 'קלט: שם אדם · פותח guidestar.org.il עם דפדפן אמיתי ומחפש בכל העמותות',
    inputType: 'שם אדם',
  },
  {
    id: 'breach',
    label: 'בדיקת הדלפות',
    icon: ShieldAlert,
    placeholder: 'user@example.com',
    description: 'קלט: אימייל · בודק האם האימייל מופיע במאגרי דלפי מידע (Breaches)',
    inputType: 'אימייל',
    enhanced: 'python',  // holehe
  },
  {
    id: 'secrets',
    label: 'סריקת סודות',
    icon: Search,
    placeholder: 'https://example.com/app.js',
    description: 'קלט: כתובת קובץ (JS/TXT) · סורק מפתחות API, טוקנים ו-JWTs',
    inputType: 'URL (לקובץ)',
    enhanced: 'docker',  // trufflehog
  },
];

// ── Shared UI components ──────────────────────────────────────────────────────
function StatusBadge({ status }) {
  const map = {
    running:   'bg-yellow-100 text-yellow-700 border-yellow-200',
    completed: 'bg-green-100  text-green-700  border-green-200',
    failed:    'bg-red-100    text-red-700    border-red-200',
  };
  const labels = { running: 'סורק...', completed: 'הושלם', failed: 'שגיאה' };
  return (
    <span className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${map[status] || ''}`}>
      {status === 'running' && <Loader2 size={11} className="animate-spin" />}
      {labels[status] || status}
    </span>
  );
}

function Section({ title, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-xl border border-slate-200 bg-white overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex w-full items-center justify-between px-4 py-3 text-sm font-semibold text-slate-700 hover:bg-slate-50 transition"
      >
        {title}
        {open ? <ChevronUp size={15} /> : <ChevronDown size={15} />}
      </button>
      {open && <div className="border-t border-slate-100 px-4 pb-4 pt-3">{children}</div>}
    </div>
  );
}

function TagList({ items, color = 'blue' }) {
  if (!items?.length) return <span className="text-slate-400 text-sm">—</span>;
  const colors = {
    blue:   'bg-blue-50   text-blue-700   border-blue-200',
    green:  'bg-green-50  text-green-700  border-green-200',
    purple: 'bg-purple-50 text-purple-700 border-purple-200',
    slate:  'bg-slate-50  text-slate-700  border-slate-200',
    red:    'bg-red-50    text-red-700    border-red-200',
  };
  return (
    <div className="flex flex-wrap gap-1.5">
      {items.map((item, i) => (
        <span key={i} className={`rounded-md border px-2 py-0.5 text-xs font-mono ${colors[color]}`}>
          {item}
        </span>
      ))}
    </div>
  );
}

function KVTable({ data }) {
  const entries = Object.entries(data || {}).filter(([, v]) => v !== null && v !== undefined && v !== '');
  if (!entries.length) return <span className="text-slate-400 text-sm">אין נתונים</span>;
  return (
    <table className="w-full text-sm">
      <tbody>
        {entries.map(([k, v]) => (
          <tr key={k} className="border-b border-slate-100 last:border-0">
            <td className="py-1.5 pr-4 font-medium text-slate-500 whitespace-nowrap w-36">{k}</td>
            <td className="py-1.5 text-slate-800 break-all font-mono text-xs">
              {Array.isArray(v) ? v.join(', ') : String(v)}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

// ── Result renderers ──────────────────────────────────────────────────────────
function Results({ scanType, data }) {
  if (data.error) {
    return (
      <div className="rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
        שגיאה: {data.error}
      </div>
    );
  }
  if (scanType === 'deep_domain')                     return <EnterpriseResults data={data} />;
  if (scanType === 'domain')                          return <DomainResults data={data} />;
  if (scanType === 'web')                             return <WebResults data={data} />;
  if (scanType === 'quick' || scanType === 'host')    return <PortResults data={data} />;
  if (scanType === 'network')                         return <NetworkResults data={data} />;
  if (scanType === 'username')                        return <UsernameResults data={data} />;
  if (scanType === 'torSearch' || scanType === 'tor') return <TorResults data={data} />;
  if (scanType === 'audit')                           return <AuditResults data={data} />;
  if (scanType === 'investigate')                     return <InvestigateResults data={data} />;
  if (scanType === 'graph')                           return <GraphResults data={data} />;
  if (scanType === 'dossier')                         return <DossierResults data={data} />;
  if (scanType === 'siteSearch')                      return <SiteSearchResults data={data} />;
  if (scanType === 'israeli')                         return <IsraeliResults data={data} />;
  if (scanType === 'guidestar')                       return <GuidestarResults data={data} />;
  if (scanType === 'breach')                          return <BreachResults data={data} />;
  if (scanType === 'secrets')                         return <SecretResults data={data} />;
  return <pre className="text-xs text-slate-600 overflow-auto">{JSON.stringify(data, null, 2)}</pre>;
}

// ── New Results Parsers ───────────────────────────────────────────────────────
function BreachResults({ data }) {
  return (
    <div className="space-y-4">
      <div className={`p-4 rounded-xl border ${data.breached ? 'bg-red-50 border-red-200' : 'bg-green-50 border-green-200'}`}>
        <h3 className={`text-lg font-bold mb-2 ${data.breached ? 'text-red-700' : 'text-green-700'}`}>
          {data.breached ? '⚠️ נמצאו דלפי מידע!' : '✅ לא נמצאו הדלפות באף מאגר גלוי'}
        </h3>
        <p className="text-sm">אימייל: <span className="font-mono bg-white px-2 py-0.5 rounded border">{data.email}</span></p>
      </div>

      {data.breaches && data.breaches.length > 0 && (
        <Section title={`הדלפות (${data.breaches.length})`}>
          <div className="grid gap-2">
            {data.breaches.map((b, i) => (
              <div key={i} className="flex justify-between items-center p-3 border border-red-100 rounded-lg bg-white">
                <div>
                  <div className="font-bold text-slate-800">{b.name}</div>
                  <div className="text-xs text-slate-500">Source: {b.source}</div>
                </div>
                <span className="bg-red-100 text-red-700 px-2 py-1 rounded text-xs font-bold border border-red-200">
                  {b.risk} Risk
                </span>
              </div>
            ))}
          </div>
        </Section>
      )}
    </div>
  );
}

function SecretResults({ data }) {
  const secretsCount = data.total_secrets_found || 0;
  return (
    <div className="space-y-4">
      <div className="p-4 rounded-xl border bg-slate-50 border-slate-200 flex justify-between items-center">
        <div>
          <h3 className="text-lg font-bold text-slate-800">תוצאות סריקת סודות</h3>
          <p className="text-sm text-slate-500 font-mono mt-1" dir="ltr">{data.url}</p>
        </div>
        <div className={`px-4 py-2 rounded-lg font-bold text-lg border ${secretsCount > 0 ? 'bg-red-100 text-red-700 border-red-200' : 'bg-green-100 text-green-700 border-green-200'}`}>
          {secretsCount} סודות נמצאו
        </div>
      </div>

      {secretsCount > 0 && Object.entries(data.findings || {}).map(([type, items]) => (
        <Section key={type} title={`${type} (${items.length})`}>
          <div className="space-y-2">
            {items.map((key, i) => (
              <div key={i} className="p-2 border border-slate-200 rounded font-mono text-sm bg-slate-900 text-green-400 break-all" dir="ltr">
                {key}
              </div>
            ))}
          </div>
        </Section>
      ))}
    </div>
  );
}

// ── Enterprise Results (Celery/Playwright/Neo4j) ───────────────────────────────
function EnterpriseResults({ data }) {
  const subs     = data.subdomains || [];
  const dns      = data.dns || {};
  const whois    = data.whois || {};
  const ssl      = data.ssl || {};
  const geo      = data.geolocation || {};
  const shodan   = data.shodan || {};
  const revIp    = data.reverse_ip || [];
  const secrets  = data.secrets || {};
  const secretsFlat = Object.values(secrets).flat();
  const httpxProbe = data.httpx_probe || [];

  return (
    <div className="space-y-4">
      {/* Header + Stats Grid */}
      <div className="rounded-xl border border-indigo-200 bg-gradient-to-r from-indigo-50 to-slate-50 p-4">
        <div className="flex items-center gap-2 mb-2">
          <Rocket size={20} className="text-indigo-600" />
          <span className="text-xl font-black text-slate-800">Enterprise Deep Scan</span>
        </div>
        <p className="font-mono text-sm text-slate-600 mb-4">יעד: <strong>{data.domain}</strong> {data.title && `— ${data.title}`}</p>
        
        <div className="flex flex-wrap gap-3">
          {[
            { val: subs.length,                           label: 'תת-דומיינים',    border: 'border-indigo-200', bg: 'bg-indigo-50', num: 'text-indigo-700', txt: 'text-indigo-600' },
            { val: data.emails_extracted?.length || 0,    label: 'מיילים',          border: 'border-red-200',    bg: 'bg-red-50',    num: 'text-red-700',    txt: 'text-red-600' },
            { val: data.dorks_hits || 0,                  label: 'Dorking',          border: 'border-purple-200', bg: 'bg-purple-50', num: 'text-purple-700', txt: 'text-purple-600' },
            { val: data.phones_found?.length || 0,        label: 'טלפונים',         border: 'border-amber-200',  bg: 'bg-amber-50',  num: 'text-amber-700',  txt: 'text-amber-600' },
            { val: data.secrets_count || 0,               label: 'סודות חשופים',    border: 'border-rose-200',   bg: 'bg-rose-50',   num: 'text-rose-700',   txt: 'text-rose-600' },
            { val: revIp.length,                          label: 'Reverse IP',       border: 'border-cyan-200',   bg: 'bg-cyan-50',   num: 'text-cyan-700',   txt: 'text-cyan-600' },
            { val: httpxProbe.length,                       label: 'httpx Probe',      border: 'border-teal-200',   bg: 'bg-teal-50',   num: 'text-teal-700',   txt: 'text-teal-600' },
          ].map(({ val, label, border, bg, num, txt }) => (
            <div key={label} className={`flex flex-col items-center rounded-lg border px-4 py-2 ${border} ${bg}`}>
              <span className={`text-2xl font-black ${num}`}>{val}</span>
              <span className={`text-xs ${txt}`}>{label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* DNS Records */}
      {dns && Object.keys(dns).length > 0 && !dns.error && (
        <Section title="רשומות DNS">
          <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
            {Object.entries(dns).filter(([,v]) => v?.length > 0).map(([type, records]) => (
              <div key={type} className="rounded-lg border border-slate-200 bg-white p-2">
                <span className="text-[10px] font-bold text-indigo-600 bg-indigo-50 border border-indigo-200 rounded px-1.5 py-0.5">{type}</span>
                <div className="mt-1 space-y-0.5">
                  {records.slice(0, 5).map((r, i) => (
                    <p key={i} className="text-xs font-mono text-slate-600 truncate">{r}</p>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* SSL Certificate */}
      {ssl && !ssl.error && (ssl.issuer || ssl.subject) && (
        <Section title="תעודת SSL">
          <div className="flex flex-wrap gap-2 text-xs">
            {(ssl.issuer || ssl.subject) && <span className="bg-green-50 border border-green-200 text-green-700 rounded px-2 py-1">מנפיק: {typeof (ssl.issuer) === 'object' ? (ssl.issuer.commonName || ssl.issuer.organizationName || JSON.stringify(ssl.issuer)) : (ssl.issuer || ssl.subject)}</span>}
            {(ssl.valid_from) && <span className="bg-slate-50 border border-slate-200 text-slate-600 rounded px-2 py-1">מ: {ssl.valid_from}</span>}
            {(ssl.valid_to || ssl.valid_until) && <span className="bg-slate-50 border border-slate-200 text-slate-600 rounded px-2 py-1">עד: {ssl.valid_to || ssl.valid_until}</span>}
            {ssl.san?.length > 0 && <span className="bg-blue-50 border border-blue-200 text-blue-600 rounded px-2 py-1">{ssl.san.length} SAN domains</span>}
          </div>
        </Section>
      )}

      {/* WHOIS */}
      {whois && !whois.error && (whois.registrar || whois.creation_date) && (
        <Section title="WHOIS">
          <div className="flex flex-wrap gap-2 text-xs">
            {whois.registrar && <span className="bg-slate-50 border border-slate-200 text-slate-700 rounded px-2 py-1">רשם: {whois.registrar}</span>}
            {whois.creation_date && <span className="bg-slate-50 border border-slate-200 text-slate-700 rounded px-2 py-1">נרשם: {whois.creation_date}</span>}
            {whois.expiration_date && <span className="bg-amber-50 border border-amber-200 text-amber-700 rounded px-2 py-1">פג: {whois.expiration_date}</span>}
            {whois.name_servers?.length > 0 && <span className="bg-slate-50 border border-slate-200 text-slate-600 rounded px-2 py-1">NS: {whois.name_servers.join(', ')}</span>}
          </div>
        </Section>
      )}

      {/* Subdomains */}
      {subs.length > 0 && (
        <Section title={`תת-דומיינים (${subs.length}) — Subfinder + Amass + crt.sh`}>
          <div className="flex flex-wrap gap-1.5">
            {subs.slice(0, 50).map((s, i) => (
              <span key={i} className="text-xs font-mono bg-indigo-50 border border-indigo-200 text-indigo-700 rounded px-2 py-0.5">{s}</span>
            ))}
            {subs.length > 50 && <span className="text-xs text-slate-400">+{subs.length - 50} עוד...</span>}
          </div>
        </Section>
      )}

      {/* httpx Probe — live subdomain probing */}
      {httpxProbe.length > 0 && (
        <Section title={`httpx Probe — תת-דומיינים חיים (${httpxProbe.length})`}>
          <div className="space-y-1.5">
            {httpxProbe.slice(0, 40).map((h, i) => (
              <div key={i} className="flex items-center gap-2 rounded-lg border border-teal-200 bg-teal-50 px-3 py-1.5">
                <span className={`text-xs font-bold rounded px-1.5 py-0.5 ${
                  h.status_code < 300 ? 'bg-green-100 text-green-700 border border-green-200' :
                  h.status_code < 400 ? 'bg-yellow-100 text-yellow-700 border border-yellow-200' :
                  'bg-red-100 text-red-700 border border-red-200'
                }`}>{h.status_code}</span>
                <a href={h.url} target="_blank" rel="noreferrer" className="text-xs font-mono text-teal-700 hover:underline truncate flex-1">{h.url}</a>
                {h.title && <span className="text-[10px] text-slate-500 truncate max-w-[180px]">{h.title}</span>}
                {h.tech?.length > 0 && (
                  <div className="flex gap-1">
                    {h.tech.slice(0, 3).map((t, j) => (
                      <span key={j} className="text-[10px] bg-violet-50 border border-violet-200 text-violet-600 rounded px-1 py-0.5">{t}</span>
                    ))}
                  </div>
                )}
                {h.webserver && <span className="text-[10px] bg-slate-100 border border-slate-200 text-slate-500 rounded px-1 py-0.5">{h.webserver}</span>}
              </div>
            ))}
            {httpxProbe.length > 40 && <span className="text-xs text-slate-400">+{httpxProbe.length - 40} עוד...</span>}
          </div>
        </Section>
      )}

      {/* Shodan / Ports */}
      {shodan && !shodan.error && (shodan.ports?.length > 0 || shodan.vulns?.length > 0) && (
        <Section title="Shodan InternetDB">
          <div className="space-y-2">
            {shodan.ports?.length > 0 && (
              <div>
                <p className="text-xs font-bold text-slate-600 mb-1">פורטים פתוחים:</p>
                <div className="flex flex-wrap gap-1.5">
                  {shodan.ports.map((p, i) => (
                    <span key={i} className="text-xs font-mono bg-blue-50 border border-blue-200 text-blue-700 rounded px-2 py-0.5">{p}</span>
                  ))}
                </div>
              </div>
            )}
            {shodan.vulns?.length > 0 && (
              <div>
                <p className="text-xs font-bold text-rose-600 mb-1">חולשות (CVE):</p>
                <div className="flex flex-wrap gap-1.5">
                  {shodan.vulns.map((v, i) => (
                    <span key={i} className="text-xs font-mono bg-rose-50 border border-rose-200 text-rose-700 rounded px-2 py-0.5">{v}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </Section>
      )}

      {/* Geolocation */}
      {geo && !geo.error && geo.ip && (
        <Section title="מיקום גיאוגרפי">
          <div className="flex flex-wrap gap-2 text-xs">
            <span className="bg-slate-50 border border-slate-200 text-slate-700 rounded px-2 py-1">IP: {geo.ip}</span>
            {geo.country && <span className="bg-slate-50 border border-slate-200 text-slate-700 rounded px-2 py-1">{geo.country}</span>}
            {geo.city && <span className="bg-slate-50 border border-slate-200 text-slate-700 rounded px-2 py-1">{geo.city}</span>}
            {geo.org && <span className="bg-slate-50 border border-slate-200 text-slate-700 rounded px-2 py-1">{geo.org}</span>}
          </div>
        </Section>
      )}

      {/* Reverse IP */}
      {revIp.length > 0 && (
        <Section title={`Reverse IP — דומיינים על אותו שרת (${revIp.length})`}>
          <div className="flex flex-wrap gap-1.5">
            {revIp.slice(0, 30).map((d, i) => (
              <span key={i} className="text-xs font-mono bg-cyan-50 border border-cyan-200 text-cyan-700 rounded px-2 py-0.5">{d}</span>
            ))}
            {revIp.length > 30 && <span className="text-xs text-slate-400">+{revIp.length - 30} עוד...</span>}
          </div>
        </Section>
      )}

      {/* Emails (merged) */}
      {data.emails_extracted?.length > 0 && (
        <Section title={`אימיילים שנמצאו (${data.emails_extracted.length})`}>
          <TagList items={data.emails_extracted} color="red" />
          <div className="flex gap-2 mt-2 text-[10px] text-slate-400">
            {data.emails_playwright?.length > 0 && <span>{data.emails_playwright.length} מ-Playwright</span>}
            {data.emails_harvester?.length > 0 && <span>{data.emails_harvester.length} מ-theHarvester</span>}
          </div>
        </Section>
      )}

      {/* Phones */}
      {data.phones_found?.length > 0 && (
        <Section title={`טלפונים (${data.phones_found.length})`}>
          <TagList items={data.phones_found} color="amber" />
        </Section>
      )}

      {/* Secrets */}
      {secretsFlat.length > 0 && (
        <Section title={`סודות חשופים (${secretsFlat.length}) — trufflehog`}>
          <div className="space-y-2">
            {secretsFlat.slice(0, 20).map((s, i) => (
              <div key={i} className="rounded-lg border border-rose-200 bg-rose-50 p-2">
                <p className="text-xs font-bold text-rose-700">{s.type || s.detector || 'secret'}</p>
                <p className="text-xs font-mono text-slate-600 truncate">{s.match || s.raw || s.value || JSON.stringify(s)}</p>
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Dorking Findings */}
      {data.dorks_data?.length > 0 && (
        <Section title={`ממצאי Dorking (${data.dorks_hits})`}>
          <div className="space-y-3">
            {data.dorks_data.map((res, i) => (
              <a key={i} href={res.link} target="_blank" rel="noreferrer"
                className="block rounded-lg border border-slate-200 bg-white p-3 hover:bg-slate-50 hover:border-slate-300 transition">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-[10px] font-mono bg-purple-100 text-purple-700 border border-purple-200 rounded px-1.5 py-0.5">
                    שאילתה: {res.dork_used}
                  </span>
                </div>
                <p className="text-sm font-semibold text-blue-700 truncate">{res.title}</p>
                <p className="text-xs font-mono text-green-700 truncate mt-0.5">{res.link}</p>
                {res.snippet && <p className="text-xs text-slate-600 mt-1 line-clamp-2 leading-relaxed">{res.snippet}</p>}
              </a>
            ))}
          </div>
        </Section>
      )}

      <div className="text-xs text-center text-slate-400 mt-4">
        סה"כ 7 שלבי סריקה: DNS/WHOIS/SSL + Subdomains (Subfinder+Amass) + httpx Probe + Dorking + Playwright + theHarvester + Secrets (TruffleHog)
      </div>
    </div>
  );
}

// ── Dossier Results ───────────────────────────────────────────────────────────
function DossierResults({ data }) {
  const found   = data.found   || {};
  const stats   = data.stats   || {};
  const israeli = data.israeli || {};

  const nodeColors = {
    person:   '#6366f1', email: '#ef4444', phone: '#f59e0b',
    github:   '#1d4ed8', gravatar: '#10b981', domain: '#8b5cf6',
    company:  '#0ea5e9', social: '#22c55e',
  };

  return (
    <div className="space-y-3">

      {/* Header + stats */}
      <div className="rounded-xl border border-indigo-200 bg-gradient-to-r from-indigo-50 to-slate-50 p-4">
        <div className="flex items-center gap-2 mb-3">
          <UserSearch size={20} className="text-indigo-600" />
          <span className="text-xl font-black text-slate-800">{data.name}</span>
        </div>
        <div className="flex flex-wrap gap-2">
          {[
            { label: 'תוצאות web',   val: stats.web_results,    color: 'blue'   },
            { label: 'אימיילים',      val: stats.emails_found,   color: 'red'    },
            { label: 'טלפונים',       val: stats.phones_found,   color: 'amber'  },
            { label: 'חשבונות',       val: stats.accounts_found, color: 'green'  },
            { label: 'חברות/עמותות', val: stats.companies_found,color: 'purple' },
          ].map(({ label, val, color }) => (
            <div key={label} className={`flex flex-col items-center rounded-lg border px-3 py-1.5
              ${color === 'blue'   ? 'bg-blue-50   border-blue-200'   : ''}
              ${color === 'red'    ? 'bg-red-50    border-red-200'    : ''}
              ${color === 'amber'  ? 'bg-amber-50  border-amber-200'  : ''}
              ${color === 'green'  ? 'bg-green-50  border-green-200'  : ''}
              ${color === 'purple' ? 'bg-purple-50 border-purple-200' : ''}
            `}>
              <span className={`text-xl font-black
                ${color === 'blue'   ? 'text-blue-700'   : ''}
                ${color === 'red'    ? 'text-red-700'    : ''}
                ${color === 'amber'  ? 'text-amber-700'  : ''}
                ${color === 'green'  ? 'text-green-700'  : ''}
                ${color === 'purple' ? 'text-purple-700' : ''}
              `}>{val ?? 0}</span>
              <span className="text-[10px] text-slate-500">{label}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Discovered entities */}
      {(found.emails?.length > 0 || found.phones?.length > 0 || found.companies?.length > 0 || found.usernames?.length > 0) && (
        <Section title="ישויות שנגלו אוטומטית">
          <div className="space-y-2">
            {found.emails?.length > 0 && (
              <div><p className="text-xs font-bold text-red-600 mb-1">אימיילים שנמצאו:</p>
                <TagList items={found.emails} color="red" /></div>
            )}
            {found.phones?.length > 0 && (
              <div><p className="text-xs font-bold text-amber-600 mb-1">טלפונים שנמצאו:</p>
                <TagList items={found.phones} color="slate" /></div>
            )}
            {found.usernames?.length > 0 && (
              <div><p className="text-xs font-bold text-blue-600 mb-1">Usernames שנמצאו:</p>
                <TagList items={found.usernames} color="blue" /></div>
            )}
            {found.companies?.length > 0 && (
              <div><p className="text-xs font-bold text-purple-600 mb-1">חברות / עמותות:</p>
                <TagList items={found.companies} color="purple" /></div>
            )}
          </div>
        </Section>
      )}

      {/* Email profiles */}
      {Object.keys(data.email_profiles || {}).length > 0 && (
        <Section title="פרופילים לפי אימייל">
          <div className="space-y-3">
            {Object.entries(data.email_profiles).map(([email, prof]) => (
              <div key={email} className="rounded-lg border border-slate-200 p-3 space-y-2">
                <p className="font-mono text-xs font-bold text-slate-700">{email}</p>

                {prof.gravatar?.found && (
                  <div className="flex items-center gap-3">
                    {prof.gravatar.avatar && <img src={prof.gravatar.avatar} className="w-10 h-10 rounded-full border" alt="" />}
                    <div>
                      <p className="text-sm font-semibold text-green-700">{prof.gravatar.display_name}</p>
                      {prof.gravatar.username && <p className="text-xs text-slate-500">@{prof.gravatar.username}</p>}
                      {prof.gravatar.location  && <p className="text-xs text-slate-500">📍 {prof.gravatar.location}</p>}
                    </div>
                    <span className="text-xs bg-green-100 text-green-700 border border-green-200 rounded-full px-2 py-0.5 mr-auto">Gravatar</span>
                  </div>
                )}

                {prof.github?.found && (
                  <div className="flex items-center gap-3">
                    {prof.github.avatar && <img src={prof.github.avatar} className="w-10 h-10 rounded-full border" alt="" />}
                    <div>
                      <a href={prof.github.profile} target="_blank" rel="noreferrer"
                        className="text-sm font-semibold text-blue-700 hover:underline flex items-center gap-1">
                        @{prof.github.username} <ExternalLink size={11} />
                      </a>
                      {prof.github.name     && <p className="text-xs text-slate-600">{prof.github.name}</p>}
                      {prof.github.company  && <p className="text-xs text-slate-500">{prof.github.company}</p>}
                      {prof.github.location && <p className="text-xs text-slate-500">📍 {prof.github.location}</p>}
                    </div>
                    <span className="text-xs bg-blue-100 text-blue-700 border border-blue-200 rounded-full px-2 py-0.5 mr-auto">GitHub</span>
                  </div>
                )}

                {prof.crtsh?.domains?.length > 0 && (
                  <div>
                    <p className="text-xs text-slate-500 mb-1">דומיינים מ-SSL certs ({prof.crtsh.cert_count} תעודות):</p>
                    <TagList items={prof.crtsh.domains.slice(0,10)} color="purple" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </Section>
      )}

      {/* Phone profiles */}
      {Object.keys(data.phone_profiles || {}).length > 0 && (
        <Section title="פרטי טלפון">
          {Object.entries(data.phone_profiles).map(([ph, prof]) => (
            <div key={ph} className="rounded-lg border border-amber-200 bg-amber-50 p-3 space-y-2">
              <p className="font-mono text-sm font-bold text-amber-800">{prof.international || ph}</p>
              <KVTable data={{ מדינה: prof.country, ספק: prof.carrier, סוג: prof.line_type }} />
              <div className="flex gap-2 mt-1">
                {prof.whatsapp && (
                  <a href={prof.whatsapp} target="_blank" rel="noreferrer"
                    className="flex items-center gap-1 rounded-lg border border-green-200 bg-green-50 px-3 py-1.5 text-xs font-semibold text-green-700 hover:bg-green-100">
                    <ExternalLink size={11} /> WhatsApp
                  </a>
                )}
                {prof.telegram && (
                  <a href={prof.telegram} target="_blank" rel="noreferrer"
                    className="flex items-center gap-1 rounded-lg border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs font-semibold text-blue-700 hover:bg-blue-100">
                    <ExternalLink size={11} /> Telegram
                  </a>
                )}
              </div>
            </div>
          ))}
        </Section>
      )}

      {/* Social accounts */}
      {data.accounts?.length > 0 && (
        <Section title={`חשבונות ברשתות (${data.accounts.length})`}>
          <div className="grid grid-cols-2 gap-2">
            {data.accounts.map((a, i) => (
              <a key={i} href={a.url} target="_blank" rel="noreferrer"
                className="flex items-center justify-between rounded-lg border border-green-200 bg-green-50 px-3 py-2 text-sm hover:bg-green-100 transition">
                <span className="font-semibold text-green-800">{a.platform}</span>
                <ExternalLink size={12} className="text-green-500" />
              </a>
            ))}
          </div>
        </Section>
      )}

      {/* Israeli records */}
      {israeli.total_found > 0 && (
        <Section title={`מודיעין ישראלי (${israeli.total_found})`}>
          <IsraeliResults data={israeli} />
        </Section>
      )}

      {/* Graph */}
      {data.graph?.nodes?.length > 0 && (
        <Section title={`גרף קשרים (${data.graph.nodes.length} צמתים, ${data.graph.edges.length} קשרים)`}>
          <DossierGraph graph={data.graph} nodeColors={nodeColors} />
        </Section>
      )}

      {/* Web results */}
      {data.web_results?.length > 0 && (
        <Section title={`תוצאות web (${data.web_results.length})`} defaultOpen={false}>
          <div className="space-y-2">
            {data.web_results.map((r, i) => (
              <a key={i} href={r.url} target="_blank" rel="noreferrer"
                className="block rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 hover:bg-blue-50 hover:border-blue-200 transition">
                <p className="text-sm font-semibold text-blue-700 truncate">{r.title || r.url}</p>
                <p className="text-xs text-slate-400 font-mono truncate">{r.url}</p>
                {r.snippet && <p className="text-xs text-slate-500 mt-0.5 line-clamp-1">{r.snippet}</p>}
              </a>
            ))}
          </div>
        </Section>
      )}
    </div>
  );
}

function DossierGraph({ graph, nodeColors }) {
  const graphRef    = useRef();
  const containerRef = useRef();
  const [dims, setDims] = useState({ width: 0, height: 420 });

  useEffect(() => {
    if (containerRef.current)
      setDims({ width: containerRef.current.offsetWidth, height: 420 });
  }, []);

  const graphData = {
    nodes: graph.nodes,
    links: graph.edges.map(e => ({ source: e.from, target: e.to, label: e.label })),
  };

  return (
    <div ref={containerRef} className="h-[420px] w-full bg-[#020617] rounded-lg overflow-hidden border border-slate-800">
      <ForceGraph2D
        ref={graphRef}
        width={dims.width}
        height={dims.height}
        graphData={graphData}
        nodeLabel="label"
        nodeColor={n => nodeColors[n.group] || '#94a3b8'}
        nodeRelSize={6}
        linkColor={() => '#334155'}
        linkWidth={1.5}
        linkDirectionalArrowLength={3}
        linkDirectionalArrowRelPos={1}
        backgroundColor="#020617"
        nodeCanvasObjectMode={() => 'after'}
        nodeCanvasObject={(node, ctx, gs) => {
          const fs = 11 / gs;
          ctx.font = `${fs}px Sans-Serif`;
          ctx.textAlign = 'center';
          ctx.fillStyle = 'rgba(255,255,255,0.85)';
          ctx.fillText(node.label, node.x, node.y + 9);
        }}
        onEngineStop={() => graphRef.current?.zoomToFit(400, 40)}
      />
    </div>
  );
}

// ── Israeli Intelligence Results ─────────────────────────────────────────────
function GuidestarResults({ data }) {
  const results = data.results || [];
  const withName = results.filter(r => r.name_found_in_page);
  const withoutName = results.filter(r => !r.name_found_in_page);

  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-blue-200 bg-gradient-to-r from-blue-50 to-slate-50 p-4">
        <div className="flex items-center gap-2 mb-1">
          <Building2 size={18} className="text-blue-600" />
          <span className="font-bold text-slate-800 text-lg">"{data.name}"</span>
          <span className="text-xs bg-blue-100 text-blue-700 border border-blue-200 rounded-full px-2 py-0.5 font-semibold">
            {data.total} עמותות נבדקו
          </span>
        </div>
        <p className="text-xs text-slate-500">guidestar.org.il · דפדפן אמיתי</p>
      </div>

      {withName.length > 0 && (
        <Section title={`השם נמצא בדף (${withName.length})`}>
          <div className="space-y-2">
            {withName.map((r, i) => (
              <a key={i} href={r.url} target="_blank" rel="noreferrer"
                className="block rounded-lg border border-green-200 bg-green-50 p-3 hover:bg-green-100 transition">
                <div className="flex items-center justify-between">
                  <p className="font-bold text-green-800 text-sm">{r.org_name}</p>
                  <span className="text-xs font-mono text-green-600">{r.org_number}</span>
                </div>
                {r.snippet && <p className="text-xs text-slate-600 mt-1 line-clamp-3 leading-relaxed">{r.snippet}</p>}
              </a>
            ))}
          </div>
        </Section>
      )}

      {withoutName.length > 0 && (
        <Section title={`עמותות שנמצאו בחיפוש (${withoutName.length})`} defaultOpen={false}>
          <div className="space-y-2">
            {withoutName.map((r, i) => (
              <a key={i} href={r.url} target="_blank" rel="noreferrer"
                className="block rounded-lg border border-slate-200 bg-white p-3 hover:bg-slate-50 transition">
                <div className="flex items-center justify-between">
                  <p className="font-semibold text-slate-700 text-sm">{r.org_name}</p>
                  <span className="text-xs font-mono text-slate-400">{r.org_number}</span>
                </div>
              </a>
            ))}
          </div>
        </Section>
      )}

      {results.length === 0 && (
        <p className="text-center text-slate-400 py-8">לא נמצאו תוצאות</p>
      )}

      {data.errors?.length > 0 && (
        <details className="text-xs text-slate-400">
          <summary className="cursor-pointer">שגיאות ({data.errors.length})</summary>
          {data.errors.map((e, i) => <p key={i}>{e}</p>)}
        </details>
      )}
    </div>
  );
}

function IsraeliResults({ data }) {
  const siteResults = data.site_results || {};
  const datagov     = data.datagov     || {};

  const siteOrder = [
    { key: 'nonprofits', color: 'blue'   },
    { key: 'companies',  color: 'purple' },
    { key: 'knesset',    color: 'green'  },
    { key: 'court',      color: 'amber'  },
    { key: 'news_biz',   color: 'slate'  },
    { key: 'news_gen',   color: 'slate'  },
    { key: 'gov_data',   color: 'slate'  },
  ];
  const bgMap = {
    blue:   'bg-blue-50   border-blue-200   text-blue-700',
    purple: 'bg-purple-50 border-purple-200 text-purple-700',
    green:  'bg-green-50  border-green-200  text-green-700',
    amber:  'bg-amber-50  border-amber-200  text-amber-700',
    slate:  'bg-slate-50  border-slate-200  text-slate-700',
  };

  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="rounded-xl border border-slate-200 bg-gradient-to-r from-blue-50 to-slate-50 p-4">
        <div className="flex items-center gap-2 mb-1">
          <Flag size={18} className="text-blue-600" />
          <span className="font-bold text-slate-800 text-lg">"{data.query}"</span>
          <span className="text-xs bg-blue-100 text-blue-700 border border-blue-200 rounded-full px-2 py-0.5 font-semibold">
            {data.total_found} תוצאות סה"כ
          </span>
        </div>
        <p className="text-xs text-slate-500">
          guidestar · רשם החברות · כנסת · פסיקות · data.gov.il · עיתונות
        </p>
      </div>

      {/* Site search results */}
      {siteOrder.map(({ key, color }) => {
        const sec = siteResults[key];
        if (!sec || sec.count === 0) return null;
        const cls = bgMap[color];
        return (
          <Section key={key} title={`${sec.label} (${sec.count})`}>
            <p className="text-xs text-slate-400 mb-2">{sec.note}</p>
            <div className="space-y-2">
              {sec.results.map((r, i) => (
                <a key={i} href={r.url} target="_blank" rel="noreferrer"
                  className={`block rounded-lg border px-3 py-2 hover:brightness-95 transition ${cls}`}>
                  <p className="text-sm font-semibold truncate">{r.title || r.url}</p>
                  <p className="text-xs opacity-60 font-mono truncate">{r.url}</p>
                  {r.snippet && <p className="text-xs mt-0.5 line-clamp-2 opacity-80">{r.snippet}</p>}
                </a>
              ))}
            </div>
          </Section>
        );
      })}

      {/* Guidestar ישיר */}
      {data.guidestar?.length > 0 && (
        <Section title={`עמותות — Guidestar ישיר (${data.guidestar.length})`}>
          <div className="space-y-2">
            {data.guidestar.map((org, i) => (
              <a key={i} href={org.url} target="_blank" rel="noreferrer"
                className="flex items-center justify-between rounded-lg border border-blue-200 bg-blue-50 px-3 py-2 hover:bg-blue-100 transition">
                <div>
                  <p className="text-sm font-bold text-blue-800">{org.name}</p>
                  <p className="text-xs text-blue-600">{org.type} · {org.status}</p>
                </div>
                {org.number && <span className="text-xs font-mono text-blue-400">{org.number}</span>}
              </a>
            ))}
          </div>
        </Section>
      )}

      {/* data.gov.il structured */}
      {['associations','companies'].map(key => {
        const recs = datagov[key]?.records || [];
        if (!recs.length) return null;
        const label = key === 'associations' ? 'עמותות — data.gov.il (מבני)' : 'חברות — data.gov.il (מבני)';
        return (
          <Section key={key} title={`${label} (${recs.length})`} defaultOpen={false}>
            <div className="space-y-2">
              {recs.map((rec, i) => (
                <div key={i} className="rounded-lg border border-slate-200 bg-white px-3 py-2">
                  <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
                    {Object.entries(rec).slice(0, 8).map(([k, v]) => (
                      <div key={k} className="text-xs">
                        <span className="text-slate-400">{k}: </span>
                        <span className="font-semibold text-slate-700">{String(v).slice(0, 60)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </Section>
        );
      })}
    </div>
  );
}

// ── Site Name Search Results ──────────────────────────────────────────────────
function SiteSearchResults({ data }) {
  const findings = data.findings || [];
  const [expanded, setExpanded] = useState(null);

  return (
    <div className="space-y-3">
      {/* Summary */}
      <div className="rounded-xl border border-slate-200 bg-gradient-to-r from-indigo-50 to-slate-50 p-4">
        <div className="flex items-center gap-2 mb-2">
          <Search size={17} className="text-indigo-600" />
          <span className="font-bold text-slate-800 text-lg">"{data.name}"</span>
          <span className="text-sm text-slate-500">באתר</span>
          <a href={data.site} target="_blank" rel="noreferrer"
            className="text-sm text-blue-600 font-mono hover:underline flex items-center gap-1">
            {data.site} <ExternalLink size={11} />
          </a>
        </div>
        <div className="flex gap-4 text-sm flex-wrap">
          <div className="flex flex-col items-center rounded-lg bg-green-50 border border-green-200 px-4 py-2">
            <span className="text-2xl font-black text-green-700">{data.pages_found}</span>
            <span className="text-xs text-green-600">דפים עם הופעה</span>
          </div>
          <div className="flex flex-col items-center rounded-lg bg-blue-50 border border-blue-200 px-4 py-2">
            <span className="text-2xl font-black text-blue-700">{data.total_hits}</span>
            <span className="text-xs text-blue-600">הופעות סה"כ</span>
          </div>
          <div className="flex flex-col items-center rounded-lg bg-slate-50 border border-slate-200 px-4 py-2">
            <span className="text-2xl font-black text-slate-500">{data.pages_crawled}</span>
            <span className="text-xs text-slate-400">דפים נסרקו</span>
          </div>
        </div>
      </div>

      {findings.length === 0 ? (
        <div className="text-center py-10 text-slate-400">
          <p className="text-4xl mb-2">🔍</p>
          <p className="text-sm">השם לא נמצא באף דף שנסרק</p>
        </div>
      ) : (
        <div className="space-y-2">
          {findings.map((f, i) => (
            <div key={i} className="rounded-xl border border-slate-200 overflow-hidden">
              <button
                onClick={() => setExpanded(expanded === i ? null : i)}
                className="w-full flex items-center justify-between px-4 py-3 bg-white hover:bg-slate-50 transition text-right"
              >
                <div className="flex items-center gap-3 min-w-0">
                  <span className="shrink-0 rounded-full bg-green-100 text-green-700 border border-green-200 text-xs font-bold px-2 py-0.5">
                    {f.count}x
                  </span>
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-slate-800 truncate">{f.title || f.url}</p>
                    <p className="text-xs text-slate-400 font-mono truncate">{f.url}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <a
                    href={f.url}
                    target="_blank"
                    rel="noreferrer"
                    onClick={e => e.stopPropagation()}
                    className="text-blue-500 hover:text-blue-700"
                  >
                    <ExternalLink size={13} />
                  </a>
                  {expanded === i ? <ChevronUp size={14} className="text-slate-400" /> : <ChevronDown size={14} className="text-slate-400" />}
                </div>
              </button>

              {expanded === i && (
                <div className="border-t border-slate-100 px-4 py-3 bg-slate-50 space-y-2">
                  {f.occurrences.map((occ, j) => (
                    <div key={j} className="rounded-lg border border-indigo-100 bg-white px-3 py-2 text-xs text-slate-700 leading-relaxed">
                      {/* מדגיש את השם בתוך הקטע */}
                      {occ.excerpt.split(new RegExp(`(${data.name})`, 'gi')).map((part, k) =>
                        part.toLowerCase() === data.name.toLowerCase()
                          ? <mark key={k} className="bg-yellow-200 text-yellow-900 font-bold rounded px-0.5">{part}</mark>
                          : part
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Graph Results (Correlation Engine) ────────────────────────────────────────
function GraphResults({ data }) {
  const graphRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 0, height: 500 });
  const containerRef = useRef();

  useEffect(() => {
    if (containerRef.current) {
      setDimensions({ width: containerRef.current.offsetWidth, height: 500 });
    }
  }, []);

  const graphData = {
    nodes: data.nodes || [],
    links: (data.edges || []).map(e => ({ source: e.from, target: e.to, label: e.label }))
  };

  const getNodeColor = (group) => {
    switch(group) {
      case 'email': return '#ef4444';
      case 'username': return '#3b82f6';
      case 'social_profile': return '#10b981';
      case 'breach': return '#f59e0b';
      case 'domain': return '#8b5cf6';
      default: return '#94a3b8';
    }
  };

  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-slate-200 bg-slate-900 p-4 text-white">
        <div className="flex items-center gap-2 mb-4">
          <Network size={18} className="text-blue-400" />
          <span className="font-bold">מפת קשרים ויזואלית: {data.target}</span>
        </div>
        
        <div ref={containerRef} className="h-[500px] w-full bg-[#020617] rounded-lg overflow-hidden relative border border-slate-800">
          {graphData.nodes.length > 0 ? (
            <ForceGraph2D
              ref={graphRef}
              width={dimensions.width}
              height={dimensions.height}
              graphData={graphData}
              nodeLabel="label"
              nodeColor={n => getNodeColor(n.group)}
              nodeRelSize={6}
              linkColor={() => '#475569'}
              linkWidth={1.5}
              linkDirectionalArrowLength={3}
              linkDirectionalArrowRelPos={1}
              backgroundColor="#020617"
              nodeCanvasObjectMode={() => 'after'}
              nodeCanvasObject={(node, ctx, globalScale) => {
                const label = node.label;
                const fontSize = 12 / globalScale;
                ctx.font = `${fontSize}px Sans-Serif`;
                ctx.textAlign = 'center';
                ctx.textBaseline = 'middle';
                ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
                ctx.fillText(label, node.x, node.y + 10);
              }}
              onEngineStop={() => graphRef.current?.zoomToFit(400, 50)}
            />
          ) : (
            <div className="flex h-full items-center justify-center text-slate-500 text-sm">
              לא נמצאו קשרים למטרה זו.
            </div>
          )}
          
          {/* Legend */}
          {graphData.nodes.length > 0 && (
            <div className="absolute bottom-4 right-4 bg-slate-800/80 p-3 rounded-lg border border-slate-700 backdrop-blur text-xs">
              <div className="font-bold mb-2 text-slate-300">מקרא:</div>
              <div className="space-y-1.5">
                <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-red-500"></span>אימייל</div>
                <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-blue-500"></span>שם משתמש</div>
                <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-green-500"></span>פרופיל ברשתות</div>
                <div className="flex items-center gap-2"><span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>דליפת מידע</div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ── Domain ───────────────────────────────────────────────────────────────────
function DomainResults({ data }) {
  const geo = data.geolocation || {};
  const ssl = data.ssl || {};
  const dns = data.dns || {};
  const who = data.whois || {};
  const subs = data.subdomains || [];

  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-slate-200 bg-gradient-to-r from-blue-50 to-slate-50 p-4">
        <div className="flex items-center gap-2 mb-2">
          <Globe size={16} className="text-blue-600" />
          <span className="font-semibold text-slate-800">{data.domain}</span>
          {geo.ip && <span className="font-mono text-xs text-slate-500">{geo.ip}</span>}
        </div>
        <div className="flex flex-wrap gap-4 text-sm text-slate-600">
          {geo.country && <span>🌍 {geo.country}{geo.city && ` · ${geo.city}`}</span>}
          {geo.isp     && <span>🔌 {geo.isp}</span>}
          {geo.asn     && <span className="font-mono text-xs">{geo.asn}</span>}
        </div>
      </div>
      <Section title="רשומות DNS">
        <div className="space-y-2">
          {Object.entries(dns).map(([type, vals]) => vals?.length ? (
            <div key={type} className="flex gap-3 text-sm">
              <span className="w-12 shrink-0 font-mono font-bold text-blue-600">{type}</span>
              <span className="text-slate-700 font-mono text-xs break-all">{vals.join(' · ')}</span>
            </div>
          ) : null)}
        </div>
      </Section>
      <Section title="WHOIS">
        <KVTable data={{ Registrar: who.registrar, Owner: who.registrant, Org: who.org, Country: who.country, Registered: who.creation_date, Expires: who.expiration_date, Emails: Array.isArray(who.emails) ? who.emails?.join(', ') : who.emails }} />
      </Section>
      <Section title="SSL Certificate">
        <KVTable data={{ 'Issued to': ssl.subject?.commonName || ssl.subject?.CN, Issuer: ssl.issuer?.organizationName || ssl.issuer?.O, 'Valid from': ssl.valid_from, 'Valid until': ssl.valid_until, SANs: ssl.san?.join(', ') }} />
      </Section>
      {subs.length > 0 && (
        <Section title={`Subdomains (${subs.length})`} defaultOpen={false}>
          <TagList items={subs} color="purple" />
        </Section>
      )}

      {/* Shodan InternetDB — חינם, ללא API key */}
      {data.shodan && !data.shodan.error && (
        <Section title={`Shodan InternetDB${data.shodan.ports?.length ? ` — ${data.shodan.ports.length} פורטים פתוחים` : ''}`}>
          <div className="space-y-3">
            {data.shodan.ports?.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-slate-500 mb-1">פורטים פתוחים</p>
                <div className="flex flex-wrap gap-1.5">
                  {data.shodan.ports.map(p => (
                    <span key={p} className="rounded-md border border-blue-200 bg-blue-50 px-2 py-0.5 text-xs font-mono font-bold text-blue-700">{p}</span>
                  ))}
                </div>
              </div>
            )}
            {data.shodan.vulns?.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-red-600 mb-1">⚠️ CVEs ({data.shodan.vulns.length})</p>
                <div className="flex flex-wrap gap-1.5">
                  {data.shodan.vulns.map(v => (
                    <a key={v} href={`https://nvd.nist.gov/vuln/detail/${v}`} target="_blank" rel="noreferrer"
                      className="rounded-md border border-red-200 bg-red-50 px-2 py-0.5 text-xs font-mono text-red-700 hover:bg-red-100">
                      {v}
                    </a>
                  ))}
                </div>
              </div>
            )}
            {data.shodan.hostnames?.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-slate-500 mb-1">Hostnames</p>
                <TagList items={data.shodan.hostnames} color="slate" />
              </div>
            )}
            {data.shodan.cpes?.length > 0 && (
              <div>
                <p className="text-xs font-semibold text-slate-500 mb-1">CPEs (תוכנות מזוהות)</p>
                <TagList items={data.shodan.cpes} color="slate" />
              </div>
            )}
          </div>
        </Section>
      )}

      {/* Reverse IP */}
      {data.reverse_ip?.length > 0 && (
        <Section title={`Reverse IP — ${data.reverse_ip.length} דומיינים על אותו IP`} defaultOpen={false}>
          <TagList items={data.reverse_ip} color="blue" />
        </Section>
      )}
    </div>
  );
}

// ── Web Scrape ────────────────────────────────────────────────────────────────
function WebResults({ data }) {
  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
        <p className="font-semibold text-slate-800 mb-0.5">{data.title || '(ללא כותרת)'}</p>
        {data.description && <p className="text-sm text-slate-500">{data.description}</p>}
        <div className="flex gap-3 mt-2 text-xs text-slate-400">
          <span>Status {data.status_code}</span>
          {data.final_url !== data.url && <span>⟶ {data.final_url}</span>}
        </div>
      </div>
      {data.emails?.length > 0 && (
        <Section title={`אימיילים (${data.emails.length})`}>
          <TagList items={data.emails} color="blue" />
        </Section>
      )}
      {data.phones?.length > 0 && (
        <Section title={`טלפונים (${data.phones.length})`}>
          <TagList items={data.phones} color="green" />
        </Section>
      )}
      {data.technologies?.length > 0 && (
        <Section title="טכנולוגיות">
          <TagList items={data.technologies} color="purple" />
        </Section>
      )}
      {Object.keys(data.social_media || {}).length > 0 && (
        <Section title="רשתות חברתיות">
          <div className="space-y-1.5">
            {Object.entries(data.social_media).map(([platform, url]) => (
              <a key={platform} href={url} target="_blank" rel="noreferrer"
                className="flex items-center gap-2 text-sm text-blue-600 hover:underline">
                <ExternalLink size={12} />
                <span className="capitalize font-medium w-24">{platform}</span>
                <span className="text-xs text-slate-400 truncate">{url}</span>
              </a>
            ))}
          </div>
        </Section>
      )}
      <Section title={`לינקים (פנימי: ${data.links?.total_internal || 0} · חיצוני: ${data.links?.total_external || 0})`} defaultOpen={false}>
        <div className="space-y-1">
          {data.links?.external?.slice(0, 20).map((link, i) => (
            <a key={i} href={link} target="_blank" rel="noreferrer"
              className="block text-xs text-slate-500 hover:text-blue-600 truncate font-mono">{link}</a>
          ))}
        </div>
      </Section>
    </div>
  );
}

// ── Port Check ────────────────────────────────────────────────────────────────
function PortResults({ data }) {
  const ports = data.open_ports || [];
  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 flex items-center gap-4">
        <Zap size={18} className="text-blue-600" />
        <div>
          <p className="font-semibold text-slate-800">{data.host}</p>
          <p className="text-sm text-slate-500">{ports.length} פורטים פתוחים</p>
        </div>
      </div>
      {ports.length > 0 ? (
        <div className="rounded-xl border border-slate-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                <th className="px-4 py-2 text-right font-semibold text-slate-600">פורט</th>
                <th className="px-4 py-2 text-right font-semibold text-slate-600">שירות</th>
                <th className="px-4 py-2 text-right font-semibold text-slate-600">מוצר</th>
              </tr>
            </thead>
            <tbody>
              {ports.map((p, i) => (
                <tr key={i} className="border-b border-slate-100 last:border-0 hover:bg-slate-50">
                  <td className="px-4 py-2 font-mono font-bold text-blue-700">{p.port}/{p.protocol || 'tcp'}</td>
                  <td className="px-4 py-2 text-slate-700">{p.service || '—'}</td>
                  <td className="px-4 py-2 text-slate-500 text-xs">{p.product || p.version || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="text-sm text-slate-400 text-center py-6">לא נמצאו פורטים פתוחים</p>
      )}
    </div>
  );
}

// ── LAN Scan ──────────────────────────────────────────────────────────────────
function NetworkResults({ data }) {
  const hosts = data.hosts || [];
  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 flex items-center gap-4">
        <Radio size={18} className="text-blue-600" />
        <div>
          <p className="font-semibold text-slate-800">{data.subnet}</p>
          <p className="text-sm text-slate-500">{hosts.length} מכשירים נמצאו</p>
        </div>
      </div>
      {hosts.length > 0 && (
        <div className="rounded-xl border border-slate-200 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-50 border-b border-slate-200">
              <tr>
                {['IP', 'Hostname', 'MAC', 'יצרן'].map(h => (
                  <th key={h} className="px-4 py-2 text-right font-semibold text-slate-600">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {hosts.map((h, i) => (
                <tr key={i} className="border-b border-slate-100 last:border-0 hover:bg-slate-50">
                  <td className="px-4 py-2 font-mono font-bold text-blue-700">{h.ip}</td>
                  <td className="px-4 py-2 text-slate-600">{h.hostname || '—'}</td>
                  <td className="px-4 py-2 font-mono text-xs text-slate-500">{h.mac || '—'}</td>
                  <td className="px-4 py-2 text-slate-600">{h.vendor || '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

// ── SOCMINT — Username ────────────────────────────────────────────────────────
const CATEGORY_LABELS = {
  social: 'רשתות חברתיות', dev: 'פיתוח', professional: 'מקצועי',
  gaming: 'גיימינג', music: 'מוזיקה', other: 'אחר',
};

function UsernameResults({ data }) {
  const found    = data.found    || [];
  const notFound = data.not_found || [];
  const summary  = data.summary  || {};

  // Group found by category
  const byCategory = found.reduce((acc, p) => {
    const cat = p.category || 'other';
    if (!acc[cat]) acc[cat] = [];
    acc[cat].push(p);
    return acc;
  }, {});

  return (
    <div className="space-y-4">
      {/* Summary bar */}
      <div className="rounded-xl border border-slate-200 bg-white p-4">
        <div className="flex items-center gap-3 mb-3">
          <User size={18} className="text-blue-600" />
          <span className="font-bold text-slate-800 text-lg">@{data.username}</span>
        </div>
        <div className="flex gap-4 text-sm">
          <div className="flex flex-col items-center rounded-lg bg-green-50 border border-green-200 px-4 py-2">
            <span className="text-2xl font-black text-green-700">{summary.found}</span>
            <span className="text-xs text-green-600">נמצא</span>
          </div>
          <div className="flex flex-col items-center rounded-lg bg-slate-50 border border-slate-200 px-4 py-2">
            <span className="text-2xl font-black text-slate-500">{summary.not_found}</span>
            <span className="text-xs text-slate-400">לא נמצא</span>
          </div>
          <div className="flex flex-col items-center rounded-lg bg-blue-50 border border-blue-200 px-4 py-2">
            <span className="text-2xl font-black text-blue-700">{summary.total}</span>
            <span className="text-xs text-blue-600">פלטפורמות</span>
          </div>
        </div>
      </div>

      {/* Found — grouped by category */}
      {Object.entries(byCategory).map(([cat, platforms]) => (
        <Section key={cat} title={`${CATEGORY_LABELS[cat] || cat} (${platforms.length})`}>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {platforms.map(p => (
              <a
                key={p.platform}
                href={p.url}
                target="_blank"
                rel="noreferrer"
                className="flex items-center justify-between rounded-lg border border-green-200 bg-green-50 px-3 py-2 text-sm hover:bg-green-100 transition"
              >
                <span className="font-semibold text-green-800">{p.platform}</span>
                <ExternalLink size={13} className="text-green-500" />
              </a>
            ))}
          </div>
        </Section>
      ))}

      {/* Not found — collapsed */}
      {notFound.length > 0 && (
        <Section title={`לא נמצא (${notFound.length})`} defaultOpen={false}>
          <TagList items={notFound.map(p => p.platform)} color="slate" />
        </Section>
      )}
    </div>
  );
}

// ── Dark Web / Tor ────────────────────────────────────────────────────────────
function TorResults({ data }) {
  // tor_search result
  if (data.onion_links !== undefined) {
    return (
      <div className="space-y-3">
        <div className="rounded-xl border border-slate-200 bg-slate-900 p-4 text-white">
          <div className="flex items-center gap-2 mb-1">
            <Eye size={16} className="text-purple-400" />
            <span className="font-bold">Dark Web Search</span>
          </div>
          <p className="text-slate-400 text-sm">"{data.query}" · {data.total} קישורים נמצאו · מקור: {data.source}</p>
          {data.note && <p className="text-xs text-slate-500 mt-1">{data.note}</p>}
        </div>
        {data.onion_links?.length > 0 ? (
          <div className="rounded-xl border border-slate-200 overflow-hidden">
            <div className="divide-y divide-slate-100">
              {data.onion_links.map((link, i) => (
                <div key={i} className="px-4 py-2.5 font-mono text-xs text-purple-700 bg-white hover:bg-purple-50 break-all">
                  {link}.onion
                </div>
              ))}
            </div>
          </div>
        ) : (
          <p className="text-center text-slate-400 text-sm py-6">לא נמצאו קישורים</p>
        )}
      </div>
    );
  }

  // tor_fetch result
  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-slate-200 bg-slate-900 p-4 text-white">
        <div className="flex items-center gap-2 mb-1">
          <Eye size={16} className="text-purple-400" />
          <span className="font-bold">Tor Fetch</span>
          {data.via_tor && <span className="text-xs bg-purple-800 text-purple-200 px-2 py-0.5 rounded-full">via Tor</span>}
        </div>
        <p className="text-slate-400 text-xs font-mono">{data.url} · Status {data.status_code}</p>
      </div>
      {data.text && (
        <Section title="תוכן הדף">
          <pre className="text-xs text-slate-600 overflow-auto max-h-64 whitespace-pre-wrap">{data.text.slice(0, 3000)}</pre>
        </Section>
      )}
    </div>
  );
}

// ── Security Audit ────────────────────────────────────────────────────────────
const SEVERITY_CONFIG = {
  critical: { label: 'קריטי',  bg: 'bg-red-100',    text: 'text-red-800',    border: 'border-red-300',    dot: 'bg-red-500'    },
  high:     { label: 'גבוה',   bg: 'bg-orange-100', text: 'text-orange-800', border: 'border-orange-300', dot: 'bg-orange-500' },
  medium:   { label: 'בינוני', bg: 'bg-yellow-100', text: 'text-yellow-800', border: 'border-yellow-300', dot: 'bg-yellow-500' },
  low:      { label: 'נמוך',   bg: 'bg-blue-100',   text: 'text-blue-800',   border: 'border-blue-300',   dot: 'bg-blue-400'   },
  info:     { label: 'מידע',   bg: 'bg-slate-100',  text: 'text-slate-700',  border: 'border-slate-300',  dot: 'bg-slate-400'  },
};

const CATEGORY_ICONS = {
  data_leak:        '🔓',
  secrets:          '🔑',
  exposure:         '📂',
  headers:          '📋',
  cookies:          '🍪',
  forms:            '📝',
  info_disclosure:  '🔍',
  cors:             '🌐',
};

function FindingCard({ finding }) {
  const [open, setOpen] = useState(false);
  const cfg = SEVERITY_CONFIG[finding.severity] || SEVERITY_CONFIG.info;

  return (
    <div className={`rounded-xl border ${cfg.border} overflow-hidden`}>
      <button
        onClick={() => setOpen(o => !o)}
        className={`flex w-full items-start gap-3 px-4 py-3 text-right ${cfg.bg} hover:brightness-95 transition`}
      >
        <div className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${cfg.dot}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-xs font-bold uppercase ${cfg.text}`}>{cfg.label}</span>
            <span className="text-xs text-slate-500">{CATEGORY_ICONS[finding.category] || '⚠️'} {finding.category}</span>
          </div>
          <p className={`text-sm font-semibold mt-0.5 ${cfg.text}`}>{finding.title}</p>
        </div>
        {open ? <ChevronUp size={15} className="shrink-0 mt-1 text-slate-500" />
               : <ChevronDown size={15} className="shrink-0 mt-1 text-slate-500" />}
      </button>

      {open && (
        <div className="px-4 py-3 bg-white space-y-3 border-t border-slate-100">
          <p className="text-sm text-slate-700">{finding.description}</p>

          {finding.evidence?.length > 0 && (
            <div>
              <p className="text-xs font-bold text-slate-500 mb-1">ראיות:</p>
              <div className="space-y-1">
                {finding.evidence.map((e, i) => (
                  <div key={i} className="rounded bg-slate-50 border border-slate-200 px-3 py-1.5 font-mono text-xs text-slate-700 break-all">
                    {e}
                  </div>
                ))}
              </div>
            </div>
          )}

          {finding.recommendation && (
            <div className="rounded-lg bg-green-50 border border-green-200 px-3 py-2">
              <p className="text-xs font-bold text-green-700 mb-0.5">המלצה:</p>
              <p className="text-xs text-green-800">{finding.recommendation}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function AuditResults({ data }) {
  const s = data.summary || {};
  const findings = data.findings || [];
  const [filter, setFilter] = useState('all');

  const riskScore = (s.critical * 10 + s.high * 5 + s.medium * 2 + s.low) || 0;
  const riskLabel = riskScore === 0 ? 'נקי' : riskScore < 10 ? 'נמוך' : riskScore < 30 ? 'בינוני' : riskScore < 60 ? 'גבוה' : 'קריטי';
  const riskColor = riskScore === 0 ? 'text-green-600' : riskScore < 10 ? 'text-blue-600' : riskScore < 30 ? 'text-yellow-600' : riskScore < 60 ? 'text-orange-600' : 'text-red-600';

  const filtered = filter === 'all' ? findings : findings.filter(f => f.severity === filter);

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="rounded-xl border border-slate-200 bg-white p-4">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="flex items-center gap-2">
              <ShieldAlert size={18} className="text-slate-700" />
              <span className="font-bold text-slate-800">Security Report</span>
            </div>
            <p className="text-xs text-slate-500 font-mono mt-0.5">{data.domain} · {s.pages_crawled} דפים נסרקו</p>
          </div>
          <div className="text-right">
            <p className="text-xs text-slate-500">Risk Score</p>
            <p className={`text-2xl font-black ${riskColor}`}>{riskLabel}</p>
          </div>
        </div>
        <div className="grid grid-cols-5 gap-2">
          {['critical','high','medium','low','info'].map(sev => {
            const cfg = SEVERITY_CONFIG[sev];
            return (
              <button
                key={sev}
                onClick={() => setFilter(filter === sev ? 'all' : sev)}
                className={`flex flex-col items-center rounded-lg border p-2 transition ${
                  filter === sev ? `${cfg.bg} ${cfg.border}` : 'border-slate-200 bg-slate-50 hover:bg-slate-100'
                }`}
              >
                <span className={`text-xl font-black ${filter === sev ? cfg.text : 'text-slate-700'}`}>{s[sev] || 0}</span>
                <span className={`text-[10px] font-semibold ${filter === sev ? cfg.text : 'text-slate-500'}`}>{cfg.label}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Findings list */}
      {filtered.length > 0 ? (
        <div className="space-y-2">
          {filtered.map((f, i) => <FindingCard key={i} finding={f} />)}
        </div>
      ) : (
        <div className="text-center py-10 text-slate-400">
          <p className="text-4xl mb-2">✅</p>
          <p className="text-sm">לא נמצאו ממצאים בקטגוריה זו</p>
        </div>
      )}
    </div>
  );
}

// ── Person Investigation ──────────────────────────────────────────────────────
function InvestigateResults({ data }) {
  const type = data.type;
  return (
    <div className="space-y-3">
      {/* Header */}
      <div className="rounded-xl border border-slate-200 bg-gradient-to-r from-indigo-50 to-slate-50 p-4">
        <div className="flex items-center gap-2 mb-1">
          <UserSearch size={18} className="text-indigo-600" />
          <span className="font-bold text-slate-800">{data.query}</span>
          <span className="text-xs bg-indigo-100 text-indigo-700 border border-indigo-200 rounded-full px-2 py-0.5 font-semibold">
            {type === 'email' ? 'אימייל' : type === 'phone' ? 'טלפון' : 'שם'}
          </span>
        </div>
      </div>

      {/* EMAIL results */}
      {type === 'email' && <>
        {data.gravatar?.found && (
          <Section title="Gravatar — פרופיל מקושר">
            <div className="flex items-center gap-4">
              {data.gravatar.avatar && (
                <img src={data.gravatar.avatar} alt="avatar"
                  className="w-16 h-16 rounded-full border border-slate-200" />
              )}
              <div className="space-y-1">
                {data.gravatar.display_name && <p className="font-bold text-slate-800">{data.gravatar.display_name}</p>}
                {data.gravatar.username     && <p className="text-sm text-slate-500">@{data.gravatar.username}</p>}
                {data.gravatar.location     && <p className="text-sm text-slate-500">📍 {data.gravatar.location}</p>}
                {data.gravatar.about        && <p className="text-sm text-slate-600 mt-1">{data.gravatar.about}</p>}
                {data.gravatar.urls?.length > 0 && data.gravatar.urls.map((u, i) => (
                  <a key={i} href={u} target="_blank" rel="noreferrer"
                    className="flex items-center gap-1 text-xs text-blue-600 hover:underline">
                    <ExternalLink size={11} />{u}
                  </a>
                ))}
              </div>
            </div>
          </Section>
        )}

        {data.breaches && (
          <Section title={`HaveIBeenPwned ${data.breaches.found === true ? `— ${data.breaches.count} דליפות` : data.breaches.found === false ? '— לא נמצא' : '— בדיקה ידנית נדרשת'}`}>
            {data.breaches.found === true ? (
              <div className="space-y-2">
                {data.breaches.breaches?.map((b, i) => (
                  <div key={i} className="rounded-lg border border-red-200 bg-red-50 p-3">
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-bold text-red-800">{b.name}</span>
                      <span className="text-xs text-red-600">{b.breach_date}</span>
                    </div>
                    <p className="text-xs text-red-600">{b.domain}</p>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {b.data_classes?.map((d, j) => (
                        <span key={j} className="text-[10px] bg-red-100 text-red-700 border border-red-200 rounded px-1.5 py-0.5">{d}</span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : data.breaches.found === false ? (
              <p className="text-sm text-green-600">✅ לא נמצא באף דליפה ידועה</p>
            ) : data.breaches.requires_key ? (
              <div className="space-y-2">
                <p className="text-sm text-amber-700">⚠️ {data.breaches.message}</p>
                <a href={data.breaches.check_url} target="_blank" rel="noreferrer"
                  className="flex items-center gap-2 rounded-lg border border-amber-200 bg-amber-50 px-4 py-2.5 text-sm font-semibold text-amber-700 hover:bg-amber-100 transition">
                  <ExternalLink size={14} />
                  בדוק ב-HaveIBeenPwned ידנית
                </a>
              </div>
            ) : (
              <p className="text-sm text-slate-400">שגיאה בבדיקה</p>
            )}
          </Section>
        )}

        {data.social_accounts && (
          <Section title={`רשתות חברתיות ${data.social_accounts.found?.length > 0 ? `— נמצא ב-${data.social_accounts.found.length}` : ''}`}>
            {data.social_accounts.found?.length > 0 ? (
              <TagList items={data.social_accounts.found} color="green" />
            ) : (
              <p className="text-sm text-slate-400">לא נמצא חשבון מקושר לאימייל זה</p>
            )}
          </Section>
        )}

        {data.validation && (
          <Section title="אימות אימייל" defaultOpen={false}>
            <KVTable data={{
              'Domain': data.validation.domain,
              'MX Records': data.validation.valid_mx ? 'תקין ✅' : 'חסר ⚠️',
              'שרתי דואר': data.validation.mx_records?.join(', '),
            }} />
          </Section>
        )}

        {data.github?.found && (
          <Section title="GitHub — פרופיל נמצא">
            <div className="flex items-start gap-4">
              {data.github.avatar && (
                <img src={data.github.avatar} alt="avatar"
                  className="w-14 h-14 rounded-full border border-slate-200 shrink-0" />
              )}
              <div className="space-y-1 min-w-0">
                {data.github.name     && <p className="font-bold text-slate-800">{data.github.name}</p>}
                {data.github.username && (
                  <a href={data.github.profile} target="_blank" rel="noreferrer"
                    className="flex items-center gap-1 text-sm text-blue-600 hover:underline">
                    <ExternalLink size={11} /> @{data.github.username}
                  </a>
                )}
                {data.github.bio      && <p className="text-sm text-slate-600">{data.github.bio}</p>}
                <KVTable data={{
                  'חברה':        data.github.company,
                  'מיקום':       data.github.location,
                  'אתר':         data.github.blog,
                  'Repos':       data.github.public_repos,
                  'Followers':   data.github.followers,
                  'נוצר':        data.github.created_at?.slice(0, 10),
                }} />
                {data.github.repos_seen?.length > 0 && (
                  <div className="mt-1">
                    <p className="text-xs text-slate-500 mb-1">Repos שנראו ב-commits:</p>
                    <TagList items={data.github.repos_seen} color="slate" />
                  </div>
                )}
              </div>
            </div>
          </Section>
        )}
      </>}

      {/* PHONE results */}
      {type === 'phone' && <>
        {data.parsed?.valid && (
          <Section title="פרטי מספר">
            <KVTable data={{
              'פורמט בינלאומי': data.parsed.international,
              'E164':           data.parsed.e164,
              'מדינה':          data.parsed.country,
              'אזור':           data.parsed.region,
              'ספק':            data.parsed.carrier,
              'סוג קו':         data.parsed.line_type,
              'אזורי זמן':      data.parsed.timezones?.join(', '),
            }} />
          </Section>
        )}

        <Section title="WhatsApp / Telegram">
          <div className="space-y-3">
            {data.whatsapp?.link && (
              <a href={data.whatsapp.link} target="_blank" rel="noreferrer"
                className="flex items-center gap-2 rounded-lg border border-green-200 bg-green-50 px-4 py-3 text-sm font-semibold text-green-700 hover:bg-green-100 transition">
                <ExternalLink size={14} />
                פתח ב-WhatsApp לאימות ידני
              </a>
            )}
            {data.telegram?.manual_check && (
              <a href={data.telegram.manual_check} target="_blank" rel="noreferrer"
                className="flex items-center gap-2 rounded-lg border border-blue-200 bg-blue-50 px-4 py-3 text-sm font-semibold text-blue-700 hover:bg-blue-100 transition">
                <ExternalLink size={14} />
                פתח ב-Telegram לאימות ידני
              </a>
            )}
          </div>
        </Section>
      </>}

      {/* NAME results */}
      {type === 'name' && <>
        {data.accounts_found?.length > 0 && (
          <Section title={`חשבונות נמצאו (${data.accounts_total})`}>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
              {data.accounts_found.map((a, i) => (
                <a key={i} href={a.url} target="_blank" rel="noreferrer"
                  className="flex items-center justify-between rounded-lg border border-green-200 bg-green-50 px-3 py-2 text-sm hover:bg-green-100 transition">
                  <div>
                    <span className="font-semibold text-green-800">{a.platform}</span>
                    <span className="text-xs text-green-600 mr-2">@{a.searched_variant}</span>
                  </div>
                  <ExternalLink size={13} className="text-green-500" />
                </a>
              ))}
            </div>
          </Section>
        )}

        <Section title="וריאציות שם משתמש שנבדקו" defaultOpen={false}>
          <TagList items={data.username_variants || []} color="purple" />
        </Section>

        <Section title="חיפוש ידני ברשתות">
          <div className="space-y-2">
            {Object.entries(data.social_search || {}).map(([name, url]) => (
              <a key={name} href={url} target="_blank" rel="noreferrer"
                className="flex items-center gap-2 text-sm text-blue-600 hover:underline capitalize">
                <ExternalLink size={12} />{name}
              </a>
            ))}
          </div>
        </Section>

        {data.deep_dorks?.length > 0 && (
          <Section title={`נמצא ברשת (${data.deep_dorks.length} תוצאות)`}>
            <div className="space-y-2">
              {data.deep_dorks.map((r, i) => (
                <a key={i} href={r.url} target="_blank" rel="noreferrer"
                  className="block rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 hover:bg-blue-50 hover:border-blue-200 transition">
                  <div className="flex items-start justify-between gap-2">
                    <div className="min-w-0">
                      <p className="text-sm font-semibold text-blue-700 truncate">{r.title || r.url}</p>
                      <p className="text-xs text-slate-500 font-mono truncate">{r.url}</p>
                      {r.snippet && <p className="text-xs text-slate-600 mt-0.5 line-clamp-2">{r.snippet}</p>}
                    </div>
                    <ExternalLink size={13} className="shrink-0 text-slate-400 mt-0.5" />
                  </div>
                </a>
              ))}
            </div>
          </Section>
        )}
      </>}

      {/* Deep Dork results — תוצאות אינטרנט אמיתיות */}
      {data.deep_dorks?.length > 0 && (
        <Section title={`נמצא ברשת (${data.deep_dorks.length} תוצאות)`}>
          <div className="space-y-2">
            {data.deep_dorks.map((r, i) => (
              <a key={i} href={r.url} target="_blank" rel="noreferrer"
                className="block rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 hover:bg-blue-50 hover:border-blue-200 transition">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="text-sm font-semibold text-blue-700 truncate">{r.title || r.url}</p>
                    <p className="text-xs text-slate-500 font-mono truncate">{r.url}</p>
                    {r.snippet && <p className="text-xs text-slate-600 mt-0.5 line-clamp-2">{r.snippet}</p>}
                  </div>
                  <ExternalLink size={13} className="shrink-0 text-slate-400 mt-0.5" />
                </div>
              </a>
            ))}
          </div>
        </Section>
      )}

      {/* Search links — always shown */}
      <Section title="חיפוש ישיר" defaultOpen={false}>
        <div className="grid grid-cols-2 gap-2">
          {Object.entries(data.search_links || {}).map(([engine, url]) => (
            <a key={engine} href={url} target="_blank" rel="noreferrer"
              className="flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-sm text-slate-700 hover:bg-slate-100 capitalize transition">
              <ExternalLink size={12} />{engine}
            </a>
          ))}
        </div>
      </Section>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function HomePage() {
  const [scanType,    setScanType]    = useState('deep_domain'); // שינוי לברירת המחדל החדשה
  const [target,      setTarget]      = useState('');
  const [extraTarget, setExtraTarget] = useState('');
  const [dossierExtra, setDossierExtra] = useState({ email: '', phone: '', username: '', company: '' });
  const [loading,     setLoading]     = useState(false);
  const [jobId,       setJobId]       = useState(null);
  const [job,         setJob]         = useState(null);
  const pollRef = useRef(null);

  const currentType = SCAN_TYPES.find(t => t.id === scanType);

  useEffect(() => {
    if (!jobId) return;

    // Connect to WebSocket for real-time progress updates
    const ws = new WebSocket('ws://localhost:8000/ws/jobs');
    ws.onmessage = (event) => {
      try {
        const msgData = JSON.parse(event.data);
        if (msgData.job_id === jobId) {
          setJob(prev => {
            if (!prev) return { status: 'running', progress: [msgData.msg] };
            return { ...prev, progress: [...(prev.progress || []), msgData.msg], status: msgData.status || prev.status };
          });
        }
      } catch (e) {
        console.error('WS parsing error', e);
      }
    };

    const MAX_POLLS = 200;
    let count = 0;
    const intervalId = setInterval(async () => {
      count++;
      if (count >= MAX_POLLS) {
        clearInterval(intervalId);
        ws.close();
        setJob({ status: 'failed', result: { error: 'הסריקה לקחה יותר מדי זמן (timeout)' } });
        setLoading(false);
        return;
      }
      try {
        const { data } = await getJob(jobId);
        setJob(data);
        if (data.status !== 'running') {
          clearInterval(intervalId);
          ws.close();
          setLoading(false);
        }
      } catch {
        clearInterval(intervalId);
        ws.close();
        setJob({ status: 'failed', result: { error: 'Job not found — השרת אולי הופעל מחדש' } });
        setLoading(false);
      }
    }, 1500);
    return () => {
      clearInterval(intervalId);
      ws.close();
    };
  }, [jobId]);

  const handleScan = async () => {
    setJob(null);
    setJobId(null);
    setLoading(true);
    try {
      let data;
      if (startScan[scanType]) {
        const fn = startScan[scanType];
        const res = currentType.noInput ? await fn() : await fn(target.trim());
        data = res.data;
      } else {
        let payload;
        if (currentType.noInput) {
          payload = {};
        } else if (currentType.dossierFields) {
          payload = { target: target.trim(), ...dossierExtra };
        } else if (currentType.extraField) {
          payload = { url: target.trim(), query: extraTarget.trim() };
        } else {
          payload = { target: target.trim() };
        }
        const res = await fetch(`http://localhost:8000/api/v1/scan/${scanType}`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) });
        data = await res.json();
        if (!res.ok) throw new Error(data.detail || data.error || 'שגיאת שרת');
      }
      setJobId(data.job_id || data.task_id); // תמיכה במזהים של Celery
    } catch (err) {
      setJob({ status: 'failed', result: { error: err.message } });
      setLoading(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto px-4 py-8" dir="rtl">

      {/* Header */}
      <div className="mb-8">
        <p className="text-xs font-bold uppercase tracking-widest text-blue-600 mb-1">WEBINT Platform</p>
        <h1 className="text-3xl font-black text-slate-900">מנוע איסוף מידע</h1>
        <p className="text-slate-500 mt-1 text-sm">בחר סוג סריקה, הכנס יעד, לחץ סרוק</p>
      </div>

      {/* Legend */}
      <div className="flex gap-4 mb-3 text-[11px] text-slate-500 flex-wrap">
        <span className="flex items-center gap-1"><span className="inline-block w-2.5 h-2.5 rounded-full bg-violet-400" /> משודרג — Docker</span>
        <span className="flex items-center gap-1"><span className="inline-block w-2.5 h-2.5 rounded-full bg-emerald-400" /> משודרג — Python</span>
        <span className="flex items-center gap-1"><span className="inline-block w-2.5 h-2.5 rounded-full bg-slate-300" /> Built-in בלבד</span>
      </div>

      {/* Scan type tabs */}
      <div className="grid grid-cols-3 sm:grid-cols-4 gap-2 mb-4">
        {SCAN_TYPES.map(({ id, label, icon: Icon, inputType, enhanced }) => {
          const isActive = scanType === id;
          const activeStyles = {
            docker:  'border-violet-500 bg-violet-50 text-violet-700 shadow-sm',
            python:  'border-emerald-500 bg-emerald-50 text-emerald-700 shadow-sm',
            partial: 'border-amber-400 bg-amber-50 text-amber-700 shadow-sm',
          };
          const idleRing = {
            docker:  'border-violet-200 hover:border-violet-300',
            python:  'border-emerald-200 hover:border-emerald-300',
            partial: 'border-amber-200 hover:border-amber-300',
          };
          const cls = isActive
            ? (activeStyles[enhanced] || 'border-blue-500 bg-blue-50 text-blue-700 shadow-sm')
            : `bg-white text-slate-600 hover:bg-slate-50 ${idleRing[enhanced] || 'border-slate-200 hover:border-slate-300'}`;
          const dotColor = { docker: 'bg-violet-400', python: 'bg-emerald-400', partial: 'bg-amber-400' };
          return (
            <button
              key={id}
              onClick={() => { setScanType(id); setJob(null); setJobId(null); setExtraTarget(''); setDossierExtra({ email: '', phone: '', username: '', company: '' }); }}
              className={`flex flex-col items-start gap-1 rounded-xl border p-3 text-right transition ${cls}`}
            >
              <div className="flex items-center gap-1.5 w-full">
                <Icon size={16} />
                {enhanced && <span className={`ml-auto w-2 h-2 rounded-full ${dotColor[enhanced]}`} title={enhanced === 'docker' ? 'Docker 🐳' : enhanced === 'python' ? 'Python 🐍' : 'חלקי'} />}
              </div>
              <span className="text-xs font-bold leading-tight">{label}</span>
              {inputType && (
                <span className="text-[10px] font-mono bg-slate-100 text-slate-500 rounded px-1 mt-0.5">{inputType}</span>
              )}
            </button>
          );
        })}
      </div>

      {/* Selected scan description */}
      {currentType.description && (
        <p className="text-xs text-slate-500 bg-slate-50 border border-slate-200 rounded-lg px-3 py-2 mb-3">
          {currentType.description}
        </p>
      )}

      {/* Input + button */}
      <div className="flex gap-2 mb-6">
        {!currentType.noInput && (
          <div className="flex flex-1 flex-col gap-2">
            <input
              type="text"
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && !loading && target.trim() && handleScan()}
              placeholder={currentType.placeholder}
              className="w-full rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm font-mono shadow-sm outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-100 transition"
              dir="ltr"
            />
            {currentType.extraField && (
              <input
                type="text"
                value={extraTarget}
                onChange={e => setExtraTarget(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && !loading && target.trim() && extraTarget.trim() && handleScan()}
                placeholder={currentType.extraField.placeholder}
                className="w-full rounded-xl border border-blue-200 bg-blue-50 px-4 py-3 text-sm shadow-sm outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-100 transition"
                dir="rtl"
              />
            )}
            {currentType.dossierFields && (
              <div className="grid grid-cols-2 gap-2">
                {[
                  { key: 'email',    ph: 'אימייל (אופציונלי)', dir: 'ltr' },
                  { key: 'phone',    ph: 'טלפון (אופציונלי)',  dir: 'ltr' },
                  { key: 'username', ph: 'Username (אופציונלי)', dir: 'ltr' },
                  { key: 'company',  ph: 'חברה / עמותה (אופציונלי)', dir: 'rtl' },
                ].map(({ key, ph, dir }) => (
                  <input
                    key={key}
                    type="text"
                    value={dossierExtra[key]}
                    onChange={e => setDossierExtra(prev => ({ ...prev, [key]: e.target.value }))}
                    placeholder={ph}
                    className="rounded-xl border border-slate-200 bg-white px-3 py-2.5 text-sm font-mono shadow-sm outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-100 transition"
                    dir={dir}
                  />
                ))}
              </div>
            )}
          </div>
        )}
        <button
          onClick={handleScan}
          disabled={loading || (!currentType.noInput && !target.trim()) || (currentType.extraField && !extraTarget.trim())}
          className={`flex items-center gap-2 rounded-xl px-5 py-3 text-sm font-bold text-white transition disabled:opacity-40 disabled:cursor-not-allowed whitespace-nowrap self-start ${scanType === 'deep_domain' ? 'bg-indigo-600 hover:bg-indigo-700' : 'bg-slate-900 hover:bg-slate-700'}`}
        >
          {loading ? <Loader2 size={16} className="animate-spin" /> : <Search size={16} />}
          {currentType.noInput ? 'סרוק רשת' : 'סרוק'}
        </button>
      </div>

      {/* Job status bar */}
      {job && (
        <div className="flex items-center justify-between mb-4 rounded-xl border border-slate-200 bg-white px-4 py-2.5">
          <div className="flex items-center gap-2 text-sm text-slate-500">
            <span className="font-mono text-xs">{jobId?.slice(0, 8)}...</span>
            <span>·</span>
            <span>{currentType.label}</span>
            {job.target && job.target !== 'local_network' && (
              <><span>·</span><span className="font-mono text-xs">{job.target}</span></>
            )}
          </div>
          <StatusBadge status={job.status} />
        </div>
      )}

      {/* Results */}
      {job?.status === 'completed' && job.result && (
        <Results scanType={scanType} data={job.result} />
      )}

      {/* Live progress log */}
      {(job?.status === 'running') && (
        <div className="rounded-xl border border-blue-200 bg-slate-900 p-4 font-mono text-xs text-green-400 space-y-1">
          <div className="flex items-center gap-2 mb-2 border-b border-slate-700 pb-2">
            <Loader2 size={12} className="animate-spin text-blue-400" />
            <span className="text-blue-400 font-bold">LOG — {currentType.label}</span>
          </div>
          {(job.progress || []).length === 0 && (
            <p className="text-slate-500">מאתחל...</p>
          )}
          {(job.progress || []).map((line, i) => (
            <p key={i}><span className="text-slate-600">[{i + 1}]</span> {line}</p>
          ))}
          <p className="text-slate-600 animate-pulse">▌</p>
        </div>
      )}
    </div>
  );
}