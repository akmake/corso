import { useEffect, useState, useCallback, useMemo, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { useReactToPrint } from 'react-to-print';
import {
  FolderOpen, Plus, Trash2, ExternalLink, ChevronDown, ChevronUp,
  Mail, Phone, User, Building2, Globe, Search, StickyNote, RefreshCw,
  Network, Printer
} from 'lucide-react';
import { casesApi, startScan, getJob } from '../utils/webintApi';
import GraphView from '../components/GraphView';
import ReportView from '../components/ReportView';

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return d.toLocaleDateString('he-IL', { day: '2-digit', month: '2-digit', year: 'numeric' })
    + ' ' + d.toLocaleTimeString('he-IL', { hour: '2-digit', minute: '2-digit' });
}

function StatBadge({ value, label, color }) {
  const colors = {
    red:    'bg-red-50   border-red-200   text-red-700',
    amber:  'bg-amber-50 border-amber-200 text-amber-700',
    blue:   'bg-blue-50  border-blue-200  text-blue-700',
    green:  'bg-green-50 border-green-200 text-green-700',
    purple: 'bg-purple-50 border-purple-200 text-purple-700',
  };
  return (
    <div className={`flex flex-col items-center rounded-lg border px-3 py-1.5 ${colors[color]}`}>
      <span className="text-lg font-black">{value ?? 0}</span>
      <span className="text-[10px] opacity-70">{label}</span>
    </div>
  );
}

function TagList({ items = [], color = 'slate' }) {
  const colors = {
    red:    'bg-red-100   text-red-700   border-red-200',
    blue:   'bg-blue-100  text-blue-700  border-blue-200',
    purple: 'bg-purple-100 text-purple-700 border-purple-200',
    slate:  'bg-slate-100 text-slate-700 border-slate-200',
    green:  'bg-green-100 text-green-700 border-green-200',
  };
  return (
    <div className="flex flex-wrap gap-1">
      {items.map((item, i) => (
        <span key={i} className={`rounded-full border px-2 py-0.5 font-mono text-xs ${colors[color] || colors.slate}`}>
          {item}
        </span>
      ))}
    </div>
  );
}

function Accordion({ title, icon: Icon, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-xl border border-slate-200 overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="flex w-full items-center justify-between bg-slate-50 px-4 py-3 text-sm font-semibold text-slate-700 hover:bg-slate-100 transition"
      >
        <span className="flex items-center gap-2">
          {Icon && <Icon size={14} className="text-slate-500" />}
          {title}
        </span>
        {open ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
      </button>
      {open && <div className="p-4">{children}</div>}
    </div>
  );
}

// ── Case Detail View ──────────────────────────────────────────────────────────

function CaseDetail({ caseData, onDelete, onNotesChange }) {
  const { subject, created_at, notes, result = {} } = caseData;
  const found   = result.found   || {};
  const stats   = result.stats   || {};
  const israeli = result.israeli || {};

  const direct = israeli.direct || {};

  const israeliCount =
    Object.values(israeli.site_results || {}).reduce((s, v) => s + (v.results?.length || 0), 0) +
    (israeli.guidestar?.length || 0) +
    (israeli.court?.length || 0) +
    (israeli.professions?.length || 0) +
    (israeli.datagov?.companies?.records?.length || 0) +
    (israeli.datagov?.associations?.records?.length || 0) +
    (israeli.datagov?.tenders?.records?.length || 0) +
    (direct.b144?.total || 0) +
    (direct.courts?.total || 0) +
    (direct.opencorporates?.total || 0) +
    Object.values(direct.datagov || {}).reduce((s, v) => s + (v.total || 0), 0);

  const [localNotes, setLocalNotes] = useState(notes || '');
  const [savingNotes, setSavingNotes] = useState(false);
  const [viewMode, setViewMode] = useState('list'); // 'list' | 'graph'

  const printRef = useRef();
  const handlePrint = useReactToPrint({
    content: () => printRef.current,
    documentTitle: `דוח_חקירה_${subject.replace(/ /g, '_')}`,
  });

  async function handleSaveNotes() {
    setSavingNotes(true);
    try {
      await casesApi.updateNotes(caseData.id, localNotes);
      onNotesChange(caseData.id, localNotes);
    } finally {
      setSavingNotes(false);
    }
  }

  return (
    <div className="space-y-4">

      {/* Header */}
      <div className="rounded-xl border border-indigo-200 bg-gradient-to-r from-indigo-50 to-slate-50 p-4">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            {caseData.avatar ? (
              <img src={caseData.avatar} className="w-12 h-12 rounded-full border-2 border-indigo-200 shadow" alt="" />
            ) : (
              <div className="w-12 h-12 rounded-full bg-indigo-100 border-2 border-indigo-200 flex items-center justify-center">
                <User size={22} className="text-indigo-500" />
              </div>
            )}
            <div>
              <h2 className="text-xl font-black text-slate-800">{subject}</h2>
              <p className="text-xs text-slate-400">{fmtDate(created_at)}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handlePrint}
              className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-xs font-semibold text-slate-700 hover:bg-slate-50 transition shadow-sm"
            >
              <Printer size={14} /> הפק דוח
            </button>
            <div className="flex bg-white rounded-lg border border-indigo-200 p-0.5 shadow-sm">
              <button
                onClick={() => setViewMode('list')}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md transition ${viewMode === 'list' ? 'bg-indigo-100 text-indigo-700' : 'text-slate-500 hover:bg-slate-50'}`}
              >
                <Search size={14} /> רשימה
              </button>
              <button
                onClick={() => setViewMode('graph')}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-md transition ${viewMode === 'graph' ? 'bg-indigo-100 text-indigo-700' : 'text-slate-500 hover:bg-slate-50'}`}
              >
                <Network size={14} /> גרף קשרים
              </button>
            </div>
            <button
              onClick={() => onDelete(caseData.id)}
              className="flex items-center gap-1.5 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-xs font-semibold text-red-600 hover:bg-red-100 transition shadow-sm"
            >
              <Trash2 size={14} /> מחק
            </button>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <StatBadge value={stats.web_results}     label="תוצאות web"   color="blue"   />
          <StatBadge value={stats.emails_found}    label="אימיילים"     color="red"    />
          <StatBadge value={stats.phones_found}    label="טלפונים"      color="amber"  />
          <StatBadge value={stats.accounts_found}  label="חשבונות"      color="green"  />
          <StatBadge value={stats.companies_found} label="חברות/עמותות" color="purple" />
        </div>
      </div>

      {/* Notes */}
      <div className="rounded-xl border border-amber-200 bg-amber-50 p-4">
        <p className="mb-2 flex items-center gap-1.5 text-xs font-bold text-amber-700">
          <StickyNote size={13} /> הערות חוקר
        </p>
        <textarea
          value={localNotes}
          onChange={e => setLocalNotes(e.target.value)}
          rows={3}
          placeholder="הוסף הערות, תובנות, מסקנות..."
          className="w-full rounded-lg border border-amber-200 bg-white px-3 py-2 text-sm text-slate-700 placeholder:text-slate-400 focus:outline-none focus:ring-1 focus:ring-amber-400 resize-none"
        />
        <button
          onClick={handleSaveNotes}
          disabled={savingNotes}
          className="mt-2 rounded-lg bg-amber-500 px-3 py-1.5 text-xs font-semibold text-white hover:bg-amber-600 disabled:opacity-50 transition"
        >
          {savingNotes ? 'שומר...' : 'שמור הערות'}
        </button>
      </div>

      {viewMode === 'graph' ? (
        <GraphView caseData={caseData} />
      ) : (
        <>
          {/* Discovered entities */}
          {(found.emails?.length > 0 || found.phones?.length > 0 || found.usernames?.length > 0 || found.companies?.length > 0) && (
            <Accordion title="ישויות שנגלו" icon={Search} defaultOpen>
          <div className="space-y-3">
            {found.emails?.length > 0 && (
              <div>
                <p className="mb-1 text-xs font-bold text-red-600 flex items-center gap-1"><Mail size={11} /> אימיילים</p>
                <TagList items={found.emails} color="red" />
              </div>
            )}
            {found.phones?.length > 0 && (
              <div>
                <p className="mb-1 text-xs font-bold text-amber-600 flex items-center gap-1"><Phone size={11} /> טלפונים</p>
                <TagList items={found.phones} color="slate" />
              </div>
            )}
            {found.usernames?.length > 0 && (
              <div>
                <p className="mb-1 text-xs font-bold text-blue-600 flex items-center gap-1"><User size={11} /> Usernames</p>
                <TagList items={found.usernames} color="blue" />
              </div>
            )}
            {found.companies?.length > 0 && (
              <div>
                <p className="mb-1 text-xs font-bold text-purple-600 flex items-center gap-1"><Building2 size={11} /> חברות / עמותות</p>
                <TagList items={found.companies} color="purple" />
              </div>
            )}
          </div>
        </Accordion>
      )}

      {/* Email profiles */}
      {Object.keys(result.email_profiles || {}).length > 0 && (
        <Accordion title="פרופילים לפי אימייל" icon={Mail} defaultOpen>
          <div className="space-y-3">
            {Object.entries(result.email_profiles).map(([email, prof]) => (
              <div key={email} className="rounded-lg border border-slate-200 p-3 space-y-2">
                <p className="font-mono text-xs font-bold text-slate-600">{email}</p>
                {prof.gravatar?.found && (
                  <div className="flex items-center gap-3">
                    {prof.gravatar.avatar && <img src={prof.gravatar.avatar} className="w-9 h-9 rounded-full border" alt="" />}
                    <div>
                      <p className="text-sm font-semibold text-green-700">{prof.gravatar.display_name}</p>
                      {prof.gravatar.username && <p className="text-xs text-slate-500">@{prof.gravatar.username}</p>}
                      {prof.gravatar.location  && <p className="text-xs text-slate-400">{prof.gravatar.location}</p>}
                    </div>
                    <span className="mr-auto text-xs bg-green-100 text-green-700 border border-green-200 rounded-full px-2 py-0.5">Gravatar</span>
                  </div>
                )}
                {prof.github?.found && (
                  <div className="flex items-center gap-3">
                    {prof.github.avatar && <img src={prof.github.avatar} className="w-9 h-9 rounded-full border" alt="" />}
                    <div>
                      <a href={prof.github.profile} target="_blank" rel="noreferrer"
                        className="text-sm font-semibold text-blue-700 hover:underline flex items-center gap-1">
                        @{prof.github.username} <ExternalLink size={10} />
                      </a>
                      {prof.github.name     && <p className="text-xs text-slate-600">{prof.github.name}</p>}
                      {prof.github.location && <p className="text-xs text-slate-400">{prof.github.location}</p>}
                      {prof.github.company  && <p className="text-xs text-slate-400">{prof.github.company}</p>}
                    </div>
                    <span className="mr-auto text-xs bg-blue-100 text-blue-700 border border-blue-200 rounded-full px-2 py-0.5">GitHub</span>
                  </div>
                )}
                {prof.crtsh?.domains?.length > 0 && (
                  <div>
                    <p className="text-xs text-slate-400 mb-1">דומיינים מ-SSL ({prof.crtsh.cert_count} תעודות):</p>
                    <TagList items={prof.crtsh.domains.slice(0, 8)} color="purple" />
                  </div>
                )}
              </div>
            ))}
          </div>
        </Accordion>
      )}

      {/* Phone profiles */}
      {Object.keys(result.phone_profiles || {}).length > 0 && (
        <Accordion title="פרטי טלפון" icon={Phone}>
          <div className="space-y-2">
            {Object.entries(result.phone_profiles).map(([ph, prof]) => (
              <div key={ph} className="rounded-lg border border-amber-200 bg-amber-50 p-3">
                <p className="font-mono text-sm font-bold text-amber-800 mb-2">{prof.international || ph}</p>
                <div className="flex gap-2 text-xs text-slate-600 mb-2">
                  {prof.country  && <span>{prof.country}</span>}
                  {prof.carrier  && <span>· {prof.carrier}</span>}
                  {prof.line_type && <span>· {prof.line_type}</span>}
                </div>
                <div className="flex gap-2">
                  {prof.whatsapp && (
                    <a href={prof.whatsapp} target="_blank" rel="noreferrer"
                      className="flex items-center gap-1 rounded-lg border border-green-200 bg-green-50 px-3 py-1.5 text-xs font-semibold text-green-700 hover:bg-green-100">
                      <ExternalLink size={10} /> WhatsApp
                    </a>
                  )}
                  {prof.telegram && (
                    <a href={prof.telegram} target="_blank" rel="noreferrer"
                      className="flex items-center gap-1 rounded-lg border border-blue-200 bg-blue-50 px-3 py-1.5 text-xs font-semibold text-blue-700 hover:bg-blue-100">
                      <ExternalLink size={10} /> Telegram
                    </a>
                  )}
                </div>
              </div>
            ))}
          </div>
        </Accordion>
      )}

      {/* Social accounts */}
      {result.accounts?.length > 0 && (
        <Accordion title={`חשבונות ברשתות (${result.accounts.length})`} icon={Globe}>
          <div className="grid grid-cols-2 gap-2">
            {result.accounts.map((a, i) => (
              <a key={i} href={a.url} target="_blank" rel="noreferrer"
                className="flex items-center justify-between rounded-lg border border-green-200 bg-green-50 px-3 py-2 text-sm hover:bg-green-100 transition">
                <span className="font-semibold text-green-800">{a.platform}</span>
                <ExternalLink size={11} className="text-green-500" />
              </a>
            ))}
          </div>
        </Accordion>
      )}

      {/* Israeli intel */}
      {israeliCount > 0 && (
        <Accordion title={`מודיעין ישראלי (${israeliCount} תוצאות)`} icon={Building2} defaultOpen>
          <div className="space-y-4">

            {/* Guidestar orgs */}
            {israeli.guidestar?.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-bold text-purple-700 border-b border-purple-100 pb-1">עמותות — Guidestar ({israeli.guidestar.length})</p>
                <div className="space-y-1">
                  {israeli.guidestar.map((o, i) => (
                    <a key={i} href={o.url} target="_blank" rel="noreferrer"
                      className="flex items-center justify-between rounded-lg border border-purple-100 bg-purple-50 px-3 py-2 hover:bg-purple-100 transition">
                      <div>
                        <p className="text-xs font-semibold text-purple-900">{o.name}</p>
                        <p className="text-[10px] text-purple-500">{o.type} · {o.status}</p>
                      </div>
                      <ExternalLink size={10} className="text-purple-400 flex-shrink-0" />
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* data.gov.il — companies */}
            {israeli.datagov?.companies?.records?.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-bold text-blue-700 border-b border-blue-100 pb-1">רשם החברות ({israeli.datagov.companies.total})</p>
                <div className="space-y-1">
                  {israeli.datagov.companies.records.slice(0, 8).map((r, i) => (
                    <div key={i} className="rounded-lg border border-blue-100 bg-blue-50 px-3 py-2 text-xs text-blue-900">
                      {r.company_name || r['שם חברה'] || r.CompanyName || Object.values(r).filter(Boolean).slice(0,3).join(' · ')}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* data.gov.il — associations */}
            {israeli.datagov?.associations?.records?.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-bold text-indigo-700 border-b border-indigo-100 pb-1">עמותות — data.gov.il ({israeli.datagov.associations.total})</p>
                <div className="space-y-1">
                  {israeli.datagov.associations.records.slice(0, 8).map((r, i) => (
                    <div key={i} className="rounded-lg border border-indigo-100 bg-indigo-50 px-3 py-2 text-xs text-indigo-900">
                      {r.association_name || r['שם עמותה'] || r.Name || Object.values(r).filter(Boolean).slice(0,3).join(' · ')}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* data.gov.il — tenders */}
            {israeli.datagov?.tenders?.records?.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-bold text-amber-700 border-b border-amber-100 pb-1">מכרזים ({israeli.datagov.tenders.total})</p>
                <div className="space-y-1">
                  {israeli.datagov.tenders.records.slice(0, 5).map((r, i) => (
                    <div key={i} className="rounded-lg border border-amber-100 bg-amber-50 px-3 py-2 text-xs text-amber-900">
                      {Object.values(r).filter(Boolean).slice(0,4).join(' · ')}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Court records */}
            {israeli.court?.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-bold text-red-700 border-b border-red-100 pb-1">פסיקות בית משפט ({israeli.court.length})</p>
                <div className="space-y-1">
                  {israeli.court.slice(0, 8).map((r, i) => (
                    <a key={i} href={r.url} target="_blank" rel="noreferrer"
                      className="flex items-start justify-between gap-2 rounded-lg border border-red-100 bg-red-50 px-3 py-2 hover:bg-red-100 transition">
                      <div className="min-w-0">
                        <p className="text-xs font-semibold text-red-900 truncate">{r.title || r.case_id}</p>
                        {r.court && <p className="text-[10px] text-red-500">{r.court} {r.date ? `· ${r.date}` : ''}</p>}
                        {r.snippet && <p className="text-[10px] text-red-600 line-clamp-2 mt-0.5">{r.snippet}</p>}
                      </div>
                      {r.url && <ExternalLink size={10} className="text-red-400 flex-shrink-0 mt-0.5" />}
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Professional registries */}
            {israeli.professions?.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-bold text-teal-700 border-b border-teal-100 pb-1">רישיונות מקצועיים ({israeli.professions.length})</p>
                <div className="space-y-1">
                  {israeli.professions.slice(0, 8).map((r, i) => (
                    <a key={i} href={r.url} target="_blank" rel="noreferrer"
                      className="flex items-start justify-between gap-2 rounded-lg border border-teal-100 bg-teal-50 px-3 py-2 hover:bg-teal-100 transition">
                      <div className="min-w-0">
                        <p className="text-[10px] text-teal-500 font-semibold mb-0.5">{r.profession_source}</p>
                        <p className="text-xs text-teal-900 truncate">{r.title}</p>
                        {r.snippet && <p className="text-[10px] text-teal-600 line-clamp-1">{r.snippet}</p>}
                      </div>
                      {r.url && <ExternalLink size={10} className="text-teal-400 flex-shrink-0 mt-0.5" />}
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* B144 — phone / address */}
            {direct.b144?.results?.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-bold text-orange-700 border-b border-orange-100 pb-1">
                  B144 — טלפון וכתובת ({direct.b144.total})
                </p>
                <div className="space-y-1">
                  {direct.b144.results.map((r, i) => (
                    <div key={i} className="rounded-lg border border-orange-100 bg-orange-50 px-3 py-2">
                      <p className="text-xs font-semibold text-orange-900">{r.name}</p>
                      <div className="flex flex-wrap gap-3 mt-0.5">
                        {r.phone   && <span className="text-[10px] text-orange-700 font-mono">📞 {r.phone}</span>}
                        {r.address && <span className="text-[10px] text-orange-600">📍 {r.address}{r.city ? `, ${r.city}` : ''}</span>}
                        {r.type    && <span className="text-[10px] text-orange-500">{r.type}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Guidestar officers — person positions in nonprofits */}
            {direct.guidestar_officers?.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-bold text-purple-700 border-b border-purple-100 pb-1">
                  תפקידים בעמותות ({direct.guidestar_officers.length})
                </p>
                <div className="space-y-1">
                  {direct.guidestar_officers.map((o, i) => (
                    <a key={i} href={o.url} target="_blank" rel="noreferrer"
                      className="flex items-center justify-between rounded-lg border border-purple-100 bg-purple-50 px-3 py-2 hover:bg-purple-100 transition">
                      <div>
                        <p className="text-xs font-semibold text-purple-900">{o.org_name}</p>
                        <p className="text-[10px] text-purple-600">{o.role}{o.name ? ` · ${o.name}` : ''}</p>
                      </div>
                      <ExternalLink size={10} className="text-purple-400 flex-shrink-0" />
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* Courts — psakdin + takdin */}
            {direct.courts?.results?.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-bold text-red-700 border-b border-red-100 pb-1">
                  פסיקות — psakdin / takdin ({direct.courts.total})
                </p>
                <div className="space-y-1">
                  {direct.courts.results.map((r, i) => (
                    <a key={i} href={r.url} target="_blank" rel="noreferrer"
                      className="flex items-start justify-between gap-2 rounded-lg border border-red-100 bg-red-50 px-3 py-2 hover:bg-red-100 transition">
                      <div className="min-w-0">
                        <p className="text-[10px] text-red-400 font-semibold">{r.source}</p>
                        <p className="text-xs font-semibold text-red-900 truncate">{r.title}</p>
                        {(r.court || r.date) && (
                          <p className="text-[10px] text-red-500">{r.court}{r.date ? ` · ${r.date}` : ''}</p>
                        )}
                        {r.snippet && <p className="text-[10px] text-red-600 line-clamp-2 mt-0.5">{r.snippet}</p>}
                      </div>
                      {r.url && <ExternalLink size={10} className="text-red-400 flex-shrink-0 mt-0.5" />}
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* OpenCorporates — Israeli companies */}
            {direct.opencorporates?.companies?.length > 0 && (
              <div>
                <p className="mb-2 text-xs font-bold text-cyan-700 border-b border-cyan-100 pb-1">
                  OpenCorporates — חברות ישראליות ({direct.opencorporates.total})
                </p>
                <div className="space-y-1">
                  {direct.opencorporates.companies.map((c, i) => (
                    <a key={i} href={c.url} target="_blank" rel="noreferrer"
                      className="flex items-center justify-between rounded-lg border border-cyan-100 bg-cyan-50 px-3 py-2 hover:bg-cyan-100 transition">
                      <div>
                        <p className="text-xs font-semibold text-cyan-900">{c.name}</p>
                        <p className="text-[10px] text-cyan-600">
                          {c.number && `#${c.number}`}
                          {c.status && ` · ${c.status}`}
                          {c.type && ` · ${c.type}`}
                          {c.incorporated && ` · הוקמה ${c.incorporated}`}
                        </p>
                        {c.address && <p className="text-[10px] text-cyan-500">{c.address}</p>}
                      </div>
                      <ExternalLink size={10} className="text-cyan-400 flex-shrink-0" />
                    </a>
                  ))}
                </div>
              </div>
            )}

            {/* data.gov.il — all categories */}
            {Object.entries(direct.datagov || {}).map(([key, cat]) => {
              if (!cat.records?.length) return null;
              const colorMap = {
                nonprofits: 'indigo', companies: 'blue', tenders: 'amber',
                company_officers: 'violet', election_funding: 'pink',
                licensed_contractors: 'emerald', gov_employees: 'slate',
              };
              const c = colorMap[key] || 'slate';
              return (
                <div key={key}>
                  <p className={`mb-2 text-xs font-bold text-${c}-700 border-b border-${c}-100 pb-1`}>
                    {cat.label} ({cat.total})
                  </p>
                  <div className="space-y-1">
                    {cat.records.slice(0, 6).map((r, i) => (
                      <div key={i} className={`rounded-lg border border-${c}-100 bg-${c}-50 px-3 py-2 text-xs text-${c}-900`}>
                        {Object.entries(r).slice(0, 5).map(([k, v]) => (
                          <span key={k} className="inline-block ml-2">
                            <span className="text-[10px] opacity-60">{k}: </span>{String(v)}
                          </span>
                        ))}
                      </div>
                    ))}
                  </div>
                </div>
              );
            })}

            {/* Site results — news + gov */}
            {Object.entries(israeli.site_results || {}).map(([key, section]) => {
              if (!section.results?.length) return null;
              return (
                <div key={key}>
                  <p className="mb-2 text-xs font-bold text-slate-600 border-b border-slate-100 pb-1">
                    {section.label} ({section.count})
                    {section.note && <span className="font-normal text-slate-400 mr-1">— {section.note}</span>}
                  </p>
                  <div className="space-y-1">
                    {section.results.slice(0, 6).map((r, i) => (
                      <a key={i} href={r.url} target="_blank" rel="noreferrer"
                        className="block rounded-lg border border-slate-200 px-3 py-2 hover:bg-slate-50 transition">
                        <p className="text-xs font-semibold text-blue-700 truncate">{r.title}</p>
                        {r.snippet && <p className="text-[10px] text-slate-500 line-clamp-2 mt-0.5">{r.snippet}</p>}
                      </a>
                    ))}
                  </div>
                </div>
              );
            })}

          </div>
        </Accordion>
      )}

      {/* Web results */}
      {result.web_results?.length > 0 && (
        <Accordion title={`תוצאות web (${result.web_results.length})`} icon={Globe}>
          <div className="space-y-2">
            {result.web_results.map((r, i) => (
              <a key={i} href={r.url} target="_blank" rel="noreferrer"
                className="block rounded-lg border border-slate-200 p-3 hover:bg-slate-50 transition">
                <p className="text-sm font-semibold text-blue-700 hover:underline truncate">{r.title}</p>
                <p className="text-xs text-slate-500 truncate">{r.url}</p>
                {r.snippet && <p className="mt-1 text-xs text-slate-600 line-clamp-2">{r.snippet}</p>}
              </a>
            ))}
          </div>
        </Accordion>
      )}
        </>
      )}
      
      {/* Hidden printable report component */}
      <div style={{ display: 'none' }}>
        <ReportView ref={printRef} caseData={caseData} />
      </div>
    </div>
  );
}

// ── New Case Dialog ───────────────────────────────────────────────────────────

function NewCaseDialog({ onClose, onCreated }) {
  const [name, setName]       = useState('');
  const [email, setEmail]     = useState('');
  const [phone, setPhone]     = useState('');
  const [username, setUsername] = useState('');
  const [company, setCompany] = useState('');
  const [loading, setLoading] = useState(false);
  const [status, setStatus]   = useState('');

  async function handleStart() {
    if (!name.trim()) return;
    setLoading(true);
    setStatus('מתחיל חקירה...');
    try {
      const payload = { target: name.trim(), email, phone, username, company };
      const { data } = await startScan.dossier(payload.target);
      const jobId = data.job_id;

      // WebSocket connection for real-time progress
      const wsUrl = `ws://localhost:8000/ws/jobs`;
      const socket = new WebSocket(wsUrl);

      socket.onmessage = (event) => {
        try {
          const msgData = JSON.parse(event.data);
          if (msgData.job_id === jobId) {
            if (msgData.msg) {
              setStatus(msgData.msg);
            }
          }
        } catch (err) {
          console.error("WS Parse Error", err);
        }
      };

      // Poll until done (as backup and to get final result)
      await new Promise((resolve, reject) => {
        const interval = setInterval(async () => {
          try {
            const { data: job } = await getJob(jobId);
            if (job.status === 'completed' || job.status === 'failed') {
              clearInterval(interval);
              socket.close();
              resolve(job);
            }
          } catch (e) {
            clearInterval(interval);
            socket.close();
            reject(e);
          }
        }, 1500);
      });

      setStatus('נשמר בהצלחה!');
      setTimeout(() => { onCreated(); onClose(); }, 800);
    } catch (e) {
      setStatus('שגיאה: ' + e.message);
      setLoading(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl">
        <h2 className="mb-4 text-lg font-black text-slate-900 flex items-center gap-2">
          <Plus size={18} className="text-indigo-600" /> פתיחת תיק חדש
        </h2>
        <div className="space-y-3">
          <div>
            <label className="mb-1 block text-xs font-semibold text-slate-600">שם היעד *</label>
            <input
              value={name} onChange={e => setName(e.target.value)}
              placeholder="שם מלא (עברית / אנגלית)"
              className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-indigo-400"
            />
          </div>
          {[
            { label: 'אימייל (אופציונלי)', val: email, set: setEmail, ph: 'user@example.com' },
            { label: 'טלפון (אופציונלי)',  val: phone, set: setPhone, ph: '05X-XXXXXXX' },
            { label: 'Username (אופציונלי)', val: username, set: setUsername, ph: '@username' },
            { label: 'חברה (אופציונלי)',  val: company, set: setCompany, ph: 'שם חברה' },
          ].map(({ label, val, set, ph }) => (
            <div key={label}>
              <label className="mb-1 block text-xs font-semibold text-slate-500">{label}</label>
              <input
                value={val} onChange={e => set(e.target.value)} placeholder={ph}
                className="w-full rounded-lg border border-slate-200 px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-indigo-400"
              />
            </div>
          ))}
        </div>

        {status && (
          <div className="mt-3 rounded-lg bg-slate-50 border border-slate-200 px-3 py-2 text-xs text-slate-600">
            {status}
          </div>
        )}

        <div className="mt-5 flex gap-2 justify-end">
          <button onClick={onClose} disabled={loading}
            className="rounded-lg border border-slate-200 px-4 py-2 text-sm text-slate-600 hover:bg-slate-50 transition">
            ביטול
          </button>
          <button onClick={handleStart} disabled={loading || !name.trim()}
            className="rounded-lg bg-indigo-600 px-4 py-2 text-sm font-semibold text-white hover:bg-indigo-700 disabled:opacity-50 transition flex items-center gap-2">
            {loading && <RefreshCw size={13} className="animate-spin" />}
            {loading ? 'חוקר...' : 'התחל חקירה'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Case List Card ────────────────────────────────────────────────────────────

function CaseCard({ c, selected, onClick }) {
  const isSelected = selected?.id === c.id;
  return (
    <button
      onClick={() => onClick(c)}
      className={`w-full text-right rounded-xl border p-3 transition-all ${
        isSelected
          ? 'border-indigo-300 bg-indigo-50 shadow-sm'
          : 'border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50'
      }`}
    >
      <div className="flex items-center gap-3">
        {c.avatar ? (
          <img src={c.avatar} className="w-9 h-9 rounded-full border flex-shrink-0" alt="" />
        ) : (
          <div className="w-9 h-9 rounded-full bg-slate-100 border flex-shrink-0 flex items-center justify-center">
            <User size={16} className="text-slate-400" />
          </div>
        )}
        <div className="min-w-0 flex-1">
          <p className="font-bold text-sm text-slate-800 truncate">{c.subject}</p>
          <p className="text-[10px] text-slate-400">{fmtDate(c.created_at)}</p>
        </div>
      </div>
      {/* Mini stats */}
      <div className="mt-2 flex gap-2 text-[10px]">
        {c.stats?.emails_found    > 0 && <span className="text-red-600 font-semibold">{c.stats.emails_found} מיילים</span>}
        {c.stats?.phones_found    > 0 && <span className="text-amber-600 font-semibold">{c.stats.phones_found} טלפונים</span>}
        {c.stats?.accounts_found  > 0 && <span className="text-green-600 font-semibold">{c.stats.accounts_found} חשבונות</span>}
      </div>
      {c.notes && <p className="mt-1.5 text-[10px] text-slate-400 truncate italic">{c.notes}</p>}
    </button>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function CasesPage() {
  const [cases, setCases]         = useState([]);
  const [selected, setSelected]   = useState(null);
  const [fullCase, setFullCase]   = useState(null);
  const [loading, setLoading]     = useState(true);
  const [showNew, setShowNew]     = useState(false);
  const [filter, setFilter]       = useState('');

  const loadCases = useCallback(async () => {
    setLoading(true);
    try {
      const { data } = await casesApi.list();
      setCases(data.cases || []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadCases(); }, [loadCases]);

  async function handleSelect(c) {
    setSelected(c);
    setFullCase(null);
    const { data } = await casesApi.get(c.id);
    setFullCase(data);
  }

  async function handleDelete(id) {
    if (!confirm('למחוק את התיק לצמיתות?')) return;
    await casesApi.delete(id);
    setCases(prev => prev.filter(c => c.id !== id));
    if (selected?.id === id) { setSelected(null); setFullCase(null); }
  }

  function handleNotesChange(id, notes) {
    setCases(prev => prev.map(c => c.id === id ? { ...c, notes } : c));
    if (fullCase?.id === id) setFullCase(prev => ({ ...prev, notes }));
  }

  const filtered = cases.filter(c =>
    c.subject.toLowerCase().includes(filter.toLowerCase()) ||
    c.notes?.toLowerCase().includes(filter.toLowerCase())
  );

  return (
    <div className="flex h-[calc(100vh-64px)] overflow-hidden bg-slate-50">

      {/* Sidebar */}
      <aside className="flex w-72 flex-shrink-0 flex-col border-r border-slate-200 bg-white">
        {/* Sidebar header */}
        <div className="border-b border-slate-100 p-4">
          <div className="mb-3 flex items-center justify-between">
            <h1 className="flex items-center gap-2 text-base font-black text-slate-900">
              <FolderOpen size={17} className="text-indigo-600" /> תיקים
            </h1>
            <button
              onClick={() => setShowNew(true)}
              className="flex items-center gap-1 rounded-lg bg-indigo-600 px-2.5 py-1.5 text-xs font-semibold text-white hover:bg-indigo-700 transition"
            >
              <Plus size={12} /> תיק חדש
            </button>
          </div>
          <input
            value={filter} onChange={e => setFilter(e.target.value)}
            placeholder="חיפוש תיקים..."
            className="w-full rounded-lg border border-slate-200 px-3 py-1.5 text-xs focus:outline-none focus:ring-1 focus:ring-indigo-300"
          />
        </div>

        {/* Case list */}
        <div className="flex-1 overflow-y-auto p-2 space-y-1.5">
          {loading ? (
            <div className="flex items-center justify-center py-10 text-sm text-slate-400">טוען...</div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-10 text-center text-slate-400">
              <FolderOpen size={32} className="mb-2 opacity-30" />
              <p className="text-sm">אין תיקים שמורים</p>
              <p className="text-xs mt-1">לחץ "תיק חדש" להתחיל</p>
            </div>
          ) : (
            filtered.map(c => (
              <CaseCard key={c.id} c={c} selected={selected} onClick={handleSelect} />
            ))
          )}
        </div>

        {cases.length > 0 && (
          <div className="border-t border-slate-100 p-3 text-center text-xs text-slate-400">
            {cases.length} תיק{cases.length !== 1 ? 'ים' : ''}
          </div>
        )}
      </aside>

      {/* Main panel */}
      <main className="flex-1 overflow-y-auto p-6">
        {!selected ? (
          <div className="flex h-full flex-col items-center justify-center text-slate-400">
            <FolderOpen size={52} className="mb-4 opacity-20" />
            <p className="text-lg font-semibold">בחר תיק מהרשימה</p>
            <p className="text-sm mt-1">או פתח תיק חדש לחקירה</p>
          </div>
        ) : !fullCase ? (
          <div className="flex h-full items-center justify-center text-slate-400">
            <RefreshCw size={24} className="animate-spin" />
          </div>
        ) : (
          <div className="mx-auto max-w-3xl">
            <CaseDetail
              caseData={{ ...fullCase, avatar: selected.avatar }}
              onDelete={handleDelete}
              onNotesChange={handleNotesChange}
            />
          </div>
        )}
      </main>

      {showNew && (
        <NewCaseDialog
          onClose={() => setShowNew(false)}
          onCreated={loadCases}
        />
      )}
    </div>
  );
}
