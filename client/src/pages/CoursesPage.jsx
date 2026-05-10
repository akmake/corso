import { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import {
  Plus, Trash2, Loader2, CheckCircle2, XCircle, Download, Play, Pause,
  Captions, Link2, FolderOpen, Upload, X, Search, ChevronLeft,
  Film, FileText, Mic, GraduationCap, BookOpen, MoreHorizontal,
  Layers, Clock, Filter, ArrowRight, Circle, AlertCircle, ExternalLink,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { coursesApi, getJob } from '../utils/webintApi';

/* ─── Constants ─────────────────────────────────────────────────────────── */
const POLL_MS = 1500;
const VIDEO_EXTS = new Set(['mp4','mkv','avi','mov','webm','m4v','mp3','m4a','wav','ogg','flac']);
const PRES_EXTS  = new Set(['pdf','pptx','ppt','odp','key']);
const MODEL_OPTIONS = [
  { value: 'large-v3', label: 'large-v3' },
  { value: 'large-v2', label: 'large-v2' },
  { value: 'medium',   label: 'medium'   },
  { value: 'small',    label: 'small'    },
];
const LANG_OPTIONS = [
  { value: 'he',   label: 'עברית'  },
  { value: 'auto', label: 'Auto'   },
  { value: 'en',   label: 'English'},
  { value: 'ar',   label: 'عربي'   },
];

/* Course accent palette — used as a single hue per course, not as decoration */
const COURSE_HUES = [
  { name: 'indigo',  base: '#6366f1', soft: '#eef2ff', text: '#4338ca' },
  { name: 'sky',     base: '#0ea5e9', soft: '#f0f9ff', text: '#0369a1' },
  { name: 'emerald', base: '#10b981', soft: '#ecfdf5', text: '#047857' },
  { name: 'amber',   base: '#f59e0b', soft: '#fffbeb', text: '#b45309' },
  { name: 'rose',    base: '#f43f5e', soft: '#fff1f2', text: '#be123c' },
  { name: 'violet',  base: '#8b5cf6', soft: '#f5f3ff', text: '#6d28d9' },
  { name: 'pink',    base: '#ec4899', soft: '#fdf2f8', text: '#be185d' },
  { name: 'teal',    base: '#14b8a6', soft: '#f0fdfa', text: '#0f766e' },
];
const hueFor = (i) => COURSE_HUES[i % COURSE_HUES.length];

/* Design tokens */
const T = {
  bg:        '#f6f6f9',
  surface:   '#ffffff',
  panel:     '#fafafc',
  line:      'rgba(15,15,18,0.07)',
  lineSoft:  'rgba(15,15,18,0.04)',
  ink:       '#0f0f12',
  text:      '#2a2a32',
  muted:     '#6b7280',
  faint:     '#9ca3af',
  ghost:     '#c7c8d1',
  accent:    '#5a51d4',
  accentSoft:'#eeedfb',
  ok:        '#10b981',
  warn:      '#f59e0b',
  err:       '#ef4444',
  info:      '#3b82f6',
};

/* ─── Tiny UI primitives ────────────────────────────────────────────────── */
function Btn({ children, variant = 'ghost', size = 'md', icon: Icon, ...rest }) {
  const sizes = {
    sm: { pad: '5px 9px',  font: 11,   gap: 5,  ic: 11 },
    md: { pad: '7px 12px', font: 12,   gap: 6,  ic: 13 },
    lg: { pad: '9px 16px', font: 13,   gap: 7,  ic: 14 },
  }[size];
  const variants = {
    primary: { bg: T.ink,        color: '#fff',     border: T.ink,    hover: '#000' },
    accent:  { bg: T.accent,     color: '#fff',     border: T.accent, hover: '#4a42c0' },
    soft:    { bg: T.accentSoft, color: T.accent,   border: T.accentSoft, hover: '#e2dffa' },
    outline: { bg: '#fff',       color: T.text,     border: T.line,   hover: '#fafafc' },
    ghost:   { bg: 'transparent',color: T.muted,    border: 'transparent', hover: 'rgba(15,15,18,0.04)' },
    danger:  { bg: '#fff',       color: T.err,      border: 'rgba(239,68,68,0.2)', hover: '#fef2f2' },
  }[variant];
  return (
    <button
      {...rest}
      style={{
        display: 'inline-flex', alignItems: 'center', gap: sizes.gap,
        padding: sizes.pad, fontSize: sizes.font, fontWeight: 600,
        borderRadius: 8, cursor: rest.disabled ? 'not-allowed' : 'pointer',
        background: variants.bg, color: variants.color,
        border: `1px solid ${variants.border}`,
        opacity: rest.disabled ? 0.45 : 1,
        transition: 'background 0.12s, border-color 0.12s, transform 0.06s',
        whiteSpace: 'nowrap', userSelect: 'none',
        ...rest.style,
      }}
      onMouseEnter={(e) => { if (!rest.disabled) e.currentTarget.style.background = variants.hover; rest.onMouseEnter?.(e); }}
      onMouseLeave={(e) => { e.currentTarget.style.background = variants.bg; rest.onMouseLeave?.(e); }}
    >
      {Icon && <Icon size={sizes.ic} />}
      {children}
    </button>
  );
}

function Chip({ children, tone = 'neutral', icon: Icon, dot, ...rest }) {
  const tones = {
    neutral: { bg: '#f3f4f6',                color: T.muted,        border: 'transparent' },
    ok:      { bg: 'rgba(16,185,129,0.09)',  color: '#047857',      border: 'rgba(16,185,129,0.18)' },
    warn:    { bg: 'rgba(245,158,11,0.09)',  color: '#b45309',      border: 'rgba(245,158,11,0.18)' },
    err:     { bg: 'rgba(239,68,68,0.09)',   color: '#b91c1c',      border: 'rgba(239,68,68,0.18)' },
    info:    { bg: 'rgba(59,130,246,0.09)',  color: '#1d4ed8',      border: 'rgba(59,130,246,0.18)' },
    accent:  { bg: T.accentSoft,             color: T.accent,       border: 'transparent' },
    pending: { bg: 'transparent',            color: T.faint,        border: T.line },
  }[tone];
  return (
    <span {...rest} style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '3px 8px', borderRadius: 999, fontSize: 11, fontWeight: 600,
      background: tones.bg, color: tones.color, border: `1px solid ${tones.border}`,
      lineHeight: 1.4, whiteSpace: 'nowrap', ...rest.style,
    }}>
      {dot && <span style={{ width: 5, height: 5, borderRadius: '50%', background: 'currentColor' }} />}
      {Icon && <Icon size={11} />}
      {children}
    </span>
  );
}

function IconBtn({ icon: Icon, tone = 'muted', size = 28, ...rest }) {
  const colors = { muted: T.faint, danger: T.err, accent: T.accent, ink: T.ink };
  return (
    <button {...rest} style={{
      width: size, height: size, display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      background: 'transparent', border: '1px solid transparent', borderRadius: 8,
      color: colors[tone], cursor: rest.disabled ? 'not-allowed' : 'pointer',
      opacity: rest.disabled ? 0.4 : 1, transition: 'background 0.12s, color 0.12s',
      ...rest.style,
    }}
      onMouseEnter={(e) => { if (!rest.disabled) { e.currentTarget.style.background = 'rgba(15,15,18,0.05)'; e.currentTarget.style.color = T.ink; } }}
      onMouseLeave={(e) => { e.currentTarget.style.background = 'transparent'; e.currentTarget.style.color = colors[tone]; }}
    >
      <Icon size={Math.round(size * 0.5)} />
    </button>
  );
}

/* ─── Job tracker (compact, inline) ─────────────────────────────────────── */
function Terminal({ lines }) {
  const ref = useRef(null);
  useEffect(() => { if (ref.current) ref.current.scrollTop = ref.current.scrollHeight; }, [lines]);
  if (!lines.length) return null;
  return (
    <div ref={ref} style={{
      marginTop: 10, maxHeight: 110, overflowY: 'auto',
      borderRadius: 8, background: '#0b0b10', padding: '10px 12px',
    }}>
      {lines.map((l, i) => (
        <p key={i} style={{
          margin: 0, fontFamily: 'ui-monospace, Menlo, monospace',
          fontSize: 11, lineHeight: '17px', color: '#86efac', wordBreak: 'break-all',
        }}>{l}</p>
      ))}
    </div>
  );
}

function JobTracker({ jobId, label, accent = T.accent, onDone }) {
  const [status, setStatus] = useState('running');
  const [lines,  setLines]  = useState([]);
  const [pct,    setPct]    = useState(null);
  useEffect(() => {
    if (!jobId) return;
    let dead = false;
    const tick = async () => {
      try {
        const { data } = await getJob(jobId);
        if (dead) return;
        setStatus(data.status); setLines(data.progress || []);
        if (data.percent != null) setPct(data.percent);
        if (data.status === 'completed' || data.status === 'failed' || data.status === 'not_found' || data.status === 'cancelled') { onDone?.(data.result); return; }
        setTimeout(tick, POLL_MS);
      } catch { setTimeout(tick, POLL_MS * 2); }
    };
    tick();
    return () => { dead = true; };
  }, [jobId]);
  if (!jobId) return null;
  const done = status !== 'running', failed = status === 'failed';
  return (
    <div style={{
      borderRadius: 10, background: T.panel,
      border: `1px solid ${T.line}`, padding: '10px 14px',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, fontWeight: 600, color: T.text }}>
          {failed  ? <XCircle      size={14} style={{ color: T.err }} />
           : done  ? <CheckCircle2 size={14} style={{ color: T.ok }} />
           :         <Loader2      size={14} className="animate-spin" style={{ color: accent }} />}
          {label}
        </span>
        {pct != null && !done && (
          <span style={{ fontFamily: 'ui-monospace, Menlo, monospace', fontSize: 12, fontWeight: 700, color: accent }}>
            {pct.toFixed(0)}%
          </span>
        )}
      </div>
      {pct != null && !done && (
        <div style={{ marginTop: 8, height: 4, borderRadius: 999, background: 'rgba(15,15,18,0.06)', overflow: 'hidden' }}>
          <div style={{ height: '100%', background: accent, borderRadius: 999, width: `${pct}%`, transition: 'width 0.4s ease' }} />
        </div>
      )}
      <Terminal lines={lines} />
    </div>
  );
}

/* ─── Lesson status helpers ─────────────────────────────────────────────── */
function lessonState(l) {
  const dl = !!l.download_job_id;
  const xj = !!l.transcript_job_id;
  const hasV = !!l.video_filename && !dl;
  const hasT = !!l.transcript_txt;
  const presN = (l.presentations || []).length;

  let stage = 'empty';
  if (dl) stage = 'downloading';
  else if (xj) stage = 'transcribing';
  else if (hasV && hasT && presN > 0) stage = 'complete';
  else if (hasV && hasT) stage = 'ready-pres';
  else if (hasV) stage = 'ready-tx';

  const pct =
    stage === 'complete'    ? 100 :
    stage === 'ready-pres'  ? 75 :
    stage === 'ready-tx'    ? 50 :
    stage === 'transcribing'? 60 :
    stage === 'downloading' ? 25 : 0;
  return { dl, xj, hasV, hasT, presN, stage, pct };
}

function PipelineDots({ state, size = 8 }) {
  const steps = [
    { key: 'video',  done: state.hasV,            active: state.dl, label: 'וידאו' },
    { key: 'tx',     done: state.hasT,            active: state.xj, label: 'תמלול' },
    { key: 'pres',   done: state.presN > 0,      active: false,    label: 'מצגות' },
  ];
  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
      {steps.map((s, i) => (
        <div key={s.key} title={s.label} style={{
          width: size, height: size, borderRadius: '50%',
          background: s.done ? T.ok : s.active ? T.warn : 'transparent',
          border: `1.5px solid ${s.done ? T.ok : s.active ? T.warn : T.ghost}`,
          animation: s.active ? 'pulse 1.4s ease-in-out infinite' : 'none',
        }} />
      ))}
    </div>
  );
}

/* ─── Add Lesson Drawer (replaces inline form) ──────────────────────────── */
function AddLessonDrawer({ open, onClose, courseId, courseHue, onAdded }) {
  const [mode, setMode] = useState('url');
  const [title, setTitle] = useState('');
  const [url, setUrl] = useState('');
  const [localPath, setLocalPath] = useState('');
  const [dropped, setDropped] = useState(null);
  const [pct, setPct] = useState(null);
  const [busy, setBusy] = useState(false);
  const [dragOver, setDragOver] = useState(false);

  useEffect(() => {
    if (!open) { setMode('url'); setTitle(''); setUrl(''); setLocalPath(''); setDropped(null); setPct(null); }
  }, [open]);

  const onVideoDrop = (file) => {
    if (!VIDEO_EXTS.has(file.name.split('.').pop().toLowerCase())) { toast.error('פורמט לא נתמך'); return; }
    setDropped(file);
    if (!title.trim()) setTitle(file.name.replace(/\.[^.]+$/, ''));
  };

  const submit = async (e) => {
    e.preventDefault(); if (!title.trim()) return; setBusy(true);
    try {
      let lesson;
      if (mode === 'url') {
        const { data } = await coursesApi.addLesson(courseId, { title: title.trim(), url: url.trim() });
        lesson = data.lesson; toast.success(data.job_id ? 'מוריד...' : 'נוסף');
      } else if (dropped) {
        const fd = new FormData(); fd.append('file', dropped); fd.append('title', title.trim());
        const { data } = await coursesApi.uploadLesson(courseId, fd, ev => setPct(Math.round(ev.loaded / ev.total * 100)));
        lesson = data.lesson; toast.success('נוסף');
      } else {
        const { data } = await coursesApi.importLesson(courseId, title.trim(), localPath.trim());
        lesson = data.lesson; toast.success('נוסף');
      }
      onAdded(lesson); onClose();
    } catch (err) { toast.error(err?.response?.data?.detail || 'שגיאה'); }
    finally { setBusy(false); setPct(null); }
  };

  const canSubmit = title.trim() && (mode === 'url' ? url.trim() : dropped || localPath.trim());

  if (!open) return null;
  return (
    <>
      <div onClick={onClose} style={{
        position: 'fixed', inset: 0, background: 'rgba(15,15,18,0.35)',
        backdropFilter: 'blur(2px)', zIndex: 60, animation: 'fadeIn 0.15s ease',
      }} />
      <div style={{
        position: 'fixed', top: 0, bottom: 0, left: 0, width: 440, zIndex: 61,
        background: '#fff', boxShadow: '0 0 60px rgba(0,0,0,0.15)',
        display: 'flex', flexDirection: 'column', animation: 'slideInLeft 0.22s cubic-bezier(0.4,0,0.2,1)',
      }}>
        <header style={{
          flexShrink: 0, padding: '20px 24px 16px',
          borderBottom: `1px solid ${T.line}`,
          display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 10,
        }}>
          <div>
            <h3 style={{ margin: 0, fontSize: 17, fontWeight: 700, color: T.ink, letterSpacing: '-0.015em' }}>שיעור חדש</h3>
            <p style={{ margin: '4px 0 0', fontSize: 12, color: T.faint }}>הוסף וידאו מ־URL, קובץ מקומי או נתיב</p>
          </div>
          <IconBtn icon={X} onClick={onClose} />
        </header>

        <form onSubmit={submit} style={{ flex: 1, overflowY: 'auto', padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: 16 }}>
          {/* Mode tabs */}
          <div style={{ display: 'flex', gap: 0, borderRadius: 10, background: T.panel, padding: 4, border: `1px solid ${T.line}` }}>
            {[
              { id: 'url',    icon: Link2,      label: 'מ־URL' },
              { id: 'upload', icon: Upload,     label: 'העלאת קובץ' },
              { id: 'path',   icon: FolderOpen, label: 'נתיב מקומי' },
            ].map(({ id, icon: Icon, label }) => (
              <button key={id} type="button" onClick={() => { setMode(id); setDropped(null); }}
                style={{
                  flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                  padding: '8px 10px', fontSize: 12, fontWeight: 600, borderRadius: 7,
                  background: mode === id ? '#fff' : 'transparent',
                  color: mode === id ? T.ink : T.muted,
                  boxShadow: mode === id ? '0 1px 3px rgba(0,0,0,0.06)' : 'none',
                  border: 'none', cursor: 'pointer', transition: 'all 0.15s',
                }}>
                <Icon size={12} />{label}
              </button>
            ))}
          </div>

          {/* Title */}
          <div>
            <label style={labelCss}>שם השיעור</label>
            <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="לדוגמה: שיעור 04 — מבני נתונים"
              style={inputCss} />
          </div>

          {/* Mode body */}
          {mode === 'url' && (
            <div>
              <label style={labelCss}>קישור</label>
              <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://..." dir="ltr"
                style={{ ...inputCss, fontFamily: 'ui-monospace, Menlo, monospace', fontSize: 12 }} />
              <p style={hintCss}>YouTube, Vimeo, Google Drive, או כל קישור ישיר</p>
            </div>
          )}
          {mode === 'upload' && (
            dropped ? (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px',
                borderRadius: 10, background: 'rgba(16,185,129,0.06)', border: `1px solid rgba(16,185,129,0.2)`,
              }}>
                <CheckCircle2 size={16} style={{ color: T.ok, flexShrink: 0 }} />
                <div style={{ flex: 1, minWidth: 0 }}>
                  <p style={{ margin: 0, fontSize: 12.5, fontWeight: 600, color: T.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{dropped.name}</p>
                  <p style={{ margin: '2px 0 0', fontSize: 11, color: T.faint }}>{(dropped.size / 1024 / 1024).toFixed(1)} MB</p>
                </div>
                <IconBtn icon={X} onClick={() => setDropped(null)} />
              </div>
            ) : (
              <div
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={(e) => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) onVideoDrop(f); }}
                style={{
                  display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 8,
                  padding: '28px 20px', borderRadius: 12,
                  border: `2px dashed ${dragOver ? courseHue.base : T.line}`,
                  background: dragOver ? courseHue.soft : T.panel,
                  textAlign: 'center', transition: 'all 0.15s',
                }}>
                <Upload size={20} style={{ color: dragOver ? courseHue.base : T.faint }} />
                <p style={{ margin: 0, fontSize: 13, fontWeight: 600, color: T.text }}>גרור לכאן וידאו</p>
                <p style={{ margin: 0, fontSize: 11, color: T.faint }}>MP4 · MKV · MOV · WEBM · MP3 · WAV</p>
                <label style={{
                  marginTop: 6, padding: '6px 14px', fontSize: 11, fontWeight: 600,
                  borderRadius: 8, border: `1px solid ${T.line}`, background: '#fff', color: T.text, cursor: 'pointer',
                }}>
                  בחר קובץ
                  <input type="file" hidden onChange={(e) => e.target.files[0] && onVideoDrop(e.target.files[0])} />
                </label>
              </div>
            )
          )}
          {mode === 'path' && (
            <div>
              <label style={labelCss}>נתיב בשרת</label>
              <input value={localPath} onChange={(e) => setLocalPath(e.target.value)} placeholder="/data/videos/lesson.mp4" dir="ltr"
                style={{ ...inputCss, fontFamily: 'ui-monospace, Menlo, monospace', fontSize: 12 }} />
              <p style={hintCss}>הקובץ יועתק למאגר הקורס</p>
            </div>
          )}

          {pct !== null && (
            <div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6, fontSize: 11, color: T.muted }}>
                <span>מעלה...</span><span style={{ fontFamily: 'ui-monospace, Menlo, monospace', fontWeight: 700 }}>{pct}%</span>
              </div>
              <div style={{ height: 4, borderRadius: 999, background: 'rgba(15,15,18,0.06)', overflow: 'hidden' }}>
                <div style={{ height: '100%', background: courseHue.base, width: `${pct}%`, transition: 'width 0.3s ease' }} />
              </div>
            </div>
          )}
        </form>

        <footer style={{ flexShrink: 0, padding: '14px 24px', borderTop: `1px solid ${T.line}`, display: 'flex', gap: 8, justifyContent: 'flex-start' }}>
          <Btn variant="primary" size="md" onClick={submit} disabled={busy || !canSubmit}
            icon={busy ? Loader2 : Plus}>
            {mode === 'url' ? 'הוסף שיעור' : mode === 'upload' ? 'העלה ושמור' : 'יבא שיעור'}
          </Btn>
          <Btn variant="ghost" onClick={onClose}>ביטול</Btn>
        </footer>
      </div>
    </>
  );
}

const labelCss = { display: 'block', fontSize: 11, fontWeight: 700, color: T.muted, letterSpacing: '0.04em', textTransform: 'uppercase', marginBottom: 6 };
const inputCss = { width: '100%', boxSizing: 'border-box', padding: '10px 12px', fontSize: 13, color: T.ink, background: '#fff', border: `1px solid ${T.line}`, borderRadius: 9, outline: 'none', transition: 'border-color 0.15s' };
const hintCss  = { margin: '6px 0 0', fontSize: 11, color: T.faint };

/* ─── Presentations panel (refined) ─────────────────────────────────────── */
function PresentationsPanel({ courseId, lessonId, initial, hue }) {
  const [files, setFiles] = useState(initial || []);
  const [dragOver, setDragOver] = useState(false);
  const [pathVal, setPathVal] = useState('');
  const [busy, setBusy] = useState(false);

  useEffect(() => { setFiles(initial || []); }, [lessonId]);

  const upload = async (file) => {
    if (!PRES_EXTS.has(file.name.split('.').pop().toLowerCase())) { toast.error('סוג קובץ לא נתמך'); return; }
    setBusy(true);
    try {
      const fd = new FormData(); fd.append('file', file);
      const { data } = await coursesApi.uploadPresentation(courseId, lessonId, fd);
      setFiles(p => [...p, data.filename]); toast.success('המצגת נוספה');
    } catch (e) { toast.error(e?.response?.data?.detail || 'שגיאה'); }
    finally { setBusy(false); }
  };
  const importPath = async () => {
    if (!pathVal.trim()) return; setBusy(true);
    try {
      const { data } = await coursesApi.importPresentation(courseId, lessonId, pathVal.trim());
      setFiles(p => [...p, data.filename]); setPathVal(''); toast.success('המצגת נוספה');
    } catch (e) { toast.error(e?.response?.data?.detail || 'שגיאה'); }
    finally { setBusy(false); }
  };
  const remove = async (f) => {
    if (!confirm(`למחוק את "${f}"?`)) return;
    try { await coursesApi.deletePresentation(courseId, lessonId, f); setFiles(p => p.filter(x => x !== f)); toast.success('נמחק'); }
    catch { toast.error('שגיאה'); }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files[0]; if (f) upload(f); }}
        style={{
          display: 'flex', alignItems: 'center', gap: 12, padding: '14px 16px',
          borderRadius: 12, border: `1.5px dashed ${dragOver ? hue.base : T.line}`,
          background: dragOver ? hue.soft : T.panel, transition: 'all 0.15s',
        }}>
        <div style={{
          width: 36, height: 36, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center',
          background: '#fff', border: `1px solid ${T.line}`, flexShrink: 0,
        }}>
          {busy ? <Loader2 size={15} className="animate-spin" style={{ color: hue.base }} />
                : <Upload size={15} style={{ color: T.faint }} />}
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <p style={{ margin: 0, fontSize: 12.5, fontWeight: 600, color: T.text }}>{dragOver ? 'שחרר כאן' : 'גרור מצגת לכאן'}</p>
          <p style={{ margin: '2px 0 0', fontSize: 11, color: T.faint }}>PDF · PPTX · PPT · ODP · KEY</p>
        </div>
        <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
          <input value={pathVal} onChange={(e) => setPathVal(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && importPath()}
            placeholder="או הזן נתיב..." dir="ltr"
            style={{ width: 180, padding: '7px 10px', fontSize: 11.5, fontFamily: 'ui-monospace, Menlo, monospace',
              border: `1px solid ${T.line}`, borderRadius: 7, background: '#fff', color: T.text, outline: 'none' }} />
          <Btn variant="outline" size="sm" onClick={importPath} disabled={busy || !pathVal.trim()}>הוסף</Btn>
        </div>
      </div>

      {/* Files grid */}
      {files.length > 0 ? (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 10 }}>
          {files.map((f) => {
            const ext = f.split('.').pop().toLowerCase();
            return (
              <div key={f} style={{
                display: 'flex', alignItems: 'center', gap: 10, padding: '10px 12px',
                borderRadius: 10, background: '#fff', border: `1px solid ${T.line}`,
                transition: 'border-color 0.12s, transform 0.06s',
              }}
                onMouseEnter={(e) => e.currentTarget.style.borderColor = T.ghost}
                onMouseLeave={(e) => e.currentTarget.style.borderColor = T.line}
              >
                <div style={{
                  width: 32, height: 38, borderRadius: 5, display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: ext === 'pdf' ? 'rgba(239,68,68,0.08)' : 'rgba(245,158,11,0.08)',
                  color: ext === 'pdf' ? T.err : T.warn,
                  fontSize: 9, fontWeight: 800, letterSpacing: '0.05em', flexShrink: 0,
                }}>
                  {ext.toUpperCase()}
                </div>
                <p style={{ flex: 1, margin: 0, fontSize: 12.5, fontWeight: 500, color: T.text,
                  overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{f}</p>
                <a href={coursesApi.presentationUrl(courseId, lessonId, f)} target="_blank" rel="noreferrer"
                  style={{ display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                    width: 26, height: 26, borderRadius: 6, color: T.faint, textDecoration: 'none' }}
                  onMouseEnter={(e) => { e.currentTarget.style.color = T.ink; e.currentTarget.style.background = 'rgba(15,15,18,0.04)'; }}
                  onMouseLeave={(e) => { e.currentTarget.style.color = T.faint; e.currentTarget.style.background = 'transparent'; }}>
                  <ExternalLink size={13} />
                </a>
                <IconBtn icon={Trash2} tone="danger" size={26} onClick={() => remove(f)} />
              </div>
            );
          })}
        </div>
      ) : (
        <p style={{ margin: 0, fontSize: 12, color: T.faint, textAlign: 'center', padding: '8px 0' }}>
          אין מצגות עדיין
        </p>
      )}
    </div>
  );
}

/* ─── Lesson Detail (tabbed workspace) ──────────────────────────────────── */
function LessonDetail({ courseId, lesson, hue, onUpdate, onDelete, onClose }) {
  const [local,    setLocal]    = useState(lesson);
  const [tab,      setTab]      = useState('video');
  const [model,    setModel]    = useState('large-v3');
  const [lang,     setLang]     = useState('he');
  const [xJobId,   setXJobId]   = useState(lesson.transcript_job_id || null);
  const [xOpen,    setXOpen]    = useState(false);
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    setLocal(lesson); setXJobId(lesson.transcript_job_id || null);
    setTab('video'); setXOpen(false);
  }, [lesson.id]);

  const upd = (fields) => { setLocal(prev => { const next = { ...prev, ...fields }; onUpdate(next); return next; }); };
  const state = lessonState(local);
  const dlActive = local.download_job_id;

  const handleDel = async () => {
    if (!confirm(`למחוק את השיעור "${local.title}"?`)) return; setDeleting(true);
    try { await coursesApi.deleteLesson(courseId, local.id); onDelete(local.id); }
    catch { toast.error('שגיאה'); setDeleting(false); }
  };

  const tabs = [
    { id: 'video',  label: 'וידאו',  icon: Film,     done: state.hasV, count: state.hasV ? 1 : 0 },
    { id: 'tx',     label: 'תמלול',  icon: Mic,      done: state.hasT, count: state.hasT ? 1 : 0 },
    { id: 'pres',   label: 'מצגות',  icon: FileText, done: state.presN > 0, count: state.presN },
  ];

  return (
    <section style={{ display: 'flex', flexDirection: 'column', height: '100%', background: '#fff', overflow: 'hidden', flex: 1, minWidth: 0 }}>
      {/* Detail header */}
      <header style={{ flexShrink: 0, padding: '18px 28px 0', borderBottom: `1px solid ${T.line}` }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16 }}>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
              <button onClick={onClose} style={{
                display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11, fontWeight: 600,
                color: T.faint, background: 'transparent', border: 'none', cursor: 'pointer', padding: 0,
              }}>
                <ChevronLeft size={12} style={{ transform: 'scaleX(-1)' }} /> חזרה לרשימה
              </button>
              <span style={{ width: 3, height: 3, borderRadius: '50%', background: T.ghost }} />
              <PipelineDots state={state} />
            </div>
            <h1 style={{ margin: 0, fontSize: 22, fontWeight: 700, color: T.ink, letterSpacing: '-0.02em', lineHeight: 1.2 }}>{local.title}</h1>
            {local.url && (
              <a href={local.url} target="_blank" rel="noreferrer" dir="ltr"
                style={{ display: 'inline-flex', alignItems: 'center', gap: 5, marginTop: 6, fontSize: 11.5, color: T.faint, fontFamily: 'ui-monospace, Menlo, monospace', textDecoration: 'none', maxWidth: 540, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                <Link2 size={11} />{local.url}
              </a>
            )}
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
            {state.hasV && (
              <Btn variant="primary" icon={Play}
                onClick={() => window.open(coursesApi.videoUrl(courseId, local.id), '_blank')}>
                נגן וידאו
              </Btn>
            )}
            <Btn variant="danger" icon={deleting ? Loader2 : Trash2} onClick={handleDel} disabled={deleting}>
              מחק
            </Btn>
          </div>
        </div>

        {/* Tabs */}
        <div style={{ display: 'flex', gap: 0, marginTop: 18 }}>
          {tabs.map((t) => {
            const active = tab === t.id;
            return (
              <button key={t.id} onClick={() => setTab(t.id)}
                style={{
                  display: 'inline-flex', alignItems: 'center', gap: 7, padding: '10px 16px 12px',
                  background: 'transparent', border: 'none', cursor: 'pointer',
                  borderBottom: `2px solid ${active ? T.ink : 'transparent'}`,
                  color: active ? T.ink : T.muted,
                  fontSize: 13, fontWeight: active ? 700 : 500, marginBottom: -1, transition: 'color 0.12s',
                }}>
                <t.icon size={13} />
                {t.label}
                {t.count > 0 && (
                  <span style={{
                    fontSize: 10, fontWeight: 700, padding: '1px 6px', borderRadius: 999,
                    background: active ? T.accentSoft : 'rgba(15,15,18,0.05)',
                    color: active ? T.accent : T.faint,
                  }}>{t.count}</span>
                )}
                {t.done && <CheckCircle2 size={12} style={{ color: T.ok }} />}
              </button>
            );
          })}
        </div>
      </header>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '24px 28px', background: T.bg }}>
        {tab === 'video' && (
          <VideoTab courseId={courseId} lesson={local} state={state} dlActive={dlActive}
            hue={hue} onDone={(r) => r?.filename && upd({ video_filename: r.filename, video_size_mb: r.size_mb, download_job_id: null })} />
        )}
        {tab === 'tx' && (
          <TranscriptTab courseId={courseId} lesson={local} state={state}
            xJobId={xJobId} setXJobId={setXJobId} xOpen={xOpen} setXOpen={setXOpen}
            model={model} setModel={setModel} lang={lang} setLang={setLang}
            onDone={(r) => {
              setXJobId(null);
              upd({ transcript_job_id: null });
              if (r?.txt_filename) {
                upd({ transcript_txt: r.txt_filename, transcript_srt: r.srt_filename });
                toast.success('תמלול הושלם');
              }
            }} />
        )}
        {tab === 'pres' && (
          <Panel title="מצגות ומקורות נלווים" subtitle={`${state.presN} קבצים בשיעור הזה`}>
            <PresentationsPanel courseId={courseId} lessonId={local.id} initial={local.presentations || []} hue={hue} />
          </Panel>
        )}
      </div>
    </section>
  );
}

function Panel({ title, subtitle, children, action }) {
  return (
    <div style={{
      borderRadius: 14, background: '#fff', border: `1px solid ${T.line}`,
      overflow: 'hidden',
    }}>
      <div style={{
        padding: '16px 20px', borderBottom: `1px solid ${T.lineSoft}`,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10,
      }}>
        <div>
          <h3 style={{ margin: 0, fontSize: 14, fontWeight: 700, color: T.ink }}>{title}</h3>
          {subtitle && <p style={{ margin: '3px 0 0', fontSize: 12, color: T.faint }}>{subtitle}</p>}
        </div>
        {action}
      </div>
      <div style={{ padding: 20 }}>{children}</div>
    </div>
  );
}

function VideoTab({ courseId, lesson, state, dlActive, hue, onDone }) {
  return (
    <Panel title="קובץ הווידאו" subtitle={lesson.url ? 'מקור: קישור חיצוני' : 'קובץ מקומי'}>
      {dlActive ? (
        <JobTracker jobId={dlActive} label="מוריד וידאו..." accent={hue.base} onDone={onDone} />
      ) : state.hasV ? (
        <div style={{ display: 'flex', alignItems: 'stretch', gap: 16 }}>
          <div style={{
            width: 220, aspectRatio: '16/9', borderRadius: 10,
            background: '#0b0b10',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            position: 'relative', overflow: 'hidden', flexShrink: 0,
          }}>
            <Play size={28} style={{ color: 'rgba(255,255,255,0.65)' }} fill="rgba(255,255,255,0.65)" />
            <div style={{
              position: 'absolute', inset: 0,
              background: `radial-gradient(circle at 30% 30%, ${hue.base}30 0%, transparent 60%)`,
            }} />
          </div>
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', justifyContent: 'space-between', minWidth: 0 }}>
            <div>
              <p style={{ margin: 0, fontSize: 13, fontWeight: 600, color: T.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{lesson.video_filename}</p>
              <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
                {lesson.video_size_mb && <Chip tone="neutral">{lesson.video_size_mb} MB</Chip>}
                <Chip tone="ok" icon={CheckCircle2}>זמין</Chip>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <Btn variant="primary" icon={Play} onClick={() => window.open(coursesApi.videoUrl(courseId, lesson.id), '_blank')}>נגן</Btn>
              <a href={coursesApi.videoUrl(courseId, lesson.id)} download
                style={{ display: 'inline-flex', alignItems: 'center', gap: 6, padding: '7px 12px', fontSize: 12, fontWeight: 600,
                  color: T.text, background: '#fff', border: `1px solid ${T.line}`, borderRadius: 8, textDecoration: 'none', cursor: 'pointer' }}>
                <Download size={13} />הורד
              </a>
            </div>
          </div>
        </div>
      ) : (
        <EmptyState icon={Film} title="אין וידאו לשיעור" hint="הוסף קישור או העלה קובץ דרך טופס הוספת השיעור" />
      )}
    </Panel>
  );
}

function TranscriptTab({ courseId, lesson, state, xJobId, setXJobId, xOpen, setXOpen, model, setModel, lang, setLang, onDone }) {
  const trigger = async () => {
    try {
      const { data } = await coursesApi.transcribe(courseId, lesson.id, { model_size: model, language: lang });
      setXJobId(data.job_id); setXOpen(false); toast.success('תמלול התחיל');
    } catch (e) { toast.error(e?.response?.data?.detail || 'שגיאה'); }
  };

  return (
    <Panel title="תמלול אוטומטי" subtitle="המרת אודיו לטקסט באמצעות Whisper"
      action={state.hasV && !xJobId && (
        <Btn variant={state.hasT ? 'outline' : 'accent'} icon={Captions} onClick={() => setXOpen(v => !v)} size="sm">
          {state.hasT ? 'תמלל מחדש' : 'התחל תמלול'}
        </Btn>
      )}>
      {xJobId && <JobTracker jobId={xJobId} label="מתמלל..." accent="#8b5cf6" onDone={onDone} />}

      {!xJobId && state.hasT && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 16px', borderRadius: 10, background: T.panel, border: `1px solid ${T.line}` }}>
          <div style={{ width: 36, height: 36, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center', background: 'rgba(139,92,246,0.1)' }}>
            <Mic size={16} style={{ color: '#8b5cf6' }} />
          </div>
          <div style={{ flex: 1 }}>
            <p style={{ margin: 0, fontSize: 13, fontWeight: 600, color: T.text }}>תמלול זמין</p>
            <p style={{ margin: '2px 0 0', fontSize: 11.5, color: T.faint }}>הורד כקובץ TXT או SRT</p>
          </div>
          <div style={{ display: 'flex', gap: 6 }}>
            <a href={coursesApi.transcriptUrl(courseId, lesson.id, 'txt')} download
              style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '7px 12px', fontSize: 11.5, fontWeight: 600, color: T.text, background: '#fff', border: `1px solid ${T.line}`, borderRadius: 8, textDecoration: 'none' }}>
              <Download size={11} /> TXT
            </a>
            {state.hasT && lesson.transcript_srt && (
              <a href={coursesApi.transcriptUrl(courseId, lesson.id, 'srt')} download
                style={{ display: 'inline-flex', alignItems: 'center', gap: 5, padding: '7px 12px', fontSize: 11.5, fontWeight: 600, color: T.text, background: '#fff', border: `1px solid ${T.line}`, borderRadius: 8, textDecoration: 'none' }}>
                <Download size={11} /> SRT
              </a>
            )}
          </div>
        </div>
      )}

      {!xJobId && !state.hasT && !state.hasV && (
        <EmptyState icon={Mic} title="דרוש קודם וידאו" hint="הוסף וידאו כדי להפעיל תמלול אוטומטי" />
      )}
      {!xJobId && !state.hasT && state.hasV && !xOpen && (
        <EmptyState icon={Mic} title="עדיין לא תומלל" hint="לחץ על 'התחל תמלול' כדי להפיק טקסט וכתוביות" />
      )}

      {xOpen && (
        <div style={{ marginTop: state.hasT ? 14 : 0, padding: 16, borderRadius: 12, background: T.panel, border: `1px solid ${T.line}` }}>
          <p style={{ margin: '0 0 14px', fontSize: 12, fontWeight: 700, color: T.text, letterSpacing: '0.02em' }}>הגדרות תמלול</p>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginBottom: 14 }}>
            <Select label="מודל" value={model} setValue={setModel} options={MODEL_OPTIONS} />
            <Select label="שפה"  value={lang}  setValue={setLang}  options={LANG_OPTIONS} />
          </div>
          <Btn variant="accent" icon={Play} onClick={trigger}>התחל תמלול</Btn>
        </div>
      )}
    </Panel>
  );
}

function Select({ label, value, setValue, options }) {
  return (
    <label style={{ display: 'block' }}>
      <span style={labelCss}>{label}</span>
      <select value={value} onChange={(e) => setValue(e.target.value)}
        style={{ ...inputCss, paddingInlineEnd: 28, appearance: 'none',
          backgroundImage: `url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%239ca3af' stroke-width='2'><polyline points='6 9 12 15 18 9'/></svg>")`,
          backgroundRepeat: 'no-repeat', backgroundPosition: 'left 10px center', backgroundSize: 12 }}>
        {options.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
      </select>
    </label>
  );
}

function EmptyState({ icon: Icon, title, hint }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10, padding: '32px 16px', textAlign: 'center' }}>
      <div style={{ width: 44, height: 44, borderRadius: 12, background: T.panel, border: `1px solid ${T.line}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Icon size={18} style={{ color: T.faint }} />
      </div>
      <div>
        <p style={{ margin: 0, fontSize: 13, fontWeight: 600, color: T.text }}>{title}</p>
        {hint && <p style={{ margin: '4px 0 0', fontSize: 11.5, color: T.faint, maxWidth: 320 }}>{hint}</p>}
      </div>
    </div>
  );
}

/* ─── Lessons table ─────────────────────────────────────────────────────── */
function LessonsTable({ lessons, selectedId, onSelect }) {
  return (
    <div style={{ borderRadius: 14, background: '#fff', border: `1px solid ${T.line}`, overflow: 'hidden' }}>
      <div style={{
        display: 'grid', gridTemplateColumns: '54px 1fr 220px 120px 80px',
        padding: '10px 16px', background: T.panel, borderBottom: `1px solid ${T.line}`,
        fontSize: 10.5, fontWeight: 700, letterSpacing: '0.08em', textTransform: 'uppercase', color: T.faint,
      }}>
        <span>#</span>
        <span>שיעור</span>
        <span>מצב</span>
        <span>גודל</span>
        <span style={{ textAlign: 'left' }}>פעולה</span>
      </div>
      {lessons.map((lesson, i) => {
        const state = lessonState(lesson);
        const isSelected = lesson.id === selectedId;
        return (
          <button key={lesson.id} onClick={() => onSelect(lesson.id)}
            style={{
              width: '100%', textAlign: 'right', display: 'grid',
              gridTemplateColumns: '54px 1fr 220px 120px 80px',
              padding: '14px 16px', background: isSelected ? T.accentSoft : '#fff',
              border: 'none', cursor: 'pointer',
              borderBottom: i < lessons.length - 1 ? `1px solid ${T.lineSoft}` : 'none',
              alignItems: 'center', transition: 'background 0.12s',
            }}
            onMouseEnter={(e) => { if (!isSelected) e.currentTarget.style.background = T.panel; }}
            onMouseLeave={(e) => { if (!isSelected) e.currentTarget.style.background = '#fff'; }}
          >
            <span style={{
              fontFamily: 'ui-monospace, Menlo, monospace', fontSize: 12, fontWeight: 700,
              color: isSelected ? T.accent : T.ghost,
            }}>{String(i + 1).padStart(2, '0')}</span>

            <div style={{ minWidth: 0, paddingInlineEnd: 12 }}>
              <p style={{ margin: 0, fontSize: 13.5, fontWeight: 600, color: T.ink,
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{lesson.title}</p>
              {lesson.url && <p style={{ margin: '3px 0 0', fontSize: 11, color: T.faint, fontFamily: 'ui-monospace, Menlo, monospace',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', direction: 'ltr', textAlign: 'right' }}>{lesson.url}</p>}
            </div>

            <div style={{ display: 'flex', gap: 5, flexWrap: 'wrap' }}>
              {state.dl && <Chip tone="warn" icon={Loader2}>מוריד</Chip>}
              {state.xj && <Chip tone="warn" icon={Loader2}>מתמלל</Chip>}
              {!state.dl && !state.xj && state.hasV && <Chip tone="ok" dot>וידאו</Chip>}
              {!state.dl && !state.xj && !state.hasV && <Chip tone="pending" dot>אין וידאו</Chip>}
              {state.hasT && <Chip tone="info" dot>תמלול</Chip>}
              {state.presN > 0 && <Chip tone="accent" icon={FileText}>{state.presN}</Chip>}
            </div>

            <span style={{ fontSize: 12, color: T.muted, fontVariantNumeric: 'tabular-nums' }}>
              {lesson.video_size_mb ? `${lesson.video_size_mb} MB` : '—'}
            </span>

            <ChevronLeft size={14} style={{ color: T.faint, justifySelf: 'end' }} />
          </button>
        );
      })}
    </div>
  );
}

/* ─── Course summary stats ──────────────────────────────────────────────── */
function CourseStats({ lessons }) {
  const total = lessons.length;
  const withVideo = lessons.filter(l => l.video_filename && !l.download_job_id).length;
  const withTx    = lessons.filter(l => l.transcript_txt).length;
  const withPres  = lessons.filter(l => (l.presentations || []).length > 0).length;
  const totalSize = lessons.reduce((s, l) => s + (l.video_size_mb || 0), 0);

  const items = [
    { label: 'סה״כ שיעורים', value: total,                   icon: Layers },
    { label: 'עם וידאו',     value: `${withVideo}/${total}`, icon: Film,     done: withVideo === total && total > 0 },
    { label: 'תומללו',       value: `${withTx}/${total}`,    icon: Mic,      done: withTx === total && total > 0 },
    { label: 'עם מצגות',     value: `${withPres}/${total}`,  icon: FileText, done: withPres === total && total > 0 },
    { label: 'נפח כולל',     value: totalSize > 0 ? (totalSize > 1024 ? `${(totalSize/1024).toFixed(1)} GB` : `${totalSize.toFixed(0)} MB`) : '—', icon: Clock },
  ];

  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 10 }}>
      {items.map(it => (
        <div key={it.label} style={{
          padding: '14px 16px', borderRadius: 12, background: '#fff', border: `1px solid ${T.line}`,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 8 }}>
            <it.icon size={12} style={{ color: T.faint }} />
            <span style={{ fontSize: 11, color: T.muted, fontWeight: 600 }}>{it.label}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
            <span style={{ fontSize: 22, fontWeight: 700, color: T.ink, letterSpacing: '-0.02em', fontVariantNumeric: 'tabular-nums' }}>{it.value}</span>
            {it.done && <CheckCircle2 size={14} style={{ color: T.ok }} />}
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Course view ───────────────────────────────────────────────────────── */
function CourseView({ course, hue, onCourseDelete }) {
  const [lessons, setLessons] = useState(Object.values(course.lessons || {}));
  const [selectedId, setSelectedId] = useState(null);
  const [addOpen, setAddOpen] = useState(false);
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const [deleting, setDeleting] = useState(false);

  useEffect(() => {
    setLessons(Object.values(course.lessons || {}));
    setSelectedId(null); setQuery(''); setFilter('all');
  }, [course.id]);

  const filtered = useMemo(() => {
    let arr = lessons;
    if (query.trim()) arr = arr.filter(l => l.title.toLowerCase().includes(query.toLowerCase()));
    if (filter !== 'all') {
      arr = arr.filter(l => {
        const s = lessonState(l);
        if (filter === 'no-video') return !s.hasV && !s.dl;
        if (filter === 'no-tx')    return s.hasV && !s.hasT && !s.xj;
        if (filter === 'in-progress') return s.dl || s.xj;
        if (filter === 'complete') return s.stage === 'complete';
        return true;
      });
    }
    return arr;
  }, [lessons, query, filter]);

  const selected = lessons.find(l => l.id === selectedId);
  const updateLesson = (u) => setLessons(p => p.map(l => l.id === u.id ? u : l));

  const handleDeleteCourse = async () => {
    if (!confirm(`למחוק את הקורס "${course.name}"? כל השיעורים יימחקו.`)) return;
    setDeleting(true);
    try { await coursesApi.delete(course.id); onCourseDelete(course.id); }
    catch { toast.error('שגיאה'); setDeleting(false); }
  };

  const filterTabs = [
    { id: 'all',          label: 'הכל' },
    { id: 'in-progress',  label: 'בעבודה' },
    { id: 'no-video',     label: 'ללא וידאו' },
    { id: 'no-tx',        label: 'לא תומלל' },
    { id: 'complete',     label: 'הושלמו' },
  ];

  if (selected) {
    return (
      <LessonDetail
        courseId={course.id}
        lesson={selected}
        hue={hue}
        onUpdate={updateLesson}
        onDelete={(id) => { setLessons(p => p.filter(l => l.id !== id)); setSelectedId(null); }}
        onClose={() => setSelectedId(null)}
      />
    );
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden', background: T.bg, flex: 1, minWidth: 0 }}>
      {/* Course header */}
      <header style={{ flexShrink: 0, padding: '24px 32px 20px', background: '#fff', borderBottom: `1px solid ${T.line}` }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 16, marginBottom: 16 }}>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span style={{
                display: 'inline-flex', alignItems: 'center', gap: 5, padding: '3px 9px',
                borderRadius: 999, background: hue.soft, color: hue.text,
                fontSize: 11, fontWeight: 600,
              }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: hue.base }} />
                קורס פעיל
              </span>
            </div>
            <h1 style={{ margin: 0, fontSize: 26, fontWeight: 700, color: T.ink, letterSpacing: '-0.025em', lineHeight: 1.15 }}>
              {course.name}
            </h1>
          </div>
          <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
            <Btn variant="primary" icon={Plus} size="md" onClick={() => setAddOpen(true)}>שיעור חדש</Btn>
            <IconBtn icon={MoreHorizontal} size={36} />
            <IconBtn icon={deleting ? Loader2 : Trash2} tone="danger" size={36} onClick={handleDeleteCourse} disabled={deleting} />
          </div>
        </div>

        <CourseStats lessons={lessons} />
      </header>

      {/* Toolbar */}
      <div style={{
        flexShrink: 0, padding: '14px 32px', background: '#fff',
        borderBottom: `1px solid ${T.line}`,
        display: 'flex', alignItems: 'center', gap: 14,
      }}>
        <div style={{
          flex: 1, maxWidth: 360, position: 'relative',
        }}>
          <Search size={13} style={{ position: 'absolute', insetInlineStart: 11, top: '50%', transform: 'translateY(-50%)', color: T.faint }} />
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="חפש שיעור..."
            style={{ width: '100%', boxSizing: 'border-box', padding: '8px 12px', paddingInlineStart: 32,
              fontSize: 12.5, color: T.ink, background: T.panel, border: `1px solid ${T.line}`,
              borderRadius: 9, outline: 'none' }} />
        </div>

        <div style={{ display: 'flex', gap: 0, padding: 3, background: T.panel, borderRadius: 9, border: `1px solid ${T.line}` }}>
          {filterTabs.map(f => (
            <button key={f.id} onClick={() => setFilter(f.id)}
              style={{
                padding: '5px 12px', fontSize: 11.5, fontWeight: 600, borderRadius: 6,
                border: 'none', cursor: 'pointer',
                background: filter === f.id ? '#fff' : 'transparent',
                color: filter === f.id ? T.ink : T.muted,
                boxShadow: filter === f.id ? '0 1px 2px rgba(0,0,0,0.05)' : 'none',
                transition: 'all 0.12s',
              }}>{f.label}</button>
          ))}
        </div>

        <span style={{ marginInlineStart: 'auto', fontSize: 11.5, color: T.faint, fontVariantNumeric: 'tabular-nums' }}>
          {filtered.length} מתוך {lessons.length} שיעורים
        </span>
      </div>

      {/* Body */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '24px 32px' }}>
        {lessons.length === 0 ? (
          <CourseEmptyState onAdd={() => setAddOpen(true)} />
        ) : filtered.length === 0 ? (
          <div style={{ padding: '60px 0', textAlign: 'center' }}>
            <Search size={28} style={{ color: T.ghost, marginBottom: 10 }} />
            <p style={{ margin: 0, fontSize: 13, fontWeight: 600, color: T.text }}>לא נמצאו שיעורים</p>
            <p style={{ margin: '4px 0 0', fontSize: 12, color: T.faint }}>נסה חיפוש אחר או שנה את הסינון</p>
          </div>
        ) : (
          <LessonsTable lessons={filtered} selectedId={selectedId} onSelect={setSelectedId} />
        )}
      </div>

      <AddLessonDrawer
        open={addOpen} onClose={() => setAddOpen(false)}
        courseId={course.id} courseHue={hue}
        onAdded={(l) => { setLessons(p => [...p, l]); setSelectedId(l.id); }}
      />
    </div>
  );
}

function CourseEmptyState({ onAdd }) {
  return (
    <div style={{
      borderRadius: 16, padding: '64px 32px', textAlign: 'center',
      background: '#fff', border: `1.5px dashed ${T.line}`,
    }}>
      <div style={{ width: 56, height: 56, margin: '0 auto 14px', borderRadius: 14,
        background: T.accentSoft, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <BookOpen size={22} style={{ color: T.accent }} />
      </div>
      <h3 style={{ margin: 0, fontSize: 16, fontWeight: 700, color: T.ink }}>הקורס ריק</h3>
      <p style={{ margin: '6px 0 18px', fontSize: 13, color: T.faint, maxWidth: 360, marginInline: 'auto' }}>
        הוסף את השיעור הראשון — קישור לסרטון, קובץ מקומי, או נתיב לוידאו על השרת.
      </p>
      <Btn variant="primary" icon={Plus} onClick={onAdd}>הוסף שיעור ראשון</Btn>
    </div>
  );
}

/* ─── Page ──────────────────────────────────────────────────────────────── */
export default function CoursesPage() {
  const [courses, setCourses] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState(null);
  const [newName, setNewName] = useState('');
  const [creating, setCreating] = useState(false);
  const [addOpen, setAddOpen] = useState(false);
  const [sidebarQuery, setSidebarQuery] = useState('');

  const load = useCallback(async () => {
    try { const { data } = await coursesApi.list(); setCourses(data.courses || []); }
    catch { toast.error('שגיאה'); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  const create = async (e) => {
    e?.preventDefault?.(); if (!newName.trim()) return; setCreating(true);
    try {
      const { data } = await coursesApi.create(newName.trim());
      const course = { ...data, lessons: {} };
      setCourses(p => [...p, course]); setSelected(course.id); setNewName(''); setAddOpen(false);
      toast.success('הקורס נוצר');
    } catch { toast.error('שגיאה'); }
    finally { setCreating(false); }
  };

  const filteredCourses = useMemo(() => {
    if (!sidebarQuery.trim()) return courses;
    return courses.filter(c => c.name.toLowerCase().includes(sidebarQuery.toLowerCase()));
  }, [courses, sidebarQuery]);

  const activeIdx = courses.findIndex(c => c.id === selected);
  const activeCourse = courses[activeIdx];
  const activeHue = activeIdx >= 0 ? hueFor(activeIdx) : hueFor(0);

  return (
    <div className="-mx-4 -mt-8 flex overflow-hidden" style={{
      height: 'calc(100vh - 97px)', borderTop: `1px solid ${T.line}`,
      background: T.bg, fontFamily: 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif',
    }}>
      <style>{`
        @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.4; } }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        @keyframes slideInLeft { from { transform: translateX(-12px); opacity: 0; } to { transform: translateX(0); opacity: 1; } }
        .animate-spin { animation: spin 1s linear infinite; }
        @keyframes spin { to { transform: rotate(360deg); } }
      `}</style>

      {/* Sidebar — courses list */}
      <aside style={{
        width: 248, flexShrink: 0, display: 'flex', flexDirection: 'column',
        background: '#fff', borderInlineEnd: `1px solid ${T.line}`,
      }}>
        <div style={{ flexShrink: 0, padding: '18px 16px 14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14 }}>
            <div style={{
              width: 28, height: 28, borderRadius: 8, background: T.ink,
              display: 'flex', alignItems: 'center', justifyContent: 'center',
            }}>
              <GraduationCap size={15} style={{ color: '#fff' }} />
            </div>
            <div>
              <p style={{ margin: 0, fontSize: 13, fontWeight: 700, color: T.ink, letterSpacing: '-0.01em' }}>לימודים</p>
              <p style={{ margin: 0, fontSize: 10.5, color: T.faint, fontWeight: 500 }}>{courses.length} קורסים</p>
            </div>
          </div>

          <div style={{ position: 'relative' }}>
            <Search size={12} style={{ position: 'absolute', insetInlineStart: 10, top: '50%', transform: 'translateY(-50%)', color: T.faint }} />
            <input value={sidebarQuery} onChange={(e) => setSidebarQuery(e.target.value)} placeholder="חפש קורס..."
              style={{ width: '100%', boxSizing: 'border-box', padding: '7px 10px', paddingInlineStart: 30,
                fontSize: 12, color: T.ink, background: T.panel, border: `1px solid ${T.line}`,
                borderRadius: 8, outline: 'none' }} />
          </div>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '0 8px' }}>
          {loading ? (
            <div style={{ padding: '20px 0', textAlign: 'center' }}>
              <Loader2 size={16} className="animate-spin" style={{ color: T.faint }} />
            </div>
          ) : filteredCourses.length === 0 ? (
            <p style={{ margin: '20px 12px', fontSize: 11.5, color: T.faint, textAlign: 'center' }}>
              {sidebarQuery ? 'אין תוצאות' : 'אין קורסים'}
            </p>
          ) : filteredCourses.map((course) => {
            const idx = courses.findIndex(c => c.id === course.id);
            const h = hueFor(idx);
            const isSelected = selected === course.id;
            const count = Object.keys(course.lessons || {}).length;
            return (
              <button key={course.id} onClick={() => setSelected(course.id)}
                style={{
                  width: '100%', display: 'flex', alignItems: 'center', gap: 10,
                  padding: '9px 10px', marginBottom: 2, borderRadius: 9,
                  background: isSelected ? T.panel : 'transparent',
                  border: 'none', cursor: 'pointer', textAlign: 'right',
                  transition: 'background 0.12s',
                }}
                onMouseEnter={(e) => { if (!isSelected) e.currentTarget.style.background = 'rgba(15,15,18,0.025)'; }}
                onMouseLeave={(e) => { if (!isSelected) e.currentTarget.style.background = 'transparent'; }}
              >
                <span style={{
                  width: 26, height: 26, borderRadius: 7, flexShrink: 0,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  background: isSelected ? h.base : h.soft,
                  color: isSelected ? '#fff' : h.text,
                  fontSize: 11, fontWeight: 700, letterSpacing: '-0.01em',
                  transition: 'all 0.15s',
                }}>{course.name.charAt(0).toUpperCase()}</span>
                <span style={{ flex: 1, minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  fontSize: 12.5, fontWeight: isSelected ? 600 : 500,
                  color: isSelected ? T.ink : T.text }}>{course.name}</span>
                <span style={{
                  flexShrink: 0, fontSize: 10.5, fontVariantNumeric: 'tabular-nums', fontWeight: 600,
                  color: isSelected ? T.ink : T.faint,
                  padding: '1px 7px', borderRadius: 999,
                  background: isSelected ? '#fff' : 'transparent',
                  border: isSelected ? `1px solid ${T.line}` : '1px solid transparent',
                }}>{count}</span>
              </button>
            );
          })}
        </div>

        <div style={{ flexShrink: 0, padding: 10, borderTop: `1px solid ${T.lineSoft}` }}>
          {addOpen ? (
            <form onSubmit={create} style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              <input value={newName} onChange={(e) => setNewName(e.target.value)} placeholder="שם הקורס" autoFocus
                style={{ width: '100%', boxSizing: 'border-box', padding: '8px 10px', fontSize: 12,
                  color: T.ink, background: '#fff', border: `1px solid ${T.accent}`, borderRadius: 8, outline: 'none' }} />
              <div style={{ display: 'flex', gap: 6 }}>
                <Btn variant="primary" size="sm" disabled={creating || !newName.trim()}
                  icon={creating ? Loader2 : Plus} style={{ flex: 1, justifyContent: 'center' }}>
                  צור קורס
                </Btn>
                <IconBtn icon={X} onClick={() => { setAddOpen(false); setNewName(''); }} />
              </div>
            </form>
          ) : (
            <button onClick={() => setAddOpen(true)}
              style={{
                width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                padding: '9px', fontSize: 12, fontWeight: 600, color: T.muted,
                background: T.panel, border: `1px dashed ${T.line}`, borderRadius: 9, cursor: 'pointer',
                transition: 'all 0.12s',
              }}
              onMouseEnter={(e) => { e.currentTarget.style.background = T.accentSoft; e.currentTarget.style.color = T.accent; e.currentTarget.style.borderColor = T.accent; }}
              onMouseLeave={(e) => { e.currentTarget.style.background = T.panel; e.currentTarget.style.color = T.muted; e.currentTarget.style.borderColor = T.line; }}>
              <Plus size={13} />קורס חדש
            </button>
          )}
        </div>
      </aside>

      {/* Main */}
      {activeCourse ? (
        <CourseView
          course={activeCourse}
          hue={activeHue}
          onCourseDelete={(id) => { setCourses(p => p.filter(c => c.id !== id)); setSelected(null); }}
        />
      ) : (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 16 }}>
          <div style={{
            width: 80, height: 80, borderRadius: 20, background: '#fff', border: `1px solid ${T.line}`,
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 1px 3px rgba(0,0,0,0.04)',
          }}>
            <GraduationCap size={32} style={{ color: T.accent }} />
          </div>
          <div style={{ textAlign: 'center', maxWidth: 360 }}>
            <h2 style={{ margin: 0, fontSize: 18, fontWeight: 700, color: T.ink, letterSpacing: '-0.02em' }}>בחר קורס מהרשימה</h2>
            <p style={{ margin: '6px 0 0', fontSize: 13, color: T.faint, lineHeight: 1.5 }}>
              נהל שיעורים, וידאו, תמלולים ומצגות במקום אחד מסודר.
              {courses.length === 0 && ' התחל ביצירת הקורס הראשון שלך.'}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
