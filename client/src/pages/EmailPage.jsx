import { useState, useRef } from 'react';
import {
  Mail, Loader2, CheckCircle2, XCircle, AlertCircle,
  ChevronDown, ChevronUp, Globe, User, Shield, Server, Zap
} from 'lucide-react';
import { startScan, getJob } from '../utils/webintApi';
import toast from 'react-hot-toast';

const POLL_INTERVAL = 1500;
const MAX_POLLS    = 120;

function Badge({ ok }) {
  if (ok === true)  return <span className="inline-flex items-center gap-1 rounded-full bg-green-50 px-2 py-0.5 text-xs font-medium text-green-700 ring-1 ring-green-200"><CheckCircle2 size={11}/> כן</span>;
  if (ok === false) return <span className="inline-flex items-center gap-1 rounded-full bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700 ring-1 ring-red-200"><XCircle size={11}/> לא</span>;
  return <span className="inline-flex items-center gap-1 rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-500">לא ידוע</span>;
}

function Section({ title, icon: Icon, children, defaultOpen = true }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="rounded-xl border border-slate-200 bg-white overflow-hidden">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 bg-slate-50 hover:bg-slate-100 transition-colors"
      >
        <span className="flex items-center gap-2 text-sm font-semibold text-slate-800">
          <Icon size={15} className="text-slate-500" />
          {title}
        </span>
        {open ? <ChevronUp size={14} className="text-slate-400" /> : <ChevronDown size={14} className="text-slate-400" />}
      </button>
      {open && <div className="p-4 space-y-2">{children}</div>}
    </div>
  );
}

function Row({ label, value }) {
  if (value === undefined || value === null || value === '') return null;
  return (
    <div className="flex items-start gap-2 text-sm">
      <span className="shrink-0 w-36 text-slate-500">{label}</span>
      <span className="text-slate-800 font-medium break-all">{String(value)}</span>
    </div>
  );
}

export default function EmailPage() {
  const [email, setEmail]     = useState('');
  const [loading, setLoading] = useState(false);
  const [progress, setProgress] = useState([]);
  const [result, setResult]   = useState(null);
  const pollRef = useRef(null);

  const isValidEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());

  async function handleSubmit(e) {
    e.preventDefault();
    if (!isValidEmail) { toast.error('כתובת מייל לא תקינה'); return; }

    setLoading(true);
    setResult(null);
    setProgress([]);

    try {
      const { data } = await startScan.email(email.trim());
      const jobId = data.job_id;

      let polls = 0;
      pollRef.current = setInterval(async () => {
        try {
          const { data: job } = await getJob(jobId);
          if (job.progress?.length) setProgress([...job.progress]);
          if (job.status === 'completed' || job.status === 'failed') {
            clearInterval(pollRef.current);
            setLoading(false);
            if (job.status === 'failed') {
              toast.error(job.result?.error || 'הסריקה נכשלה');
            } else {
              setResult(job.result);
              toast.success('הסריקה הושלמה');
            }
          }
          if (++polls >= MAX_POLLS) {
            clearInterval(pollRef.current);
            setLoading(false);
            toast.error('הסריקה ארכה יותר מדי זמן');
          }
        } catch {
          clearInterval(pollRef.current);
          setLoading(false);
          toast.error('שגיאה בקבלת תוצאות');
        }
      }, POLL_INTERVAL);
    } catch {
      setLoading(false);
      toast.error('שגיאה בהתחלת הסריקה');
    }
  }

  const services = result?.registered_services || [];
  const gravatar = result?.gravatar;
  const profiles = result?.profiles || [];

  return (
    <div className="mx-auto max-w-2xl px-4 py-10 space-y-6">

      {/* Header */}
      <div className="text-center space-y-1">
        <div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-900 text-white mb-2">
          <Mail size={22} strokeWidth={2} />
        </div>
        <h1 className="text-2xl font-black tracking-tight text-slate-900">חקירת מייל</h1>
        <p className="text-sm text-slate-500">הזן כתובת מייל לקבלת כל המידע הזמין עליה</p>
      </div>

      {/* Input */}
      <form onSubmit={handleSubmit} className="flex gap-2">
        <input
          type="text"
          value={email}
          onChange={e => setEmail(e.target.value)}
          placeholder="example@domain.com"
          dir="ltr"
          className="flex-1 rounded-xl border border-slate-200 bg-white px-4 py-3 text-sm text-slate-800 placeholder-slate-400 shadow-sm outline-none focus:border-slate-400 focus:ring-2 focus:ring-slate-100"
        />
        <button
          type="submit"
          disabled={loading || !isValidEmail}
          className="flex items-center gap-2 rounded-xl bg-slate-900 px-5 py-3 text-sm font-semibold text-white shadow-sm transition-all hover:bg-slate-700 disabled:opacity-40"
        >
          {loading ? <Loader2 size={15} className="animate-spin" /> : <Zap size={15} />}
          {loading ? 'סורק...' : 'סרוק'}
        </button>
      </form>

      {/* Progress */}
      {loading && progress.length > 0 && (
        <div className="rounded-xl border border-slate-200 bg-slate-50 p-4 space-y-1">
          {progress.map((msg, i) => (
            <p key={i} className="text-xs text-slate-600 flex items-center gap-2">
              <span className="h-1.5 w-1.5 rounded-full bg-slate-400 shrink-0" />
              {msg}
            </p>
          ))}
          <p className="text-xs text-slate-400 flex items-center gap-1 pt-1">
            <Loader2 size={11} className="animate-spin" /> מחכה לתוצאות...
          </p>
        </div>
      )}

      {/* Results */}
      {result && (
        <div className="space-y-3">

          {/* Delivery / SMTP */}
          <Section title="תקינות ומסירה" icon={Server}>
            <div className="flex items-center gap-3">
              <span className="text-sm text-slate-500">ניתן למסירה</span>
              <Badge ok={result.deliverable} />
            </div>
            <Row label="שרת MX" value={result.mx} />
            {result.hunter_status && (
              <Row label="Hunter סטטוס" value={result.hunter_status} />
            )}
            {result.hunter_score !== undefined && (
              <Row label="Hunter ציון" value={`${result.hunter_score}/100`} />
            )}
          </Section>

          {/* Gravatar */}
          {gravatar && (
            <Section title="Gravatar / פרופיל ציבורי" icon={User}>
              {gravatar.display_name && <Row label="שם" value={gravatar.display_name} />}
              {gravatar.username    && <Row label="שם משתמש" value={gravatar.username} />}
              {gravatar.location    && <Row label="מיקום" value={gravatar.location} />}
              {gravatar.about_me    && <Row label="אודות" value={gravatar.about_me} />}
              {gravatar.profile_url && (
                <div className="text-sm">
                  <span className="text-slate-500 w-36 inline-block">קישור</span>
                  <a href={gravatar.profile_url} target="_blank" rel="noreferrer"
                    className="text-blue-600 hover:underline break-all">{gravatar.profile_url}</a>
                </div>
              )}
            </Section>
          )}

          {/* Linked profiles */}
          {profiles.length > 0 && (
            <Section title="פרופילים מקושרים" icon={Globe}>
              {profiles.map((p, i) => (
                <div key={i} className="flex items-center gap-2 text-sm">
                  <span className="w-24 text-slate-500 capitalize">{p.service}</span>
                  {p.url
                    ? <a href={p.url} target="_blank" rel="noreferrer" className="text-blue-600 hover:underline break-all">{p.url}</a>
                    : <span className="text-slate-800">נמצא</span>
                  }
                </div>
              ))}
            </Section>
          )}

          {/* Services (Holehe) */}
          {services.length > 0 && (
            <Section title={`שירותים רשומים (${services.length})`} icon={Shield}>
              <div className="flex flex-wrap gap-2">
                {services.map((s, i) => (
                  <span key={i} className="rounded-lg bg-emerald-50 px-3 py-1 text-xs font-medium text-emerald-700 ring-1 ring-emerald-200">
                    {s.service}
                  </span>
                ))}
              </div>
            </Section>
          )}

          {services.length === 0 && !gravatar && profiles.length === 0 && (
            <div className="flex items-center gap-2 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-700">
              <AlertCircle size={15} />
              לא נמצא מידע נוסף מעבר לבדיקת SMTP
            </div>
          )}
        </div>
      )}
    </div>
  );
}
