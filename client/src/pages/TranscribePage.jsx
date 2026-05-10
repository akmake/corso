import { useEffect, useRef, useState } from 'react';
import {
  AudioLines,
  Loader2,
  CheckCircle2,
  XCircle,
  Download,
  FileAudio,
  Sparkles,
  Languages,
  Captions,
  RefreshCw,
} from 'lucide-react';
import toast from 'react-hot-toast';
import { getJob, transcribeApi, videoApi } from '../utils/webintApi';

const POLL_MS = 1200;
const MAX_POLL_ERRORS = 4;

const MODEL_OPTIONS = [
  { value: 'large-v3', label: 'large-v3 (דיוק מקסימלי)' },
  { value: 'large-v2', label: 'large-v2 (יציב וטוב)' },
  { value: 'medium', label: 'medium (מהיר יותר)' },
  { value: 'small', label: 'small (מהיר וחסכוני)' },
  { value: 'base', label: 'base (קל מאוד)' },
];

const LANGUAGE_OPTIONS = [
  { value: 'he', label: 'עברית' },
  { value: 'auto', label: 'זיהוי אוטומטי' },
  { value: 'en', label: 'אנגלית' },
  { value: 'ar', label: 'ערבית' },
  { value: 'ru', label: 'רוסית' },
];

function extractErrorMessage(err, fallback = 'שגיאה לא ידועה') {
  const data = err?.response?.data;
  if (typeof data === 'string' && data.trim()) return data.trim();
  if (data?.detail) return String(data.detail);
  if (data?.error) return String(data.error);
  if (err?.message) return String(err.message);
  return fallback;
}

function ProgressLog({ progress }) {
  const logRef = useRef(null);

  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [progress]);

  if (!progress.length) return null;

  return (
    <div className="mt-4 rounded-2xl border border-slate-200 bg-slate-950 p-3" ref={logRef}>
      {progress.map((line, i) => (
        <p key={i} className="break-all font-mono text-xs text-emerald-400">{line}</p>
      ))}
    </div>
  );
}

function ResultDownloads({ result }) {
  if (!result || result.error) return null;

  const files = [
    { key: 'txt_filename', label: 'TXT', filename: result.txt_filename },
    { key: 'srt_filename', label: 'SRT', filename: result.srt_filename },
    { key: 'json_filename', label: 'JSON', filename: result.json_filename },
  ].filter((f) => f.filename);

  return (
    <div className="mt-5 rounded-2xl border border-emerald-200 bg-emerald-50 p-4">
      <div className="flex items-center gap-2 text-emerald-700">
        <CheckCircle2 size={16} />
        <p className="text-sm font-bold">התמלול הושלם</p>
      </div>

      <div className="mt-2 text-xs text-emerald-700">
        <p>שפה: {result.language || 'לא זוהתה'} | סגמנטים: {result.segments_count || 0}</p>
        <p>מודל: {result.model} | GPU/CPU: {result.device} ({result.compute_type})</p>
      </div>

      <div className="mt-3 flex flex-wrap gap-2">
        {files.map((f) => (
          <a
            key={f.key}
            href={videoApi.fileUrl(f.filename)}
            download={f.filename}
            className="inline-flex items-center gap-2 rounded-xl bg-emerald-700 px-3 py-2 text-xs font-bold text-white hover:bg-emerald-800"
          >
            <Download size={13} />
            הורד {f.label}
          </a>
        ))}
      </div>
    </div>
  );
}

export default function TranscribePage() {
  const [file, setFile] = useState(null);
  const [modelSize, setModelSize] = useState('large-v3');
  const [language, setLanguage] = useState('he');
  const [task, setTask] = useState('transcribe');
  const [wordTimestamps, setWordTimestamps] = useState(false);

  const [jobId, setJobId] = useState(null);
  const [status, setStatus] = useState('idle');
  const [progress, setProgress] = useState([]);
  const [percent, setPercent] = useState(0);
  const [result, setResult] = useState(null);

  useEffect(() => {
    if (!jobId || status !== 'running') return undefined;

    let pollErrors = 0;

    const timer = setInterval(async () => {
      try {
        const { data } = await getJob(jobId);
        pollErrors = 0;
        setProgress(data.progress || []);
        setPercent(typeof data.percent === 'number' ? data.percent : 0);

        if (data.status === 'completed') {
          setStatus('completed');
          setResult(data.result || null);
          if (!data.result?.error) toast.success('התמלול הסתיים בהצלחה');
          clearInterval(timer);
        } else if (data.status === 'not_found') {
          setStatus('failed');
          setResult({ error: 'המשימה לא נמצאה בשרת. ייתכן שהשרת הופעל מחדש.' });
          clearInterval(timer);
        } else if (data.status === 'failed') {
          setStatus('failed');
          setResult(data.result || { error: 'המשימה נכשלה ללא פירוט מהשרת.' });
          clearInterval(timer);
        }
      } catch (err) {
        pollErrors += 1;
        if (pollErrors >= MAX_POLL_ERRORS) {
          setStatus('failed');
          setResult({
            error: `איבדנו חיבור לשרת בזמן התמלול. ${extractErrorMessage(err, 'בדוק שה-API רץ על פורט 8000.')}`,
          });
          clearInterval(timer);
        }
      }
    }, POLL_MS);

    return () => clearInterval(timer);
  }, [jobId, status]);

  async function handleStart() {
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);
    formData.append('model_size', modelSize);
    formData.append('language', language);
    formData.append('task', task);
    formData.append('word_timestamps', wordTimestamps ? 'true' : 'false');

    setStatus('running');
    setResult(null);
    setProgress([]);
    setPercent(0);

    try {
      const { data } = await transcribeApi.transcribeFile(formData);
      if (!data?.job_id) {
        throw new Error('השרת לא החזיר מזהה משימה.');
      }
      setJobId(data.job_id);
    } catch (err) {
      const message = extractErrorMessage(err, 'שגיאה בהתחלת התמלול');
      setStatus('failed');
      setResult({ error: message });
      toast.error(message);
    }
  }

  function handleReset() {
    setFile(null);
    setJobId(null);
    setStatus('idle');
    setProgress([]);
    setPercent(0);
    setResult(null);
  }

  const isRunning = status === 'running';

  return (
    <div className="mx-auto max-w-3xl px-4 py-10 pt-24" dir="rtl">
      <div className="mb-7 rounded-3xl border border-cyan-200 bg-gradient-to-br from-cyan-50 via-white to-amber-50 p-6 shadow-sm">
        <div className="mb-2 flex items-center gap-3">
          <div className="rounded-2xl bg-cyan-700 p-2.5 text-white">
            <AudioLines size={20} />
          </div>
          <div>
            <h1 className="text-2xl font-black text-slate-900">תמלול אודיו/וידאו</h1>
            <p className="text-sm text-slate-600">`faster-whisper` מקומי על ה-GPU שלך</p>
          </div>
        </div>
        <p className="text-xs text-slate-500">
          תומך בקבצי MP3/MP4 ועוד, כולל פלט TXT + SRT + JSON.
        </p>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
        <label className="mb-2 block text-sm font-semibold text-slate-700">קובץ לתמלול</label>
        <label className="flex cursor-pointer items-center justify-center gap-3 rounded-xl border-2 border-dashed border-slate-200 bg-slate-50 px-4 py-6 text-slate-500 transition hover:border-cyan-300 hover:bg-cyan-50">
          <FileAudio size={18} />
          <span className="text-sm">{file ? file.name : 'לחץ לבחירה או גרור קובץ לכאן'}</span>
          <input
            type="file"
            className="hidden"
            accept="audio/*,video/*,.mp3,.mp4,.m4a,.wav,.ogg,.webm,.flac,.aac,.mov,.mkv,.avi"
            onChange={(e) => setFile(e.target.files?.[0] || null)}
            disabled={isRunning}
          />
        </label>

        <div className="mt-5 grid gap-3 sm:grid-cols-2">
          <label className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5">
            <span className="mb-1.5 flex items-center gap-1 text-[11px] font-bold text-slate-500">
              <Sparkles size={12} /> מודל
            </span>
            <select
              value={modelSize}
              onChange={(e) => setModelSize(e.target.value)}
              disabled={isRunning}
              className="w-full border-none bg-transparent text-sm font-semibold text-slate-800 outline-none"
            >
              {MODEL_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </label>

          <label className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5">
            <span className="mb-1.5 flex items-center gap-1 text-[11px] font-bold text-slate-500">
              <Languages size={12} /> שפת דיבור
            </span>
            <select
              value={language}
              onChange={(e) => setLanguage(e.target.value)}
              disabled={isRunning}
              className="w-full border-none bg-transparent text-sm font-semibold text-slate-800 outline-none"
            >
              {LANGUAGE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>{opt.label}</option>
              ))}
            </select>
          </label>

          <label className="rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5">
            <span className="mb-1.5 flex items-center gap-1 text-[11px] font-bold text-slate-500">
              <Captions size={12} /> משימה
            </span>
            <select
              value={task}
              onChange={(e) => setTask(e.target.value)}
              disabled={isRunning}
              className="w-full border-none bg-transparent text-sm font-semibold text-slate-800 outline-none"
            >
              <option value="transcribe">תמלול לשפת המקור</option>
              <option value="translate">תרגום לאנגלית</option>
            </select>
          </label>

          <label className="flex items-center gap-2 rounded-xl border border-slate-200 bg-slate-50 px-3 py-2.5 text-sm font-semibold text-slate-700">
            <input
              type="checkbox"
              checked={wordTimestamps}
              onChange={(e) => setWordTimestamps(e.target.checked)}
              disabled={isRunning}
              className="h-4 w-4 accent-cyan-700"
            />
            מיקוד זמנים למילים (JSON כבד יותר)
          </label>
        </div>

        <div className="mt-5 flex gap-2">
          <button
            onClick={handleStart}
            disabled={!file || isRunning}
            className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-cyan-700 py-2.5 text-sm font-bold text-white hover:bg-cyan-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {isRunning ? <><Loader2 size={15} className="animate-spin" /> מתמלל...</> : <><AudioLines size={15} /> התחל תמלול</>}
          </button>

          {(isRunning || status !== 'idle') && (
            <button
              onClick={handleReset}
              className="rounded-xl border border-slate-200 px-3 text-slate-500 hover:bg-slate-50"
            >
              <RefreshCw size={15} />
            </button>
          )}
        </div>

        {(isRunning || status === 'completed') && (
          <div className="mt-4">
            <div className="mb-1.5 flex items-center justify-between text-xs text-slate-500">
              <span>התקדמות תמלול</span>
              <span className="font-bold text-slate-700">{Math.max(0, Math.min(100, percent)).toFixed(1)}%</span>
            </div>
            <div className="h-2.5 w-full overflow-hidden rounded-full bg-slate-100">
              <div
                className="h-full rounded-full bg-cyan-700 transition-all duration-500"
                style={{ width: `${Math.max(0, Math.min(100, percent))}%` }}
              />
            </div>
          </div>
        )}

        <ProgressLog progress={progress} />

        {status === 'failed' && (
          <div className="mt-4 flex items-start gap-2 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
            <XCircle size={16} className="mt-0.5 shrink-0" />
            {result?.error || 'שגיאה לא ידועה'}
          </div>
        )}

        <ResultDownloads result={result} />
      </div>
    </div>
  );
}
