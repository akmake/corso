import { useState, useRef, useEffect } from 'react';
import { FileVideo, Music, Download, Loader2, CheckCircle2, XCircle, RefreshCw, Trash2 } from 'lucide-react';
import { videoConverterApi, getJob, videoApi } from '../utils/webintApi';
import toast from 'react-hot-toast';

const POLL_MS = 1000;

function useJobPoller(jobId, setStatus, setProgress, setResult, onDone) {
  const timerRef = useRef(null);

  useEffect(() => {
    if (!jobId) return;

    timerRef.current = setInterval(async () => {
      try {
        const { data } = await getJob(jobId);
        setProgress(data.progress || []);

        if (data.status === 'completed') {
          clearInterval(timerRef.current);
          setStatus('completed');
          setResult(data.result);
          onDone?.(data.result);
        } else if (data.status === 'failed') {
          clearInterval(timerRef.current);
          setStatus('failed');
          setResult(data.result);
        }
      } catch {
        // ignore poll errors
      }
    }, POLL_MS);

    return () => clearInterval(timerRef.current);
  }, [jobId, onDone, setProgress, setResult, setStatus]);
}

function ProgressBox({ progress, status, result }) {
  const logRef = useRef(null);

  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [progress]);

  if (!progress.length && status === 'idle') return null;

  const isDone = status === 'completed' && result && !result.error;
  const isFailed = status === 'failed' || (status === 'completed' && result?.error);

  return (
    <div className="mt-4 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
      <div className="mb-2 flex items-center gap-2">
        {status === 'running' && <Loader2 size={14} className="animate-spin text-slate-500" />}
        {isDone && <CheckCircle2 size={14} className="text-emerald-500" />}
        {isFailed && <XCircle size={14} className="text-red-500" />}
        <span className="text-sm font-semibold text-slate-700">
          {isDone ? 'הושלם!' : isFailed ? 'נכשל' : 'מעבד...'}
        </span>
      </div>

      <div ref={logRef} className="max-h-32 overflow-y-auto rounded-lg bg-slate-950 p-2">
        {progress.map((line, i) => (
          <p key={i} className="break-all font-mono text-xs text-green-400">{line}</p>
        ))}
      </div>
    </div>
  );
}

function SuccessBox({ result, onDelete }) {
  if (!result || result.error) return null;

  return (
    <div className="mt-4 rounded-2xl border border-emerald-200 bg-emerald-50 p-4">
      <div className="mb-1 flex items-center gap-2 font-bold text-emerald-700">
        <CheckCircle2 size={16} /> הושלם!
      </div>

      <p className="mb-3 text-sm text-emerald-600" dir="ltr">
        {result.filename} · {result.size_mb} MB
      </p>

      <div className="flex gap-2">
        <a
          href={videoApi.fileUrl(result.filename)}
          download={result.filename}
          className="inline-flex items-center gap-2 rounded-xl bg-emerald-700 px-4 py-2 text-sm font-bold text-white hover:bg-emerald-800"
        >
          <Download size={14} /> הורד
        </a>

        <button
          onClick={() => onDelete(result.filename)}
          className="inline-flex items-center gap-2 rounded-xl border border-slate-200 px-3 py-2 text-sm text-slate-500 hover:bg-red-50 hover:text-red-500"
        >
          <Trash2 size={14} /> מחק
        </button>
      </div>
    </div>
  );
}

function FileDrop({ accept, label, icon: Icon, file, onFile, disabled }) {
  const inputRef = useRef(null);
  const [drag, setDrag] = useState(false);

  function handleDrop(e) {
    e.preventDefault();
    setDrag(false);
    const f = e.dataTransfer.files[0];
    if (f) onFile(f);
  }

  return (
    <div
      onClick={() => !disabled && inputRef.current?.click()}
      onDragOver={(e) => {
        e.preventDefault();
        setDrag(true);
      }}
      onDragLeave={() => setDrag(false)}
      onDrop={handleDrop}
      className={`flex cursor-pointer flex-col items-center justify-center gap-2 rounded-xl border-2 border-dashed px-4 py-6 transition
        ${drag ? 'border-slate-500 bg-slate-100' : 'border-slate-200 bg-slate-50 hover:bg-slate-100'}
        ${disabled ? 'cursor-not-allowed opacity-50' : ''}`}
    >
      <Icon size={22} className="text-slate-400" />
      {file ? (
        <span className="max-w-xs truncate text-sm font-medium text-slate-700" dir="ltr">{file.name}</span>
      ) : (
        <span className="text-sm text-slate-500">{label}</span>
      )}
      <input
        ref={inputRef}
        type="file"
        accept={accept}
        className="hidden"
        onChange={(e) => onFile(e.target.files[0])}
        disabled={disabled}
      />
    </div>
  );
}

function Mp3Section() {
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState('idle');
  const [progress, setProgress] = useState([]);
  const [result, setResult] = useState(null);
  const [jobId, setJobId] = useState(null);

  useJobPoller(jobId, setStatus, setProgress, setResult, (r) => {
    if (!r?.error) toast.success('ההמרה הושלמה!');
  });

  async function handleConvert() {
    if (!file) return;
    const fd = new FormData();
    fd.append('file', file);
    setStatus('running');
    setProgress([]);
    setResult(null);

    try {
      const { data } = await videoConverterApi.convertToMp3(fd);
      setJobId(data.job_id);
    } catch {
      setStatus('failed');
      toast.error('שגיאה בהתחלת ההמרה');
    }
  }

  function reset() {
    setFile(null);
    setStatus('idle');
    setProgress([]);
    setResult(null);
    setJobId(null);
  }

  async function handleDelete(filename) {
    await videoApi.delete(filename);
    toast.success('הקובץ נמחק');
    reset();
  }

  const running = status === 'running';

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="mb-4 flex items-center gap-3">
        <div className="rounded-xl bg-purple-100 p-2.5 text-purple-700"><Music size={20} /></div>
        <div>
          <h2 className="font-bold text-slate-900">MP4 → MP3</h2>
          <p className="text-xs text-slate-500">חלץ את השמע מהסרטון</p>
        </div>
      </div>

      <FileDrop
        accept="video/*,.mp4,.mkv,.avi,.mov,.webm"
        label="גרור MP4 לכאן או לחץ לבחירה"
        icon={FileVideo}
        file={file}
        onFile={setFile}
        disabled={running}
      />

      <div className="mt-4 flex gap-2">
        <button
          onClick={handleConvert}
          disabled={!file || running}
          className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-purple-700 py-2.5 text-sm font-bold text-white hover:bg-purple-800 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {running ? <><Loader2 size={15} className="animate-spin" /> ממיר...</> : <><Music size={15} /> המר ל-MP3</>}
        </button>

        {(running || status !== 'idle') && (
          <button onClick={reset} className="rounded-xl border border-slate-200 p-2.5 text-slate-500 hover:bg-slate-50">
            <RefreshCw size={15} />
          </button>
        )}
      </div>

      <ProgressBox progress={progress} status={status} result={result} />
      <SuccessBox result={result} onDelete={handleDelete} />
      {result?.error && (
        <div className="mt-4 flex items-start gap-2 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          <XCircle size={15} className="mt-0.5 shrink-0" />{result.error}
        </div>
      )}
    </div>
  );
}

function AudioOnlyMp4Section() {
  const [file, setFile] = useState(null);
  const [status, setStatus] = useState('idle');
  const [progress, setProgress] = useState([]);
  const [result, setResult] = useState(null);
  const [jobId, setJobId] = useState(null);

  useJobPoller(jobId, setStatus, setProgress, setResult, (r) => {
    if (!r?.error) toast.success('הקובץ נוצר!');
  });

  async function handleConvert() {
    if (!file) return;
    const fd = new FormData();
    fd.append('file', file);
    setStatus('running');
    setProgress([]);
    setResult(null);

    try {
      const { data } = await videoConverterApi.convertToAudioMp4(fd);
      setJobId(data.job_id);
    } catch {
      setStatus('failed');
      toast.error('שגיאה בהתחלת ההמרה');
    }
  }

  function reset() {
    setFile(null);
    setStatus('idle');
    setProgress([]);
    setResult(null);
    setJobId(null);
  }

  async function handleDelete(filename) {
    await videoApi.delete(filename);
    toast.success('הקובץ נמחק');
    reset();
  }

  const running = status === 'running';

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">
      <div className="mb-4 flex items-center gap-3">
        <div className="rounded-xl bg-blue-100 p-2.5 text-blue-700"><Music size={20} /></div>
        <div>
          <h2 className="font-bold text-slate-900">MP4 אודיו בלבד</h2>
          <p className="text-xs text-slate-500">מסיר את הוידאו ומשאיר קובץ MP4 עם אודיו בלבד</p>
        </div>
      </div>

      <FileDrop
        accept="video/*,.mp4,.mkv,.avi,.mov,.webm"
        label="גרור קובץ וידאו לכאן או לחץ לבחירה"
        icon={FileVideo}
        file={file}
        onFile={setFile}
        disabled={running}
      />

      <div className="mt-4 flex gap-2">
        <button
          onClick={handleConvert}
          disabled={!file || running}
          className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-blue-700 py-2.5 text-sm font-bold text-white hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-40"
        >
          {running ? <><Loader2 size={15} className="animate-spin" /> מעבד...</> : <><Music size={15} /> הפק MP4 אודיו בלבד</>}
        </button>

        {(running || status !== 'idle') && (
          <button onClick={reset} className="rounded-xl border border-slate-200 p-2.5 text-slate-500 hover:bg-slate-50">
            <RefreshCw size={15} />
          </button>
        )}
      </div>

      <ProgressBox progress={progress} status={status} result={result} />
      <SuccessBox result={result} onDelete={handleDelete} />
      {result?.error && (
        <div className="mt-4 flex items-start gap-2 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          <XCircle size={15} className="mt-0.5 shrink-0" />{result.error}
        </div>
      )}
    </div>
  );
}

export default function VideoConverterPage() {
  return (
    <div className="mx-auto max-w-2xl px-4 py-10 pt-24" dir="rtl">
      <div className="mb-8 flex items-center gap-3">
        <div className="rounded-xl bg-slate-900 p-3 text-white">
          <FileVideo size={22} />
        </div>
        <div>
          <h1 className="text-2xl font-black text-slate-900">המרת וידאו</h1>
          <p className="text-sm text-slate-500">MP4 → MP3 או MP4 אודיו בלבד</p>
        </div>
      </div>

      <div className="space-y-6">
        <Mp3Section />
        <AudioOnlyMp4Section />
      </div>
    </div>
  );
}