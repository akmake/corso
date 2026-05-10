import { useState, useRef, useEffect } from 'react';
import { Download, FileVideo, Music, Loader2, CheckCircle2, XCircle, Trash2, RefreshCw, Radar } from 'lucide-react';
import { videoApi, getJob } from '../utils/webintApi';
import toast from 'react-hot-toast';

const POLL_MS = 1000;

// Parse yt-dlp progress line: "[download]  45.3% of  234.56MiB at  1.23MiB/s ETA 00:45"
function parseProgress(lines) {
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    const m = line.match(/(\d+\.?\d*)%\s+of\s+([\d.]+\s*\S+)\s+at\s+([\d.]+\s*\S+\/s)\s+ETA\s+(\S+)/);
    if (m) return { pct: parseFloat(m[1]), total: m[2], speed: m[3], eta: m[4] };
    // fragment download (no ETA line yet)
    const m2 = line.match(/(\d+\.?\d*)%/);
    if (m2) return { pct: parseFloat(m2[1]), total: null, speed: null, eta: null };
  }
  return null;
}

function statusLabel(lines) {
  if (!lines.length) return 'מתחיל...';
  const last = lines[lines.length - 1];
  if (last.includes('Downloading webpage') || last.includes('Extracting URL')) return 'מאתר סרטון...';
  if (last.includes('Downloading m3u8') || last.includes('playlist')) return 'קורא playlist...';
  if (last.includes('[download]') && last.includes('%')) return 'מוריד...';
  if (last.includes('Merging') || last.includes('ffmpeg')) return 'ממזג וידאו+שמע...';
  if (last.includes('Destination')) return 'מוריד...';
  return 'מעבד...';
}

export default function VideoDownloaderPage() {
  const [url, setUrl] = useState('');
  const [format, setFormat] = useState('best');
  const [jobId, setJobId] = useState(null);
  const [status, setStatus] = useState('idle');
  const [progress, setProgress] = useState([]);
  const [result, setResult] = useState(null);
  const [files, setFiles] = useState([]);

  // Sniffer state
  const [sniffUrl, setSniffUrl] = useState('');
  const [sniffJobId, setSniffJobId] = useState(null);
  const [sniffStatus, setSniffStatus] = useState('idle');
  const [sniffLog, setSniffLog] = useState([]);
  const [sniffResult, setSniffResult] = useState(null);
  const sniffPollRef = useRef(null);

  const logRef = useRef(null);
  const pollRef = useRef(null);

  useEffect(() => { loadFiles(); }, []);

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
          if (!data.result?.error) { toast.success('ההורדה הושלמה!'); loadFiles(); }
        } else if (data.status === 'failed') {
          clearInterval(pollRef.current);
          setStatus('failed');
          setResult(data.result);
        }
      } catch { /* ignore */ }
    }, POLL_MS);
    return () => clearInterval(pollRef.current);
  }, [jobId, status]);

  useEffect(() => {
    if (!sniffJobId || sniffStatus !== 'running') return;
    sniffPollRef.current = setInterval(async () => {
      try {
        const { data } = await getJob(sniffJobId);
        setSniffLog(data.progress || []);
        if (data.status === 'completed') {
          clearInterval(sniffPollRef.current);
          setSniffStatus('completed');
          setSniffResult(data.result);
        } else if (data.status === 'failed') {
          clearInterval(sniffPollRef.current);
          setSniffStatus('failed');
          setSniffResult(data.result);
        }
      } catch { /* ignore */ }
    }, POLL_MS);
    return () => clearInterval(sniffPollRef.current);
  }, [sniffJobId, sniffStatus]);

  async function handleSniff() {
    if (!sniffUrl.trim()) return;
    setSniffStatus('running');
    setSniffLog([]);
    setSniffResult(null);
    try {
      const { data } = await videoApi.sniff(sniffUrl.trim(), 60);
      setSniffJobId(data.job_id);
    } catch {
      setSniffStatus('failed');
    }
  }

  async function loadFiles() {
    try {
      const { data } = await videoApi.list();
      setFiles(data.files || []);
    } catch { /* silent */ }
  }

  async function handleDownload() {
    if (!url.trim()) return;
    setStatus('running');
    setProgress([]);
    setResult(null);
    try {
      const { data } = await videoApi.download(url.trim(), format, null);
      setJobId(data.job_id);
    } catch {
      setStatus('failed');
      toast.error('שגיאה בהתחלת ההורדה');
    }
  }

  function handleReset() {
    clearInterval(pollRef.current);
    setUrl(''); setStatus('idle'); setProgress([]); setResult(null); setJobId(null);
  }

  async function handleDelete(filename) {
    await videoApi.delete(filename);
    setFiles(f => f.filter(x => x.filename !== filename));
    toast.success('הקובץ נמחק');
  }

  const isRunning = status === 'running';
  const isDone = status === 'completed' && result && !result.error;
  const isFailed = status === 'failed' || (status === 'completed' && result?.error);

  return (
    <div className="mx-auto max-w-2xl px-4 py-10 pt-24" dir="rtl">

      {/* Header */}
      <div className="mb-8 flex items-center gap-3">
        <div className="rounded-xl bg-slate-900 p-3 text-white">
          <FileVideo size={22} />
        </div>
        <div>
          <h1 className="text-2xl font-black text-slate-900">מוריד סרטונים</h1>
          <p className="text-sm text-slate-500">הדבק קישור — YouTube, m3u8, mp4, ועוד</p>
        </div>
      </div>

      {/* Auto Sniffer */}
      <div className="mb-4 rounded-2xl border border-blue-100 bg-blue-50 p-5">
        <div className="mb-3 flex items-center gap-2">
          <Radar size={16} className="text-blue-600" />
          <span className="text-sm font-bold text-blue-800">זיהוי URL אוטומטי</span>
          <span className="text-xs text-blue-500">— הדבק את כתובת הדף, לא של הסרטון</span>
        </div>
        <div className="flex gap-2">
          <input
            type="url"
            value={sniffUrl}
            onChange={e => setSniffUrl(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && sniffStatus !== 'running' && handleSniff()}
            placeholder="https://openu.ac.il/courses/..."
            disabled={sniffStatus === 'running'}
            className="flex-1 rounded-xl border border-blue-200 bg-white px-4 py-2.5 text-sm text-slate-900 placeholder:text-slate-400 focus:border-blue-400 focus:outline-none disabled:opacity-50"
            dir="ltr"
          />
          <button
            onClick={handleSniff}
            disabled={!sniffUrl.trim() || sniffStatus === 'running'}
            className="flex items-center gap-2 rounded-xl bg-blue-600 px-4 py-2.5 text-sm font-semibold text-white hover:bg-blue-700 disabled:opacity-40"
          >
            {sniffStatus === 'running'
              ? <><Loader2 size={15} className="animate-spin" /> מאזין...</>
              : <><Radar size={15} /> אתר</>}
          </button>
        </div>

        {sniffLog.length > 0 && (
          <div className="mt-3 max-h-24 overflow-y-auto rounded-lg bg-blue-900 p-2">
            {sniffLog.map((l, i) => (
              <p key={i} className="font-mono text-xs text-blue-200 break-all">{l}</p>
            ))}
          </div>
        )}

        {sniffResult?.urls?.length > 0 && (
          <div className="mt-3 space-y-1">
            <p className="text-xs font-semibold text-blue-700">נמצאו — לחץ להדבקה:</p>
            {sniffResult.urls.map((u, i) => (
              <button
                key={i}
                onClick={() => { setUrl(u); toast.success('URL הודבק!'); }}
                className="block w-full truncate rounded-lg border border-blue-200 bg-white px-3 py-2 text-right text-xs text-blue-700 hover:bg-blue-50"
                dir="ltr"
                title={u}
              >
                {u.length > 80 ? u.slice(0, 80) + '...' : u}
              </button>
            ))}
          </div>
        )}

        {sniffResult?.error && (
          <p className="mt-2 text-xs text-red-600">{sniffResult.error}</p>
        )}
      </div>

      {/* Main Card */}
      <div className="rounded-2xl border border-slate-200 bg-white p-6 shadow-sm">

        {/* URL */}
        <label className="mb-2 block text-sm font-semibold text-slate-700">קישור</label>
        <textarea
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder={"https://souvod.bynetcdn.com/...playlist.m3u8?...\nאו כל URL של סרטון"}
          rows={3}
          disabled={isRunning}
          className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 font-mono text-sm text-slate-900 placeholder:text-slate-400 focus:border-slate-400 focus:outline-none focus:ring-2 focus:ring-slate-100 disabled:opacity-50 resize-none"
          dir="ltr"
        />

        {/* Format */}
        <div className="mt-4 flex gap-2 flex-wrap">
          {[
            { value: 'best',       label: '⭐ הטוב ביותר' },
            { value: 'bestvideo[height<=1080]+bestaudio/best', label: '🎬 1080p' },
            { value: 'bestvideo[height<=720]+bestaudio/best',  label: '🎬 720p'  },
            { value: 'bestvideo[height<=480]+bestaudio/best',  label: '🎬 480p'  },
            { value: 'audio_only', label: '🎵 MP3 בלבד' },
          ].map(opt => (
            <button
              key={opt.value}
              onClick={() => setFormat(opt.value)}
              disabled={isRunning}
              className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                format === opt.value
                  ? 'bg-slate-900 text-white'
                  : 'border border-slate-200 text-slate-600 hover:bg-slate-50'
              } disabled:opacity-50`}
            >
              {opt.label}
            </button>
          ))}
        </div>

        {/* Action Buttons */}
        <div className="mt-4 flex gap-2">
          <button
            onClick={handleDownload}
            disabled={!url.trim() || isRunning}
            className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-slate-900 py-3 text-sm font-bold text-white transition hover:bg-slate-700 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {isRunning
              ? <><Loader2 size={16} className="animate-spin" /> מוריד...</>
              : <><Download size={16} /> הורד</>}
          </button>
          {(isRunning || isDone || isFailed) && (
            <button onClick={handleReset} className="rounded-xl border border-slate-200 p-3 text-slate-500 hover:bg-slate-50">
              <RefreshCw size={16} />
            </button>
          )}
        </div>
      </div>

      {/* Progress */}
      {(isRunning || isFailed || isDone) && progress.length > 0 && (() => {
        const parsed = parseProgress(progress);
        const label = statusLabel(progress);
        return (
          <div className="mt-4 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm">
            {/* Status row */}
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                {isRunning && <Loader2 size={15} className="animate-spin text-slate-500" />}
                {isDone && <CheckCircle2 size={15} className="text-emerald-500" />}
                {isFailed && <XCircle size={15} className="text-red-500" />}
                <span className="text-sm font-semibold text-slate-800">
                  {isDone ? 'הושלם' : isFailed ? 'נכשל' : label}
                </span>
              </div>
              {parsed && (
                <span className="text-sm font-bold text-slate-700">{parsed.pct.toFixed(1)}%</span>
              )}
            </div>

            {/* Progress bar */}
            {parsed && (
              <>
                <div className="h-2.5 w-full rounded-full bg-slate-100 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-slate-900 transition-all duration-500"
                    style={{ width: `${parsed.pct}%` }}
                  />
                </div>
                <div className="mt-2 flex gap-4 text-xs text-slate-400">
                  {parsed.total && <span>גודל: {parsed.total}</span>}
                  {parsed.speed && <span>מהירות: {parsed.speed}</span>}
                  {parsed.eta   && <span>נותר: {parsed.eta}</span>}
                </div>
              </>
            )}

            {/* Raw log toggle */}
            <details className="mt-3">
              <summary className="cursor-pointer text-xs text-slate-400 hover:text-slate-600 select-none">
                לוג מלא
              </summary>
              <div ref={logRef} className="mt-2 max-h-40 overflow-y-auto rounded-lg bg-slate-950 p-3" dir="ltr">
                {progress.map((line, i) => (
                  <p key={i} className="font-mono text-xs text-green-400 break-all">{line}</p>
                ))}
              </div>
            </details>
          </div>
        );
      })()}

      {/* Success */}
      {isDone && (
        <div className="mt-4 rounded-2xl border border-emerald-200 bg-emerald-50 p-5">
          <div className="flex items-center gap-2 text-emerald-700 font-bold">
            <CheckCircle2 size={18} /> הושלם!
          </div>
          <p className="mt-1 text-sm text-emerald-600">{result.filename} · {result.size_mb} MB</p>
          <a
            href={videoApi.fileUrl(result.filename)}
            download={result.filename}
            className="mt-3 inline-flex items-center gap-2 rounded-xl bg-emerald-700 px-4 py-2.5 text-sm font-bold text-white hover:bg-emerald-800"
          >
            <Download size={15} /> שמור קובץ
          </a>
        </div>
      )}

      {/* Error */}
      {isFailed && result?.error && (
        <div className="mt-4 flex items-start gap-2 rounded-2xl border border-red-200 bg-red-50 p-5 text-sm text-red-700">
          <XCircle size={16} className="mt-0.5 shrink-0" />
          <span>{result.error}</span>
        </div>
      )}

      {/* Downloaded Files */}
      {files.length > 0 && (
        <div className="mt-8">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-700">קבצים שהורדו</h2>
            <button onClick={loadFiles} className="text-xs text-slate-400 hover:text-slate-600">רענן</button>
          </div>
          <div className="space-y-2">
            {files.map(f => (
              <div key={f.filename} className="flex items-center justify-between rounded-xl border border-slate-200 bg-white px-4 py-3">
                <div className="flex items-center gap-3 min-w-0">
                  {f.filename.endsWith('.mp3')
                    ? <Music size={16} className="text-purple-500 shrink-0" />
                    : <FileVideo size={16} className="text-blue-500 shrink-0" />}
                  <div className="min-w-0">
                    <p className="truncate text-sm font-medium text-slate-800" dir="ltr">{f.filename}</p>
                    <p className="text-xs text-slate-400">{f.size_mb} MB</p>
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0 mr-3">
                  <a
                    href={videoApi.fileUrl(f.filename)}
                    download={f.filename}
                    className="rounded-lg bg-slate-900 px-3 py-1.5 text-xs font-semibold text-white hover:bg-slate-700"
                  >
                    הורד
                  </a>
                  <button onClick={() => handleDelete(f.filename)}
                    className="rounded-lg p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-500">
                    <Trash2 size={14} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
