import { useState, useRef, useCallback, useEffect } from 'react';
import {
  FileText, Upload, Trash2, GripVertical, Download, Loader2,
  ChevronUp, ChevronDown, Eye, EyeOff, Scissors, X,
  CheckSquare, Square, ZoomIn, ChevronLeft, ChevronRight,
  ScanText, Languages, Settings2,
} from 'lucide-react';
import toast from 'react-hot-toast';

const API = 'http://localhost:8000';

// ─────────────────────────────────────────────────────────────────────────────
// Shared: drop-zone
// ─────────────────────────────────────────────────────────────────────────────
function DropZone({ onFiles, multiple = false, color = 'red' }) {
  const ref = useRef(null);
  const colors = {
    red:    'hover:border-red-400 hover:bg-red-50',
    blue:   'hover:border-blue-400 hover:bg-blue-50',
    purple: 'hover:border-purple-400 hover:bg-purple-50',
  };
  return (
    <div
      className={`flex flex-col items-center justify-center gap-2 rounded-2xl border-2 border-dashed border-slate-300 bg-slate-50 px-4 py-6 cursor-pointer transition ${colors[color]}`}
      onClick={() => ref.current?.click()}
      onDragOver={e => e.preventDefault()}
      onDrop={e => { e.preventDefault(); onFiles(e.dataTransfer.files); }}
    >
      <Upload size={22} className="text-slate-400" />
      <span className="text-sm font-semibold text-slate-500">גרור PDF לכאן או לחץ לבחירה</span>
      <input ref={ref} type="file" accept="application/pdf" multiple={multiple} className="hidden"
        onChange={e => onFiles(e.target.files)} />
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 1: Merge
// ─────────────────────────────────────────────────────────────────────────────
function MergeTab() {
  const [files, setFiles]           = useState([]);
  const [previewId, setPreviewId]   = useState(null);
  const [merging, setMerging]       = useState(false);
  const [draggingId, setDraggingId] = useState(null);
  const dragOverId = useRef(null);

  function addFiles(list) {
    const added = Array.from(list)
      .filter(f => f.type === 'application/pdf')
      .map(f => ({ id: crypto.randomUUID(), file: f, blobUrl: URL.createObjectURL(f), name: f.name, size: (f.size / 1024 / 1024).toFixed(2) }));
    if (!added.length) { toast.error('בחר קבצי PDF בלבד'); return; }
    setFiles(prev => [...prev, ...added]);
    if (!previewId && added.length) setPreviewId(added[0].id);
  }

  function removeFile(id) {
    setFiles(prev => { const n = prev.filter(f => f.id !== id); if (previewId === id) setPreviewId(n[0]?.id ?? null); return n; });
  }

  function moveFile(id, dir) {
    setFiles(prev => {
      const idx = prev.findIndex(f => f.id === id); const next = [...prev]; const swap = idx + dir;
      if (swap < 0 || swap >= next.length) return prev;
      [next[idx], next[swap]] = [next[swap], next[idx]]; return next;
    });
  }

  function onDrop() {
    if (!draggingId || !dragOverId.current || draggingId === dragOverId.current) { setDraggingId(null); return; }
    setFiles(prev => {
      const next = [...prev];
      const fi = next.findIndex(f => f.id === draggingId); const ti = next.findIndex(f => f.id === dragOverId.current);
      const [item] = next.splice(fi, 1); next.splice(ti, 0, item); return next;
    });
    setDraggingId(null); dragOverId.current = null;
  }

  async function handleMerge() {
    if (files.length < 2) { toast.error('הוסף לפחות 2 קבצים'); return; }
    setMerging(true);
    try {
      const form = new FormData();
      files.forEach(f => form.append('files', f.file, f.name));
      const resp = await fetch(`${API}/api/v1/pdf/merge`, { method: 'POST', body: form });
      if (!resp.ok) throw new Error(await resp.text());
      const blob = await resp.blob();
      const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'merged.pdf'; a.click();
      toast.success('PDF מאוחד הורד בהצלחה');
    } catch (e) { toast.error('שגיאה: ' + e.message); }
    finally { setMerging(false); }
  }

  const previewFile = files.find(f => f.id === previewId);

  return (
    <div className="flex gap-4" style={{ minHeight: '70vh' }}>
      <div className="flex flex-col gap-3" style={{ width: '340px', flexShrink: 0 }}>
        <DropZone onFiles={addFiles} multiple color="red" />
        {files.length > 0 && (
          <div className="flex flex-col gap-1.5 overflow-y-auto" style={{ maxHeight: '55vh' }}>
            {files.map((f, i) => (
              <div key={f.id} draggable
                onDragStart={() => setDraggingId(f.id)}
                onDragOver={e => { e.preventDefault(); dragOverId.current = f.id; }}
                onDrop={onDrop}
                onClick={() => setPreviewId(f.id)}
                className={`flex items-center gap-2 rounded-xl border px-3 py-2.5 cursor-pointer transition select-none
                  ${previewId === f.id ? 'border-red-400 bg-red-50 ring-1 ring-red-200' : 'border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50'}
                  ${draggingId === f.id ? 'opacity-40' : ''}`}
              >
                <GripVertical size={14} className="shrink-0 text-slate-300 cursor-grab" />
                <span className="shrink-0 w-5 text-center text-xs font-mono font-bold text-slate-400">{i + 1}</span>
                <div className="flex-1 min-w-0">
                  <p className="truncate text-xs font-semibold text-slate-800">{f.name}</p>
                  <p className="text-xs text-slate-400">{f.size} MB</p>
                </div>
                <div className="flex flex-col shrink-0">
                  <button onClick={e => { e.stopPropagation(); moveFile(f.id, -1); }} disabled={i === 0} className="text-slate-300 hover:text-slate-600 disabled:opacity-20"><ChevronUp size={13} /></button>
                  <button onClick={e => { e.stopPropagation(); moveFile(f.id, 1); }} disabled={i === files.length - 1} className="text-slate-300 hover:text-slate-600 disabled:opacity-20"><ChevronDown size={13} /></button>
                </div>
                <button onClick={e => { e.stopPropagation(); setPreviewId(previewId === f.id ? null : f.id); }} className="shrink-0 text-slate-300 hover:text-red-500 transition">
                  {previewId === f.id ? <EyeOff size={13} /> : <Eye size={13} />}
                </button>
                <button onClick={e => { e.stopPropagation(); removeFile(f.id); }} className="shrink-0 text-slate-300 hover:text-red-500 transition"><Trash2 size={13} /></button>
              </div>
            ))}
          </div>
        )}
        {files.length >= 2 && (
          <button onClick={handleMerge} disabled={merging}
            className="flex items-center justify-center gap-2 rounded-xl bg-red-600 py-3 text-sm font-bold text-white hover:bg-red-700 disabled:opacity-40 transition mt-auto">
            {merging ? <><Loader2 size={15} className="animate-spin" /> ממזג...</> : <><Download size={15} /> מזג {files.length} קבצים</>}
          </button>
        )}
      </div>
      <div className="flex-1 rounded-2xl border border-slate-200 bg-slate-50 overflow-hidden">
        {previewFile
          ? <iframe key={previewFile.id} src={previewFile.blobUrl} title={previewFile.name} className="w-full h-full" style={{ minHeight: '70vh' }} />
          : <div className="flex h-full items-center justify-center text-slate-400" style={{ minHeight: '70vh' }}>
              <div className="text-center"><FileText size={40} className="mx-auto mb-3 opacity-30" /><p className="text-sm">בחר קובץ לתצוגה מקדימה</p></div>
            </div>}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 2: Split  (thumbnail card + preview modal, extracted inline)
// ─────────────────────────────────────────────────────────────────────────────
function PageThumb({ src, pageNum, selected, onToggle, onPreview }) {
  return (
    <div className={`group relative flex flex-col items-center rounded-xl border-2 transition-all ${selected ? 'border-blue-500 bg-blue-50 shadow-md shadow-blue-200' : 'border-slate-200 bg-white hover:border-slate-300 opacity-40 grayscale-[30%]'}`}>
      <button onClick={() => onPreview(pageNum)} className="absolute top-2 left-2 z-10 rounded-lg bg-white/90 p-1.5 text-slate-500 opacity-0 group-hover:opacity-100 hover:bg-blue-50 hover:text-blue-600 shadow transition-all">
        <ZoomIn size={14} />
      </button>
      <button onClick={() => onToggle(pageNum)} className="cursor-pointer p-2 pb-0 w-full">
        <img src={src} alt={`עמוד ${pageNum}`} className="rounded-lg w-full" draggable={false} />
      </button>
      <button onClick={() => onToggle(pageNum)} className={`w-full flex items-center justify-center gap-1.5 py-2 text-xs font-bold cursor-pointer ${selected ? 'text-blue-600' : 'text-slate-400'}`}>
        {selected ? <CheckSquare size={13} /> : <Square size={13} />} עמוד {pageNum}
      </button>
    </div>
  );
}

function PreviewModal({ file, pageNum, totalPages, selected, onToggle, onClose, onNavigate }) {
  const [imgUrl, setImgUrl] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!file || !pageNum) return;
    let cancelled = false; setLoading(true); setImgUrl(null);
    (async () => {
      try {
        const form = new FormData(); form.append('file', file, file.name); form.append('page', pageNum);
        const resp = await fetch(`${API}/api/v1/pdf/page-image`, { method: 'POST', body: form });
        if (cancelled || !resp.ok) return;
        setImgUrl(URL.createObjectURL(await resp.blob()));
      } catch { /* ignore */ } finally { if (!cancelled) setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [file, pageNum]);

  useEffect(() => {
    function onKey(e) {
      if (e.key === 'Escape') onClose();
      else if (e.key === 'ArrowRight' && pageNum > 1) onNavigate(pageNum - 1);
      else if (e.key === 'ArrowLeft'  && pageNum < totalPages) onNavigate(pageNum + 1);
      else if (e.key === ' ') { e.preventDefault(); onToggle(pageNum); }
    }
    window.addEventListener('keydown', onKey); return () => window.removeEventListener('keydown', onKey);
  }, [pageNum, totalPages, onClose, onNavigate, onToggle]);

  const isSel = selected.has(pageNum);
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div className="relative flex flex-col items-center max-w-[90vw] max-h-[95vh]" onClick={e => e.stopPropagation()}>
        <div className="mb-3 flex items-center gap-3">
          <button onClick={() => pageNum < totalPages && onNavigate(pageNum + 1)} disabled={pageNum >= totalPages} className="rounded-full bg-white/20 p-2 text-white hover:bg-white/30 disabled:opacity-30 transition"><ChevronRight size={20} /></button>
          <div className="flex items-center gap-3 rounded-2xl bg-white/10 backdrop-blur-md px-5 py-2.5">
            <span className="text-white font-bold text-sm">עמוד {pageNum} מתוך {totalPages}</span>
            <button onClick={() => onToggle(pageNum)} className={`flex items-center gap-1.5 rounded-xl px-4 py-1.5 text-xs font-bold transition ${isSel ? 'bg-blue-500 text-white hover:bg-blue-600' : 'bg-white/20 text-white hover:bg-white/30'}`}>
              {isSel ? <CheckSquare size={13} /> : <Square size={13} />} {isSel ? 'נבחר' : 'לא נבחר'}
            </button>
          </div>
          <button onClick={() => pageNum > 1 && onNavigate(pageNum - 1)} disabled={pageNum <= 1} className="rounded-full bg-white/20 p-2 text-white hover:bg-white/30 disabled:opacity-30 transition"><ChevronLeft size={20} /></button>
          <button onClick={onClose} className="rounded-full bg-white/20 p-2 text-white hover:bg-red-500/80 transition mr-2"><X size={18} /></button>
        </div>
        <div className="overflow-auto rounded-2xl shadow-2xl bg-white" style={{ maxHeight: 'calc(95vh - 70px)' }}>
          {loading ? <div className="flex items-center justify-center w-[600px] h-[800px] text-slate-400"><Loader2 size={32} className="animate-spin" /></div>
            : imgUrl && <img src={imgUrl} alt={`עמוד ${pageNum}`} className="block max-w-full" />}
        </div>
        <div className="mt-2 text-white/50 text-[10px] flex gap-4"><span>← → ניווט</span><span>רווח = סימון</span><span>ESC = סגירה</span></div>
      </div>
    </div>
  );
}

function SplitTab() {
  const [file, setFile]               = useState(null);
  const [totalPages, setTotalPages]   = useState(null);
  const [thumbnails, setThumbnails]   = useState([]);
  const [loading, setLoading]         = useState(false);
  const [selected, setSelected]       = useState(new Set());
  const [splitting, setSplitting]     = useState(false);
  const [rangeStart, setRangeStart]   = useState('');
  const [rangeEnd, setRangeEnd]       = useState('');
  const [previewPage, setPreviewPage] = useState(null);

  async function loadFile(f) {
    if (!f || f.type !== 'application/pdf') { toast.error('בחר קובץ PDF בלבד'); return; }
    setFile({ file: f, name: f.name, size: (f.size / 1024 / 1024).toFixed(2) });
    setThumbnails([]); setSelected(new Set()); setTotalPages(null); setLoading(true);
    try {
      const form = new FormData(); form.append('file', f, f.name);
      const resp = await fetch(`${API}/api/v1/pdf/thumbnails`, { method: 'POST', body: form });
      if (!resp.ok) throw new Error(await resp.text());
      const data = await resp.json();
      setTotalPages(data.pages); setThumbnails(data.thumbnails);
      setSelected(new Set(Array.from({ length: data.pages }, (_, i) => i + 1)));
    } catch (e) { toast.error('לא ניתן לקרוא את הקובץ: ' + e.message); }
    finally { setLoading(false); }
  }

  const onDropZone = useCallback((list) => { if (list[0]) loadFile(list[0]); }, []);
  function togglePage(n) { setSelected(prev => { const s = new Set(prev); s.has(n) ? s.delete(n) : s.add(n); return s; }); }
  function selectAll()   { if (totalPages) setSelected(new Set(Array.from({ length: totalPages }, (_, i) => i + 1))); }
  function selectNone()  { setSelected(new Set()); }
  function invertSel()   { if (!totalPages) return; setSelected(prev => { const s = new Set(); for (let i = 1; i <= totalPages; i++) if (!prev.has(i)) s.add(i); return s; }); }
  function selectRange() {
    const s = parseInt(rangeStart, 10), e = parseInt(rangeEnd, 10);
    if (!s || !e || s < 1 || e > totalPages || s > e) { toast.error(`הזן טווח תקין (1–${totalPages})`); return; }
    const n = new Set(); for (let i = s; i <= e; i++) n.add(i); setSelected(n);
  }

  async function handleSplit() {
    if (!file) { toast.error('העלה קובץ PDF קודם'); return; }
    if (selected.size === 0) { toast.error('בחר לפחות עמוד אחד'); return; }
    setSplitting(true);
    try {
      const form = new FormData(); form.append('file', file.file, file.name);
      form.append('pages', [...selected].sort((a, b) => a - b).join(','));
      const resp = await fetch(`${API}/api/v1/pdf/split`, { method: 'POST', body: form });
      if (!resp.ok) { const err = await resp.json().catch(() => ({ detail: resp.statusText })); throw new Error(err.detail ?? resp.statusText); }
      const blob = await resp.blob(); const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = `${file.name.replace(/\.pdf$/i, '')}_${selected.size}_pages.pdf`; a.click();
      URL.revokeObjectURL(url); toast.success(`${selected.size} עמודים הורדו בהצלחה`);
    } catch (e) { toast.error('שגיאה: ' + e.message); }
    finally { setSplitting(false); }
  }

  if (!file) return <DropZone onFiles={onDropZone} color="blue" />;

  return (
    <>
      <div className="mb-4 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm flex items-center gap-4 flex-wrap">
        <div className="flex items-center gap-3 flex-1 min-w-0">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-blue-50 text-blue-500"><FileText size={20} /></div>
          <div className="min-w-0">
            <div className="truncate text-sm font-semibold text-slate-800">{file.name}</div>
            <div className="mt-0.5 flex gap-3 text-xs text-slate-400">
              <span>{file.size} MB</span>
              {loading ? <span className="flex items-center gap-1"><Loader2 size={11} className="animate-spin" /> טוען...</span>
                : totalPages != null && <span>{totalPages.toLocaleString()} עמודים</span>}
            </div>
          </div>
        </div>
        {totalPages && (
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-bold text-blue-600 bg-blue-50 rounded-lg px-3 py-1.5">{selected.size} / {totalPages} נבחרו</span>
            <button onClick={selectAll}  className="rounded-lg bg-slate-100 px-3 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-200 transition">בחר הכל</button>
            <button onClick={selectNone} className="rounded-lg bg-slate-100 px-3 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-200 transition">נקה הכל</button>
            <button onClick={invertSel}  className="rounded-lg bg-slate-100 px-3 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-200 transition">הפוך</button>
            <div className="flex items-center gap-1.5 mr-2">
              <input type="number" min="1" max={totalPages} value={rangeStart} onChange={e => setRangeStart(e.target.value)} placeholder="מ-"
                className="w-16 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1.5 text-xs text-center font-mono outline-none focus:border-slate-400" />
              <span className="text-xs text-slate-400">–</span>
              <input type="number" min={rangeStart || 1} max={totalPages} value={rangeEnd} onChange={e => setRangeEnd(e.target.value)} placeholder="עד"
                className="w-16 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1.5 text-xs text-center font-mono outline-none focus:border-slate-400" />
              <button onClick={selectRange} className="rounded-lg bg-blue-100 px-3 py-1.5 text-xs font-semibold text-blue-700 hover:bg-blue-200 transition">טווח</button>
            </div>
          </div>
        )}
        <button onClick={() => { setFile(null); setTotalPages(null); setThumbnails([]); setSelected(new Set()); }} className="shrink-0 rounded-lg p-2 text-slate-400 hover:bg-red-50 hover:text-red-500 transition"><X size={16} /></button>
      </div>

      {loading
        ? <div className="flex flex-col items-center justify-center py-20 text-slate-400 gap-3"><Loader2 size={28} className="animate-spin" /><span className="text-sm">מייצר תמונות ממוזערות...</span></div>
        : thumbnails.length > 0 && (
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-4 mb-6">
            {thumbnails.map((b64, i) => (
              <PageThumb key={i} src={`data:image/jpeg;base64,${b64}`} pageNum={i + 1}
                selected={selected.has(i + 1)} onToggle={togglePage} onPreview={setPreviewPage} />
            ))}
          </div>
        )}

      <div className="sticky bottom-4 flex justify-center">
        <button onClick={handleSplit} disabled={!file || splitting || selected.size === 0}
          className="flex items-center gap-2 rounded-2xl bg-slate-900 px-8 py-3.5 text-sm font-bold text-white shadow-lg hover:bg-slate-700 transition disabled:opacity-40 disabled:cursor-not-allowed">
          {splitting ? <><Loader2 size={16} className="animate-spin" /> חותך...</> : <><Download size={16} /> הורד {selected.size} עמודים</>}
        </button>
      </div>

      {previewPage && file && (
        <PreviewModal file={file.file} pageNum={previewPage} totalPages={totalPages}
          selected={selected} onToggle={togglePage} onClose={() => setPreviewPage(null)} onNavigate={setPreviewPage} />
      )}
    </>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 3: OCR
// ─────────────────────────────────────────────────────────────────────────────
function OcrTab() {
  const [file,    setFile]    = useState(null);
  const [lang,    setLang]    = useState('heb+eng');
  const [dpi,     setDpi]     = useState(300);
  const [busy,    setBusy]    = useState(false);
  const [showAdv, setShowAdv] = useState(false);

  const LANG_PRESETS = [
    { label: 'עברית + אנגלית', value: 'heb+eng' },
    { label: 'עברית בלבד',     value: 'heb'     },
    { label: 'אנגלית בלבד',    value: 'eng'     },
    { label: 'ערבית + עברית',  value: 'ara+heb' },
  ];

  function loadFile(list) {
    const f = list[0];
    if (!f || f.type !== 'application/pdf') { toast.error('בחר קובץ PDF בלבד'); return; }
    setFile({ file: f, name: f.name, size: (f.size / 1024 / 1024).toFixed(2) });
  }

  async function handleOcr() {
    if (!file) { toast.error('בחר קובץ קודם'); return; }
    setBusy(true);
    try {
      const form = new FormData();
      form.append('file', file.file, file.name);
      form.append('lang', lang);
      form.append('dpi',  dpi);
      const resp = await fetch(`${API}/api/v1/pdf/ocr`, { method: 'POST', body: form });
      if (!resp.ok) {
        const e = await resp.json().catch(() => ({ detail: resp.statusText }));
        throw new Error(e.detail ?? resp.statusText);
      }
      const blob = await resp.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = file.name.replace(/\.pdf$/i, '') + '_ocr.txt';
      a.click();
      URL.revokeObjectURL(url);
      toast.success('OCR הושלם — הקובץ הורד');
    } catch (e) {
      toast.error('שגיאה: ' + e.message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4 max-w-2xl">

      <div className="rounded-xl border border-purple-100 bg-purple-50 px-4 py-3 text-sm text-purple-800">
        <strong>מה זה עושה?</strong> סורק כל עמוד ב-PDF, ממיר לתמונה, ומחלץ טקסט (OCR).
        מקבלים קובץ <code className="font-mono bg-purple-100 px-1 rounded">.txt</code> — שימושי לקריאה ע"י בינה מלאכותית.
        <br /><span className="text-xs text-purple-600 mt-1 block">⚠️ תהליך ארוך — ~5 שניות לעמוד. הדפדפן ישאר "תפוס" עד הסיום.</span>
      </div>

      {!file
        ? <DropZone onFiles={loadFile} color="purple" />
        : (
          <div className="flex items-center gap-3 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-purple-50 text-purple-500"><ScanText size={20} /></div>
            <div className="flex-1 min-w-0">
              <p className="truncate text-sm font-semibold text-slate-800">{file.name}</p>
              <p className="text-xs text-slate-400">{file.size} MB</p>
            </div>
            <button onClick={() => setFile(null)} className="rounded-lg p-2 text-slate-400 hover:bg-red-50 hover:text-red-500 transition"><X size={16} /></button>
          </div>
        )}

      <div>
        <label className="mb-2 block text-xs font-bold text-slate-500 uppercase tracking-widest">שפה</label>
        <div className="flex flex-wrap gap-2">
          {LANG_PRESETS.map(p => (
            <button key={p.value} onClick={() => setLang(p.value)}
              className={`rounded-xl border px-4 py-2 text-sm font-semibold transition ${lang === p.value ? 'border-purple-500 bg-purple-50 text-purple-700' : 'border-slate-200 bg-white text-slate-600 hover:border-slate-300'}`}>
              {p.label}
            </button>
          ))}
        </div>
      </div>

      <button onClick={() => setShowAdv(v => !v)} className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-600 transition">
        <Settings2 size={13} /> הגדרות מתקדמות {showAdv ? '▲' : '▼'}
      </button>
      {showAdv && (
        <div className="rounded-xl border border-slate-200 bg-white p-4 space-y-3">
          <div>
            <label className="mb-1 block text-xs font-semibold text-slate-500">DPI — {dpi}</label>
            <input type="range" min={150} max={600} step={50} value={dpi} onChange={e => setDpi(Number(e.target.value))} className="w-full accent-purple-600" />
            <p className="text-xs text-slate-400 mt-1">200 = מהיר | 300 = מאוזן | 400+ = דיוק גבוה (אטי)</p>
          </div>
          <div>
            <label className="mb-1 block text-xs font-semibold text-slate-500">קוד שפה מותאם</label>
            <input type="text" value={lang} onChange={e => setLang(e.target.value)} dir="ltr" placeholder="heb+eng"
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-3 py-2 font-mono text-sm focus:border-purple-400 focus:outline-none" />
          </div>
        </div>
      )}

      <button onClick={handleOcr} disabled={!file || busy}
        className="flex items-center gap-2 rounded-xl bg-purple-700 px-6 py-3 text-sm font-bold text-white hover:bg-purple-800 disabled:opacity-40 transition">
        {busy
          ? <><Loader2 size={15} className="animate-spin" /> מבצע OCR — אנא המתן...</>
          : <><ScanText size={15} /> הפעל OCR והורד טקסט</>}
      </button>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────
const TABS = [
  { id: 'merge', label: 'איחוד PDF',   icon: FileText,  color: 'red'    },
  { id: 'split', label: 'חיתוך עמודים', icon: Scissors,  color: 'blue'   },
  { id: 'ocr',   label: 'OCR — טקסט מתמונה', icon: ScanText,  color: 'purple' },
];

const TAB_HEADER_COLOR = {
  red:    'bg-red-600',
  blue:   'bg-blue-600',
  purple: 'bg-purple-700',
};

const TAB_ACTIVE = {
  red:    'border-red-500 text-red-700 bg-red-50',
  blue:   'border-blue-500 text-blue-700 bg-blue-50',
  purple: 'border-purple-500 text-purple-700 bg-purple-50',
};

export default function PdfPage() {
  const [tab, setTab] = useState('merge');
  const active = TABS.find(t => t.id === tab);

  return (
    <div className="mx-auto max-w-7xl px-4 pt-20 pb-16" dir="rtl">

      {/* Header */}
      <div className="mb-6 flex items-center gap-3 pt-4">
        <div className={`rounded-xl ${TAB_HEADER_COLOR[active.color]} p-3 text-white`}>
          <active.icon size={22} />
        </div>
        <div>
          <h1 className="text-2xl font-black text-slate-900">כלי PDF</h1>
          <p className="text-sm text-slate-500">איחוד · חיתוך · זיהוי טקסט (OCR)</p>
        </div>
      </div>

      {/* Tabs */}
      <div className="mb-6 flex gap-1 rounded-2xl border border-slate-200 bg-slate-50 p-1 w-fit">
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className={`flex items-center gap-2 rounded-xl border px-4 py-2 text-sm font-semibold transition ${
              tab === t.id ? TAB_ACTIVE[t.color] : 'border-transparent text-slate-500 hover:text-slate-800'
            }`}>
            <t.icon size={15} /> {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'merge'  && <MergeTab />}
      {tab === 'split'  && <SplitTab />}
      {tab === 'ocr'    && <OcrTab />}
    </div>
  );
}
