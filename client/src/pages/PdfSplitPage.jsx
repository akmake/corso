import { useState, useRef, useCallback, useEffect } from 'react';
import { Scissors, Upload, FileText, Download, Loader2, X, CheckSquare, Square, ZoomIn, ChevronLeft, ChevronRight } from 'lucide-react';
import toast from 'react-hot-toast';

const API = 'http://localhost:8000';

// ── Thumbnail card ────────────────────────────────────────────────────────────
function PageThumb({ src, pageNum, selected, onToggle, onPreview }) {
  return (
    <div className={`group relative flex flex-col items-center rounded-xl border-2 transition-all duration-150 ${
      selected
        ? 'border-blue-500 bg-blue-50 shadow-md shadow-blue-200'
        : 'border-slate-200 bg-white hover:border-slate-300 opacity-40 grayscale-[30%]'
    }`}>
      <button
        onClick={() => onPreview(pageNum)}
        className="absolute top-2 left-2 z-10 rounded-lg bg-white/90 p-1.5 text-slate-500 opacity-0 group-hover:opacity-100 hover:bg-blue-50 hover:text-blue-600 shadow transition-all"
        title="תצוגה מקדימה"
      >
        <ZoomIn size={14} />
      </button>
      <button onClick={() => onToggle(pageNum)} className="cursor-pointer p-2 pb-0 w-full">
        <img src={src} alt={`עמוד ${pageNum}`} className="rounded-lg w-full" draggable={false} />
      </button>
      <button
        onClick={() => onToggle(pageNum)}
        className={`w-full flex items-center justify-center gap-1.5 py-2 text-xs font-bold cursor-pointer ${
          selected ? 'text-blue-600' : 'text-slate-400'
        }`}
      >
        {selected ? <CheckSquare size={13} /> : <Square size={13} />}
        עמוד {pageNum}
      </button>
    </div>
  );
}

// ── Full preview modal ────────────────────────────────────────────────────────
function PreviewModal({ file, pageNum, totalPages, selected, onToggle, onClose, onNavigate }) {
  const [imgUrl, setImgUrl]   = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!file || !pageNum) return;
    let cancelled = false;
    setLoading(true);
    setImgUrl(null);
    (async () => {
      try {
        const form = new FormData();
        form.append('file', file, file.name);
        form.append('page', pageNum);
        const resp = await fetch(`${API}/api/v1/pdf/page-image`, { method: 'POST', body: form });
        if (cancelled) return;
        if (!resp.ok) throw new Error('failed');
        const blob = await resp.blob();
        setImgUrl(URL.createObjectURL(blob));
      } catch { /* ignore */ }
      finally { if (!cancelled) setLoading(false); }
    })();
    return () => { cancelled = true; };
  }, [file, pageNum]);

  useEffect(() => {
    function handleKey(e) {
      if (e.key === 'Escape') onClose();
      else if (e.key === 'ArrowRight' && pageNum > 1) onNavigate(pageNum - 1);
      else if (e.key === 'ArrowLeft' && pageNum < totalPages) onNavigate(pageNum + 1);
      else if (e.key === ' ') { e.preventDefault(); onToggle(pageNum); }
    }
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [pageNum, totalPages, onClose, onNavigate, onToggle]);

  const isSel = selected.has(pageNum);

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm" onClick={onClose}>
      <div className="relative flex flex-col items-center max-w-[90vw] max-h-[95vh]" onClick={(e) => e.stopPropagation()}>
        <div className="mb-3 flex items-center gap-3">
          <button onClick={() => pageNum < totalPages && onNavigate(pageNum + 1)} disabled={pageNum >= totalPages}
            className="rounded-full bg-white/20 p-2 text-white hover:bg-white/30 disabled:opacity-30 transition-colors">
            <ChevronRight size={20} />
          </button>
          <div className="flex items-center gap-3 rounded-2xl bg-white/10 backdrop-blur-md px-5 py-2.5">
            <span className="text-white font-bold text-sm">עמוד {pageNum} מתוך {totalPages}</span>
            <button onClick={() => onToggle(pageNum)}
              className={`flex items-center gap-1.5 rounded-xl px-4 py-1.5 text-xs font-bold transition-colors ${
                isSel ? 'bg-blue-500 text-white hover:bg-blue-600' : 'bg-white/20 text-white hover:bg-white/30'
              }`}>
              {isSel ? <CheckSquare size={13} /> : <Square size={13} />}
              {isSel ? 'נבחר' : 'לא נבחר'}
            </button>
          </div>
          <button onClick={() => pageNum > 1 && onNavigate(pageNum - 1)} disabled={pageNum <= 1}
            className="rounded-full bg-white/20 p-2 text-white hover:bg-white/30 disabled:opacity-30 transition-colors">
            <ChevronLeft size={20} />
          </button>
          <button onClick={onClose} className="rounded-full bg-white/20 p-2 text-white hover:bg-red-500/80 transition-colors mr-2">
            <X size={18} />
          </button>
        </div>
        <div className="overflow-auto rounded-2xl shadow-2xl bg-white" style={{ maxHeight: 'calc(95vh - 70px)' }}>
          {loading
            ? <div className="flex items-center justify-center w-[600px] h-[800px] text-slate-400"><Loader2 size={32} className="animate-spin" /></div>
            : imgUrl && <img src={imgUrl} alt={`עמוד ${pageNum}`} className="block max-w-full" />
          }
        </div>
        <div className="mt-2 text-white/50 text-[10px] flex gap-4">
          <span>← → ניווט</span>
          <span>רווח = סימון</span>
          <span>ESC = סגירה</span>
        </div>
      </div>
    </div>
  );
}

export default function PdfSplitPage() {
  const [file, setFile]               = useState(null);
  const [totalPages, setTotalPages]   = useState(null);
  const [thumbnails, setThumbnails]   = useState([]);
  const [loading, setLoading]         = useState(false);
  const [selected, setSelected]       = useState(new Set());
  const [splitting, setSplitting]     = useState(false);
  const [rangeStart, setRangeStart]   = useState('');
  const [rangeEnd, setRangeEnd]       = useState('');
  const [previewPage, setPreviewPage] = useState(null);
  const inputRef = useRef(null);

  async function loadFile(f) {
    if (!f || f.type !== 'application/pdf') { toast.error('בחר קובץ PDF בלבד'); return; }
    setFile({ file: f, name: f.name, size: (f.size / 1024 / 1024).toFixed(2) });
    setThumbnails([]);
    setSelected(new Set());
    setTotalPages(null);
    setLoading(true);
    try {
      const form = new FormData();
      form.append('file', f, f.name);
      const resp = await fetch(`${API}/api/v1/pdf/thumbnails`, { method: 'POST', body: form });
      if (!resp.ok) throw new Error(await resp.text());
      const data = await resp.json();
      setTotalPages(data.pages);
      setThumbnails(data.thumbnails);
      setSelected(new Set(Array.from({ length: data.pages }, (_, i) => i + 1)));
    } catch (e) {
      toast.error('לא ניתן לקרוא את הקובץ: ' + e.message);
    } finally {
      setLoading(false);
    }
  }

  function removeFile() {
    setFile(null); setTotalPages(null); setThumbnails([]); setSelected(new Set()); setPreviewPage(null);
  }

  const onDropZone = useCallback((e) => {
    e.preventDefault();
    if (e.dataTransfer.files[0]) loadFile(e.dataTransfer.files[0]);
  }, []);

  function togglePage(num) {
    setSelected(prev => { const n = new Set(prev); n.has(num) ? n.delete(num) : n.add(num); return n; });
  }
  function selectAll()  { if (totalPages) setSelected(new Set(Array.from({ length: totalPages }, (_, i) => i + 1))); }
  function selectNone() { setSelected(new Set()); }
  function invertSelection() {
    if (!totalPages) return;
    setSelected(prev => { const n = new Set(); for (let i = 1; i <= totalPages; i++) { if (!prev.has(i)) n.add(i); } return n; });
  }
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
      const form = new FormData();
      form.append('file', file.file, file.name);
      form.append('pages', [...selected].sort((a, b) => a - b).join(','));
      const resp = await fetch(`${API}/api/v1/pdf/split`, { method: 'POST', body: form });
      if (!resp.ok) { const err = await resp.json().catch(() => ({ detail: resp.statusText })); throw new Error(err.detail ?? resp.statusText); }
      const blob = await resp.blob();
      const url  = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url;
      a.download = `${file.name.replace(/\.pdf$/i, '')}_${selected.size}_pages.pdf`;
      a.click(); URL.revokeObjectURL(url);
      toast.success(`${selected.size} עמודים הורדו בהצלחה`);
    } catch (e) { toast.error('שגיאה: ' + e.message); }
    finally { setSplitting(false); }
  }

  return (
    <div className="mx-auto max-w-7xl px-4 py-8" dir="rtl">
      <div className="mb-6">
        <h1 className="text-2xl font-black text-slate-900 flex items-center gap-2">
          <Scissors size={24} /> חיתוך עמודים מ-PDF
        </h1>
        <p className="mt-1 text-sm text-slate-500">העלה קובץ PDF, סמן את העמודים שברצונך לשמור והורד קובץ חדש</p>
      </div>

      {!file ? (
        <div onDragOver={(e) => e.preventDefault()} onDrop={onDropZone} onClick={() => inputRef.current?.click()}
          className="flex flex-col items-center justify-center gap-3 rounded-2xl border-2 border-dashed border-slate-200 bg-slate-50 p-16 text-slate-400 cursor-pointer hover:border-slate-400 hover:bg-slate-100 transition-colors">
          <Upload size={40} strokeWidth={1.5} />
          <div className="text-sm font-medium">גרור קובץ PDF לכאן או לחץ לבחירה</div>
          <input ref={inputRef} type="file" accept="application/pdf" className="hidden"
            onChange={(e) => { if (e.target.files[0]) loadFile(e.target.files[0]); }} />
        </div>
      ) : (
        <>
          {/* Info bar */}
          <div className="mb-4 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-3 flex-1 min-w-0">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-red-50 text-red-500"><FileText size={20} /></div>
              <div className="min-w-0">
                <div className="truncate text-sm font-semibold text-slate-800">{file.name}</div>
                <div className="mt-0.5 flex gap-3 text-xs text-slate-400">
                  <span>{file.size} MB</span>
                  {loading ? <span className="flex items-center gap-1"><Loader2 size={11} className="animate-spin" /> מייצר תמונות...</span>
                    : totalPages != null && <span>{totalPages.toLocaleString()} עמודים</span>}
                </div>
              </div>
            </div>
            {totalPages && (
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs font-bold text-blue-600 bg-blue-50 rounded-lg px-3 py-1.5">{selected.size} / {totalPages} נבחרו</span>
                <button onClick={selectAll} className="rounded-lg bg-slate-100 px-3 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-200 transition-colors">בחר הכל</button>
                <button onClick={selectNone} className="rounded-lg bg-slate-100 px-3 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-200 transition-colors">נקה הכל</button>
                <button onClick={invertSelection} className="rounded-lg bg-slate-100 px-3 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-200 transition-colors">הפוך בחירה</button>
                <div className="flex items-center gap-1.5 mr-2">
                  <input type="number" min="1" max={totalPages} value={rangeStart} onChange={(e) => setRangeStart(e.target.value)} placeholder="מ-"
                    className="w-16 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1.5 text-xs text-center font-mono outline-none focus:border-slate-400" />
                  <span className="text-xs text-slate-400">–</span>
                  <input type="number" min={rangeStart || 1} max={totalPages} value={rangeEnd} onChange={(e) => setRangeEnd(e.target.value)} placeholder="עד"
                    className="w-16 rounded-lg border border-slate-200 bg-slate-50 px-2 py-1.5 text-xs text-center font-mono outline-none focus:border-slate-400" />
                  <button onClick={selectRange} className="rounded-lg bg-blue-100 px-3 py-1.5 text-xs font-semibold text-blue-700 hover:bg-blue-200 transition-colors">טווח</button>
                </div>
              </div>
            )}
            <button onClick={removeFile} className="shrink-0 rounded-lg p-2 text-slate-400 hover:bg-red-50 hover:text-red-500 transition-colors"><X size={16} /></button>
          </div>

          {/* Thumbnails grid */}
          {loading ? (
            <div className="flex flex-col items-center justify-center py-20 text-slate-400 gap-3">
              <Loader2 size={28} className="animate-spin" />
              <span className="text-sm font-medium">מייצר תמונות ממוזערות... זה ייקח כמה שניות</span>
            </div>
          ) : thumbnails.length > 0 && (
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-5 xl:grid-cols-6 gap-4 mb-6">
              {thumbnails.map((b64, i) => (
                <PageThumb
                  key={i}
                  src={`data:image/jpeg;base64,${b64}`}
                  pageNum={i + 1}
                  selected={selected.has(i + 1)}
                  onToggle={togglePage}
                  onPreview={setPreviewPage}
                />
              ))}
            </div>
          )}

          {/* Download */}
          <div className="sticky bottom-4 flex justify-center">
            <button onClick={handleSplit} disabled={!file || splitting || selected.size === 0}
              className="flex items-center gap-2 rounded-2xl bg-slate-900 px-8 py-3.5 text-sm font-bold text-white shadow-lg hover:bg-slate-700 transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
              {splitting ? <><Loader2 size={16} className="animate-spin" /> חותך...</> : <><Download size={16} /> הורד {selected.size} עמודים</>}
            </button>
          </div>
        </>
      )}

      {previewPage && file && (
        <PreviewModal file={file.file} pageNum={previewPage} totalPages={totalPages}
          selected={selected} onToggle={togglePage} onClose={() => setPreviewPage(null)} onNavigate={setPreviewPage} />
      )}
    </div>
  );
}
