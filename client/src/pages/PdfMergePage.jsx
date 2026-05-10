import { useState, useRef, useCallback } from 'react';
import { FileText, Upload, Trash2, GripVertical, Download, Loader2, ChevronUp, ChevronDown, Eye, EyeOff } from 'lucide-react';
import toast from 'react-hot-toast';

const API = 'http://localhost:8000';

export default function PdfMergePage() {
  const [files, setFiles]           = useState([]);   // [{id, file, blobUrl, name, size}]
  const [previewId, setPreviewId]   = useState(null);
  const [merging, setMerging]       = useState(false);
  const [draggingId, setDraggingId] = useState(null);
  const dragOverId = useRef(null);
  const inputRef   = useRef(null);

  // ── File helpers ────────────────────────────────────────────────────────────
  function addFiles(newFileList) {
    const added = Array.from(newFileList)
      .filter(f => f.type === 'application/pdf')
      .map(f => ({
        id:      crypto.randomUUID(),
        file:    f,
        blobUrl: URL.createObjectURL(f),
        name:    f.name,
        size:    (f.size / 1024 / 1024).toFixed(2),
      }));
    if (!added.length) { toast.error('בחר קבצי PDF בלבד'); return; }
    setFiles(prev => [...prev, ...added]);
    if (!previewId && added.length) setPreviewId(added[0].id);
  }

  function removeFile(id) {
    setFiles(prev => {
      const next = prev.filter(f => f.id !== id);
      if (previewId === id) setPreviewId(next[0]?.id ?? null);
      return next;
    });
  }

  function moveFile(id, dir) {
    setFiles(prev => {
      const idx  = prev.findIndex(f => f.id === id);
      const next = [...prev];
      const swap = idx + dir;
      if (swap < 0 || swap >= next.length) return prev;
      [next[idx], next[swap]] = [next[swap], next[idx]];
      return next;
    });
  }

  // ── Drag-and-drop reorder ───────────────────────────────────────────────────
  function onDragStart(id) { setDraggingId(id); }
  function onDragOver(e, id) { e.preventDefault(); dragOverId.current = id; }
  function onDrop() {
    if (!draggingId || !dragOverId.current || draggingId === dragOverId.current) {
      setDraggingId(null); return;
    }
    setFiles(prev => {
      const next    = [...prev];
      const fromIdx = next.findIndex(f => f.id === draggingId);
      const toIdx   = next.findIndex(f => f.id === dragOverId.current);
      const [item]  = next.splice(fromIdx, 1);
      next.splice(toIdx, 0, item);
      return next;
    });
    setDraggingId(null);
    dragOverId.current = null;
  }

  // ── Drop-zone for uploading ─────────────────────────────────────────────────
  const onDropZone = useCallback((e) => {
    e.preventDefault();
    addFiles(e.dataTransfer.files);
  }, []);

  // ── Merge ───────────────────────────────────────────────────────────────────
  async function handleMerge() {
    if (files.length < 2) { toast.error('הוסף לפחות 2 קבצים'); return; }
    setMerging(true);
    try {
      const form = new FormData();
      files.forEach(f => form.append('files', f.file, f.name));
      const resp = await fetch(`${API}/api/v1/pdf/merge`, { method: 'POST', body: form });
      if (!resp.ok) throw new Error(await resp.text());
      const blob = await resp.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = 'merged.pdf';
      a.click();
      URL.revokeObjectURL(url);
      toast.success('PDF מאוחד הורד בהצלחה');
    } catch (e) {
      toast.error('שגיאה: ' + e.message);
    } finally {
      setMerging(false);
    }
  }

  const previewFile = files.find(f => f.id === previewId);

  return (
    <div className="mx-auto max-w-6xl px-4 pt-20 pb-16" dir="rtl">

      {/* Header */}
      <div className="mb-6 flex items-center gap-3 pt-4">
        <div className="rounded-xl bg-red-600 p-3 text-white">
          <FileText size={22} />
        </div>
        <div>
          <h1 className="text-2xl font-black text-slate-900">איחוד PDF</h1>
          <p className="text-sm text-slate-500">גרור קבצים, סדר אותם, וקבל PDF אחד מאוחד</p>
        </div>
      </div>

      <div className="flex gap-4" style={{ minHeight: '70vh' }}>

        {/* ── Left: file list ── */}
        <div className="flex flex-col gap-3" style={{ width: '340px', flexShrink: 0 }}>

          {/* Drop zone */}
          <div
            className="flex flex-col items-center justify-center gap-2 rounded-2xl border-2 border-dashed border-slate-300 bg-slate-50 px-4 py-6 cursor-pointer hover:border-red-400 hover:bg-red-50 transition"
            onClick={() => inputRef.current?.click()}
            onDragOver={e => e.preventDefault()}
            onDrop={onDropZone}
          >
            <Upload size={22} className="text-slate-400" />
            <span className="text-sm font-semibold text-slate-500">גרור PDF לכאן או לחץ לבחירה</span>
            <input
              ref={inputRef}
              type="file"
              accept="application/pdf"
              multiple
              className="hidden"
              onChange={e => addFiles(e.target.files)}
            />
          </div>

          {/* Files list */}
          {files.length > 0 && (
            <div className="flex flex-col gap-1.5 overflow-y-auto" style={{ maxHeight: '55vh' }}>
              {files.map((f, i) => (
                <div
                  key={f.id}
                  draggable
                  onDragStart={() => onDragStart(f.id)}
                  onDragOver={e => onDragOver(e, f.id)}
                  onDrop={onDrop}
                  onClick={() => setPreviewId(f.id)}
                  className={`flex items-center gap-2 rounded-xl border px-3 py-2.5 cursor-pointer transition select-none
                    ${previewId === f.id ? 'border-red-400 bg-red-50 ring-1 ring-red-200' : 'border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50'}
                    ${draggingId === f.id ? 'opacity-40' : 'opacity-100'}`}
                >
                  {/* Drag handle */}
                  <GripVertical size={14} className="shrink-0 text-slate-300 cursor-grab" />

                  {/* Index */}
                  <span className="shrink-0 w-5 text-center text-xs font-mono font-bold text-slate-400">{i + 1}</span>

                  {/* Name + size */}
                  <div className="flex-1 min-w-0">
                    <p className="truncate text-xs font-semibold text-slate-800" title={f.name}>{f.name}</p>
                    <p className="text-xs text-slate-400">{f.size} MB</p>
                  </div>

                  {/* Up / Down */}
                  <div className="flex flex-col shrink-0">
                    <button onClick={e => { e.stopPropagation(); moveFile(f.id, -1); }}
                      className="text-slate-300 hover:text-slate-600 disabled:opacity-20"
                      disabled={i === 0}><ChevronUp size={13} /></button>
                    <button onClick={e => { e.stopPropagation(); moveFile(f.id, 1); }}
                      className="text-slate-300 hover:text-slate-600 disabled:opacity-20"
                      disabled={i === files.length - 1}><ChevronDown size={13} /></button>
                  </div>

                  {/* Preview toggle */}
                  <button
                    onClick={e => { e.stopPropagation(); setPreviewId(previewId === f.id ? null : f.id); }}
                    className="shrink-0 text-slate-300 hover:text-red-500 transition"
                    title="תצוגה מקדימה"
                  >
                    {previewId === f.id ? <EyeOff size={13} /> : <Eye size={13} />}
                  </button>

                  {/* Delete */}
                  <button
                    onClick={e => { e.stopPropagation(); removeFile(f.id); }}
                    className="shrink-0 text-slate-300 hover:text-red-500 transition"
                    title="הסר"
                  >
                    <Trash2 size={13} />
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Merge button */}
          {files.length >= 2 && (
            <button
              onClick={handleMerge}
              disabled={merging}
              className="flex items-center justify-center gap-2 rounded-xl bg-red-600 py-3 text-sm font-bold text-white hover:bg-red-700 disabled:opacity-40 transition mt-auto"
            >
              {merging
                ? <><Loader2 size={15} className="animate-spin" /> ממזג...</>
                : <><Download size={15} /> מזג {files.length} קבצים</>}
            </button>
          )}
        </div>

        {/* ── Right: preview ── */}
        <div className="flex-1 rounded-2xl border border-slate-200 bg-slate-50 overflow-hidden">
          {previewFile ? (
            <iframe
              key={previewFile.id}
              src={previewFile.blobUrl}
              title={previewFile.name}
              className="w-full h-full"
              style={{ minHeight: '70vh' }}
            />
          ) : (
            <div className="flex h-full items-center justify-center text-slate-400" style={{ minHeight: '70vh' }}>
              <div className="text-center">
                <FileText size={40} className="mx-auto mb-3 opacity-30" />
                <p className="text-sm">בחר קובץ לתצוגה מקדימה</p>
              </div>
            </div>
          )}
        </div>

      </div>
    </div>
  );
}
