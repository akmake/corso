import { useState, useRef, useEffect } from 'react';
import {
  BookOpen, Download, Package, Loader2, Terminal,
  RefreshCw, AlertCircle, FileText, Eye, EyeOff,
  LogIn, ChevronLeft, Save, Trash2, Zap,
} from 'lucide-react';

const STORAGE_KEY = 'openu_credentials';

// Combopage page IDs from course 10406 — extracted from scan logs.
// Each ID is a combopage/view.php?id=XXXXX page that contains a PDF.
// Using these skips the full browser scan — much faster.
const COURSE_10406_PAGE_IDS = [
  // יחידה 1
  6881642, 6881645, 6881648, 6881651, 6881672, 6881675, 6881678, 6881795,
  // יחידה 2
  6881656, 6881659, 6881662, 6881665, 6881668, 6881819,
  // יחידה 3
  6881615, 6881620, 6881623, 6881626, 6881629, 6881681, 6881632, 6881818,
  // יחידה 4
  6881686, 6881689, 6881692, 6881695, 6881698, 6881817,
  // יחידה 5
  6881704, 6881707, 6881710, 6881713, 6881716, 6881816,
  // יחידה 6
  6881721, 6881724, 6881727, 6881730, 6881823,
  // יחידה 7
  6881736, 6881739, 6881742, 6881745, 6881750, 6881753, 6881822,
  // יחידה 8
  6881757, 6881760, 6881763, 6881766, 6881769, 6881772, 6881776, 6881821,
  // יחידה 9
  6881780, 6881783, 6881786, 6881789, 6881792, 6881820,
  // יחידה 10
  6881801, 6881804, 6881807, 6881810, 6881813, 6881834, 6881832,
  // יחידה 11
  6881839, 6881854, 6881855, 6881856, 6881857, 6881858, 6881852,
  // יחידה 12
  6881897, 6881946, 6881947, 6881948, 6881949, 6881950, 6881951, 6881952, 6881953, 6881954, 6881909,
  // יחידה 13
  6881967, 6881970, 6881973, 6881975, 6881981,
];

// Book IDs from course 10406 — extracted from known logs
const COURSE_10406_BOOK_IDS = [
  // יחידה 2
  115782, 115783, 115784, 115785, 115786, 115835,
  // יחידה 3
  115772, 115773, 115774, 115775, 115776, 115790, 115777, 115834,
  // יחידה 4
  115791, 115792, 115793, 115794, 115795, 115833,
  // יחידה 5
  115796, 115797, 115798, 115799, 115800, 115801, 115832,
  // יחידה 6
  115802, 115803, 115804, 115805, 115806, 115839,
  // יחידה 7
  115807, 115808, 115809, 115810, 115811, 115812, 115813, 115838,
  // יחידה 8
  115814, 115815, 115816, 115817, 115818, 115819, 115820, 115837,
  // יחידה 9
  115821, 115822, 115823, 115824, 115825, 115836,
  // יחידה 10
  115827, 115828, 115829, 115830, 115831, 115841, 115840,
  // יחידה 11
  115842, 115844, 115845, 115846, 115847, 115848, 115843,
  // יחידה 12
  115857, 115875, 115876, 115877, 115878, 115879, 115880, 115881, 115882, 115883, 115858,
];
import axios from 'axios';
import toast from 'react-hot-toast';

const API = 'http://localhost:8000';
const client = axios.create({ baseURL: API });
const POLL_MS = 1500;

// ── Small helpers ─────────────────────────────────────────────────────────────

function ProgressLog({ lines, running }) {
  const ref = useRef(null);
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [lines]);
  if (!lines.length) return null;
  return (
    <div className="mt-4 rounded-2xl border border-slate-800 bg-slate-950 p-4">
      <div className="mb-2 flex items-center gap-2">
        <Terminal size={13} className="text-slate-400" />
        <span className="text-xs font-semibold uppercase tracking-widest text-slate-400">לוג</span>
        {running && <Loader2 size={11} className="animate-spin text-slate-500" />}
      </div>
      <div ref={ref} className="max-h-48 overflow-y-auto space-y-0.5" dir="ltr">
        {lines.map((line, i) => (
          <p key={i} className="font-mono text-xs text-green-400 break-all">{line}</p>
        ))}
      </div>
    </div>
  );
}

function ErrorBox({ msg }) {
  if (!msg) return null;
  return (
    <div className="mt-4 flex items-start gap-2 rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
      <AlertCircle size={16} className="mt-0.5 shrink-0" />
      <span>{msg}</span>
    </div>
  );
}

function FileRow({ file, courseFolder }) {
  const downloadUrl = `${API}/api/v1/openu/files/${encodeURIComponent(courseFolder)}/${encodeURIComponent(file.filename)}`;
  return (
    <div className="flex items-center gap-3 rounded-lg border border-slate-100 bg-white px-3 py-2 hover:bg-slate-50 transition">
      <FileText size={15} className="shrink-0 text-blue-500" />
      <p className="flex-1 min-w-0 truncate text-sm font-medium text-slate-800" dir="ltr">{file.filename}</p>
      <span className="shrink-0 text-xs text-slate-400">{file.size_mb} MB</span>
      <a
        href={downloadUrl}
        download={file.filename}
        className="shrink-0 rounded-lg border border-slate-200 p-1.5 text-slate-500 hover:bg-slate-100 transition"
        title="הורד"
      >
        <Download size={13} />
      </a>
    </div>
  );
}

// ── Hook: poll a job until done ───────────────────────────────────────────────
function useJobPoller(jobId, onDone, onFail) {
  const [progress, setProgress] = useState([]);
  const pollRef = useRef(null);

  useEffect(() => {
    if (!jobId) return;
    pollRef.current = setInterval(async () => {
      try {
        const { data } = await client.get(`/api/v1/jobs/${jobId}`);
        setProgress(data.progress || []);
        if (data.status === 'completed') {
          clearInterval(pollRef.current);
          onDone(data.result);
        } else if (data.status === 'failed') {
          clearInterval(pollRef.current);
          onFail(data.result);
        }
      } catch { /* ignore */ }
    }, POLL_MS);
    return () => clearInterval(pollRef.current);
  }, [jobId]);

  function reset() {
    clearInterval(pollRef.current);
    setProgress([]);
  }

  return { progress, reset };
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function OpenUPage() {
  // ── Step 1: login state ──────────────────────────────────────────────────
  const [username,  setUsername]  = useState('');
  const [password,  setPassword]  = useState('');
  const [idNumber,  setIdNumber]  = useState('');
  const [showPass,  setShowPass]  = useState(false);
  const [savedCreds, setSavedCreds] = useState(false);  // true = credentials saved

  // Load saved credentials on mount
  useEffect(() => {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const { username: u, password: pw, id_number: id } = JSON.parse(raw);
        if (u) setUsername(u);
        if (pw) setPassword(pw);
        if (id) setIdNumber(id);
        setSavedCreds(true);
      }
    } catch { /* ignore */ }
  }, []);
  const [loginJobId, setLoginJobId] = useState(null);
  const [loginBusy,  setLoginBusy]  = useState(false);
  const [loginError, setLoginError] = useState('');

  // ── Step 2: course selection ─────────────────────────────────────────────
  const [sessionId,      setSessionId]      = useState(null);
  const [courses,        setCourses]        = useState([]);
  const [selectedCourse, setSelectedCourse] = useState(null);

  // ── Step 2.5: sections scan ───────────────────────────────────────────────
  const [sectionsJobId, setSectionsJobId] = useState(null);
  const [sectionsBusy,  setSectionsBusy]  = useState(false);
  const [sections,      setSections]      = useState(null);
  const [sectionsError, setSectionsError] = useState('');

  // ── Step 2.5: unit nav items (pages inside a section) ────────────────────
  const [unitNavJobId,  setUnitNavJobId]  = useState(null);
  const [unitNavBusy,   setUnitNavBusy]   = useState(false);
  const [unitNav,       setUnitNav]       = useState(null);
  const [unitNavError,  setUnitNavError]  = useState('');

  // ── Step 2.7: single section file scan ────────────────────────────────────
  const [selectedSection,  setSelectedSection]  = useState(null);
  const [selectedNavItem,  setSelectedNavItem]  = useState(null);
  const [scanJobId,        setScanJobId]        = useState(null);
  const [scanBusy,         setScanBusy]         = useState(false);
  const [sectionFiles,     setSectionFiles]     = useState(null);
  const [scanError,        setScanError]        = useState('');

  // ── Step 2.8: bulk download selected units ────────────────────────────────
  const [checkedSections, setCheckedSections] = useState(new Set());
  const [dlUnitJobId,   setDlUnitJobId]   = useState(null);
  const [dlUnitBusy,    setDlUnitBusy]    = useState(false);
  const [dlUnitError,   setDlUnitError]   = useState('');
  const [dlUnitResult,  setDlUnitResult]  = useState(null);
  const [dlUnitSection, setDlUnitSection] = useState(null);

  // ── Step 3: download ──────────────────────────────────────────────────────
  const [dlJobId,    setDlJobId]    = useState(null);
  const [dlBusy,     setDlBusy]     = useState(false);
  const [dlError,    setDlError]    = useState('');
  const [dlResult,   setDlResult]   = useState(null);

  // ── Fast download by IDs ─────────────────────────────────────────────────
  const [fastIds,       setFastIds]       = useState('');
  const [fastFolder,    setFastFolder]    = useState('');
  const [fastJobId,     setFastJobId]     = useState(null);
  const [fastBusy,      setFastBusy]      = useState(false);
  const [fastError,     setFastError]     = useState('');
  const [fastResult,    setFastResult]    = useState(null);
  const [showFastPanel, setShowFastPanel] = useState(false);

  // ── Auto download by page IDs (one-click, no scanning) ───────────────────
  const [autoJobId,  setAutoJobId]  = useState(null);
  const [autoBusy,   setAutoBusy]   = useState(false);
  const [autoError,  setAutoError]  = useState('');
  const [autoResult, setAutoResult] = useState(null);

  // ── Pollers ──────────────────────────────────────────────────────────────
  const { progress: loginProgress, reset: resetLoginPoll } = useJobPoller(
    loginJobId,
    (result) => {
      setLoginBusy(false);
      if (result.error) {
        setLoginError(result.error);
        return;
      }
      setSessionId(result.session_id);
      setCourses(result.courses || []);
      if (!result.courses?.length) {
        setLoginError('לא נמצאו קורסים — בדוק שהפרטים נכונים');
      }
    },
    (result) => {
      setLoginBusy(false);
      setLoginError(result?.error || 'כניסה נכשלה');
    },
  );

  const { progress: sectionsProgress, reset: resetSectionsPoll } = useJobPoller(
    sectionsJobId,
    (result) => {
      setSectionsBusy(false);
      if (result.error) { setSectionsError(result.error); return; }
      setSections(result.sections || []);
      if (!result.sections?.length) {
        setSectionsError('לא נמצאו סקשנים — ייתכן שהקורס ריק או שהמבנה שונה');
      }
    },
    (result) => {
      setSectionsBusy(false);
      setSectionsError(result?.error || 'סריקה נכשלה');
    },
  );

  const { progress: unitNavProgress, reset: resetUnitNavPoll } = useJobPoller(
    unitNavJobId,
    (result) => {
      setUnitNavBusy(false);
      if (result.error) { setUnitNavError(result.error); return; }
      setUnitNav(result.nav_items || []);
    },
    (result) => {
      setUnitNavBusy(false);
      setUnitNavError(result?.error || 'טעינת ניווט נכשלה');
    },
  );

  const { progress: scanProgress, reset: resetScanPoll } = useJobPoller(
    scanJobId,
    (result) => {
      setScanBusy(false);
      if (result.error) { setScanError(result.error); return; }
      setSectionFiles(result.files || []);
    },
    (result) => {
      setScanBusy(false);
      setScanError(result?.error || 'סריקה נכשלה');
    },
  );

  const { progress: fastProgress, reset: resetFastPoll } = useJobPoller(
    fastJobId,
    (result) => {
      setFastBusy(false);
      setFastResult(result);
      if (result.error) { setFastError(result.error); return; }
      toast.success(`הושלם! ${result.total ?? 0} קבצים הורדו`);
    },
    (result) => {
      setFastBusy(false);
      setFastError(result?.error || 'הורדה נכשלה');
    },
  );

  const { progress: autoProgress, reset: resetAutoPoll } = useJobPoller(
    autoJobId,
    (result) => {
      setAutoBusy(false);
      setAutoResult(result);
      if (result.error) { setAutoError(result.error); return; }
      toast.success(`הושלם! ${result.total ?? 0} קבצים הורדו`);
    },
    (result) => {
      setAutoBusy(false);
      setAutoError(result?.error || 'הורדה נכשלה');
    },
  );

  const { progress: dlProgress, reset: resetDlPoll } = useJobPoller(
    dlJobId,
    (result) => {
      setDlBusy(false);
      setDlResult(result);
      toast.success(`הושלם! ${result.pdfs_downloaded ?? 0} PDF הורדו`);
    },
    (result) => {
      setDlBusy(false);
      setDlError(result?.error || 'הורדה נכשלה');
    },
  );

  const { progress: dlUnitProgress, reset: resetDlUnitPoll } = useJobPoller(
    dlUnitJobId,
    (result) => {
      setDlUnitBusy(false);
      setDlUnitResult(result);
      if (result.error) { setDlUnitError(result.error); return; }
      toast.success(`הורדה הסתיימה! ${result.total ?? 0} קבצים`);
    },
    (result) => {
      setDlUnitBusy(false);
      setDlUnitError(result?.error || 'הורדה נכשלה');
    },
  );

  // ── Actions ──────────────────────────────────────────────────────────────
  function handleSaveCreds() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({
      username, password, id_number: idNumber,
    }));
    setSavedCreds(true);
    toast.success('פרטי ההתחברות נשמרו');
  }

  function handleClearCreds() {
    localStorage.removeItem(STORAGE_KEY);
    setSavedCreds(false);
    setUsername('');
    setPassword('');
    setIdNumber('');
    toast.success('פרטים נמחקו');
  }

  async function handleLogin() {
    if (!username.trim() || !password.trim() || !idNumber.trim()) return;
    setLoginBusy(true);
    setLoginError('');
    setCourses([]);
    setSessionId(null);
    setSelectedCourse(null);
    setDlResult(null);
    resetLoginPoll();
    try {
      const { data } = await client.post('/api/v1/openu/login', {
        username:  username.trim(),
        password,
        id_number: idNumber.trim(),
      });
      setLoginJobId(data.job_id);
    } catch {
      setLoginBusy(false);
      setLoginError('שגיאת תקשורת עם השרת');
    }
  }

  async function handleGetUnitNav(section) {
    if (!sessionId) return;
    setSelectedSection(section);
    setUnitNavBusy(true);
    setUnitNavError('');
    setUnitNav(null);
    setSelectedNavItem(null);
    setSectionFiles(null);
    setScanError('');
    resetUnitNavPoll();
    try {
      const { data } = await client.post('/api/v1/openu/unit-nav', {
        session_id:    sessionId,
        section_url:   section.url   || '',
        section_title: section.title || '',
        course_url:    selectedCourse?.url || '',
      });
      setUnitNavJobId(data.job_id);
    } catch {
      setUnitNavBusy(false);
      setUnitNavError('שגיאת תקשורת עם השרת');
    }
  }

  async function handleDownloadUnit(section) {
    await _startUnitDownload([section]);
  }

  async function handleDownloadChecked() {
    if (!sections) return;
    const selected = sections.filter((_, i) => checkedSections.has(i));
    if (!selected.length) return;
    await _startUnitDownload(selected);
  }

  async function _startUnitDownload(sectionList) {
    if (!sessionId) return;
    setDlUnitSection(sectionList.length === 1 ? sectionList[0] : null);
    setDlUnitBusy(true);
    setDlUnitError('');
    setDlUnitResult(null);
    resetDlUnitPoll();
    try {
      const endpoint = sectionList.length === 1
        ? '/api/v1/openu/download-unit'
        : '/api/v1/openu/download-units';
      const body = sectionList.length === 1
        ? { session_id: sessionId, section_url: sectionList[0].url || '', section_title: sectionList[0].title || '', course_url: selectedCourse?.url || '', course_folder: selectedCourse?.name || 'course' }
        : { session_id: sessionId, sections: sectionList, course_url: selectedCourse?.url || '', course_folder: selectedCourse?.name || 'course' };
      const { data } = await client.post(endpoint, body);
      setDlUnitJobId(data.job_id);
    } catch {
      setDlUnitBusy(false);
      setDlUnitError('שגיאת תקשורת עם השרת');
    }
  }

  async function handleScanSection(navItem) {
    if (!sessionId) return;
    setSelectedNavItem(navItem);
    setScanBusy(true);
    setScanError('');
    setSectionFiles(null);
    resetScanPoll();
    try {
      const { data } = await client.post('/api/v1/openu/scan-section', {
        session_id:    sessionId,
        section_url:   navItem.url || '',
        section_title: navItem.title || '',
        course_url:    selectedCourse?.url || '',
      });
      setScanJobId(data.job_id);
    } catch {
      setScanBusy(false);
      setScanError('שגיאת תקשורת עם השרת');
    }
  }

  async function handleScanSections() {
    if (!selectedCourse || !sessionId) return;
    setSectionsBusy(true);
    setSectionsError('');
    setSections(null);
    setSelectedSection(null); setSectionFiles(null);
    resetSectionsPoll();
    try {
      const { data } = await client.post('/api/v1/openu/sections', {
        session_id: sessionId,
        course_url: selectedCourse.url,
      });
      setSectionsJobId(data.job_id);
    } catch {
      setSectionsBusy(false);
      setSectionsError('שגיאת תקשורת עם השרת');
    }
  }

  async function handleDownload() {
    if (!selectedCourse || !sessionId) return;
    setDlBusy(true);
    setDlError('');
    setDlResult(null);
    resetDlPoll();
    try {
      const { data } = await client.post('/api/v1/openu/download', {
        session_id:    sessionId,
        course_url:    selectedCourse.url,
        course_name:   selectedCourse.name,
        course_number: selectedCourse.number || '',
      });
      setDlJobId(data.job_id);
    } catch {
      setDlBusy(false);
      setDlError('שגיאת תקשורת עם השרת');
    }
  }

  async function handleFastDownload() {
    if (!sessionId) return;
    const ids = fastIds
      .split(/[\s,\n]+/)
      .map(s => parseInt(s.trim(), 10))
      .filter(n => !isNaN(n));
    if (!ids.length) { setFastError('לא הוזנו IDs תקינים'); return; }
    setFastBusy(true);
    setFastError('');
    setFastResult(null);
    resetFastPoll();
    try {
      const { data } = await client.post('/api/v1/openu/fast-download', {
        session_id:    sessionId,
        book_ids:      ids,
        course_folder: fastFolder.trim() || 'fast_download',
      });
      setFastJobId(data.job_id);
    } catch {
      setFastBusy(false);
      setFastError('שגיאת תקשורת עם השרת');
    }
  }

  async function handleAutoDownload10406() {
    if (!sessionId) return;
    setAutoBusy(true);
    setAutoError('');
    setAutoResult(null);
    resetAutoPoll();
    try {
      const { data } = await client.post('/api/v1/openu/fast-download-pages', {
        session_id:    sessionId,
        page_ids:      COURSE_10406_PAGE_IDS,
        course_folder: '10406',
      });
      setAutoJobId(data.job_id);
    } catch {
      setAutoBusy(false);
      setAutoError('שגיאת תקשורת עם השרת');
    }
  }

  async function handleDownload10406() {
    if (!sessionId) return;
    setFastBusy(true);
    setFastError('');
    setFastResult(null);
    resetFastPoll();
    try {
      const { data } = await client.post('/api/v1/openu/fast-download', {
        session_id:    sessionId,
        book_ids:      COURSE_10406_BOOK_IDS,
        course_folder: '10406',
      });
      setFastJobId(data.job_id);
    } catch {
      setFastBusy(false);
      setFastError('שגיאת תקשורת עם השרת');
    }
  }

  function handleReset() {
    resetLoginPoll(); resetSectionsPoll(); resetDlPoll(); resetFastPoll();
    setLoginJobId(null);    setLoginBusy(false);    setLoginError('');
    setSessionId(null);     setCourses([]);          setSelectedCourse(null);
    setSectionsJobId(null); setSectionsBusy(false); setSections(null); setSectionsError('');
    setUnitNavJobId(null); setUnitNavBusy(false); setUnitNav(null); setUnitNavError('');
    setSelectedSection(null); setSelectedNavItem(null); setScanJobId(null); setScanBusy(false); setSectionFiles(null); setScanError('');
    setDlUnitJobId(null); setDlUnitBusy(false); setDlUnitResult(null); setDlUnitError(''); setDlUnitSection(null); resetDlUnitPoll();
    setCheckedSections(new Set());
    setDlJobId(null);       setDlBusy(false);        setDlError('');    setDlResult(null);
    setFastJobId(null); setFastBusy(false); setFastError(''); setFastResult(null); setShowFastPanel(false);
    setAutoJobId(null); setAutoBusy(false); setAutoError(''); setAutoResult(null); resetAutoPoll();
  }

  // ── Derived ───────────────────────────────────────────────────────────────
  const loggedIn   = !!sessionId && courses.length > 0;
  const courseFolder = dlResult
    ? (dlResult.course_number
        ? `${dlResult.course_number}_${dlResult.course_name}`
        : dlResult.course_name
      ).replace(/[<>:"/\\|?*\x00-\x1f]/g, '_').trimEnd()
    : '';

  return (
    <div className="mx-auto max-w-2xl px-4 pt-20 pb-16" dir="rtl">

      {/* Header */}
      <div className="mb-6 flex items-center gap-3 pt-4">
        <div className="rounded-xl bg-blue-700 p-3 text-white">
          <BookOpen size={22} />
        </div>
        <div>
          <h1 className="text-2xl font-black text-slate-900">הורדת חומרי לימוד — האוניברסיטה הפתוחה</h1>
          <p className="text-sm text-slate-500">כנס, בחר קורס, וקבל את כל ה-PDF בתיקייה מסודרת</p>
        </div>
      </div>

      {/* Privacy notice */}
      <div className="mb-5 rounded-xl border border-blue-100 bg-blue-50 px-4 py-3 text-xs text-blue-800">
        הפרטים עוברים רק לשרת המקומי שלך. אם תשמור פרטים — הם ישמרו ב-localStorage של הדפדפן בלבד.
      </div>

      {/* ── STEP 1: Login form ── */}
      {!loggedIn && (
        <div className="rounded-2xl border border-slate-200 bg-white p-5 shadow-sm space-y-4">
          <h2 className="text-sm font-bold text-slate-700 mb-1">שלב 1 — כניסה</h2>

          <div>
            <label className="mb-1 block text-xs font-semibold text-slate-500">שם משתמש</label>
            <input
              type="text" value={username} onChange={e => setUsername(e.target.value)}
              placeholder="DAYOSE4"
              disabled={loginBusy} dir="ltr"
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-sm focus:border-slate-400 focus:outline-none disabled:opacity-50"
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-semibold text-slate-500">סיסמה</label>
            <div className="relative">
              <input
                type={showPass ? 'text' : 'password'} value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="••••••••"
                disabled={loginBusy} dir="ltr"
                className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 pr-10 text-sm focus:border-slate-400 focus:outline-none disabled:opacity-50"
              />
              <button type="button" onClick={() => setShowPass(v => !v)}
                className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600">
                {showPass ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
          </div>

          <div>
            <label className="mb-1 block text-xs font-semibold text-slate-500">מספר זהות</label>
            <input
              type="text" value={idNumber} onChange={e => setIdNumber(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleLogin()}
              placeholder="123456789"
              disabled={loginBusy} dir="ltr"
              className="w-full rounded-xl border border-slate-200 bg-slate-50 px-4 py-2.5 text-sm focus:border-slate-400 focus:outline-none disabled:opacity-50"
            />
          </div>

          {/* Save / Clear credentials */}
          <div className="flex gap-2">
            <button
              type="button"
              onClick={handleSaveCreds}
              disabled={loginBusy || !username.trim() || !password.trim() || !idNumber.trim()}
              className="flex items-center gap-1.5 rounded-xl border border-slate-200 px-4 py-2 text-xs font-semibold text-slate-600 hover:bg-slate-50 transition disabled:opacity-40"
              title="שמור פרטים לשימוש עתידי"
            >
              <Save size={13} />
              {savedCreds ? 'עדכן שמור' : 'שמור פרטים'}
            </button>
            {savedCreds && (
              <button
                type="button"
                onClick={handleClearCreds}
                className="flex items-center gap-1.5 rounded-xl border border-red-100 px-3 py-2 text-xs font-semibold text-red-500 hover:bg-red-50 transition"
                title="מחק פרטים שמורים"
              >
                <Trash2 size={13} /> מחק
              </button>
            )}
            {savedCreds && (
              <span className="flex items-center gap-1 text-xs text-green-600 mr-1">
                <Save size={11} /> פרטים שמורים
              </span>
            )}
          </div>

          <button
            onClick={handleLogin}
            disabled={loginBusy || !username.trim() || !password.trim() || !idNumber.trim()}
            className="flex w-full items-center justify-center gap-2 rounded-xl bg-blue-700 py-3 text-sm font-bold text-white transition hover:bg-blue-800 disabled:cursor-not-allowed disabled:opacity-40"
          >
            {loginBusy
              ? <><Loader2 size={15} className="animate-spin" /> מתחבר...</>
              : <><LogIn size={15} /> כניסה והצגת קורסים</>}
          </button>

          <ProgressLog lines={loginProgress} running={loginBusy} />
          <ErrorBox msg={loginError} />
        </div>
      )}

      {/* ── Auto-download 10406 (one-click after login) ── */}
      {loggedIn && (
        <div className="mb-4 rounded-2xl border border-green-200 bg-green-50 p-4">
          <div className="flex items-center justify-between gap-3">
            <div>
              <p className="text-sm font-bold text-green-900">קורס 10406 — מדע המדינה</p>
              <p className="text-xs text-green-700">{COURSE_10406_PAGE_IDS.length} דפים · יחידות 1–13 · ללא סריקה</p>
            </div>
            <button
              onClick={handleAutoDownload10406}
              disabled={autoBusy}
              className="shrink-0 flex items-center gap-2 rounded-xl bg-green-700 px-5 py-2.5 text-sm font-bold text-white hover:bg-green-800 disabled:opacity-40 transition"
            >
              {autoBusy
                ? <><Loader2 size={14} className="animate-spin" /> מוריד...</>
                : <><Zap size={14} /> הורד הכל</>}
            </button>
          </div>
          {autoError && <ErrorBox msg={autoError} />}
          {autoResult && !autoResult.error && (
            <p className="mt-2 text-xs font-semibold text-green-800">
              ✓ הורדו {autoResult.total} קבצים לתיקייה 10406
            </p>
          )}
          <ProgressLog lines={autoProgress} running={autoBusy} />
        </div>
      )}

      {/* ── STEP 2: Course selection ── */}
      {loggedIn && !dlResult && (
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-bold text-slate-700">
              שלב 2 — בחר קורס ({courses.length} קורסים)
            </h2>
            <div className="flex items-center gap-3">
              <button
                onClick={() => setShowFastPanel(v => !v)}
                className="flex items-center gap-1 text-xs font-semibold text-amber-600 hover:text-amber-800 transition"
                title="הורדה מהירה לפי book IDs"
              >
                <Zap size={13} /> הורדה מהירה
              </button>
              <button onClick={handleReset}
                className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-600 transition">
                <RefreshCw size={12} /> התנתק
              </button>
            </div>
          </div>

          {/* Fast download panel */}
          {showFastPanel && (
            <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 space-y-3">
              <div className="flex items-center gap-2">
                <Zap size={14} className="text-amber-600" />
                <span className="text-sm font-bold text-amber-800">הורדה מהירה לפי Book IDs</span>
                <span className="text-xs text-amber-600">— ללא ניווט בדפדפן</span>
              </div>

              {/* One-click preset for course 10406 */}
              <div className="rounded-xl border border-amber-300 bg-white px-4 py-3 flex items-center justify-between">
                <div>
                  <p className="text-sm font-bold text-slate-800">קורס 10406 — מדע המדינה</p>
                  <p className="text-xs text-slate-500">{COURSE_10406_BOOK_IDS.length} קבצים · יחידות 2–12</p>
                </div>
                <button
                  onClick={handleDownload10406}
                  disabled={fastBusy}
                  className="flex items-center gap-2 rounded-xl bg-amber-600 px-4 py-2 text-sm font-bold text-white hover:bg-amber-700 disabled:opacity-40 transition"
                >
                  {fastBusy
                    ? <><Loader2 size={14} className="animate-spin" /> מוריד...</>
                    : <><Zap size={14} /> הורד הכל</>}
                </button>
              </div>
              <div>
                <label className="mb-1 block text-xs font-semibold text-slate-500">
                  Book IDs (מופרדים בפסיק, רווח או שורה חדשה)
                </label>
                <textarea
                  value={fastIds}
                  onChange={e => setFastIds(e.target.value)}
                  disabled={fastBusy}
                  dir="ltr"
                  placeholder={"115782, 115783, 115784\n115785, 115786, 115835"}
                  rows={4}
                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 font-mono text-xs focus:border-amber-400 focus:outline-none disabled:opacity-50"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-semibold text-slate-500">
                  שם תיקייה לשמירה
                </label>
                <input
                  type="text"
                  value={fastFolder}
                  onChange={e => setFastFolder(e.target.value)}
                  disabled={fastBusy}
                  dir="ltr"
                  placeholder="fast_download"
                  className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-sm focus:border-amber-400 focus:outline-none disabled:opacity-50"
                />
              </div>
              <button
                onClick={handleFastDownload}
                disabled={fastBusy || !fastIds.trim()}
                className="flex items-center gap-2 rounded-xl bg-amber-600 px-4 py-2.5 text-sm font-bold text-white hover:bg-amber-700 disabled:opacity-40 transition"
              >
                {fastBusy
                  ? <><Loader2 size={14} className="animate-spin" /> מוריד...</>
                  : <><Zap size={14} /> הורד עכשיו</>}
              </button>
              <ProgressLog lines={fastProgress} running={fastBusy} />
              <ErrorBox msg={fastError} />
              {fastResult && !fastError && (
                <div className="rounded-xl border border-green-200 bg-green-50 p-3 space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-bold text-green-800">
                      הושלם — {fastResult.total} קבצים
                    </span>
                    <div className="flex items-center gap-2">
                      {fastResult.course_folder && (
                        <a
                          href={`${API}/api/v1/openu/zip/${encodeURIComponent(fastResult.course_folder)}`}
                          download={`${fastResult.course_folder}.zip`}
                          className="flex items-center gap-1 rounded-lg bg-slate-800 px-2.5 py-1 text-xs font-bold text-white hover:bg-slate-700 transition"
                        >
                          <Package size={11} /> ZIP
                        </a>
                      )}
                      <button onClick={() => setFastResult(null)} className="text-xs text-green-600 hover:text-green-800">✕</button>
                    </div>
                  </div>
                  {fastResult.downloaded?.map((f, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs text-green-700">
                      <FileText size={11} className="shrink-0" />
                      <span className="flex-1 truncate font-mono">{f.filename}</span>
                      <span className="shrink-0">{f.size_mb} MB</span>
                    </div>
                  ))}
                  {fastResult.errors?.length > 0 && (
                    <details className="mt-1">
                      <summary className="cursor-pointer text-xs text-red-600">שגיאות ({fastResult.errors.length})</summary>
                      {fastResult.errors.map((e, i) => (
                        <p key={i} className="font-mono text-xs text-red-700 break-all">{e}</p>
                      ))}
                    </details>
                  )}
                </div>
              )}
            </div>
          )}


          {/* Course list */}
          <div className="space-y-2 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm">
            {courses.map((course) => {
              const isSelected = selectedCourse?.id === course.id;
              return (
                <button
                  key={course.id}
                  onClick={() => setSelectedCourse(course)}
                  disabled={dlBusy}
                  className={`w-full text-right rounded-xl border px-4 py-3 transition ${
                    isSelected
                      ? 'border-blue-400 bg-blue-50 ring-2 ring-blue-200'
                      : 'border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50'
                  } disabled:opacity-50`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-sm font-semibold text-slate-800">{course.name}</span>
                    {course.number && (
                      <span className="shrink-0 rounded-full bg-slate-100 px-2 py-0.5 text-xs text-slate-500 font-mono">
                        {course.number}
                      </span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>

          {/* Scan sections button */}
          {selectedCourse && sections === null && (
            <button
              onClick={handleScanSections}
              disabled={sectionsBusy}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-slate-800 py-3 text-sm font-bold text-white transition hover:bg-slate-900 disabled:opacity-40"
            >
              {sectionsBusy
                ? <><Loader2 size={15} className="animate-spin" /> סורק מבנה קורס...</>
                : <><RefreshCw size={15} /> סרוק מבנה קורס</>}
            </button>
          )}

          <ProgressLog lines={sectionsProgress} running={sectionsBusy} />
          <ErrorBox msg={sectionsError} />

          {/* Sections list — each row is clickable */}
          {sections !== null && (
            <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm space-y-1">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-widest">
                  מבנה הקורס — {sections.length} יחידות
                </span>
                <div className="flex items-center gap-2">
                  {checkedSections.size > 0 && (
                    <button
                      onClick={handleDownloadChecked}
                      disabled={dlUnitBusy}
                      className="flex items-center gap-1 rounded-lg bg-green-700 px-2.5 py-1 text-xs font-bold text-white hover:bg-green-800 disabled:opacity-40 transition"
                    >
                      {dlUnitBusy ? <Loader2 size={11} className="animate-spin" /> : <Download size={11} />}
                      הורד {checkedSections.size} נבחרות
                    </button>
                  )}
                  <button
                    onClick={() => setCheckedSections(
                      checkedSections.size === sections.length
                        ? new Set()
                        : new Set(sections.map((_, i) => i))
                    )}
                    className="text-xs text-slate-400 hover:text-slate-600"
                  >
                    {checkedSections.size === sections.length ? 'בטל הכל' : 'בחר הכל'}
                  </button>
                  <button onClick={() => handleScanSections()}
                    className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-600">
                    <RefreshCw size={11} /> רענן
                  </button>
                </div>
              </div>
              {sections.map((s, i) => {
                const isSelected = selectedSection?.title === s.title;
                const isDlActive = dlUnitSection?.title === s.title;
                const isChecked  = checkedSections.has(i);
                return (
                  <div key={i} className="flex items-center gap-2">
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={() => {
                        const next = new Set(checkedSections);
                        isChecked ? next.delete(i) : next.add(i);
                        setCheckedSections(next);
                      }}
                      className="shrink-0 h-4 w-4 rounded accent-green-700 cursor-pointer"
                    />
                    <button
                      onClick={() => handleGetUnitNav(s)}
                      disabled={unitNavBusy || scanBusy || dlUnitBusy}
                      className={`flex-1 text-right flex items-center gap-2 rounded-lg border px-3 py-2 transition
                        ${isSelected ? 'border-blue-400 bg-blue-50 ring-1 ring-blue-200' : 'border-slate-100 bg-slate-50 hover:border-slate-300 hover:bg-white'}
                        cursor-pointer disabled:opacity-50`}
                    >
                      <span className="text-xs text-slate-400 font-mono w-5 shrink-0">{i + 1}</span>
                      <span className="text-sm text-slate-800 flex-1">{s.title}</span>
                      {isSelected && unitNavBusy && <Loader2 size={13} className="animate-spin text-blue-500 shrink-0" />}
                    </button>
                    <button
                      onClick={() => handleDownloadUnit(s)}
                      disabled={dlUnitBusy}
                      title="הורד את כל ה-PDF מהיחידה"
                      className={`shrink-0 flex items-center gap-1 rounded-lg border px-2.5 py-2 text-xs font-semibold transition
                        ${isDlActive && dlUnitBusy ? 'border-green-400 bg-green-50 text-green-700' : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50'}
                        disabled:opacity-40`}
                    >
                      {isDlActive && dlUnitBusy
                        ? <Loader2 size={12} className="animate-spin" />
                        : <Download size={12} />}
                    </button>
                  </div>
                );
              })}
            </div>
          )}

          <ProgressLog lines={dlUnitProgress} running={dlUnitBusy} />
          <ErrorBox msg={dlUnitError} />

          {dlUnitResult && !dlUnitError && (
            <div className="rounded-2xl border border-green-200 bg-green-50 p-4 space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold text-green-800">
                  {dlUnitSection?.title} — {dlUnitResult.total} קבצים הורדו
                </span>
                <button onClick={() => { setDlUnitResult(null); setDlUnitSection(null); }}
                  className="text-xs text-green-600 hover:text-green-800">✕</button>
              </div>
              {dlUnitResult.files?.map((f, i) => (
                <div key={i} className="flex items-center gap-2 text-xs text-green-700">
                  <FileText size={11} className="shrink-0" />
                  <span className="flex-1 truncate">{f.filename}</span>
                  <span className="shrink-0 font-mono">{f.size_mb} MB</span>
                </div>
              ))}
            </div>
          )}

          <ProgressLog lines={unitNavProgress} running={unitNavBusy} />
          <ErrorBox msg={unitNavError} />

          {/* Unit nav items list */}
          {unitNav !== null && (
            <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm space-y-1">
              <div className="mb-2">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-widest">
                  {selectedSection?.title} — {unitNav.length} דפים
                </span>
              </div>
              {unitNav.map((item, i) => {
                const isSelected = selectedNavItem?.url === item.url;
                return (
                  <button
                    key={i}
                    onClick={() => handleScanSection(item)}
                    disabled={scanBusy}
                    className={`w-full text-right flex items-center gap-2 rounded-lg border px-3 py-2 transition
                      ${isSelected ? 'border-green-400 bg-green-50 ring-1 ring-green-200' : 'border-slate-100 bg-slate-50 hover:border-slate-300 hover:bg-white'}
                      cursor-pointer disabled:opacity-50`}
                  >
                    <span className="text-xs text-slate-400 font-mono w-5 shrink-0">{i + 1}</span>
                    <span className="text-sm text-slate-800 flex-1">{item.title}</span>
                    {isSelected && scanBusy && <Loader2 size={13} className="animate-spin text-green-500 shrink-0" />}
                    {isSelected && !scanBusy && sectionFiles !== null && (
                      <span className="text-xs text-green-600 shrink-0">{sectionFiles.length} קבצים</span>
                    )}
                  </button>
                );
              })}
            </div>
          )}

          {/* Section files result */}
          {sectionFiles !== null && (
            <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm space-y-1">
              <div className="mb-2">
                <span className="text-xs font-bold text-slate-500 uppercase tracking-widest">
                  {selectedNavItem?.title || 'קבצים'} — {sectionFiles.length} נמצאו
                </span>
              </div>
              {sectionFiles.length === 0
                ? <p className="text-sm text-slate-400">לא נמצאו קבצים בסקשן זה</p>
                : sectionFiles.map((f, i) => (
                  <div key={i} className="flex items-center gap-2 rounded-lg border border-slate-100 bg-slate-50 px-3 py-2">
                    <FileText size={13} className="shrink-0 text-blue-500" />
                    <span className="text-sm text-slate-800 flex-1 truncate">{f.title}</span>
                    <span className="text-xs text-slate-400 shrink-0 font-mono">{f.type}</span>
                    {f.type === 'book_pdf' && (
                      <button
                        onClick={async () => {
                          try {
                            const resp = await client.post('/api/v1/openu/proxy-file',
                              { session_id: sessionId, file_url: f.url },
                              { responseType: 'blob' }
                            );
                            const blob = new Blob([resp.data], { type: 'application/pdf' });
                            const a = document.createElement('a');
                            a.href = URL.createObjectURL(blob);
                            a.download = f.title.replace(/[<>:"/\\|?*]/g,'_') + '.pdf';
                            a.click();
                          } catch { toast.error('הורדה נכשלה'); }
                        }}
                        className="shrink-0 rounded-lg border border-slate-200 p-1.5 text-slate-500 hover:bg-slate-100 transition"
                        title="הורד PDF"
                      >
                        <Download size={13} />
                      </button>
                    )}
                  </div>
                ))
              }
            </div>
          )}

          <ProgressLog lines={scanProgress} running={scanBusy} />
          <ErrorBox msg={scanError} />
        </div>
      )}

      {/* ── STEP 3: Results ── */}
      {dlResult && (
        <div className="space-y-4">
          {/* Header + back */}
          <div className="flex items-center justify-between">
            <h2 className="text-base font-black text-slate-900">{dlResult.course_name}</h2>
            <button
              onClick={() => { setDlResult(null); setDlJobId(null); setDlError(''); resetDlPoll(); }}
              className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-600 transition"
            >
              <ChevronLeft size={13} /> חזור לקורסים
            </button>
          </div>

          {/* Stats */}
          <div className="grid grid-cols-3 gap-3">
            {[
              { label: 'דפים נסרקו',  value: dlResult.pages_crawled ?? 0 },
              { label: 'PDF נמצאו',   value: dlResult.pdfs_found ?? 0 },
              { label: 'PDF הורדו',   value: dlResult.pdfs_downloaded ?? 0 },
            ].map(s => (
              <div key={s.label} className="rounded-xl border border-slate-200 bg-white p-4 text-center">
                <p className="text-2xl font-black text-slate-900">{s.value}</p>
                <p className="text-xs text-slate-500">{s.label}</p>
              </div>
            ))}
          </div>

          {/* Download ZIP */}
          {dlResult.files?.length > 0 && courseFolder && (
            <a
              href={`${API}/api/v1/openu/zip/${encodeURIComponent(courseFolder)}`}
              download={`${courseFolder}.zip`}
              className="flex items-center gap-2 rounded-xl bg-slate-900 px-4 py-2.5 text-sm font-bold text-white hover:bg-slate-700 transition w-fit"
            >
              <Package size={14} /> הורד הכל כ-ZIP ({dlResult.files.length} קבצים)
            </a>
          )}

          {/* File list */}
          {dlResult.files?.length > 0 && (
            <div className="rounded-2xl border border-slate-200 bg-slate-50 p-4 space-y-1.5 max-h-[400px] overflow-y-auto">
              {dlResult.files.map((f, i) => (
                <FileRow key={i} file={f} courseFolder={courseFolder} />
              ))}
            </div>
          )}

          {/* Errors */}
          {dlResult.errors?.length > 0 && (
            <details className="rounded-xl border border-red-100 bg-red-50 p-3">
              <summary className="cursor-pointer text-xs font-semibold text-red-600">
                שגיאות ({dlResult.errors.length})
              </summary>
              <div className="mt-2 space-y-1">
                {dlResult.errors.map((e, i) => (
                  <p key={i} className="font-mono text-xs text-red-700 break-all">{e}</p>
                ))}
              </div>
            </details>
          )}

          {/* Download another course */}
          <button
            onClick={() => { setDlResult(null); setDlJobId(null); setDlError(''); resetDlPoll(); }}
            className="flex items-center gap-2 rounded-xl border border-slate-200 px-4 py-2 text-sm text-slate-600 hover:bg-slate-50 transition"
          >
            <BookOpen size={14} /> הורד קורס נוסף
          </button>
        </div>
      )}
    </div>
  );
}
