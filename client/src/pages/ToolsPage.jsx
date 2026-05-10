import { useState, useEffect } from 'react';
import { getToolsStatus } from '../utils/webintApi';
import { CheckCircle2, XCircle, Terminal, Download, RefreshCw } from 'lucide-react';

const TOOL_META = {
  maigret:      { label: 'Maigret',       desc: 'Username OSINT — 2,500+ אתרים',               module: 'socmint.py' },
  holehe:       { label: 'Holehe',         desc: 'בדיקת אימייל — 120+ שירותים',                  module: 'person_intel.py' },
  subfinder:    { label: 'Subfinder',      desc: 'סאבדומיינים — 40+ מקורות',                     module: 'domain_intel.py' },
  nuclei:       { label: 'Nuclei',         desc: 'סורק פגיעויות — 7,000+ templates',             module: 'auditor.py' },
  ffuf:         { label: 'ffuf',           desc: 'Directory Fuzzing מהיר',                       module: 'dir_fuzzer.py' },
  trufflehog:   { label: 'TruffleHog',    desc: 'סריקת סודות — 700+ patterns',                  module: 'secret_scanner.py' },
  theHarvester: { label: 'theHarvester',   desc: 'חיפוש אימיילים מדומיין',                       module: 'email_finder.py' },
  katana:       { label: 'Katana',         desc: 'Web Crawler מבית ProjectDiscovery',            module: 'site_downloader.py' },
};

export default function ToolsPage() {
  const [tools, setTools] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchStatus = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await getToolsStatus();
      setTools(res.data.tools);
    } catch (err) {
      setError('לא ניתן להתחבר לשרת Python');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchStatus(); }, []);

  const available = tools ? Object.values(tools).filter(t => t.available).length : 0;
  const total = tools ? Object.keys(tools).length : 0;

  return (
    <div className="mx-auto max-w-4xl px-4 py-8" dir="rtl">
      <div className="mb-8 flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-black text-slate-900 flex items-center gap-2">
            <Terminal size={24} /> כלים חיצוניים
          </h1>
          <p className="mt-1 text-sm text-slate-500">
            כלי OSINT ואבטחה מקוד פתוח שמשדרגים את Webint כשהם מותקנים
          </p>
        </div>
        <button
          onClick={fetchStatus}
          disabled={loading}
          className="flex items-center gap-1.5 rounded-lg bg-slate-100 px-4 py-2 text-sm font-semibold text-slate-700 hover:bg-slate-200 transition-colors disabled:opacity-50"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
          רענן
        </button>
      </div>

      {error && (
        <div className="mb-6 rounded-xl border border-red-200 bg-red-50 p-4 text-sm text-red-700">
          {error}
        </div>
      )}

      {tools && (
        <div className="mb-6 flex gap-3">
          <div className="rounded-xl border border-green-200 bg-green-50 px-4 py-3 flex-1 text-center">
            <div className="text-2xl font-black text-green-700">{available}</div>
            <div className="text-xs text-green-600 font-medium">מותקנים</div>
          </div>
          <div className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 flex-1 text-center">
            <div className="text-2xl font-black text-slate-700">{total}</div>
            <div className="text-xs text-slate-500 font-medium">סה״כ נתמכים</div>
          </div>
          <div className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 flex-1 text-center">
            <div className="text-2xl font-black text-amber-700">{total - available}</div>
            <div className="text-xs text-amber-600 font-medium">לא מותקנים</div>
          </div>
        </div>
      )}

      {loading && !tools ? (
        <div className="text-center py-12 text-slate-400">טוען...</div>
      ) : tools && (
        <div className="space-y-3">
          {Object.entries(tools).map(([key, info]) => {
            const meta = TOOL_META[key] || { label: key, desc: info.description, module: '' };
            return (
              <div
                key={key}
                className={`rounded-xl border p-4 transition-all ${
                  info.available
                    ? 'border-green-200 bg-green-50/50'
                    : 'border-slate-200 bg-white'
                }`}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {info.available ? (
                      <CheckCircle2 size={20} className="text-green-600 shrink-0" />
                    ) : (
                      <XCircle size={20} className="text-slate-300 shrink-0" />
                    )}
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-slate-900">{meta.label}</span>
                        {info.available && info.mode === 'docker' && (
                          <span className="rounded-full bg-blue-100 px-2 py-0.5 text-[10px] font-bold text-blue-700">
                            Docker 🐳
                          </span>
                        )}
                        {info.available && info.mode === 'native' && (
                          <span className="rounded-full bg-green-100 px-2 py-0.5 text-[10px] font-bold text-green-700">
                            Native
                          </span>
                        )}
                      </div>
                      <div className="text-xs text-slate-500 mt-0.5">{meta.desc}</div>
                      {meta.module && (
                        <div className="text-[10px] text-slate-400 mt-0.5">
                          משתלב עם: <span className="font-mono">{meta.module}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="text-left flex flex-col items-end gap-1">
                    {info.available ? (
                      <span dir="ltr" className="text-[10px] font-mono text-green-600 truncate max-w-[200px]">
                        {info.path}
                      </span>
                    ) : (
                      <div className="flex items-center gap-1.5">
                        <Download size={12} className="text-slate-400" />
                        <code dir="ltr" className="text-[10px] bg-slate-100 rounded px-2 py-0.5 text-slate-600 select-all">
                          {info.install_hint}
                        </code>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      <div className="mt-8 rounded-xl border border-blue-200 bg-blue-50 p-5">
        <h3 className="font-bold text-blue-900 mb-2">איך זה עובד?</h3>
        <ul className="text-sm text-blue-800 space-y-1 list-disc list-inside">
          <li>כל כלי משדרג אוטומטית את המודול המתאים כשהוא מותקן</li>
          <li>אם הכלי לא מותקן — המערכת משתמשת במנוע המובנה (fallback)</li>
          <li>לא צריך לשנות שום דבר בקוד — פשוט התקן ותריץ</li>
          <li>כלי Go (subfinder, nuclei, ffuf, katana, trufflehog): רצים דרך Docker אוטומטית 🐳</li>
          <li>כלי Python (maigret, holehe, theHarvester): <code className="bg-blue-100 px-1 rounded">pip install</code></li>
          <li>אם קיים Docker עם ה-image המתאים — הכלי רץ בתוך קונטיינר בלי התקנה מקומית</li>
        </ul>
      </div>
    </div>
  );
}
