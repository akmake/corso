import React, { forwardRef } from 'react';
import { Mail, Phone, Building2, Globe, FileText, User } from 'lucide-react';

function fmtDate(iso) {
  if (!iso) return '';
  const d = new Date(iso);
  return d.toLocaleDateString('he-IL') + ' ' + d.toLocaleTimeString('he-IL');
}

// The component to be printed. Using standard CSS that looks good on A4 paper.
const ReportView = forwardRef(({ caseData }, ref) => {
  if (!caseData) return null;

  const { subject, created_at, notes, result = {} } = caseData;
  const found = result.found || {};
  const stats = result.stats || {};
  const israeli = result.israeli || {};

  return (
    <div ref={ref} className="bg-white p-8 text-black print:p-0" dir="rtl" style={{ direction: 'rtl', fontFamily: 'sans-serif' }}>
      
      {/* Report Header */}
      <div className="border-b-4 border-indigo-600 pb-4 mb-6 flex justify-between items-end">
        <div>
          <h1 className="text-4xl font-black text-slate-800 mb-2">דוח חקירה: {subject}</h1>
          <p className="text-slate-500">הופק בתאריך: {new Date().toLocaleDateString('he-IL')} | תאריך פתיחת תיק: {fmtDate(created_at)}</p>
        </div>
        <div className="text-left flex flex-col items-end">
          <div className="bg-indigo-100 text-indigo-800 px-3 py-1 rounded font-bold text-sm">
            Webint OSINT System
          </div>
        </div>
      </div>

      {/* Executive Summary / Notes */}
      {notes && (
        <div className="mb-6 p-4 bg-slate-50 rounded-lg border border-slate-200 break-inside-avoid">
          <h2 className="text-lg font-bold text-slate-800 mb-2 flex items-center gap-2">
            <FileText size={18} /> תמצית מנהלים (הערות חוקר)
          </h2>
          <p className="whitespace-pre-wrap text-slate-700">{notes}</p>
        </div>
      )}

      {/* Statistics */}
      <div className="mb-8 grid grid-cols-4 gap-4 break-inside-avoid">
        <div className="p-3 border rounded text-center bg-blue-50 border-blue-200">
          <div className="text-2xl font-black text-blue-700">{stats.web_results || 0}</div>
          <div className="text-xs text-blue-600">תוצאות Web</div>
        </div>
        <div className="p-3 border rounded text-center bg-red-50 border-red-200">
          <div className="text-2xl font-black text-red-700">{stats.emails_found || 0}</div>
          <div className="text-xs text-red-600">אימיילים</div>
        </div>
        <div className="p-3 border rounded text-center bg-amber-50 border-amber-200">
          <div className="text-2xl font-black text-amber-700">{stats.phones_found || 0}</div>
          <div className="text-xs text-amber-600">טלפונים</div>
        </div>
        <div className="p-3 border rounded text-center bg-green-50 border-green-200">
          <div className="text-2xl font-black text-green-700">{stats.accounts_found || 0}</div>
          <div className="text-xs text-green-600">חשבונות ברשת</div>
        </div>
      </div>

      {/* Entities Found */}
      <div className="mb-8 break-inside-avoid">
        <h2 className="text-xl font-bold border-b border-slate-300 pb-2 mb-4 text-slate-800">ישויות מרכזיות שזוהו</h2>
        
        <div className="grid grid-cols-2 gap-6">
          {/* Emails */}
          {found.emails?.length > 0 && (
            <div>
              <h3 className="font-semibold flex items-center gap-1 text-red-700 mb-2"><Mail size={16}/> אימיילים</h3>
              <ul className="list-disc list-inside px-2 text-slate-700 text-sm">
                {found.emails.map((e, i) => <li key={i}>{e}</li>)}
              </ul>
            </div>
          )}
          
          {/* Phones */}
          {found.phones?.length > 0 && (
            <div>
              <h3 className="font-semibold flex items-center gap-1 text-amber-700 mb-2"><Phone size={16}/> טלפונים</h3>
              <ul className="list-disc list-inside px-2 text-slate-700 text-sm">
                {found.phones.map((p, i) => <li key={i} dir="ltr" className="text-right">{p}</li>)}
              </ul>
            </div>
          )}

          {/* Usernames */}
          {found.usernames?.length > 0 && (
            <div>
              <h3 className="font-semibold flex items-center gap-1 text-blue-700 mb-2"><User size={16}/> Usernames</h3>
              <ul className="list-disc list-inside px-2 text-slate-700 text-sm">
                {found.usernames.map((u, i) => <li key={i}>{u}</li>)}
              </ul>
            </div>
          )}

          {/* Companies */}
          {found.companies?.length > 0 && (
            <div>
              <h3 className="font-semibold flex items-center gap-1 text-purple-700 mb-2"><Building2 size={16}/> ארגונים/חברות</h3>
              <ul className="list-disc list-inside px-2 text-slate-700 text-sm">
                {found.companies.map((c, i) => <li key={i}>{c}</li>)}
              </ul>
            </div>
          )}
        </div>
      </div>

      {/* Accounts */}
      {result.accounts?.length > 0 && (
        <div className="mb-8 break-inside-avoid">
          <h2 className="text-xl font-bold border-b border-slate-300 pb-2 mb-4 text-slate-800 flex items-center gap-2">
            <Globe size={18}/> חשבונות חברתיים שנקשרו
          </h2>
          <div className="grid grid-cols-2 gap-3">
            {result.accounts.map((a, i) => (
              <div key={i} className="p-2 border border-slate-200 rounded text-sm flex justify-between bg-slate-50">
                <span className="font-semibold">{a.platform}</span>
                <span dir="ltr" className="text-slate-500 text-xs truncate ml-2 max-w-[200px]">{a.url}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Israeli Intel */}
      {(israeli.guidestar?.length > 0 || israeli.court?.length > 0 || israeli.datagov?.companies?.records?.length > 0) && (
        <div className="mb-8 break-inside-wrap">
          <h2 className="text-xl font-bold border-b border-slate-300 pb-2 mb-4 text-slate-800 flex items-center gap-2">
            <Building2 size={18} /> מודיעין ישראלי מורחב
          </h2>
          <div className="space-y-4 text-sm text-slate-700">
            {israeli.guidestar?.length > 0 && (
              <div className="break-inside-avoid">
                <h4 className="font-semibold text-purple-700 mb-1">עמותות (Guidestar)</h4>
                <ul className="list-disc list-inside space-y-1">
                  {israeli.guidestar.map((o, i) => <li key={i}>{o.name} ({o.type} - {o.status})</li>)}
                </ul>
              </div>
            )}
            {israeli.court?.length > 0 && (
              <div className="break-inside-avoid">
                <h4 className="font-semibold text-red-700 mb-1">פסיקות בתי משפט</h4>
                <ul className="list-disc list-inside space-y-1">
                  {israeli.court.slice(0,10).map((c, i) => <li key={i}>{c.title || c.case_id} <span className="text-xs text-slate-500">[{c.court}]</span></li>)}
                </ul>
              </div>
            )}
            {israeli.datagov?.companies?.records?.length > 0 && (
              <div className="break-inside-avoid">
                <h4 className="font-semibold text-blue-700 mb-1">רשם החברות / שותפויות</h4>
                <ul className="list-disc list-inside space-y-1">
                  {israeli.datagov.companies.records.slice(0, 10).map((r, i) => (
                     <li key={i}>{r.company_name || r['שם חברה'] || r.CompanyName || Object.values(r).filter(Boolean).slice(0,2).join(' ')}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Footer */}
      <div className="mt-12 pt-4 border-t border-slate-300 text-center text-xs text-slate-400 print:text-[10px]">
        <p>דוח זה הופק באופן אוטומטי במערכת Webint.</p>
        <p>מיועד לשימוש פנימי בלבד. יש לוודא את מהימנות הנתונים באופן ידני.</p>
      </div>
    </div>
  );
});

export default ReportView;
