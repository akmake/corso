// client/src/pages/AutonomousAgentPage.jsx

import React, { useState, useEffect, useRef } from 'react';

const AutonomousAgentPage = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [aggressiveness, setAggressiveness] = useState('normal');
  const [supabaseUrl, setSupabaseUrl] = useState('');
  const [supabaseKey, setSupabaseKey] = useState('');
  const [showManual, setShowManual] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  
  // State for live updates
  const [logs, setLogs] = useState([]);
  const [findings, setFindings] = useState([]);
  const [techStack, setTechStack] = useState([]);
  
  const terminalEndRef = useRef(null);

  // Auto-scroll terminal to bottom
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const startAutonomousScan = async () => {
    if (!targetUrl) return alert("אנא הזן כתובת אתר למטרה");

    setIsRunning(true);
    setLogs([{ time: new Date().toLocaleTimeString(), msg: '🔗 מתחבר לערוץ הפיקוד...', level: 'info' }]);
    setFindings([]);
    setTechStack([]);

    // פותחים WebSocket לפני הקריאה ל-scan כדי לא לפספס לוגים ראשוניים
    const ws = new WebSocket('ws://localhost:8000/ws/jobs');

    await new Promise((resolve) => { ws.onopen = resolve; });
    addLog("🔗 מחובר. שולח פקודת תקיפה לשרת...", "info");

    try {
      const res = await fetch('http://localhost:8000/api/v1/scan/terminator', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: targetUrl, query: aggressiveness, cookies: supabaseKey ? `supabase_url=${supabaseUrl}|||${supabaseKey}` : '' }),
      });

      const data = await res.json();
      const jobId = data.job_id;
      addLog(`📡 Job ID: ${jobId}`, "system");

      ws.onmessage = (event) => {
        const msgData = JSON.parse(event.data);
        if (msgData.job_id !== jobId) return;
        if (msgData.msg === "__done__") {
          setIsRunning(false);
          ws.close();
          fetchFinalResults(jobId);
          return;
        }

        let level = "system";
        if (msgData.msg.includes("⚠️") || msgData.msg.includes("קריטי")) level = "danger";
        else if (msgData.msg.includes("✅") || msgData.msg.includes("הצלחה")) level = "success";
        else if (msgData.msg.includes("🧠") || msgData.msg.includes("🤖")) level = "system";
        else if (msgData.msg.includes("🔍") || msgData.msg.includes("👀")) level = "info";

        addLog(msgData.msg, level);

        if (msgData.status === "completed" || msgData.status === "failed") {
          setIsRunning(false);
          ws.close();
          if (msgData.status === "completed") fetchFinalResults(jobId);
        }
      };

      ws.onerror = () => {
        addLog("שגיאת WebSocket — בודק סטטוס ידנית...", "danger");
        setIsRunning(false);
      };
    } catch (err) {
      addLog(`שגיאת תקשורת עם השרת: ${err.message}`, "danger");
      ws.close();
      setIsRunning(false);
    }
  };

  // פונקציה חדשה שמושכת את ה-JSON הסופי אחרי שהסוכן סיים לעבוד
  const fetchFinalResults = async (jobId) => {
    try {
      const res = await fetch(`http://localhost:8000/api/v1/jobs/${jobId}`);
      const data = await res.json();
      
      if (data.result && data.result.findings) {
        // שולח את הממצאים האמיתיים ללוח שבימין המסך
        setFindings(data.result.findings);
      }
      if (data.result && data.result.summary && data.result.summary.technologies) {
         setTechStack(data.result.summary.technologies);
      }
    } catch (err) {
      console.error("שגיאה במשיכת תוצאות סופיות:", err);
    }
  };

  const addLog = (msg, level) => {
    setLogs(prev => [...prev, { time: new Date().toLocaleTimeString(), msg, level }]);
  };

  return (
    <div className="min-h-screen bg-gray-900 text-white p-6 font-sans" dir="rtl">
      <div className="max-w-7xl mx-auto space-y-6">
        
        {/* Header */}
        <div className="flex justify-between items-center border-b border-gray-700 pb-4">
          <div>
            <h1 className="text-3xl font-bold text-green-400">Terminator AI 🤖</h1>
            <p className="text-gray-400 mt-1">מנוע בדיקות חדירות אוטונומי מבוסס AI</p>
          </div>
          {isRunning && (
            <div className="flex items-center space-x-2 space-x-reverse text-green-400 animate-pulse">
              <span className="relative flex h-3 w-3">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-3 w-3 bg-green-500"></span>
              </span>
              <span>סריקה פעילה...</span>
            </div>
          )}
        </div>

        {/* Controls */}
        <div className="bg-gray-800 p-5 rounded-lg shadow-lg flex flex-col gap-4">
          <div className="flex flex-col md:flex-row gap-4 items-end">
            <div className="flex-1 w-full">
              <label className="block text-sm text-gray-400 mb-1">מטרת תקיפה (URL)</label>
              <input
                type="text"
                placeholder="https://example.com"
                className="w-full bg-gray-700 text-white border border-gray-600 rounded px-4 py-2 focus:outline-none focus:border-green-500 text-left"
                dir="ltr"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                disabled={isRunning}
              />
            </div>
            <div className="w-full md:w-48">
              <label className="block text-sm text-gray-400 mb-1">רמת אגרסיביות</label>
              <select
                className="w-full bg-gray-700 text-white border border-gray-600 rounded px-4 py-2 focus:outline-none"
                value={aggressiveness}
                onChange={(e) => setAggressiveness(e.target.value)}
                disabled={isRunning}
              >
                <option value="recon">מודיעין בלבד (Recon)</option>
                <option value="normal">רגיל (קריאה בלבד)</option>
                <option value="aggressive">אגרסיבי (כתיבה/BOLA)</option>
              </select>
            </div>
            <button
              onClick={startAutonomousScan}
              disabled={isRunning}
              className={`px-8 py-2 rounded font-bold transition-all whitespace-nowrap ${isRunning ? 'bg-gray-600 text-gray-400 cursor-not-allowed' : 'bg-green-600 hover:bg-green-500 text-white'}`}
            >
              {isRunning ? 'תוקף...' : 'התחל תקיפה'}
            </button>
          </div>

          {/* Manual BaaS Override */}
          <div>
            <button
              onClick={() => setShowManual(v => !v)}
              className="text-xs text-gray-500 hover:text-gray-300 flex items-center gap-1 transition-colors"
              disabled={isRunning}
            >
              <span>{showManual ? '▲' : '▼'}</span>
              הזנה ידנית של Supabase / Firebase (אם כבר מצאת את המפתחות)
            </button>
            {showManual && (
              <div className="mt-3 flex flex-col md:flex-row gap-3">
                <div className="flex-1">
                  <label className="block text-xs text-gray-500 mb-1">Supabase URL</label>
                  <input
                    type="text"
                    placeholder="https://xxxx.supabase.co"
                    className="w-full bg-gray-900 text-green-300 border border-gray-600 rounded px-3 py-1.5 text-sm focus:outline-none focus:border-green-500 text-left font-mono"
                    dir="ltr"
                    value={supabaseUrl}
                    onChange={(e) => setSupabaseUrl(e.target.value)}
                    disabled={isRunning}
                  />
                </div>
                <div className="flex-1">
                  <label className="block text-xs text-gray-500 mb-1">Anon Key / API Key</label>
                  <input
                    type="text"
                    placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                    className="w-full bg-gray-900 text-green-300 border border-gray-600 rounded px-3 py-1.5 text-sm focus:outline-none focus:border-green-500 text-left font-mono"
                    dir="ltr"
                    value={supabaseKey}
                    onChange={(e) => setSupabaseKey(e.target.value)}
                    disabled={isRunning}
                  />
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          
          {/* Left Column: Terminal & Tech Stack (Takes 2/3 width) */}
          <div className="lg:col-span-2 space-y-6">
            
            {/* Tech Stack Pills */}
            <div className="bg-gray-800 p-4 rounded-lg shadow-lg flex items-center gap-3 overflow-x-auto">
              <span className="text-gray-400 text-sm whitespace-nowrap">טכנולוגיות שזוהו:</span>
              {techStack.length === 0 ? (
                <span className="text-gray-600 text-sm">ממתין לסריקה...</span>
              ) : (
                techStack.map((tech, i) => (
                  <span key={i} className="px-3 py-1 bg-blue-900/50 text-blue-300 border border-blue-700 rounded-full text-sm">
                    {tech}
                  </span>
                ))
              )}
            </div>

            {/* Live Terminal */}
            <div className="bg-black border border-gray-700 rounded-lg shadow-lg h-96 flex flex-col">
              <div className="bg-gray-800 px-4 py-2 border-b border-gray-700 flex items-center gap-2 rounded-t-lg">
                <div className="w-3 h-3 rounded-full bg-red-500"></div>
                <div className="w-3 h-3 rounded-full bg-yellow-500"></div>
                <div className="w-3 h-3 rounded-full bg-green-500"></div>
                <span className="text-gray-400 text-xs ml-4 font-mono">agent_terminal_tty1</span>
              </div>
              <div className="p-4 flex-1 overflow-y-auto font-mono text-sm space-y-2">
                {logs.length === 0 && <span className="text-gray-600">Waiting for commands...</span>}
                {logs.map((log, i) => {
                  let color = "text-gray-300";
                  if (log.level === 'info') color = "text-blue-400";
                  if (log.level === 'success') color = "text-green-400";
                  if (log.level === 'warning') color = "text-yellow-400";
                  if (log.level === 'danger') color = "text-red-400";
                  if (log.level === 'system') color = "text-purple-400 font-bold";

                  return (
                    <div key={i} className="flex gap-3">
                      <span className="text-gray-600 flex-shrink-0">[{log.time}]</span>
                      <span className={`${color}`}>{log.msg}</span>
                    </div>
                  );
                })}
                <div ref={terminalEndRef} />
              </div>
            </div>
          </div>

          {/* Right Column: Findings */}
          <div className="bg-gray-800 rounded-lg shadow-lg p-5 flex flex-col h-full max-h-[500px]">
            <h2 className="text-xl font-bold text-white mb-4 border-b border-gray-700 pb-2">ממצאים וחולשות ({findings.length})</h2>
            <div className="flex-1 overflow-y-auto space-y-4 pr-2">
              {findings.length === 0 ? (
                <div className="text-center text-gray-500 mt-10">
                  <span className="text-4xl block mb-2">🛡️</span>
                  עדיין לא נמצאו חולשות
                </div>
              ) : (
                findings.map((f, i) => (
                  <div key={i} className="bg-gray-900 border border-red-900/50 rounded-lg p-4 relative overflow-hidden">
                    <div className="absolute top-0 right-0 w-1 h-full bg-red-500"></div>
                    <div className="flex justify-between items-start mb-2">
                      <h3 className="font-bold text-red-400">{f.title}</h3>
                      <span className="text-xs bg-red-500/20 text-red-300 px-2 py-1 rounded border border-red-500/30">
                        {f.severity.toUpperCase()}
                      </span>
                    </div>
                    <p className="text-sm text-gray-400 leading-relaxed">{f.description || f.desc}</p>
                  </div>
                ))
              )}
            </div>
          </div>

        </div>
      </div>
    </div>
  );
};

export default AutonomousAgentPage;