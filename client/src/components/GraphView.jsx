import React, { useRef, useEffect, useState, useMemo } from 'react';
import ForceGraph2D from 'react-force-graph-2d';
import { Maximize2, ZoomIn, ZoomOut } from 'lucide-react';

export default function GraphView({ caseData }) {
  const containerRef = useRef(null);
  const fgRef = useRef();
  const [dimensions, setDimensions] = useState({ width: 800, height: 600 });

  useEffect(() => {
    // Basic responsive handling
    const updateSize = () => {
      if (containerRef.current) {
        setDimensions({
          width: containerRef.current.offsetWidth,
          height: containerRef.current.offsetHeight
        });
      }
    };
    updateSize();
    window.addEventListener('resize', updateSize);
    return () => window.removeEventListener('resize', updateSize);
  }, []);

  // Transform case data into nodes and links
  const graphData = useMemo(() => {
    if (!caseData || !caseData.result) return { nodes: [], links: [] };
    
    const nodes = [];
    const links = [];
    const addedNodes = new Set();

    const addNode = (id, primary, group, color, val = 1) => {
      if (!id || addedNodes.has(id)) return;
      nodes.push({ id, primary, group, color, val });
      addedNodes.add(id);
    };

    const addLink = (source, target, label) => {
      if (!source || !target || !addedNodes.has(source) || !addedNodes.has(target)) return;
      links.push({ source, target, label });
    };

    // Center Node (Target)
    const rootId = caseData.subject;
    addNode(rootId, rootId, 'root', '#4f46e5', 5);

    const { found = {}, email_profiles = {}, phone_profiles = {} } = caseData.result;

    // Emails
    (found.emails || []).forEach(email => {
      addNode(email, email, 'email', '#ef4444', 2);
      addLink(rootId, email, 'has_email');
      
      const prof = email_profiles[email];
      if (prof) {
        if (prof.gravatar?.found) {
          const gId = `Gravatar-${email}`;
          addNode(gId, 'Gravatar Details', 'gravatar', '#22c55e', 1);
          addLink(email, gId, 'from_gravatar');
        }
        if (prof.github?.found) {
          const ghId = `GitHub-${prof.github.username}`;
          addNode(ghId, `GitHub: ${prof.github.username}`, 'github', '#1e293b', 2);
          addLink(email, ghId, 'github_profile');
        }
      }
    });

    // Phones
    (found.phones || []).forEach(phone => {
      addNode(phone, phone, 'phone', '#f59e0b', 2);
      addLink(rootId, phone, 'has_phone');

      const prof = phone_profiles[phone];
      if (prof) {
        if (prof.telegram) {
          addNode(`TG-${phone}`, 'Telegram', 'app', '#3b82f6', 1);
          addLink(phone, `TG-${phone}`, 'has_telegram');
        }
        if (prof.whatsapp) {
          addNode(`WA-${phone}`, 'WhatsApp', 'app', '#22c55e', 1);
          addLink(phone, `WA-${phone}`, 'has_whatsapp');
        }
      }
    });

    // Usernames
    (found.usernames || []).forEach(uname => {
      addNode(`usr-${uname}`, uname, 'username', '#3b82f6', 1.5);
      addLink(rootId, `usr-${uname}`, 'used_username');
    });

    // Companies
    (found.companies || []).forEach(comp => {
      addNode(`comp-${comp}`, comp, 'company', '#a855f7', 2);
      addLink(rootId, `comp-${comp}`, 'related_to_company');
    });

    return { nodes, links };
  }, [caseData]);

  const handleCenter = () => {
    if (fgRef.current) {
      fgRef.current.zoomToFit(400, 50);
    }
  };

  return (
    <div ref={containerRef} className="relative w-full h-[600px] bg-slate-50 border border-slate-200 rounded-xl overflow-hidden shadow-inner">
      {/* Overlay Toolbar */}
      <div className="absolute top-4 right-4 z-10 flex flex-col gap-2">
        <button 
          onClick={handleCenter}
          className="p-2 bg-white rounded-lg shadow border border-slate-200 text-slate-600 hover:text-indigo-600 focus:outline-none transition-colors"
          title="מכז תצוגה"
        >
          <Maximize2 size={18} />
        </button>
      </div>

      <ForceGraph2D
        ref={fgRef}
        width={dimensions.width}
        height={dimensions.height}
        graphData={graphData}
        nodeLabel="primary"
        nodeColor={node => node.color}
        nodeRelSize={4}
        linkColor={() => '#cbd5e1'}
        linkWidth={1.5}
        d3VelocityDecay={0.6}
        cooldownTicks={100}
        onEngineStop={handleCenter}
        nodeCanvasObject={(node, ctx, globalScale) => {
          const label = node.primary;
          const fontSize = 12/globalScale;
          ctx.font = `${fontSize}px Sans-Serif`;
          const textWidth = ctx.measureText(label).width;
          const bckgDimensions = [textWidth, fontSize].map(n => n + fontSize * 0.2);

          ctx.fillStyle = 'rgba(255, 255, 255, 0.8)';
          ctx.fillRect(node.x - bckgDimensions[0] / 2, node.y - bckgDimensions[1] / 2 - 8/globalScale, bckgDimensions[0], bckgDimensions[1]);

          ctx.textAlign = 'center';
          ctx.textBaseline = 'middle';
          ctx.fillStyle = node.color;
          
          // Draw circle
          ctx.beginPath();
          ctx.arc(node.x, node.y, 4, 0, 2 * Math.PI, false);
          ctx.fill();

          // Draw Text
          ctx.fillText(label, node.x, node.y - 8/globalScale);
        }}
      />
      
      {/* Legend */}
      <div className="absolute bottom-4 left-4 z-10 bg-white/90 backdrop-blur p-3 rounded-lg border border-slate-200 shadow-sm text-xs space-y-1">
        <div className="font-bold text-slate-700 mb-2">מקרא</div>
        <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-[#4f46e5]"></span>יעד חקירה</div>
        <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-[#ef4444]"></span>אימייל</div>
        <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-[#f59e0b]"></span>טלפון</div>
        <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-[#3b82f6]"></span>Username</div>
        <div className="flex items-center gap-2"><span className="w-3 h-3 rounded-full bg-[#a855f7]"></span>חברה / ארגון</div>
      </div>
    </div>
  );
}
