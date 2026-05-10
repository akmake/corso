import { Link, NavLink } from 'react-router-dom';
import { GraduationCap, Zap } from 'lucide-react';

export default function Navbar() {
  return (
    <nav className="fixed inset-x-0 top-0 z-50 border-b border-slate-200/70 bg-white/90 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3 sm:px-6">
        <Link to="/courses" className="flex items-center gap-2.5 select-none">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-600 to-teal-700 text-white shadow-sm">
            <Zap size={17} strokeWidth={2.4} />
          </div>
          <div>
            <p className="text-[11px] font-black tracking-[0.24em] text-slate-900 uppercase">WEBINT</p>
            <p className="text-[10px] text-slate-500">Courses Workspace</p>
          </div>
        </Link>

        <NavLink
          to="/courses"
          className={({ isActive }) =>
            `inline-flex items-center gap-2 rounded-xl border px-3 py-2 text-xs font-bold transition ${
              isActive
                ? 'border-cyan-300 bg-cyan-50 text-cyan-700'
                : 'border-slate-200 bg-white text-slate-600 hover:bg-slate-50'
            }`
          }
        >
          <GraduationCap size={14} />
          קורסים
        </NavLink>
      </div>
    </nav>
  );
}
