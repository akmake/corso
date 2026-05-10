import { Outlet } from 'react-router-dom';
import Navbar from './Navbar';

export default function Layout() {
  return (
    <div className="min-h-screen flex flex-col bg-slate-100 text-slate-900">
      <Navbar />
      <main className="flex-grow pt-24">
        <Outlet />
      </main>
      <footer className="border-t border-slate-200 bg-white py-6 text-center text-sm text-slate-500">
        <p>© {new Date().getFullYear()} WEBINT Platform</p>
      </footer>
    </div>
  );
}
