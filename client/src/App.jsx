import { lazy, Suspense } from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import Layout from './components/layout/Layout';
const CoursesPage = lazy(() => import('./pages/CoursesPage'));

function PageLoader() {
  return (
    <div className="flex min-h-[50vh] items-center justify-center text-slate-500">
      טוען עמוד...
    </div>
  );
}

export default function App() {
  return (
    <Suspense fallback={<PageLoader />}>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Navigate to="courses" replace />} />
          <Route path="courses" element={<CoursesPage />} />
          <Route path="*" element={<Navigate to="/courses" replace />} />
        </Route>
        <Route path="*" element={<Navigate to="/courses" replace />} />
      </Routes>
    </Suspense>
  );
}
