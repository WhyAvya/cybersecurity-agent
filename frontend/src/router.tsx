import { createBrowserRouter, type RouteObject } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { Dashboard } from './pages/Dashboard';
import { Health } from './pages/Health';
import { NewScan } from './pages/NewScan';
import { PlaceholderPage } from './pages/PlaceholderPage';
import { ScanProgressPage } from './pages/ScanProgressPage';

export const routes: RouteObject[] = [
  {
    path: '/',
    element: <AppShell />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'scan', element: <NewScan /> },
      { path: 'scan/:scanId', element: <ScanProgressPage /> },
      { path: 'compare', element: <PlaceholderPage title="Compare Modes" description="Comparison UI is a later phase and will not display accuracy metrics for arbitrary scans." /> },
      { path: 'evaluation', element: <PlaceholderPage title="Frozen Evaluation" description="The page shell is ready; full artifact presentation is deferred beyond Phase 1." /> },
      { path: 'health', element: <Health /> },
      { path: 'about', element: <PlaceholderPage title="About Project" description="Project context and limitations will be expanded without changing backend behavior." /> },
    ],
  },
];

export const router = createBrowserRouter(routes);
