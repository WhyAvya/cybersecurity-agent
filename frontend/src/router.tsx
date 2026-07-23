import { createBrowserRouter, type RouteObject } from 'react-router-dom';
import { AppShell } from './components/AppShell';
import { Dashboard } from './pages/Dashboard';
import { About } from './pages/About';
import { CompareModes } from './pages/CompareModes';
import { Evaluation } from './pages/Evaluation';
import { Health } from './pages/Health';
import { NewScan } from './pages/NewScan';
import { ScanProgressPage } from './pages/ScanProgressPage';

export const routes: RouteObject[] = [
  {
    path: '/',
    element: <AppShell />,
    children: [
      { index: true, element: <Dashboard /> },
      { path: 'scan', element: <NewScan /> },
      { path: 'scan/:scanId', element: <ScanProgressPage /> },
      { path: 'compare', element: <CompareModes /> },
      { path: 'evaluation', element: <Evaluation /> },
      { path: 'health', element: <Health /> },
      { path: 'about', element: <About /> },
    ],
  },
];

export const router = createBrowserRouter(routes);
