import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import SidebarNav from './SidebarNav';
import HeaderBar from './HeaderBar';

export default function AppShell() {
  const [collapsed, setCollapsed] = useState(false);
  const [activeRepo, setActiveRepo] = useState(null);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Fixed Left Navigation */}
      <SidebarNav
        collapsed={collapsed}
        onToggle={() => setCollapsed((prev) => !prev)}
      />

      {/* Top Header Bar */}
      <HeaderBar
        collapsed={collapsed}
        activeRepo={activeRepo}
      />

      {/* Main Responsive Content Area */}
      <main
        className={`flex-1 pt-16 transition-all duration-300 ${
          collapsed ? 'pl-20' : 'pl-64'
        }`}
      >
        <div className="max-w-7xl mx-auto p-6 md:p-8">
          <Outlet context={{ activeRepo, setActiveRepo }} />
        </div>
      </main>
    </div>
  );
}
