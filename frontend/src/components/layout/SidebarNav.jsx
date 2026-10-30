import { NavLink } from 'react-router-dom';
import {
  LayoutDashboard,
  GitBranch,
  ShieldAlert,
  Search,
  Wrench,
  FileText,
  Settings,
  Shield,
  ChevronLeft,
  ChevronRight
} from 'lucide-react';

const NAV_ITEMS = [
  { name: 'Overview', to: '/overview', icon: LayoutDashboard },
  { name: 'Repositories', to: '/repositories', icon: GitBranch },
  { name: 'Scan Engine', to: '/scan', icon: ShieldAlert },
  { name: 'Findings Explorer', to: '/findings', icon: Search },
  { name: 'Remediation', to: '/remediation', icon: Wrench },
  { name: 'Reports', to: '/reports', icon: FileText },
  { name: 'Settings', to: '/settings', icon: Settings },
];

export default function SidebarNav({ collapsed, onToggle }) {
  return (
    <aside
      className={`fixed top-0 left-0 z-30 h-screen bg-slate-950 border-r border-slate-800 transition-all duration-300 flex flex-col ${
        collapsed ? 'w-20' : 'w-64'
      }`}
      aria-label="Main Navigation"
    >
      {/* Brand Header */}
      <div className="h-16 flex items-center justify-between px-4 border-b border-slate-800/80">
        <div className="flex items-center gap-3 overflow-hidden">
          <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-white shadow-lg shadow-cyan-950/50 flex-shrink-0">
            <Shield className="w-5 h-5 text-white" />
          </div>
          {!collapsed && (
            <div className="flex flex-col">
              <span className="font-bold tracking-wider text-base text-slate-100 font-mono">
                VULNEX
              </span>
              <span className="text-[10px] text-cyan-400 font-medium tracking-tight">
                AI APPSEC REMEDIATION
              </span>
            </div>
          )}
        </div>
        <button
          onClick={onToggle}
          className="p-1.5 rounded-lg text-slate-400 hover:text-slate-200 hover:bg-slate-800/60 focus:outline-none focus:ring-2 focus:ring-cyan-500 transition-colors"
          title={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
          aria-label={collapsed ? 'Expand Sidebar' : 'Collapse Sidebar'}
        >
          {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* Navigation Links */}
      <nav className="flex-1 px-3 py-4 space-y-1.5 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon;
          return (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm font-medium transition-all duration-200 group focus:outline-none focus:ring-2 focus:ring-cyan-500 ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900 border border-transparent'
                }`
              }
              title={collapsed ? item.name : undefined}
            >
              <Icon className="w-5 h-5 flex-shrink-0 transition-transform group-hover:scale-105" />
              {!collapsed && <span className="truncate">{item.name}</span>}
            </NavLink>
          );
        })}
      </nav>

      {/* Closed Remediation Loop Badge / Footer */}
      {!collapsed ? (
        <div className="p-4 m-3 rounded-xl bg-slate-900/60 border border-slate-800/80">
          <div className="flex items-center gap-2 mb-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
              Core Loop
            </span>
          </div>
          <div className="text-[11px] font-mono text-slate-400 space-y-1">
            <div className="text-cyan-400">DETECT ➔ INVESTIGATE</div>
            <div className="text-blue-400">PATCH ➔ VERIFY</div>
          </div>
          <div className="mt-2.5 pt-2 border-t border-slate-800 text-[10px] text-slate-500 leading-tight">
            Human-supervised deterministic proof
          </div>
        </div>
      ) : (
        <div className="p-2 mb-2 flex justify-center">
          <div className="w-2.5 h-2.5 rounded-full bg-emerald-400" title="Core Loop Active" />
        </div>
      )}
    </aside>
  );
}
