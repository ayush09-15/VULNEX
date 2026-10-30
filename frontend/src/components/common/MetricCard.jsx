export default function MetricCard({
  title,
  value,
  subtext,
  icon: Icon,
  variant = 'default',
  trend = null,
  badge = null,
}) {
  const getVariantStyles = () => {
    switch (variant) {
      case 'danger':
        return 'border-red-900/40 bg-slate-900/80 hover:border-red-700/50';
      case 'warning':
        return 'border-amber-900/40 bg-slate-900/80 hover:border-amber-700/50';
      case 'success':
        return 'border-emerald-900/40 bg-slate-900/80 hover:border-emerald-700/50';
      case 'accent':
        return 'border-cyan-900/40 bg-slate-900/80 hover:border-cyan-700/50';
      default:
        return 'border-slate-800 bg-slate-900/80 hover:border-slate-700';
    }
  };

  const getIconStyles = () => {
    switch (variant) {
      case 'danger':
        return 'text-red-400 bg-red-950/40 border border-red-800/40';
      case 'warning':
        return 'text-amber-400 bg-amber-950/40 border border-amber-800/40';
      case 'success':
        return 'text-emerald-400 bg-emerald-950/40 border border-emerald-800/40';
      case 'accent':
        return 'text-cyan-400 bg-cyan-950/40 border border-cyan-800/40';
      default:
        return 'text-slate-300 bg-slate-800/60 border border-slate-700/60';
    }
  };

  return (
    <div
      className={`p-5 rounded-xl border backdrop-blur-sm transition-all duration-200 ${getVariantStyles()}`}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-semibold uppercase tracking-wider text-slate-400">
          {title}
        </span>
        {Icon && (
          <div className={`p-2 rounded-lg ${getIconStyles()}`}>
            <Icon className="w-4 h-4" />
          </div>
        )}
      </div>

      <div className="flex items-baseline justify-between">
        <div className="text-2xl font-bold tracking-tight text-slate-100 font-mono">
          {value}
        </div>
        {badge && (
          <span className="text-xs px-2 py-0.5 rounded font-mono font-medium bg-slate-800 text-slate-300 border border-slate-700">
            {badge}
          </span>
        )}
      </div>

      {(subtext || trend) && (
        <div className="mt-2 flex items-center justify-between text-xs text-slate-400">
          {subtext && <span>{subtext}</span>}
          {trend && (
            <span className={trend > 0 ? 'text-red-400' : 'text-emerald-400'}>
              {trend > 0 ? `+${trend}` : trend}
            </span>
          )}
        </div>
      )}
    </div>
  );
}
