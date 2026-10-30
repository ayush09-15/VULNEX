import { SEVERITY_LEVELS } from '../../types';

export default function SeverityBadge({ severity = 'INFO', size = 'sm', className = '' }) {
  const normSev = (severity || 'INFO').toUpperCase();
  const config = SEVERITY_LEVELS[normSev] || SEVERITY_LEVELS.INFO;

  const sizeClasses = size === 'xs'
    ? 'text-xs px-2 py-0.5'
    : size === 'md'
    ? 'text-sm px-3 py-1 font-semibold'
    : 'text-xs px-2.5 py-1 font-medium';

  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border ${config.bg} ${config.text} ${config.border} ${sizeClasses} ${className}`}
      role="status"
      aria-label={`Severity: ${config.label}`}
    >
      <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`} aria-hidden="true" />
      <span>{config.label}</span>
    </span>
  );
}
