import { mitreUrl, splitEventThreat, tagLabel } from '../api'

export default function EventThreatCell({ event, compact = false }) {
  const { primary, secondary, primaryMitre, secondaryMitre } = splitEventThreat(event)

  if (!primary) {
    return <span className="text-slate-600">—</span>
  }

  return (
    <div className={`flex flex-col ${compact ? 'gap-0.5' : 'gap-1'}`}>
      <div className="flex items-center gap-1.5 flex-wrap">
        <span className="text-[10px] font-semibold text-red-400 uppercase tracking-wide">
          {tagLabel(primary.classification)}
        </span>
        {primary.confidence != null && (
          <span className="text-[9px] text-slate-500">{Math.round(primary.confidence * 100)}%</span>
        )}
      </div>

      {primaryMitre.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {primaryMitre.map((t) => (
            <a
              key={t.id}
              href={mitreUrl(t.id)}
              target="_blank"
              rel="noopener noreferrer"
              className="mono text-[10px] font-medium text-purple-400 hover:text-purple-300"
              title={t.name}
            >
              {t.id}
            </a>
          ))}
        </div>
      )}

      {secondary.length > 0 && (
        <div className="flex flex-wrap gap-1 items-center">
          <span className="text-[9px] text-slate-600">+</span>
          {secondary.map((c) => (
            <span
              key={c.classification}
              className="text-[9px] text-slate-500 bg-surface-border/60 px-1.5 py-0.5 rounded"
              title={c.confidence != null ? `${Math.round(c.confidence * 100)}% confidence` : undefined}
            >
              {tagLabel(c.classification)}
            </span>
          ))}
        </div>
      )}

      {!compact && secondaryMitre.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {secondaryMitre.slice(0, 4).map((t) => (
            <a
              key={t.id}
              href={mitreUrl(t.id)}
              target="_blank"
              rel="noopener noreferrer"
              className="mono text-[9px] text-slate-500 hover:text-slate-400"
              title={`${t.name} (context)`}
            >
              {t.id}
            </a>
          ))}
        </div>
      )}
    </div>
  )
}