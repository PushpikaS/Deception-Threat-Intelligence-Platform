import { formatTime, serviceLabel } from '../api'
import Card from './Card'
import { SkeletonTable } from './LoadingSkeleton'

export default function AttackChains({ chains, loading, onSelectIp }) {
  if (loading && (!chains || chains.length === 0)) {
    return (
      <Card title="Cross-Service Attack Chains">
        <SkeletonTable rows={3} cols={3} />
      </Card>
    )
  }

  return (
    <Card title="Cross-Service Attack Chains">
      <div className="space-y-3">
        {(chains || []).length === 0 ? (
          <p className="text-slate-500 text-sm text-center py-6">No cross-service chains detected</p>
        ) : (
          chains.map((c) => (
            <div
              key={c.id}
              className="p-3 bg-surface rounded-lg border border-surface-border hover:border-accent/20 transition-colors animate-in cursor-pointer"
              onClick={() => onSelectIp?.(c.ip)}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="mono text-sm text-accent">{c.ip}</span>
                <span className="text-xs text-accent-warn font-semibold">Risk {c.risk_score}</span>
              </div>
              <p className="text-xs text-slate-400 mb-2">{c.chain_summary}</p>
              <div className="flex gap-1 flex-wrap">
                {(c.services || []).map((s) => (
                  <span key={s} className="px-2 py-0.5 bg-accent/10 text-accent rounded text-[10px]">{serviceLabel(s)}</span>
                ))}
              </div>
              <p className="text-[10px] text-slate-600 mt-2">{formatTime(c.last_activity)}</p>
            </div>
          ))
        )}
      </div>
    </Card>
  )
}