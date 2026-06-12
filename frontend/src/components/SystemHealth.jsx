import Card from './Card'

const statusColor = {
  ok: 'text-accent-ok',
  degraded: 'text-accent-warn',
  stale: 'text-accent-danger',
}

export default function SystemHealth({ health, platform, loading }) {
  if (loading && !health) return null

  const apiOk = health?.status === 'healthy'
  const engine = platform?.status || 'unknown'

  return (
    <Card title="Platform Health">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
        <HealthItem label="Threat API" value={apiOk ? 'healthy' : health?.status} ok={apiOk} />
        <HealthItem label="Threat engine" value={engine} ok={engine === 'ok'} warn={engine === 'degraded'} />
        <HealthItem label="Engine lag" value={platform?.engine_lag ?? '—'} ok={(platform?.engine_lag ?? 99) <= 50} />
        <HealthItem label="Profiles" value={platform?.profiles_total?.toLocaleString() ?? '—'} ok />
      </div>
      {platform?.engine_lag > 50 && (
        <p className="text-[10px] text-amber-400/80 mt-3">
          Engine is {platform.engine_lag} events behind — processing will catch up automatically.
        </p>
      )}
    </Card>
  )
}

function HealthItem({ label, value, ok, warn }) {
  return (
    <div className="bg-surface rounded-lg p-3 border border-surface-border">
      <p className="text-slate-500 text-[10px] uppercase mb-1">{label}</p>
      <p className={`font-medium ${ok ? 'text-accent-ok' : warn ? 'text-accent-warn' : 'text-accent-danger'}`}>{value}</p>
    </div>
  )
}