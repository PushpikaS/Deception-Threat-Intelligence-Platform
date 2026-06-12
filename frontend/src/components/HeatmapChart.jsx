import Card from './Card'

const CLASS_COLORS = {
  sqli_attempt: '#ef4444',
  rce_attempt: '#dc2626',
  malware_indicator: '#b91c1c',
  honeytoken_trigger: '#f97316',
  brute_force: '#f59e0b',
  credential_stuffing: '#eab308',
  scanner_tool: '#38bdf8',
  cross_service_probe: '#a78bfa',
  anomalous_velocity: '#ec4899',
  reconnaissance: '#64748b',
}

export default function HeatmapChart({ data }) {
  const buckets = [...new Set((data || []).map((d) => d.bucket))].sort()
  const types = [...new Set((data || []).map((d) => d.classification))]
  const lookup = {}
  let maxCount = 1
  for (const d of data || []) {
    const key = `${d.bucket}|${d.classification}`
    lookup[key] = Number(d.count)
    maxCount = Math.max(maxCount, Number(d.count))
  }

  if (buckets.length === 0) {
    return (
      <Card title="Threat Heatmap (24h)">
        <p className="text-slate-500 text-sm text-center py-12">Heatmap populates as classifications accumulate</p>
      </Card>
    )
  }

  const displayBuckets = buckets.slice(-12)

  return (
    <Card title="Threat Heatmap (24h)">
      <div className="overflow-x-auto">
        <div className="min-w-[500px]">
          <div className="flex gap-1 mb-2">
            <div className="w-24 shrink-0" />
            {displayBuckets.map((b) => (
              <div key={b} className="flex-1 text-center text-[9px] text-slate-600 truncate">
                {new Date(b).toLocaleTimeString([], { hour: '2-digit' })}
              </div>
            ))}
          </div>
          {types.map((type) => (
            <div key={type} className="flex gap-1 mb-1 items-center">
              <div className="w-24 shrink-0 text-[10px] text-slate-500 truncate pr-1" title={type}>
                {type.replace(/_/g, ' ')}
              </div>
              {displayBuckets.map((b) => {
                const count = lookup[`${b}|${type}`] || 0
                const intensity = count / maxCount
                const color = CLASS_COLORS[type] || '#64748b'
                return (
                  <div
                    key={`${b}-${type}`}
                    className="flex-1 h-5 rounded-sm transition-all duration-300 tooltip"
                    style={{
                      backgroundColor: count > 0 ? color : '#1e293b',
                      opacity: count > 0 ? 0.3 + intensity * 0.7 : 0.3,
                    }}
                    title={`${type}: ${count} at ${new Date(b).toLocaleString()}`}
                  />
                )
              })}
            </div>
          ))}
        </div>
      </div>
    </Card>
  )
}