import Card from './Card'

export default function AsnIntelPanel({ data, loading }) {
  const rows = data || []

  return (
    <Card title="ASN Rollup">
      {loading && !rows.length ? (
        <p className="text-slate-500 text-sm text-center py-8">Loading…</p>
      ) : !rows.length ? (
        <p className="text-slate-500 text-sm text-center py-8">ASN rollups populate as events are processed</p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-[10px] uppercase tracking-wider text-slate-500 border-b border-surface-border">
                <th className="text-left py-2 px-2">ASN</th>
                <th className="text-left py-2 px-2">Organization</th>
                <th className="text-right py-2 px-2">IPs</th>
                <th className="text-right py-2 px-2">Avg risk</th>
                <th className="text-right py-2 px-2">High risk</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-surface-border/60">
              {rows.slice(0, 8).map((r) => (
                <tr key={r.asn} className="hover:bg-surface/40">
                  <td className="py-2 px-2 mono text-slate-300">{r.asn}</td>
                  <td className="py-2 px-2 text-slate-400 truncate max-w-[140px]">{r.org || '—'}</td>
                  <td className="py-2 px-2 text-right tabular-nums text-slate-300">{r.ip_count}</td>
                  <td className={`py-2 px-2 text-right tabular-nums font-bold ${r.avg_risk_score >= 60 ? 'text-red-400' : r.avg_risk_score >= 40 ? 'text-amber-400' : 'text-slate-300'}`}>
                    {Math.round(r.avg_risk_score)}
                  </td>
                  <td className="py-2 px-2 text-right tabular-nums text-red-400/90">{r.malicious_hits || 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}