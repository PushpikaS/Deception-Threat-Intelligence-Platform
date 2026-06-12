import { useMemo, useState } from 'react'
import { riskBg, riskColor, tagLabel, formatTime, sortBy, exportCSV } from '../api'
import Card from './Card'
import { SkeletonTable } from './LoadingSkeleton'

export default function ProfilesTable({ profiles, loading, onSelectIp }) {
  const [search, setSearch] = useState('')
  const [minRisk, setMinRisk] = useState(0)
  const [sortKey, setSortKey] = useState('risk_score')
  const [sortDir, setSortDir] = useState('desc')

  const filtered = useMemo(() => {
    let items = profiles || []
    if (search) {
      const q = search.toLowerCase()
      items = items.filter((p) =>
        p.ip?.toLowerCase().includes(q) ||
        p.geo_country?.toLowerCase().includes(q) ||
        p.geo_city?.toLowerCase().includes(q) ||
        p.geo_isp?.toLowerCase().includes(q) ||
        (p.behavior_tags || []).some((t) => t.includes(q))
      )
    }
    if (minRisk > 0) items = items.filter((p) => p.risk_score >= minRisk)
    return sortBy(items, sortKey, sortDir)
  }, [profiles, search, minRisk, sortKey, sortDir])

  const blocklistCount = useMemo(
    () => (profiles || []).filter((p) => p.risk_score >= 20).length,
    [profiles],
  )

  const filtersActive = Boolean(search || minRisk > 0)
  const clearFilters = () => {
    setSearch('')
    setMinRisk(0)
  }

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir((d) => (d === 'desc' ? 'asc' : 'desc'))
    else { setSortKey(key); setSortDir('desc') }
  }

  const SortIcon = ({ col }) => sortKey === col ? (sortDir === 'desc' ? ' ↓' : ' ↑') : ''

  return (
    <Card
      title="Attacker Profiles"
      actions={
        <>
          <button
            onClick={() => exportCSV('/export/blocklist.txt?min_risk=20', 'blocklist.txt')}
            className="px-2 py-1 text-[10px] font-medium bg-surface-border hover:bg-slate-600 rounded transition-colors tooltip"
            title={blocklistCount ? `${blocklistCount} profile(s) at risk ≥ 20` : 'No profiles at risk ≥ 20 yet'}
          >
            Blocklist{blocklistCount ? ` (${blocklistCount})` : ''}
          </button>
          <button
            onClick={() => exportCSV('/export/profiles.csv', 'profiles.csv')}
            className="px-2 py-1 text-[10px] font-medium bg-surface-border hover:bg-slate-600 rounded transition-colors"
          >
            Export CSV
          </button>
        </>
      }
    >
      <div className="flex flex-wrap gap-3 mb-4">
        <input
          type="text"
          placeholder="Search IP, country, ISP, tags…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 min-w-[200px] px-3 py-1.5 text-xs bg-surface border border-surface-border rounded-md text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-accent/50"
        />
        <select
          value={minRisk}
          onChange={(e) => setMinRisk(Number(e.target.value))}
          className="px-3 py-1.5 text-xs bg-surface border border-surface-border rounded-md text-slate-300"
        >
          <option value={0}>All risk levels</option>
          <option value={20}>Risk ≥ 20</option>
          <option value={40}>Risk ≥ 40</option>
          <option value={60}>Risk ≥ 60</option>
        </select>
        {filtersActive && (
          <button
            type="button"
            onClick={clearFilters}
            className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 border border-surface-border rounded-md hover:bg-surface-border/50"
          >
            Clear filters
          </button>
        )}
      </div>

      {loading ? <SkeletonTable rows={6} cols={7} /> : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-slate-500 uppercase tracking-wider">
                <th className="pb-3 pr-4 cursor-pointer hover:text-slate-300" onClick={() => toggleSort('ip')}>IP<SortIcon col="ip" /></th>
                <th className="pb-3 pr-4 cursor-pointer hover:text-slate-300" onClick={() => toggleSort('risk_score')}>Risk<SortIcon col="risk_score" /></th>
                <th className="pb-3 pr-4">Location</th>
                <th className="pb-3 pr-4 tooltip">
                  Behavior / MITRE
                  <span className="tooltip-text">MITRE ATT&CK techniques mapped from detected behavior</span>
                </th>
                <th className="pb-3 pr-4 cursor-pointer hover:text-slate-300" onClick={() => toggleSort('total_requests')}>Requests<SortIcon col="total_requests" /></th>
                <th className="pb-3 pr-4">ISP / ASN</th>
                <th className="pb-3 cursor-pointer hover:text-slate-300" onClick={() => toggleSort('last_seen')}>Last Seen<SortIcon col="last_seen" /></th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={7} className="py-8 text-center text-slate-500">No profiles match filters</td></tr>
              ) : (
                filtered.map((p) => (
                  <tr
                    key={p.ip}
                    className="border-t border-surface-border hover:bg-surface/30 transition-colors cursor-pointer"
                    onClick={() => onSelectIp?.(p.ip)}
                  >
                    <td className="py-3 pr-4 mono text-accent tooltip">
                      {p.ip}
                      <span className="tooltip-text">Click for full profile · First seen: {formatTime(p.first_seen)}</span>
                    </td>
                    <td className="py-3 pr-4">
                      <span className={`inline-flex px-2 py-0.5 rounded text-xs font-semibold border ${riskBg(p.risk_score)} ${riskColor(p.risk_score)}`}>
                        {p.risk_score}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-xs text-slate-400">
                      {p.geo_city
                        ? [p.geo_city, p.geo_region, p.geo_country_code || p.geo_country].filter(Boolean).join(', ')
                        : p.geo_country || '—'}
                    </td>
                    <td className="py-3 pr-4">
                      <div className="flex flex-wrap gap-1">
                        {(p.behavior_tags || []).slice(0, 2).map((t) => (
                          <span key={t} className="px-1.5 py-0.5 bg-surface-border rounded text-[10px] text-slate-400">
                            {tagLabel(t)}
                          </span>
                        ))}
                        {(p.metadata?.mitre_techniques || []).slice(0, 2).map((t) => (
                          <span key={t.id} className="px-1.5 py-0.5 bg-purple-500/10 text-purple-400 rounded text-[10px] tooltip">
                            {t.id}
                            <span className="tooltip-text">{t.name} — {t.tactic}</span>
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 pr-4 text-slate-400">{p.total_requests}</td>
                    <td className="py-3 pr-4 text-[10px] text-slate-500 max-w-[140px] truncate tooltip">
                      {p.geo_isp || '—'}
                      <span className="tooltip-text">{p.geo_asn || 'Unknown ASN'}</span>
                    </td>
                    <td className="py-3 text-slate-500 text-xs">{formatTime(p.last_seen)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  )
}