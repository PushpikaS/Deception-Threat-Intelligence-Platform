import { useMemo, useState } from 'react'
import { formatTime, serviceLabel, sortBy, exportCSV } from '../api'
import Card from './Card'
import EventThreatCell from './EventThreatCell'
import { SkeletonTable } from './LoadingSkeleton'

const serviceColors = {
  'honeypot-web': 'text-purple-400',
  'honeypot-api': 'text-accent',
  'honeypot-auth': 'text-amber-400',
}

export default function EventsFeed({ events, loading, onSelectIp }) {
  const [search, setSearch] = useState('')
  const [serviceFilter, setServiceFilter] = useState('')
  const [sortKey, setSortKey] = useState('created_at')
  const [sortDir, setSortDir] = useState('desc')

  const filtered = useMemo(() => {
    let items = events || []
    if (search) {
      const q = search.toLowerCase()
      items = items.filter((e) =>
        e.ip?.toLowerCase().includes(q) ||
        e.endpoint?.toLowerCase().includes(q) ||
        e.method?.toLowerCase().includes(q)
      )
    }
    if (serviceFilter) items = items.filter((e) => e.service === serviceFilter)
    return sortBy(items, sortKey, sortDir)
  }, [events, search, serviceFilter, sortKey, sortDir])

  const services = useMemo(() => [...new Set((events || []).map((e) => e.service))], [events])
  const filtersActive = Boolean(search || serviceFilter)
  const clearFilters = () => {
    setSearch('')
    setServiceFilter('')
  }

  const toggleSort = (key) => {
    if (sortKey === key) setSortDir((d) => (d === 'desc' ? 'asc' : 'desc'))
    else { setSortKey(key); setSortDir('desc') }
  }

  return (
    <Card
      title="Event Stream"
      actions={
        <button
          onClick={() => exportCSV('/export/events.csv', 'events.csv')}
          className="px-2 py-1 text-[10px] font-medium bg-surface-border hover:bg-slate-600 rounded transition-colors"
        >
          Export CSV
        </button>
      }
    >
      <div className="flex flex-wrap gap-3 mb-4">
        <input
          type="text"
          placeholder="Search IP, endpoint, method…"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="flex-1 min-w-[200px] px-3 py-1.5 text-xs bg-surface border border-surface-border rounded-md text-slate-300 placeholder:text-slate-600 focus:outline-none focus:border-accent/50"
        />
        <select
          value={serviceFilter}
          onChange={(e) => setServiceFilter(e.target.value)}
          className="px-3 py-1.5 text-xs bg-surface border border-surface-border rounded-md text-slate-300"
        >
          <option value="">All services</option>
          {services.map((s) => <option key={s} value={s}>{serviceLabel(s)}</option>)}
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

      {loading ? <SkeletonTable rows={8} cols={7} /> : (
        <div className="overflow-x-auto max-h-96 overflow-y-auto">
          <table className="w-full text-sm">
            <thead className="sticky top-0 bg-surface-light">
              <tr className="text-left text-xs text-slate-500 uppercase tracking-wider">
                <th className="pb-3 pr-4 cursor-pointer hover:text-slate-300" onClick={() => toggleSort('created_at')}>Time</th>
                <th className="pb-3 pr-4">Service</th>
                <th className="pb-3 pr-4 cursor-pointer hover:text-slate-300" onClick={() => toggleSort('ip')}>IP</th>
                <th className="pb-3 pr-4">Method</th>
                <th className="pb-3 pr-4">Endpoint</th>
                <th className="pb-3 pr-4">Threat / MITRE</th>
                <th className="pb-3">Status</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr><td colSpan={7} className="py-8 text-center text-slate-500">No events match filters</td></tr>
              ) : (
                filtered.map((e) => (
                  <tr key={e.id} className="border-t border-surface-border hover:bg-surface/30 transition-colors animate-in">
                    <td className="py-2.5 pr-4 text-xs text-slate-500 whitespace-nowrap">{formatTime(e.created_at)}</td>
                    <td className={`py-2.5 pr-4 text-xs font-medium ${serviceColors[e.service] || 'text-slate-400'}`}>{serviceLabel(e.service)}</td>
                    <td
                      className="py-2.5 pr-4 mono text-xs text-slate-300 cursor-pointer hover:text-accent"
                      onClick={() => onSelectIp?.(e.ip)}
                    >{e.ip}</td>
                    <td className="py-2.5 pr-4 text-xs text-slate-400">{e.method}</td>
                    <td className="py-2.5 pr-4 mono text-xs text-slate-400 truncate max-w-xs">{e.endpoint}</td>
                    <td className="py-2.5 pr-4 text-xs max-w-[220px]" onClick={(ev) => ev.stopPropagation()}>
                      <EventThreatCell event={e} />
                    </td>
                    <td className="py-2.5 text-xs">{e.status_code}</td>
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