import { useState } from 'react'
import { fetchJSON, formatTime, tagLabel } from '../api'
import Card from './Card'

export default function GlobalSearch({ onSelectIp }) {
  const [q, setQ] = useState('')
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [lastQuery, setLastQuery] = useState('')

  const clearSearch = () => {
    setQ('')
    setResults(null)
    setLastQuery('')
  }

  const handleQueryChange = (e) => {
    const next = e.target.value
    setQ(next)
    if (!next.trim()) {
      setResults(null)
      setLastQuery('')
    }
  }

  const search = async (e) => {
    e.preventDefault()
    const trimmed = q.trim()
    if (!trimmed) {
      clearSearch()
      return
    }
    setLoading(true)
    try {
      const data = await fetchJSON(`/search?q=${encodeURIComponent(trimmed)}`)
      setResults(data)
      setLastQuery(trimmed)
    } catch {
      setResults(null)
      setLastQuery('')
    } finally {
      setLoading(false)
    }
  }

  const hasActiveSearch = Boolean(lastQuery || results)

  return (
    <Card title="Global Search">
      <form onSubmit={search} className="flex gap-2 mb-4">
        <input
          type="text"
          value={q}
          onChange={handleQueryChange}
          onKeyDown={(e) => {
            if (e.key === 'Escape') clearSearch()
          }}
          placeholder="IP, endpoint, classification, country…"
          className="flex-1 px-3 py-2 text-xs bg-surface border border-surface-border rounded-md text-slate-300"
        />
        <button
          type="submit"
          disabled={loading || !q.trim()}
          className="px-4 py-2 text-xs font-medium bg-surface-border rounded-md hover:bg-slate-600 disabled:opacity-50"
        >
          {loading ? '…' : 'Search'}
        </button>
        {hasActiveSearch && (
          <button
            type="button"
            onClick={clearSearch}
            className="px-3 py-2 text-xs font-medium text-slate-400 hover:text-slate-200 rounded-md border border-surface-border hover:bg-surface-border/50"
          >
            Clear
          </button>
        )}
      </form>
      {results && (
        <div>
          <p className="text-[10px] text-slate-500 mb-3">
            Results for <span className="text-slate-300 mono">&quot;{lastQuery}&quot;</span>
          </p>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-xs">
            <ResultCol title="Profiles" empty={!results.profiles?.length}>
              {results.profiles?.map((p) => (
                <button key={p.ip} onClick={() => onSelectIp?.(p.ip)} className="block w-full text-left py-1.5 hover:text-accent mono">
                  {p.ip} <span className="text-slate-500">({p.risk_score})</span>
                </button>
              ))}
            </ResultCol>
            <ResultCol title="Events" empty={!results.events?.length}>
              {results.events?.map((ev) => (
                <div key={ev.id} className="py-1.5 text-slate-400 truncate">
                  <button onClick={() => onSelectIp?.(ev.ip)} className="mono text-accent hover:underline">{ev.ip}</button>
                  {' '}{ev.endpoint}
                </div>
              ))}
            </ResultCol>
            <ResultCol title="Classifications" empty={!results.classifications?.length}>
              {results.classifications?.map((c, i) => (
                <div key={i} className="py-1.5">
                  <span className="text-red-400">{tagLabel(c.classification)}</span>
                  <span className="text-slate-500 mono ml-1">{c.ip}</span>
                  <span className="text-slate-600 block text-[10px]">{formatTime(c.last_seen)}</span>
                </div>
              ))}
            </ResultCol>
          </div>
        </div>
      )}
    </Card>
  )
}

function ResultCol({ title, children, empty }) {
  return (
    <div className="bg-surface rounded-lg p-3 border border-surface-border max-h-40 overflow-y-auto">
      <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-2">{title}</p>
      {empty ? <p className="text-slate-600">No matches</p> : children}
    </div>
  )
}