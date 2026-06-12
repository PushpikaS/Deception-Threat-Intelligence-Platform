import Card from './Card'
import { SkeletonCard } from './LoadingSkeleton'

const items = [
  { key: 'total_events', label: 'Total Events', icon: '📡' },
  { key: 'events_last_hour', label: 'Last Hour', icon: '⚡' },
  { key: 'total_profiles', label: 'Attacker Profiles', icon: '👤' },
  { key: 'high_risk_profiles', label: 'High Risk', icon: '🔴', danger: true },
]

export default function StatsCards({ overview, loading }) {
  if (loading && !overview) {
    return (
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {items.map(({ key }) => <SkeletonCard key={key} />)}
      </div>
    )
  }

  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
      {items.map(({ key, label, icon, danger }) => (
        <Card key={key} className="hover:border-accent/20 transition-colors">
          <div className="flex items-start justify-between">
            <div>
              <p className="text-xs text-slate-500 uppercase tracking-wider mb-1">{label}</p>
              <p className={`text-2xl sm:text-3xl font-bold transition-all ${danger ? 'text-accent-danger' : 'text-white'}`}>
                {overview ? overview[key]?.toLocaleString() ?? '0' : '—'}
              </p>
            </div>
            <span className="text-2xl opacity-60">{icon}</span>
          </div>
        </Card>
      ))}
    </div>
  )
}