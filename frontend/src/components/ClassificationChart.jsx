import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import Card from './Card'
import { SkeletonCard } from './LoadingSkeleton'

const COLORS = ['#ef4444', '#f59e0b', '#38bdf8', '#a78bfa', '#22c55e', '#ec4899', '#f97316', '#64748b']

export default function ClassificationChart({ overview, loading }) {
  const data = (overview?.by_classification || []).map((d) => ({
    name: d.classification.replace(/_/g, ' '),
    count: Number(d.count),
  }))

  if (loading && data.length === 0) {
    return (
      <Card title="Behavior Classification">
        <div className="h-64"><SkeletonCard /></div>
      </Card>
    )
  }

  return (
    <Card title="Behavior Classification">
      <div className="h-64">
        {data.length === 0 ? (
          <p className="text-slate-500 text-sm text-center py-16">Classifications appear as the engine processes events.</p>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} layout="vertical" margin={{ left: 90 }}>
              <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 10 }} width={85} />
              <Tooltip contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }} />
              <Bar dataKey="count" radius={[0, 4, 4, 0]} animationDuration={800}>
                {data.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        )}
      </div>
    </Card>
  )
}