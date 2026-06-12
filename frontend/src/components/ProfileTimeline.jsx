import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

export default function ProfileTimeline({ data }) {
  const chartData = (data || []).map((d) => ({
    time: new Date(d.bucket).toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit' }),
    events: Number(d.count),
  }))

  if (!chartData.length) {
    return <p className="text-slate-600 text-xs text-center py-8">No activity in this window</p>
  }

  return (
    <div className="h-48">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData}>
          <XAxis dataKey="time" tick={{ fill: '#64748b', fontSize: 9 }} interval="preserveStartEnd" />
          <YAxis tick={{ fill: '#64748b', fontSize: 10 }} allowDecimals={false} />
          <Tooltip
            contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8, fontSize: 11 }}
          />
          <Bar dataKey="events" fill="#38bdf8" radius={[4, 4, 0, 0]} name="Events" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}