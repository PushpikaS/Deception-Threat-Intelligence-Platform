import { useEffect, useState } from 'react'
import {
  fetchProfile, fetchProfileTimeline, formatCoordinates, formatGeoLocation, formatTime,
  isEstimatedGeo, riskBg, riskColor, tagLabel,
  mitreUrl, exportCSV, copyText, firewallRule, splitBehaviorTags,
} from '../api'
import ProfileTimeline from './ProfileTimeline'
import EventThreatCell from './EventThreatCell'
const TABS = ['overview', 'timeline', 'events', 'classifications', 'mitre', 'actions']

export default function ProfileDetailModal({ ip, onClose }) {
  const [data, setData] = useState(null)
  const [timeline, setTimeline] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [tab, setTab] = useState('overview')
  const [copied, setCopied] = useState('')

  useEffect(() => {
    if (!ip) return
    setLoading(true)
    setError(null)
    setTab('overview')
    Promise.all([fetchProfile(ip), fetchProfileTimeline(ip)])
      .then(([profileData, tl]) => {
        setData(profileData)
        setTimeline(tl)
      })
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false))
  }, [ip])

  useEffect(() => {
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const doCopy = async (label, text) => {
    await copyText(text)
    setCopied(label)
    setTimeout(() => setCopied(''), 2000)
  }

  if (!ip) return null

  const profile = data?.profile
  const meta = profile?.metadata || {}
  const techniques = meta.mitre_techniques || []
  const contextClassifications = meta.context_classifications || []
  const { event: eventTags, context: contextTags } = splitBehaviorTags(profile?.behavior_tags || [])

  return (
    <div className="fixed inset-0 z-[2000] flex items-center justify-center p-4 bg-black/60 backdrop-blur-sm" onClick={onClose}>
      <div
        className="bg-surface-light border border-surface-border rounded-xl w-full max-w-3xl max-h-[90vh] overflow-hidden shadow-2xl animate-in"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-5 py-4 border-b border-surface-border flex items-center justify-between">
          <div>
            <h2 className="text-sm font-semibold text-white mono">{ip}</h2>
            <p className="text-[10px] text-slate-500 mt-0.5">Attacker profile drill-down</p>
          </div>
          <button onClick={onClose} className="w-8 h-8 flex items-center justify-center rounded-md text-slate-400 hover:text-white hover:bg-surface-border" aria-label="Close">✕</button>
        </div>

        {loading ? (
          <div className="p-8 text-center text-slate-500 text-sm">Loading profile…</div>
        ) : error ? (
          <div className="p-8 text-center text-accent-danger text-sm">{error}</div>
        ) : (
          <>
            <div className="px-5 pt-4 flex gap-1 border-b border-surface-border overflow-x-auto">
              {TABS.map((t) => (
                <button
                  key={t}
                  onClick={() => setTab(t)}
                  className={`px-3 py-2 text-[10px] font-medium uppercase tracking-wider rounded-t-md whitespace-nowrap transition-colors ${
                    tab === t ? 'bg-surface text-accent border-b-2 border-accent' : 'text-slate-500 hover:text-slate-300'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>

            <div className="p-5 overflow-y-auto max-h-[calc(90vh-140px)]">
              {tab === 'overview' && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <Stat label="Risk" value={<span className={`px-2 py-0.5 rounded text-xs font-bold border ${riskBg(profile.risk_score)} ${riskColor(profile.risk_score)}`}>{profile.risk_score}</span>} />
                    <Stat label="Requests" value={profile.total_requests} />
                    <Stat label="First seen" value={formatTime(profile.first_seen)} small />
                    <Stat label="Last seen" value={formatTime(profile.last_seen)} small />
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs">
                    <div className="bg-surface rounded-lg p-3 border border-surface-border">
                      <p className="text-slate-500 mb-1">Registry location</p>
                      <p className="text-slate-300">{formatGeoLocation(profile)}</p>
                      {formatCoordinates(profile.geo_latitude, profile.geo_longitude) && (
                        <p className="mono text-[10px] text-slate-500 mt-1">
                          {formatCoordinates(profile.geo_latitude, profile.geo_longitude)}
                          {profile.geo_accuracy_km != null && ` · ±${profile.geo_accuracy_km} km`}
                        </p>
                      )}
                      {profile.geo_timezone && (
                        <p className="text-[10px] text-slate-500 mt-0.5">{profile.geo_timezone}</p>
                      )}
                      {isEstimatedGeo(profile.metadata?.geo_source) && (
                        <p className="text-[10px] text-amber-400/90 mt-1.5">Location unavailable</p>
                      )}
                    </div>
                    <div className="bg-surface rounded-lg p-3 border border-surface-border">
                      <p className="text-slate-500 mb-1">Network</p>
                      <p className="text-slate-300">{profile.geo_isp || '—'}</p>
                      {profile.geo_asn && <p className="mono text-[10px] text-slate-500 mt-0.5">{profile.geo_asn}</p>}
                    </div>
                  </div>
                  <div>
                    <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-2">Event threats (per-request)</p>
                    <div className="flex flex-wrap gap-1 mb-4">
                      {eventTags.length ? eventTags.map((t) => (
                        <span key={t} className="px-2 py-0.5 bg-red-500/10 border border-red-500/20 rounded text-[10px] text-red-400">{tagLabel(t)}</span>
                      )) : <span className="text-[10px] text-slate-600">None yet</span>}
                    </div>
                    <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-2">Session context (IP-wide)</p>
                    {contextClassifications.length ? (
                      <div className="space-y-2">
                        {contextClassifications.map((c) => (
                          <div key={c.classification} className="flex flex-wrap items-center gap-2">
                            <span className="px-2 py-0.5 bg-surface-border rounded text-[10px] text-slate-400">{tagLabel(c.classification)}</span>
                            {(c.mitre || []).map((t) => (
                              <a key={t.id} href={mitreUrl(t.id)} target="_blank" rel="noopener noreferrer" className="mono text-[10px] text-slate-500 hover:text-purple-400">{t.id}</a>
                            ))}
                          </div>
                        ))}
                      </div>
                    ) : contextTags.length ? (
                      <div className="flex flex-wrap gap-1">
                        {contextTags.map((t) => (
                          <span key={t} className="px-2 py-0.5 bg-surface-border rounded text-[10px] text-slate-400">{tagLabel(t)}</span>
                        ))}
                      </div>
                    ) : (
                      <span className="text-[10px] text-slate-600">No session-wide patterns</span>
                    )}
                  </div>
                </div>
              )}

              {tab === 'timeline' && <ProfileTimeline data={timeline} />}

              {tab === 'events' && (
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-left text-slate-500 uppercase tracking-wider">
                      <th className="pb-2 pr-3">Time</th><th className="pb-2 pr-3">Service</th>
                      <th className="pb-2 pr-3">Method</th><th className="pb-2 pr-3">Endpoint</th>
                      <th className="pb-2 pr-3">Threat / MITRE</th><th className="pb-2">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(data.events || []).map((e) => (
                      <tr key={e.id} className="border-t border-surface-border">
                        <td className="py-2 pr-3 text-slate-500 whitespace-nowrap">{formatTime(e.created_at)}</td>
                        <td className="py-2 pr-3 text-accent">{e.service}</td>
                        <td className="py-2 pr-3 text-slate-400">{e.method}</td>
                        <td className="py-2 pr-3 mono text-slate-400">{e.endpoint}</td>
                        <td className="py-2 pr-3"><EventThreatCell event={e} compact /></td>
                        <td className="py-2">{e.status_code}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}

              {tab === 'classifications' && (
                <div className="space-y-2">
                  {(data.classifications || []).map((c, i) => (
                    <div key={i} className="bg-surface rounded-lg p-3 border border-surface-border">
                      <div className="flex justify-between mb-1">
                        <span className="text-xs font-medium text-red-400">{tagLabel(c.classification)}</span>
                        {c.details?.scope === 'event' && (
                          <span className="text-[9px] text-slate-600 ml-2">event</span>
                        )}
                        <span className="text-[10px] text-slate-500">{formatTime(c.created_at)}{c.confidence != null ? ` · ${(c.confidence * 100).toFixed(0)}%` : ''}</span>
                      </div>
                      {c.details?.trap && <p className="text-[10px] text-slate-500">Trap: {c.details.trap}</p>}
                      {(c.mitre || c.details?.mitre || []).length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {(c.mitre || c.details?.mitre || []).map((t) => (
                            <a key={t.id} href={mitreUrl(t.id)} target="_blank" rel="noopener noreferrer" className="mono text-[10px] text-purple-400 hover:text-purple-300">{t.id}</a>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}

              {tab === 'mitre' && (
                <div className="space-y-3">
                  {techniques.length ? techniques.map((t) => (
                    <a
                      key={t.id}
                      href={mitreUrl(t.id)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-start gap-3 bg-purple-500/5 border border-purple-500/20 rounded-lg p-3 hover:border-purple-400/40 transition-colors"
                    >
                      <span className="mono text-sm font-bold text-purple-400 shrink-0">{t.id}</span>
                      <div>
                        <p className="text-sm text-slate-200">{t.name}</p>
                        <p className="text-[10px] text-purple-300/70 uppercase">{t.tactic}</p>
                        <p className="text-[10px] text-slate-500 mt-1">View on attack.mitre.org →</p>
                      </div>
                    </a>
                  )) : (
                    <p className="text-center text-slate-600 py-6 text-sm">No MITRE techniques — likely benign activity</p>
                  )}
                </div>
              )}

              {tab === 'actions' && (
                <div className="space-y-4 text-xs">
                  <ActionBlock
                    title="Export evidence"
                    desc="Download STIX 2.1 bundle for SIEM or sharing"
                    buttons={[
                      { label: 'Download STIX JSON', onClick: () => exportCSV(`/export/stix/${encodeURIComponent(ip)}`, `stix-${ip}.json`) },
                      { label: 'Export profiles CSV', onClick: () => exportCSV('/export/profiles.csv', 'profiles.csv') },
                    ]}
                  />
                  <ActionBlock
                    title="Block at firewall"
                    desc="Suggested iptables rule — apply on your edge device"
                    code={firewallRule(ip)}
                    onCopy={() => doCopy('fw', firewallRule(ip))}
                    copied={copied === 'fw'}
                  />
                  <ActionBlock
                    title="Blocklist"
                    desc={
                      profile.risk_score >= 40
                        ? 'This IP meets the recommended block threshold (risk ≥ 40)'
                        : `Risk ${profile.risk_score} — below recommended block threshold (40). Single-IP export still available.`
                    }
                    buttons={[
                      { label: `Block ${ip}`, onClick: () => exportCSV(`/export/blocklist/${encodeURIComponent(ip)}`, `blocklist-${ip}.txt`) },
                      { label: 'All IPs (risk ≥ 20)', onClick: () => exportCSV('/export/blocklist.txt?min_risk=20', 'blocklist.txt') },
                    ]}
                  />
                </div>
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}

function Stat({ label, value, small }) {
  return (
    <div className="bg-surface rounded-lg p-3 border border-surface-border">
      <p className="text-[10px] text-slate-500 uppercase mb-1">{label}</p>
      <div className={small ? 'text-[10px] text-slate-300' : 'text-sm text-slate-200 font-medium'}>{value}</div>
    </div>
  )
}

function ActionBlock({ title, desc, buttons, code, onCopy, copied }) {
  return (
    <div className="bg-surface rounded-lg p-4 border border-surface-border">
      <p className="text-sm font-medium text-slate-200 mb-1">{title}</p>
      <p className="text-slate-500 mb-3">{desc}</p>
      {code && (
        <div className="flex items-center gap-2 mb-2">
          <code className="flex-1 mono text-[10px] bg-surface-light p-2 rounded border border-surface-border text-slate-400">{code}</code>
          <button onClick={onCopy} className="px-2 py-1 text-[10px] bg-surface-border rounded hover:bg-slate-600">{copied ? 'Copied' : 'Copy'}</button>
        </div>
      )}
      {buttons?.map((b) => (
        <button key={b.label} onClick={b.onClick} className="mr-2 mt-1 px-3 py-1.5 text-[10px] font-medium bg-surface-border rounded hover:bg-slate-600">{b.label}</button>
      ))}
    </div>
  )
}