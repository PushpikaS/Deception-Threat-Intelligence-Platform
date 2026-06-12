import { useCallback, useEffect, useRef, useState } from 'react'
import { AuthError, clearLegacyAuth, fetchAuthConfig, fetchJSON, loadTaxonomy, logoutDashboard, validateSession } from './api'
import DashboardAuth from './components/DashboardAuth'
import StatsCards from './components/StatsCards'
import AttackTimeline from './components/AttackTimeline'
import ThreatMap from './components/ThreatMap'
import ProfilesTable from './components/ProfilesTable'
import EventsFeed from './components/EventsFeed'
import ClassificationChart from './components/ClassificationChart'
import AttackChains from './components/AttackChains'
import HeatmapChart from './components/HeatmapChart'
import ProfileDetailModal from './components/ProfileDetailModal'
import MitreGuide from './components/MitreGuide'
import GlobalSearch from './components/GlobalSearch'
import TrendStats from './components/TrendStats'
import SystemHealth from './components/SystemHealth'
import CountryChart from './components/CountryChart'
import AsnIntelPanel from './components/AsnIntelPanel'
import { useLiveFeed } from './hooks/useWebSocket'

export default function App() {
  const [bootstrapped, setBootstrapped] = useState(false)
  const [authed, setAuthed] = useState(false)
  const [overview, setOverview] = useState(null)
  const [trends, setTrends] = useState(null)
  const [timeline, setTimeline] = useState([])
  const [profiles, setProfiles] = useState([])
  const [events, setEvents] = useState([])
  const [chains, setChains] = useState([])
  const [mapData, setMapData] = useState([])
  const [heatmap, setHeatmap] = useState([])
  const [mitreMap, setMitreMap] = useState(null)
  const [health, setHealth] = useState(null)
  const [platform, setPlatform] = useState(null)
  const [countries, setCountries] = useState([])
  const [countryHours, setCountryHours] = useState(24)
  const [asnStats, setAsnStats] = useState([])
  const [liveConnected, setLiveConnected] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastRefresh, setLastRefresh] = useState(null)
  const [selectedIp, setSelectedIp] = useState(null)
  const [authRequired, setAuthRequired] = useState(false)

  const openProfile = useCallback((ip) => setSelectedIp(ip), [])
  const closeProfile = useCallback(() => setSelectedIp(null), [])
  const refreshRef = useRef(null)

  const refresh = useCallback(async (silent = false) => {
    if (authRequired && !authed) return
    if (!silent) setLoading(true)
    const requests = [
      ['overview', fetchJSON('/stats/overview')],
      ['trends', fetchJSON('/stats/trends')],
      ['timeline', fetchJSON('/timeline?hours=24')],
      ['profiles', fetchJSON('/profiles/search?limit=50&sort=risk')],
      ['events', fetchJSON('/events?limit=50')],
      ['chains', fetchJSON('/chains?limit=15')],
      ['map', fetchJSON('/map')],
      ['heatmap', fetchJSON('/heatmap?hours=24')],
      ['mitre', fetchJSON('/mitre/map')],
      ['health', fetchJSON('/health')],
      ['platform', fetchJSON('/health/platform')],
      ['countries', fetchJSON(`/stats/countries?limit=8&hours=${countryHours}`)],
      ['asn', fetchJSON('/stats/asn?limit=10')],
    ]
    const results = await Promise.allSettled(requests.map(([, p]) => p))
    let authErr = false
    let failed = 0
    const data = {}
    results.forEach((res, i) => {
      const key = requests[i][0]
      if (res.status === 'fulfilled') {
        data[key] = res.value
      } else if (res.reason instanceof AuthError) {
        authErr = true
      } else {
        failed++
        console.error(`Failed to load ${key}:`, res.reason)
      }
    })
    if (authErr) {
      await logoutDashboard()
      setAuthRequired(true)
      setAuthed(false)
      setBootstrapped(true)
      setLoading(false)
      return
    }
    setOverview(data.overview ?? null)
    setTrends(data.trends ?? null)
    setTimeline(data.timeline ?? [])
    setProfiles(data.profiles ?? [])
    setEvents(data.events ?? [])
    setChains(data.chains ?? [])
    setMapData(data.map ?? [])
    setHeatmap(data.heatmap ?? [])
    setMitreMap(data.mitre ?? null)
    setHealth(data.health ?? null)
    setPlatform(data.platform ?? null)
    setCountries(data.countries ?? [])
    setAsnStats(data.asn ?? [])
    setLastRefresh(new Date())
    setAuthed(true)
    setError(failed ? `Some sections failed to load (${failed}). Core data may still be visible.` : null)
    setLoading(false)
  }, [authRequired, authed, countryHours])

  refreshRef.current = refresh

  useEffect(() => {
    let cancelled = false
    ;(async () => {
      try {
        const cfg = await fetchAuthConfig()
        if (cancelled) return
        setAuthRequired(cfg.required)

        clearLegacyAuth()
        if (cfg.required) {
          const valid = await validateSession()
          if (cancelled) return
          if (!valid) {
            setAuthed(false)
            setLoading(false)
            setBootstrapped(true)
            return
          }
          setAuthed(true)
        } else {
          setAuthed(true)
        }

        await loadTaxonomy()
        if (!cancelled) await refreshRef.current()
        if (!cancelled) setBootstrapped(true)
      } catch (err) {
        if (!cancelled) {
          setError(err.message || 'Failed to initialize dashboard')
          setLoading(false)
          setBootstrapped(true)
        }
      }
    })()
    return () => { cancelled = true }
  }, [])

  useEffect(() => {
    if (!bootstrapped || (authRequired && !authed)) return undefined
    const interval = setInterval(() => refresh(true), 10000)
    return () => clearInterval(interval)
  }, [bootstrapped, authRequired, authed, refresh])

  const { connected: wsConnected } = useLiveFeed(authed, () => refresh(true))
  useEffect(() => { setLiveConnected(wsConnected) }, [wsConnected])

  if (!bootstrapped && loading) {
    return (
      <div className="min-h-screen bg-surface flex items-center justify-center">
        <p className="text-sm text-slate-500">Loading dashboard…</p>
      </div>
    )
  }

  if (authRequired && !authed) {
    return (
      <DashboardAuth
        onSuccess={async () => {
          setAuthed(true)
          setAuthRequired(true)
          setBootstrapped(true)
          setLoading(true)
          setError(null)
          await loadTaxonomy()
          await refreshRef.current()
        }}
      />
    )
  }

  return (
    <div className="min-h-screen bg-surface">
      <header className="border-b border-surface-border bg-surface-light/50 backdrop-blur sticky top-0 z-50">
        <div className="max-w-[1600px] mx-auto px-4 sm:px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-accent/20 flex items-center justify-center">
              <span className="text-accent text-lg">🍯</span>
            </div>
            <div>
              <h1 className="text-lg font-bold text-white tracking-tight">HoneyPot+</h1>
              <p className="text-xs text-slate-500">Threat Intelligence Platform v2</p>
            </div>
          </div>
          <div className="flex items-center gap-3 sm:gap-4">
            {liveConnected && (
              <span className="hidden sm:inline-flex items-center gap-1 text-[10px] text-emerald-400/90">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" /> Live
              </span>
            )}
            {lastRefresh && (
              <span className="hidden sm:inline text-[10px] text-slate-600">
                Updated {lastRefresh.toLocaleTimeString()}
              </span>
            )}
            {authRequired && authed && (
              <button
                onClick={async () => {
                  await logoutDashboard()
                  setAuthed(false)
                  setError(null)
                  setAuthRequired(true)
                }}
                className="px-2 py-1 text-[10px] text-slate-500 hover:text-slate-300"
              >
                Sign out
              </button>
            )}
            <button
              onClick={() => refresh()}
              disabled={loading}
              className="px-3 py-1.5 text-xs font-medium bg-surface-border hover:bg-slate-600 rounded-md transition-colors disabled:opacity-50"
            >
              {loading ? 'Loading…' : 'Refresh'}
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-[1600px] mx-auto px-4 sm:px-6 py-6 space-y-6">
        {error && (
          <div className="px-4 py-3 bg-red-500/10 border border-red-500/30 rounded-lg text-sm text-red-400">{error}</div>
        )}

        <SystemHealth health={health} platform={platform} loading={loading} />
        <StatsCards overview={overview} loading={loading} />
        <TrendStats trends={trends} loading={loading} />

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <CountryChart
            data={countries}
            loading={loading}
            hours={countryHours}
            onHoursChange={setCountryHours}
          />
          <AsnIntelPanel data={asnStats} loading={loading} />
        </div>

        <GlobalSearch onSelectIp={openProfile} />
        <MitreGuide mitreMap={mitreMap} loading={loading} />

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <div className="xl:col-span-2">
            <AttackTimeline data={timeline} loading={loading} />
          </div>
          <ClassificationChart overview={overview} loading={loading} />
        </div>

        <HeatmapChart data={heatmap} />
        <ThreatMap mapData={mapData} onSelectIp={openProfile} />

        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          <ProfilesTable profiles={profiles} loading={loading} onSelectIp={openProfile} />
          <AttackChains chains={chains} loading={loading} onSelectIp={openProfile} />
        </div>

        <EventsFeed events={events} loading={loading} onSelectIp={openProfile} />
      </main>

      <ProfileDetailModal ip={selectedIp} onClose={closeProfile} />
    </div>
  )
}