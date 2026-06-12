const API = import.meta.env.VITE_API_URL || '/api'
const LEGACY_AUTH_KEY = 'hp_dashboard_auth'

const JSONB_FIELDS = new Set(['metadata', 'payload', 'details'])

export class AuthError extends Error {
  constructor(message) {
    super(message)
    this.name = 'AuthError'
  }
}

function normalizeRecord(row) {
  if (!row || typeof row !== 'object') return row
  const out = { ...row }
  for (const key of JSONB_FIELDS) {
    if (typeof out[key] === 'string') {
      try { out[key] = JSON.parse(out[key]) } catch { /* keep */ }
    }
  }
  return out
}

/** Remove legacy sessionStorage credentials from older builds. */
const SERVICE_LABELS = {
  'honeypot-web': 'Web',
  'honeypot-api': 'API',
  'honeypot-auth': 'Identity',
}

export function serviceLabel(service) {
  return SERVICE_LABELS[service] || service || '—'
}

export function clearLegacyAuth() {
  try {
    sessionStorage.removeItem(LEGACY_AUTH_KEY)
  } catch { /* ignore */ }
}

export async function loginDashboard(user, pass) {
  clearLegacyAuth()
  const res = await fetch(`${API}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ username: user, password: pass }),
  })
  if (res.status === 401) throw new AuthError('Invalid credentials')
  if (!res.ok) throw new Error(`Login failed: ${res.status}`)
  return res.json()
}

export async function logoutDashboard() {
  clearLegacyAuth()
  try {
    await fetch(`${API}/auth/logout`, { method: 'POST', credentials: 'include' })
  } catch { /* best effort */ }
  _taxonomy = null
}

export async function validateSession() {
  clearLegacyAuth()
  const res = await fetch(`${API}/auth/session`, { credentials: 'include' })
  if (!res.ok) return false
  const data = await res.json()
  return !!data.authenticated
}

export async function fetchJSON(path) {
  const res = await fetch(`${API}${path}`, { credentials: 'include' })
  if (res.status === 401) {
    await logoutDashboard()
    throw new AuthError('Authentication required')
  }
  if (!res.ok) throw new Error(`API error: ${res.status}`)
  const data = await res.json()
  if (Array.isArray(data)) return data.map(normalizeRecord)
  if (data?.profile) {
    return {
      ...data,
      profile: normalizeRecord(data.profile),
      events: (data.events || []).map(normalizeRecord),
      classifications: (data.classifications || []).map(normalizeRecord),
    }
  }
  return data
}

export async function fetchProfile(ip) {
  const data = await fetchJSON(`/profiles/${encodeURIComponent(ip)}`)
  if (data?.error) throw new Error('Profile not found')
  return data
}

export async function fetchProfileTimeline(ip, hours = 48) {
  return fetchJSON(`/profiles/${encodeURIComponent(ip)}/timeline?hours=${hours}`)
}

export function mitreUrl(techniqueId) {
  const base = techniqueId.split('.')[0]
  return `https://attack.mitre.org/techniques/${base}/`
}

export async function exportCSV(path, filename) {
  const res = await fetch(`${API}${path}`, { credentials: 'include' })
  if (res.status === 401) {
    await logoutDashboard()
    throw new AuthError('Authentication required')
  }
  if (!res.ok) throw new Error(`Export failed: ${res.status}`)
  const blob = await res.blob()
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = filename
  a.click()
  URL.revokeObjectURL(a.href)
}

export function copyText(text) {
  return navigator.clipboard?.writeText(text)
}

export function firewallRule(ip) {
  return `iptables -A INPUT -s ${ip} -j DROP`
}

export function riskColor(score) {
  if (score >= 70) return 'text-accent-danger'
  if (score >= 40) return 'text-accent-warn'
  return 'text-accent-ok'
}

export function riskBg(score) {
  if (score >= 70) return 'bg-red-500/20 border-red-500/40'
  if (score >= 40) return 'bg-amber-500/20 border-amber-500/40'
  return 'bg-emerald-500/20 border-emerald-500/40'
}

export function formatTime(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

export function tagLabel(tag) {
  return tag.replace(/_/g, ' ')
}

let _taxonomy = null

export async function loadTaxonomy() {
  if (_taxonomy) return _taxonomy
  _taxonomy = await fetchJSON('/taxonomy')
  return _taxonomy
}

export function getTaxonomy() {
  return _taxonomy
}

export async function fetchAuthConfig() {
  const res = await fetch(`${API}/auth/config`, { credentials: 'include' })
  if (!res.ok) throw new Error(`Auth config error: ${res.status}`)
  return res.json()
}

export function isContextClassification(name) {
  const list = _taxonomy?.profile_context_classifications || []
  return list.includes(name)
}

export function splitBehaviorTags(tags = []) {
  const event = []
  const context = []
  for (const tag of tags) {
    if (isContextClassification(tag)) context.push(tag)
    else event.push(tag)
  }
  return { event, context }
}

export function geoSourceLabel(source) {
  if (source === 'maxmind' || source === 'ipapi') return 'Verified'
  if (source === 'private') return 'Unavailable'
  return 'Unavailable'
}

export function isEstimatedGeo(source) {
  return source === 'private' || source === 'unknown' || !source
}

export function isVerifiedGeo(source) {
  return source === 'maxmind' || source === 'ipapi'
}

/** Production-style location string: City, Region, Country (CC) */
export function formatGeoLocation(profile) {
  if (!profile) return 'Unknown'
  const parts = []
  if (profile.geo_city) parts.push(profile.geo_city)
  if (profile.geo_region && profile.geo_region !== profile.geo_city) parts.push(profile.geo_region)
  if (profile.geo_country) {
    const cc = profile.geo_country_code || profile.metadata?.geo_country_code
    parts.push(cc ? `${profile.geo_country} (${cc})` : profile.geo_country)
  }
  if (profile.geo_postal_code) parts.push(profile.geo_postal_code)
  return parts.length ? parts.join(', ') : 'Unknown'
}

/** Six-decimal WGS84 coordinates as used in production SIEM exports */
export function formatCoordinates(lat, lon) {
  if (lat == null || lon == null) return null
  const la = Number(lat)
  const lo = Number(lon)
  if (Number.isNaN(la) || Number.isNaN(lo)) return null
  return `${la.toFixed(6)}, ${lo.toFixed(6)}`
}

/** Leaflet zoom level from geo accuracy radius (km) */
export function zoomForAccuracy(km) {
  if (km == null || km <= 0) return 8
  if (km <= 15) return 11
  if (km <= 30) return 9
  if (km <= 75) return 7
  return 5
}

export function splitEventThreat(event) {
  const classifications = [...(event?.classifications || [])]
  const threatPriority = _taxonomy?.threat_priority || {}
  if (!classifications.length) {
    return { primary: null, secondary: [], primaryMitre: [], secondaryMitre: [], allMitre: [] }
  }

  classifications.sort((a, b) => {
    const pa = threatPriority[a.classification] ?? 3
    const pb = threatPriority[b.classification] ?? 3
    if (pa !== pb) return pa - pb
    return (b.confidence ?? 0) - (a.confidence ?? 0)
  })

  const primary = classifications[0]
  const secondary = classifications.slice(1)
  const primaryMitre = primary?.mitre || []
  const primaryIds = new Set(primaryMitre.map((t) => t.id))
  const secondaryMitre = []
  const seen = new Set(primaryIds)
  for (const clf of secondary) {
    for (const tech of clf.mitre || []) {
      if (!seen.has(tech.id)) {
        seen.add(tech.id)
        secondaryMitre.push(tech)
      }
    }
  }

  return {
    primary,
    secondary,
    primaryMitre,
    secondaryMitre,
    allMitre: event?.mitre_techniques || [...primaryMitre, ...secondaryMitre],
  }
}

export function sortBy(items, key, dir = 'desc') {
  return [...items].sort((a, b) => {
    const av = a[key], bv = b[key]
    if (av == null) return 1
    if (bv == null) return -1
    if (typeof av === 'number') return dir === 'desc' ? bv - av : av - bv
    return dir === 'desc'
      ? String(bv).localeCompare(String(av))
      : String(av).localeCompare(String(bv))
  })
}

export function trendDelta(current, previous) {
  if (!previous) return current > 0 ? '+100%' : '0%'
  const pct = Math.round(((current - previous) / previous) * 100)
  return `${pct >= 0 ? '+' : ''}${pct}%`
}