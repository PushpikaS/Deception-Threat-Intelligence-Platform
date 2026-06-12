import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import L from 'leaflet'
import { CircleMarker, MapContainer, Popup, TileLayer, useMap } from 'react-leaflet'
import MarkerClusterGroup from 'react-leaflet-cluster'
import {
  formatCoordinates, formatGeoLocation, formatTime, isVerifiedGeo,
  riskBg, riskColor, tagLabel, zoomForAccuracy,
} from '../api'
import Card from './Card'
import { MAP_BASE, MAP_LABELS_EN } from '../lib/mapLayers'

const RISK_FILTERS = [
  { id: 'all', label: 'All', min: 0 },
  { id: 'elevated', label: '40+', min: 40 },
  { id: 'critical', label: '70+', min: 70 },
]

function riskTier(score) {
  if (score >= 70) return 'critical'
  if (score >= 40) return 'elevated'
  return 'low'
}

function pinStyle(score, active = false) {
  const tier = riskTier(score)
  const base = tier === 'critical'
    ? { color: '#7f1d1d', fillColor: '#ef4444', fillOpacity: 0.92, weight: active ? 3 : 2.5 }
    : tier === 'elevated'
      ? { color: '#92400e', fillColor: '#f59e0b', fillOpacity: 0.9, weight: active ? 3 : 2 }
      : { color: '#065f46', fillColor: '#10b981', fillOpacity: 0.88, weight: active ? 3 : 2 }
  if (active) return { ...base, color: '#0369a1', weight: 3 }
  return base
}

function accuracyKm(threat) {
  const km = threat.geo_accuracy_km
  return km != null && km > 0 ? km : 25
}

function accuracyPathOptions(source) {
  if (source === 'maxmind') {
    return { color: '#0369a1', fillColor: '#0ea5e9', fillOpacity: 0.28, weight: 2.5, dashArray: '7 5' }
  }
  return { color: '#6d28d9', fillColor: '#8b5cf6', fillOpacity: 0.22, weight: 2.5, dashArray: '6 4' }
}

/** Ensure rings are visible at the current zoom (toggle was invisible at world scale). */
function ringRadiusMeters(map, center, accuracyKmValue) {
  const base = accuracyKmValue * 1000
  const point = map.latLngToContainerPoint(center)
  const minPixels = map.getZoom() <= 3 ? 32 : map.getZoom() <= 5 ? 22 : 14
  const edge = map.containerPointToLatLng(L.point(point.x + minPixels, point.y))
  return Math.max(base, map.distance(center, edge))
}

function AccuracyRingsLayer({ threats, visible }) {
  const map = useMap()

  useEffect(() => {
    if (!visible || !threats.length) return undefined

    const group = L.layerGroup()

    const draw = () => {
      group.clearLayers()
      for (const p of threats) {
        const center = L.latLng(Number(p.geo_latitude), Number(p.geo_longitude))
        const radius = ringRadiusMeters(map, center, accuracyKm(p))
        L.circle(center, {
          radius,
          ...accuracyPathOptions(p.geo_source),
          interactive: false,
        }).addTo(group)
      }
    }

    draw()
    group.addTo(map)
    map.on('zoomend', draw)
    map.on('moveend', draw)

    return () => {
      map.off('zoomend', draw)
      map.off('moveend', draw)
      map.removeLayer(group)
    }
  }, [map, threats, visible])

  return null
}

function pinRadius(score) {
  if (score >= 70) return 11
  if (score >= 40) return 9
  return 7
}

function createClusterIcon(cluster) {
  const markers = cluster.getAllChildMarkers()
  const count = cluster.getChildCount()
  const maxRisk = markers.reduce((m, mk) => {
    const r = mk.options?.riskScore ?? 0
    return Math.max(m, r)
  }, 0)
  const tier = riskTier(maxRisk)
  const size = count < 8 ? 36 : count < 20 ? 44 : 52
  return L.divIcon({
    html: `<div class="threat-cluster threat-cluster--${tier}"><span>${count}</span></div>`,
    className: 'threat-cluster-wrap',
    iconSize: L.point(size, size),
  })
}

function MapBounds({ threats, resetKey }) {
  const map = useMap()
  const initialFitDone = useRef(false)

  useEffect(() => {
    const isReset = resetKey > 0
    if (!threats.length) {
      if (isReset) {
        map.setView([20, 0], 2, { animate: true, duration: 0.5 })
        initialFitDone.current = false
      }
      return
    }

    // Fit only on first data load or explicit "Reset view" — not on 10s dashboard refresh
    if (!isReset && initialFitDone.current) return

    const bounds = L.latLngBounds(threats.map((p) => [Number(p.geo_latitude), Number(p.geo_longitude)]))
    if (bounds.isValid()) {
      map.fitBounds(bounds.pad(0.18), { maxZoom: 6, animate: true, duration: 0.5 })
      initialFitDone.current = true
    }
  }, [map, threats, resetKey])

  return null
}

function FlyToIp({ target }) {
  const map = useMap()
  useEffect(() => {
    if (!target) return
    map.flyTo([target.lat, target.lng], target.zoom, {
      duration: 0.85,
      easeLinearity: 0.25,
    })
  }, [map, target])
  return null
}

function ThreatPopup({ threat, onSelectIp }) {
  const coords = formatCoordinates(threat.geo_latitude, threat.geo_longitude)
  const tags = (threat.behavior_tags || []).slice(0, 4)

  return (
    <div className="threat-popup">
      <div className="flex items-start justify-between gap-3 mb-3">
        <div>
          <span className="mono text-sm font-semibold text-white block">{threat.ip}</span>
          <span className="text-[10px] text-slate-500 mt-0.5 block">{formatGeoLocation(threat)}</span>
        </div>
        <span className={`px-2 py-0.5 rounded text-xs font-bold border tabular-nums ${riskBg(threat.risk_score)} ${riskColor(threat.risk_score)}`}>
          {threat.risk_score}
        </span>
      </div>

      {tags.length > 0 && (
        <div className="flex flex-wrap gap-1 mb-3">
          {tags.map((t) => (
            <span key={t} className="px-1.5 py-0.5 bg-red-500/10 border border-red-500/20 rounded text-[10px] text-red-300">
              {tagLabel(t)}
            </span>
          ))}
        </div>
      )}

      <dl className="threat-popup-grid">
        {coords && (
          <div>
            <dt>Coordinates</dt>
            <dd className="mono">{coords}</dd>
          </div>
        )}
        {threat.geo_isp && (
          <div>
            <dt>Network</dt>
            <dd>{threat.geo_isp}{threat.geo_asn ? ` · ${threat.geo_asn}` : ''}</dd>
          </div>
        )}
        <div>
          <dt>Requests</dt>
          <dd className="tabular-nums">{threat.total_requests ?? 0}</dd>
        </div>
        {threat.geo_accuracy_km != null && (
          <div>
            <dt>Accuracy</dt>
            <dd>±{threat.geo_accuracy_km} km</dd>
          </div>
        )}
        <div>
          <dt>Last seen</dt>
          <dd>{formatTime(threat.last_seen)}</dd>
        </div>
      </dl>

      {onSelectIp && (
        <button
          type="button"
          className="threat-popup-action"
          onClick={() => onSelectIp(threat.ip)}
        >
          Open full profile
        </button>
      )}
    </div>
  )
}

function MapToolbar({ showRings, onToggleRings, riskFilter, onRiskFilter, onReset, count }) {
  return (
    <div className="map-toolbar">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-[10px] uppercase tracking-wider text-slate-500 mr-1">Risk</span>
        {RISK_FILTERS.map((f) => (
          <button
            key={f.id}
            type="button"
            onClick={() => onRiskFilter(f.min)}
            className={`map-toolbar-btn ${riskFilter === f.min ? 'map-toolbar-btn--active' : ''}`}
          >
            {f.label}
          </button>
        ))}
      </div>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={onToggleRings}
          className={`map-toolbar-btn ${showRings ? 'map-toolbar-btn--active' : ''}`}
        >
          {showRings ? 'Hide rings' : 'Accuracy rings'}
        </button>
        <button type="button" onClick={onReset} className="map-toolbar-btn">Reset view</button>
        <span className="text-[10px] text-slate-500 tabular-nums">{count} origins</span>
      </div>
    </div>
  )
}

function MapLegend({ showRings }) {
  return (
    <div className="map-overlay map-overlay--legend">
      <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-2 font-semibold">Legend</p>
      <ul className="space-y-1.5 text-[11px] text-slate-400">
        <li className="flex items-center gap-2"><span className="legend-dot legend-dot--critical" /> Critical (70+)</li>
        <li className="flex items-center gap-2"><span className="legend-dot legend-dot--elevated" /> Elevated (40–69)</li>
        <li className="flex items-center gap-2"><span className="legend-dot legend-dot--low" /> Low (&lt;40)</li>
        {showRings && (
          <li className="flex items-center gap-2 pt-1 border-t border-surface-border/60">
            <span className="legend-ring legend-ring--on" /> Location accuracy
          </li>
        )}
      </ul>
    </div>
  )
}

function MapStats({ stats }) {
  return (
    <div className="map-overlay map-overlay--stats">
      <p className="text-[10px] uppercase tracking-wider text-slate-500 mb-2 font-semibold">Geo intelligence</p>
      <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
        <Stat label="Origins" value={stats.origins} />
        <Stat label="Countries" value={stats.countries} />
        <Stat label="Critical" value={stats.highRisk} warn={stats.highRisk > 0} />
        <Stat label="Verified" value={stats.verified} accent />
      </div>
    </div>
  )
}

function Stat({ label, value, warn, accent }) {
  return (
    <div>
      <p className="text-[10px] text-slate-500">{label}</p>
      <p className={`text-base font-bold tabular-nums ${warn ? 'text-red-400' : accent ? 'text-sky-400' : 'text-slate-100'}`}>{value}</p>
    </div>
  )
}

function OriginSidebar({ threats, activeIp, search, onSearch, onFocus, onSelectIp }) {
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    if (!q) return threats
    return threats.filter((p) =>
      p.ip?.toLowerCase().includes(q)
      || p.geo_country?.toLowerCase().includes(q)
      || p.geo_city?.toLowerCase().includes(q)
      || p.geo_isp?.toLowerCase().includes(q),
    )
  }, [threats, search])

  return (
    <aside className="threat-map-sidebar">
      <div className="threat-map-sidebar-head">
        <p className="text-[10px] uppercase tracking-wider text-slate-500 font-semibold">Threat origins</p>
        <input
          type="search"
          value={search}
          onChange={(e) => onSearch(e.target.value)}
          placeholder="Filter IP, country, ISP…"
          className="threat-map-search"
        />
      </div>
      <div className="threat-map-sidebar-list">
        {filtered.length === 0 ? (
          <p className="text-slate-600 text-xs text-center py-8">No matches</p>
        ) : (
          filtered.map((p) => {
            const active = activeIp === p.ip
            const tier = riskTier(p.risk_score)
            return (
              <button
                key={p.ip}
                type="button"
                className={`threat-origin-row ${active ? 'threat-origin-row--active' : ''}`}
                onClick={() => onFocus(p)}
              >
                <span className={`threat-origin-dot threat-origin-dot--${tier}`} />
                <div className="min-w-0 flex-1">
                  <div className="flex items-center justify-between gap-2">
                    <span className="mono text-slate-200 text-[11px] truncate">{p.ip}</span>
                    <span className={`text-[11px] font-bold tabular-nums shrink-0 ${riskColor(p.risk_score)}`}>{p.risk_score}</span>
                  </div>
                  <p className="text-[10px] text-slate-500 truncate mt-0.5">{formatGeoLocation(p)}</p>
                  <div className="flex items-center gap-2 mt-1 text-[10px] text-slate-600">
                    <span>{p.total_requests ?? 0} req</span>
                    {p.geo_country_code && <span className="mono">{p.geo_country_code}</span>}
                  </div>
                </div>
                {onSelectIp && (
                  <span
                    role="button"
                    tabIndex={0}
                    className="threat-origin-profile"
                    onClick={(e) => { e.stopPropagation(); onSelectIp(p.ip) }}
                    onKeyDown={(e) => { if (e.key === 'Enter') { e.stopPropagation(); onSelectIp(p.ip) } }}
                  >
                    →
                  </span>
                )}
              </button>
            )
          })
        )}
      </div>
    </aside>
  )
}

export default function ThreatMap({ mapData, onSelectIp }) {
  const mapRef = useRef(null)
  const [flyTarget, setFlyTarget] = useState(null)
  const [activeIp, setActiveIp] = useState(null)
  const [showRings, setShowRings] = useState(true)
  const [riskFilter, setRiskFilter] = useState(0)
  const [resetKey, setResetKey] = useState(0)
  const [search, setSearch] = useState('')

  const allThreats = useMemo(
    () => (mapData || []).filter(
      (p) => p.geo_latitude != null && p.geo_longitude != null && isVerifiedGeo(p.geo_source),
    ),
    [mapData],
  )

  const threats = useMemo(
    () => allThreats.filter((p) => p.risk_score >= riskFilter),
    [allThreats, riskFilter],
  )

  const stats = useMemo(() => {
    const countries = new Set(threats.map((p) => p.geo_country_code || p.geo_country).filter(Boolean))
    return {
      origins: threats.length,
      countries: countries.size,
      highRisk: threats.filter((p) => p.risk_score >= 70).length,
      verified: threats.filter((p) => isVerifiedGeo(p.geo_source)).length,
    }
  }, [threats])

  const sortedList = useMemo(
    () => [...threats].sort((a, b) => b.risk_score - a.risk_score),
    [threats],
  )

  const focusIp = useCallback((threat) => {
    setActiveIp(threat.ip)
    setFlyTarget({
      lat: Number(threat.geo_latitude),
      lng: Number(threat.geo_longitude),
      zoom: zoomForAccuracy(threat.geo_accuracy_km),
      key: Date.now(),
    })
  }, [])

  const resetView = useCallback(() => {
    setActiveIp(null)
    setResetKey((k) => k + 1)
  }, [])

  const openProfile = useCallback((ip) => {
    mapRef.current?.closePopup()
    onSelectIp?.(ip)
  }, [onSelectIp])

  return (
    <Card title="Global Threat Map">
      <MapToolbar
        showRings={showRings}
        onToggleRings={() => setShowRings((v) => !v)}
        riskFilter={riskFilter}
        onRiskFilter={setRiskFilter}
        onReset={resetView}
        count={threats.length}
      />

      <div className="threat-map-layout">
        <div className="threat-map-shell rounded-xl overflow-hidden border border-surface-border">
          <MapContainer
            ref={mapRef}
            center={[20, 0]}
            zoom={2}
            minZoom={2}
            maxZoom={18}
            scrollWheelZoom
            zoomSnap={0.5}
            zoomDelta={0.5}
            wheelPxPerZoomLevel={90}
            zoomAnimation
            fadeAnimation
            className="threat-map-canvas threat-map-canvas--colorful"
            zoomControl
          >
            <TileLayer
              url={MAP_BASE.url}
              attribution={MAP_BASE.attribution}
              subdomains={MAP_BASE.subdomains}
              maxZoom={MAP_BASE.maxZoom}
            />
            <TileLayer
              url={MAP_LABELS_EN.url}
              maxZoom={MAP_LABELS_EN.maxZoom}
              opacity={MAP_LABELS_EN.opacity}
            />
            <MapBounds threats={threats} resetKey={resetKey} />
            <FlyToIp target={flyTarget} />
            <AccuracyRingsLayer threats={threats} visible={showRings} />

            <MarkerClusterGroup
              chunkedLoading
              spiderfyOnMaxZoom
              showCoverageOnHover={false}
              maxClusterRadius={42}
              iconCreateFunction={createClusterIcon}
            >
              {threats.map((p) => {
                const isActive = activeIp === p.ip
                const tier = riskTier(p.risk_score)
                return (
                  <CircleMarker
                    key={p.ip}
                    center={[Number(p.geo_latitude), Number(p.geo_longitude)]}
                    radius={isActive ? pinRadius(p.risk_score) + 3 : pinRadius(p.risk_score)}
                    pathOptions={pinStyle(p.risk_score, isActive)}
                    riskScore={p.risk_score}
                    className={tier === 'critical' ? 'threat-marker-pulse' : undefined}
                    eventHandlers={{
                      click: () => setActiveIp(p.ip),
                      popupopen: () => setActiveIp(p.ip),
                    }}
                  >
                    <Popup className="threat-leaflet-popup" minWidth={280} maxWidth={320}>
                      <ThreatPopup threat={p} onSelectIp={openProfile} />
                    </Popup>
                  </CircleMarker>
                )
              })}
            </MarkerClusterGroup>
          </MapContainer>

          <MapStats stats={stats} />
          <MapLegend showRings={showRings} />

          {threats.length === 0 && (
            <div className="threat-map-empty">
              <p className="text-slate-200 text-sm font-semibold">No geolocated threats in view</p>
              <p className="text-slate-500 text-xs mt-2 max-w-sm leading-relaxed">
                {allThreats.length > 0
                  ? 'Adjust the risk filter or wait for new public-IP traffic to appear.'
                  : 'Attack traffic from routable IPs is mapped automatically after geo enrichment.'}
              </p>
            </div>
          )}
        </div>

        <OriginSidebar
          threats={sortedList}
          activeIp={activeIp}
          search={search}
          onSearch={setSearch}
          onFocus={focusIp}
          onSelectIp={openProfile}
        />
      </div>
    </Card>
  )
}