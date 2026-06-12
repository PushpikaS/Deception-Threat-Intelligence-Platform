/**
 * Threat map tile layers — colorful Carto Voyager base with English-only labels.
 * No API keys: CARTO rastertiles + Esri reference overlay (Latin/English exonyms).
 */

export const MAP_BASE = {
  url: 'https://{s}.basemaps.cartocdn.com/rastertiles/voyager_nolabels/{z}/{x}/{y}{r}.png',
  subdomains: 'abcd',
  maxZoom: 20,
  attribution:
    '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> '
    + '&copy; <a href="https://carto.com/attributions">CARTO</a> '
    + '&copy; <a href="https://www.esri.com/">Esri</a>',
}

/** English place-name overlay (countries, cities, regions). */
export const MAP_LABELS_EN = {
  url: 'https://services.arcgisonline.com/ArcGIS/rest/services/Reference/World_Boundaries_and_Places/MapServer/tile/{z}/{y}/{x}',
  maxZoom: 16,
  opacity: 0.92,
}