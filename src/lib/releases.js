import { GAME, PLATFORMS, RELEASES_URL, DOWNLOAD_LINKS } from '../config'

// Link manual (DOWNLOAD_LINKS) diprioritaskan; sisanya diambil dari rilis terbaru GitHub.
export async function fetchDownloads() {
  const result = { version: GAME.version, windows: null, android: null, fallback: RELEASES_URL }
  const manual = {}
  for (const k of ['windows', 'android']) {
    if (DOWNLOAD_LINKS[k]) manual[k] = { url: DOWNLOAD_LINKS[k] }
  }
  if (manual.windows && manual.android) return { ...result, ...manual }
  try {
    const r = await fetch(`https://api.github.com/repos/${GAME.repo}/releases/latest`)
    if (!r.ok) throw new Error(r.status)
    const rel = await r.json()
    result.version = (rel.tag_name || GAME.version).replace(/^v/, '')
    for (const key of ['windows', 'android']) {
      const p = PLATFORMS[key]
      const assets = rel.assets.filter((a) => p.ext.test(a.name))
      const a = assets.find((x) => p.hint.test(x.name)) || assets[0]
      if (a) result[key] = { url: a.browser_download_url, name: a.name, size: a.size }
    }
  } catch {
    /* gunakan fallback */
  }
  return { ...result, ...manual }
}

export const fmtSize = (b) => (b ? `${(b / 1048576).toFixed(0)} MB` : '')
