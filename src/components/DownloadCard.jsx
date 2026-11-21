import { fmtSize } from '../lib/releases'
import { PLATFORMS } from '../config'

// Ikon dari Feather Icons (https://feathericons.com), MIT.
const FEATHER = {
  monitor: (
    <>
      <rect x="2" y="3" width="20" height="14" rx="2" ry="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
    </>
  ),
  smartphone: (
    <>
      <rect x="5" y="2" width="14" height="20" rx="2" ry="2" />
      <line x1="12" y1="18" x2="12.01" y2="18" />
    </>
  ),
}

function Icon({ name }) {
  return (
    <svg className="card__svg" width="48" height="48" viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      {FEATHER[name]}
    </svg>
  )
}

export default function DownloadCard({ platform, data, fallback, version, detected }) {
  const p = PLATFORMS[platform]
  const href = data?.url || fallback
  return (
    <article className={`card${detected ? ' card--detected' : ''}`}>
      {detected && <span className="badge">Perangkat Anda</span>}
      <div className="card__icon"><Icon name={p.icon} /></div>
      <h3>{p.label}</h3>
      <p className="card__req">{p.req}</p>
      <p className="card__meta">
        Versi {version}{data?.size ? ` · ${fmtSize(data.size)}` : ''}
      </p>
      <a className="btn" href={href} {...(data?.url ? { download: '' } : { target: '_blank', rel: 'noreferrer' })}>
        Unduh untuk {p.label}
      </a>
    </article>
  )
}
