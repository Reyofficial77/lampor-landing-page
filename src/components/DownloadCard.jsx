import { fmtSize } from '../lib/releases'
import { PLATFORMS } from '../config'

export default function DownloadCard({ platform, data, fallback, version, detected }) {
  const p = PLATFORMS[platform]
  const href = data?.url || fallback
  return (
    <article className={`card${detected ? ' card--detected' : ''}`}>
      {detected && <span className="badge">Perangkat Anda</span>}
      <div className="card__icon" aria-hidden="true">{p.icon}</div>
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
