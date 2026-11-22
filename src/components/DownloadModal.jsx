import { useEffect, useLayoutEffect, useRef } from 'react'
import { DONATION_URL, GAME, PLATFORMS } from '../config'
import { fmtSize } from '../lib/releases'
import FeatherIcon from './FeatherIcon'

export default function DownloadModal({ platform, data, fallback, version, onClose, returnFocusTo }) {
  const dialogRef = useRef(null)

  useLayoutEffect(() => {
    const dialog = dialogRef.current
    if (!dialog) return

    if (platform) {
      if (!dialog.open) dialog.showModal()
      document.body.style.overflow = 'hidden'
    } else if (dialog.open) {
      dialog.close()
      document.body.style.overflow = ''
    }

    return () => {
      document.body.style.overflow = ''
    }
  }, [platform])

  useEffect(() => {
    if (!platform && returnFocusTo?.current) {
      returnFocusTo.current.focus()
      returnFocusTo.current = null
    }
  }, [platform, returnFocusTo])

  if (!platform) return <dialog ref={dialogRef} className="modal" />

  const p = PLATFORMS[platform]
  const isDirect = Boolean(data?.url)
  const href = data?.url || fallback
  const size = fmtSize(data?.size)

  // Clicking the native ::backdrop dispatches click on the <dialog> element itself.
  const handleDialogClick = (e) => {
    if (e.target === dialogRef.current) onClose()
  }

  // Keep React state in sync when Escape triggers the native cancel event.
  const handleCancel = (e) => {
    e.preventDefault()
    onClose()
  }

  return (
    <dialog
      ref={dialogRef}
      className="modal"
      aria-labelledby="download-modal-title"
      aria-describedby="download-modal-desc"
      onClick={handleDialogClick}
      onCancel={handleCancel}
    >
      <div className="modal__panel">
        <button
          type="button"
          className="modal__close"
          onClick={onClose}
          aria-label="Tutup jendela unduhan"
        >
          <FeatherIcon name="x" size={20} />
        </button>

        <div className="modal__head">
          <img className="modal__emblem" src="/icon.png" alt="" width="44" height="44" />
          <p className="modal__meta">
            <FeatherIcon name={p.icon} size={15} />
            <span>
              {p.label} · Versi {version}
              {size ? ` · ${size}` : ''}
            </span>
          </p>
        </div>

        <h2 id="download-modal-title" className="modal__title">
          {isDirect ? 'LAMPOR sedang diunduh...' : 'Halaman unduhan LAMPOR dibuka'}
        </h2>

        <p id="download-modal-desc" className="modal__body">
          {GAME.name} tersedia gratis untuk Anda mainkan. Dukungan Anda membantu {GAME.developer} terus mengembangkan game ini.
        </p>

        <div className="modal__actions">
          <a
            className="btn modal__cta"
            href={DONATION_URL}
            target="_blank"
            rel="noopener noreferrer"
          >
            Donasi di Saweria
          </a>
        </div>

        <p className="modal__fallback">
          {isDirect ? (
            <>
              Unduhan belum mulai otomatis?{' '}
              <a href={href} download target="_blank" rel="noopener noreferrer">
                Coba unduh ulang
              </a>
            </>
          ) : (
            <>
              Tab rilis belum terbuka?{' '}
              <a href={href} target="_blank" rel="noopener noreferrer">
                Buka GitHub Releases
              </a>
            </>
          )}
        </p>
      </div>
    </dialog>
  )
}
