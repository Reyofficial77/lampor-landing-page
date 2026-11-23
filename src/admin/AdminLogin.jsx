import { useCallback, useEffect, useState } from 'react'
import { getAdminSession, loginAdmin } from './adminApi'

export default function AdminLogin({ onAuthenticated, onNavigateHome, initialNotice = '' }) {
  const [checking, setChecking] = useState(true)
  const [sessionError, setSessionError] = useState('')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [website, setWebsite] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [powStatus, setPowStatus] = useState('')
  const [formError, setFormError] = useState(initialNotice)

  const checkSession = useCallback(async () => {
    setChecking(true)
    setSessionError('')
    try {
      const session = await getAdminSession()
      if (session?.ok && session.admin) {
        onAuthenticated(session)
        return
      }
    } catch (err) {
      setSessionError(err.message || 'Gagal memeriksa sesi admin dari server.')
    } finally {
      setChecking(false)
    }
  }, [onAuthenticated])

  useEffect(() => {
    checkSession()
  }, [checkSession])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setFormError('')

    const cleanUser = username.trim()
    if (!/^[a-zA-Z0-9_]{3,24}$/.test(cleanUser)) {
      setFormError('Username admin harus 3 hingga 24 karakter (huruf, angka, atau garis bawah).')
      return
    }
    if (password.length < 8) {
      setFormError('Kata sandi minimal 8 karakter.')
      return
    }

    setSubmitting(true)
    setPowStatus('Memulai verifikasi anti-bot...')
    try {
      const result = await loginAdmin({
        username: cleanUser,
        password,
        website,
        onStatus: setPowStatus,
      })
      if (result?.ok && result.admin) {
        onAuthenticated(result)
      } else {
        setFormError('Respons login tidak valid dari server.')
      }
    } catch (err) {
      setFormError(err.message || 'Login administrator gagal.')
    } finally {
      setSubmitting(false)
      setPowStatus('')
    }
  }

  const handleHomeClick = (e) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    if (onNavigateHome) {
      e.preventDefault()
      onNavigateHome()
    }
  }

  return (
    <main className="admin-gate">
      <section className="admin-gate__panel" aria-labelledby="admin-login-heading">
        <div className="admin-gate__head">
          <img src="/icon.png" alt="Lambang LAMPOR" width="40" height="40" />
          <div>
            <h1 id="admin-login-heading">Konsol Admin LAMPOR</h1>
            <p className="admin-field__hint">Gerbang Autentikasi Server v1.3.0</p>
          </div>
        </div>

        <p className="admin-gate__desc">
          Masuk dengan akun administrator LAMPOR untuk mengelola pemain, room multiplayer,
          pengaturan pemeliharaan, dan log pertahanan server.
        </p>

        {checking ? (
          <div className="admin-state-box" role="status" aria-live="polite">
            <h3>Memeriksa Sesi Aktif</h3>
            <p>Menghubungi endpoint sesi admin sebelum membuka panel kontrol...</p>
          </div>
        ) : sessionError ? (
          <div className="admin-state-box" role="alert">
            <h3>Koneksi Konsol Terputus</h3>
            <p>{sessionError}</p>
            <button type="button" className="admin-btn admin-btn--primary" onClick={checkSession}>
              Coba Periksa Ulang
            </button>
          </div>
        ) : (
          <form className="admin-form" onSubmit={handleSubmit} noValidate>
            <div className="admin-field">
              <label htmlFor="admin-username">Username Admin</label>
              <input
                id="admin-username"
                name="username"
                type="text"
                className="admin-input"
                autoComplete="username"
                placeholder="Nama akun administrator"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                disabled={submitting}
                required
              />
            </div>

            <div className="admin-field">
              <label htmlFor="admin-password">Kata Sandi</label>
              <div className="admin-input-group">
                <input
                  id="admin-password"
                  name="password"
                  type={showPassword ? 'text' : 'password'}
                  className="admin-input"
                  autoComplete="current-password"
                  placeholder="Minimal 8 karakter"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  disabled={submitting}
                  required
                />
                <button
                  type="button"
                  className="admin-btn admin-btn--ghost admin-btn--sm"
                  aria-pressed={showPassword}
                  onClick={() => setShowPassword((prev) => !prev)}
                  disabled={submitting}
                >
                  {showPassword ? 'Tutup' : 'Lihat'}
                </button>
              </div>
            </div>

            <div className="hp-field" aria-hidden="true">
              <label htmlFor="admin-website-hp">Situs Web</label>
              <input
                id="admin-website-hp"
                name="website"
                type="text"
                tabIndex={-1}
                autoComplete="off"
                value={website}
                onChange={(e) => setWebsite(e.target.value)}
              />
            </div>

            {powStatus && (
              <div className="admin-alert" role="status" aria-live="polite">
                <span>{powStatus}</span>
              </div>
            )}

            {formError && (
              <div className="admin-alert admin-alert--error" role="alert">
                <span>{formError}</span>
              </div>
            )}

            <button
              type="submit"
              className="admin-btn admin-btn--primary"
              disabled={submitting}
            >
              {submitting ? 'Memverifikasi Akses...' : 'Masuk ke Konsol Admin'}
            </button>
          </form>
        )}

        <div className="admin-gate__footer">
          <span className="admin-field__hint">Dilindungi tantangan PoW SHA-256 &amp; CSRF</span>
          <a href="/" className="admin-btn admin-btn--ghost admin-btn--sm" onClick={handleHomeClick}>
            Kembali ke Beranda
          </a>
        </div>
      </section>
    </main>
  )
}
