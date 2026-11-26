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
      <div className="admin-gate__layout">
        <section className="admin-gate__brief" aria-labelledby="admin-login-heading">
          <div className="admin-gate__brief-top">
            <div className="admin-gate__brand">
              <img src="/icon.png" alt="Lambang LAMPOR" width="44" height="44" />
              <div>
                <p className="admin-gate__eyebrow">Konsol Operasi Server v1.3.0</p>
                <h1 id="admin-login-heading">Gerbang Konsol Admin LAMPOR</h1>
              </div>
            </div>

            <p className="admin-gate__lead">
              Akses terpusat bagi operator server untuk mengawasi integritas akun pemain, room
              multiplayer aktif, serta kebijakan pertahanan sistem.
            </p>
          </div>

          <div className="admin-gate__scope">
            <h2 className="admin-gate__scope-title">Ruang Lingkup Konsol</h2>
            <ol className="admin-gate__facts">
              <li>
                <span className="admin-gate__fact-num" aria-hidden="true">
                  01
                </span>
                <span>Kelola akun pemain, status online, dan moderasi akses.</span>
              </li>
              <li>
                <span className="admin-gate__fact-num" aria-hidden="true">
                  02
                </span>
                <span>Awasi room Co-op / Sandbox serta siaran darurat HUD.</span>
              </li>
              <li>
                <span className="admin-gate__fact-num" aria-hidden="true">
                  03
                </span>
                <span>
                  Akun <code>admin_lampor</code> khusus akses konsol web dan tidak dapat dipakai
                  bermain di dalam game.
                </span>
              </li>
            </ol>
          </div>
        </section>

        <section className="admin-gate__panel" aria-labelledby="admin-auth-heading">
          <div className="admin-gate__panel-head">
            <h2 id="admin-auth-heading">Autentikasi Operator</h2>
            <p className="admin-field__hint">
              Masukkan kredensial administrator untuk membuka sesi konsol.
            </p>
          </div>

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
                  spellCheck={false}
                  autoCapitalize="none"
                  autoCorrect="off"
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
                className="admin-btn admin-btn--primary admin-gate__submit"
                disabled={submitting}
              >
                {submitting ? 'Memverifikasi Akses...' : 'Masuk ke Konsol Admin'}
              </button>
            </form>
          )}

          <div className="admin-gate__footer">
            <span className="admin-field__hint">Akses khusus operator konsol · Non-playable di game</span>
            <a href="/" className="admin-btn admin-btn--ghost admin-btn--sm" onClick={handleHomeClick}>
              Kembali ke Beranda
            </a>
          </div>
        </section>
      </div>
    </main>
  )
}
