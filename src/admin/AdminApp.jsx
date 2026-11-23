import { useCallback, useEffect, useRef, useState } from 'react'
import './admin.css'
import AdminLogin from './AdminLogin'
import OverviewTab from './OverviewTab'
import RoomsTab from './RoomsTab'
import SecurityTab from './SecurityTab'
import UsersTab from './UsersTab'
import { logoutAdmin } from './adminApi'

const NAV_GROUPS = [
  {
    group: 'Server',
    items: [
      {
        id: 'overview',
        label: 'Ringkasan Server',
        subtitle: 'Metrik operasional langsung dan gerbang pemeliharaan',
        icon: 'server',
      },
    ],
  },
  {
    group: 'Komunitas',
    items: [
      {
        id: 'users',
        label: 'Akun Pemain',
        subtitle: 'Kelola akun, progres koin, moderasi ban, dan sesi',
        icon: 'users',
      },
      {
        id: 'rooms',
        label: 'Server Multiplayer',
        subtitle: 'Pantau room Co-op dan Sandbox, kick pemain, dan pengumuman',
        icon: 'rooms',
      },
    ],
  },
  {
    group: 'Pertahanan',
    items: [
      {
        id: 'security',
        label: 'Keamanan & Redeem',
        subtitle: 'Blokir IP, rate limiter, kode hadiah, dan log audit',
        icon: 'shield',
      },
    ],
  },
]

function NavGlyph({ name }) {
  return (
    <svg
      width="18"
      height="18"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.75"
      strokeLinecap="square"
      strokeLinejoin="miter"
      aria-hidden="true"
    >
      {name === 'server' && (
        <>
          <rect x="3" y="4" width="18" height="6" />
          <rect x="3" y="14" width="18" height="6" />
          <line x1="7" y1="7" x2="9" y2="7" />
          <line x1="7" y1="17" x2="9" y2="17" />
        </>
      )}
      {name === 'users' && (
        <>
          <rect x="7" y="4" width="6" height="6" />
          <path d="M3 20V16C3 14.3 4.3 13 6 13H14C15.7 13 17 14.3 17 16V20" />
          <path d="M17 7H21" />
          <path d="M19 5V9" />
        </>
      )}
      {name === 'rooms' && (
        <>
          <rect x="3" y="4" width="8" height="7" />
          <rect x="13" y="4" width="8" height="7" />
          <rect x="8" y="14" width="8" height="6" />
          <line x1="7" y1="11" x2="7" y2="17" />
          <line x1="17" y1="11" x2="17" y2="17" />
        </>
      )}
      {name === 'shield' && (
        <>
          <path d="M12 3L4 6V12C4 16.8 7.4 20.6 12 22C16.6 20.6 20 16.8 20 12V6L12 3Z" />
          <line x1="12" y1="8" x2="12" y2="13" />
          <line x1="12" y1="16" x2="12.01" y2="16" />
        </>
      )}
    </svg>
  )
}

export default function AdminApp({ onNavigateHome }) {
  const [admin, setAdmin] = useState(null)
  const [loginNotice, setLoginNotice] = useState('')
  const [activeTab, setActiveTab] = useState('overview')
  const [collapsed, setCollapsed] = useState(false)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [refreshTick, setRefreshTick] = useState(0)
  const [loggingOut, setLoggingOut] = useState(false)
  const [toast, setToast] = useState(null)

  const mobileTriggerRef = useRef(null)
  const wasMobileOpenRef = useRef(false)

  const showToast = useCallback((type, text) => {
    setToast({ id: Date.now(), type, text })
  }, [])

  useEffect(() => {
    if (!toast) return undefined
    const timer = setTimeout(() => setToast(null), 5500)
    return () => clearTimeout(timer)
  }, [toast])

  useEffect(() => {
    if (mobileOpen) {
      wasMobileOpenRef.current = true
      const onKeyDown = (e) => {
        if (e.key === 'Escape') {
          setMobileOpen(false)
        }
      }
      window.addEventListener('keydown', onKeyDown)
      return () => window.removeEventListener('keydown', onKeyDown)
    }

    if (wasMobileOpenRef.current) {
      wasMobileOpenRef.current = false
      mobileTriggerRef.current?.focus()
    }
    return undefined
  }, [mobileOpen])

  const handleUnauthorized = useCallback((message) => {
    setAdmin(null)
    setMobileOpen(false)
    setLoginNotice(message || 'Sesi administrator berakhir. Silakan masuk kembali.')
  }, [])

  const handleAuthenticated = useCallback((session) => {
    setLoginNotice('')
    setAdmin(session.admin)
    setToast(null)
  }, [])

  const handleLogout = async () => {
    setLoggingOut(true)
    try {
      await logoutAdmin()
    } finally {
      setLoggingOut(false)
      setAdmin(null)
      setMobileOpen(false)
      setLoginNotice('Anda telah keluar dari Konsol Admin.')
    }
  }

  const handleHomeLink = (e) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    if (onNavigateHome) {
      e.preventDefault()
      onNavigateHome()
    }
  }

  if (!admin) {
    return (
      <AdminLogin
        onAuthenticated={handleAuthenticated}
        onNavigateHome={onNavigateHome}
        initialNotice={loginNotice}
      />
    )
  }

  const currentItem =
    NAV_GROUPS.flatMap((g) => g.items).find((item) => item.id === activeTab) || NAV_GROUPS[0].items[0]

  return (
    <div className={`admin-shell${collapsed ? ' is-collapsed' : ''}`}>
      {mobileOpen && (
        <button
          type="button"
          className="admin-drawer-scrim is-visible"
          aria-label="Tutup panel navigasi"
          onClick={() => setMobileOpen(false)}
        />
      )}

      <aside
        id="admin-nav-rail"
        className={`admin-rail${mobileOpen ? ' is-mobile-open' : ''}`}
        aria-label="Navigasi Konsol Admin"
      >
        <div className="admin-rail__top">
          <div className="admin-rail__brand">
            <div className="admin-rail__logo">
              <img src="/icon.png" alt="Lambang LAMPOR" width="32" height="32" />
              <span className="admin-rail__logo-text">LAMPOR ADMIN</span>
            </div>
            <button
              type="button"
              className="admin-rail__collapse"
              aria-expanded={!collapsed}
              aria-label={collapsed ? 'Perluas bilah navigasi' : 'Ciutkan bilah navigasi'}
              onClick={() => setCollapsed((prev) => !prev)}
            >
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="square"
                aria-hidden="true"
              >
                {collapsed ? (
                  <polyline points="9 6 15 12 9 18" />
                ) : (
                  <polyline points="15 6 9 12 15 18" />
                )}
              </svg>
            </button>
          </div>

          <nav className="admin-rail__groups" aria-label="Kategori konsol">
            {NAV_GROUPS.map((section) => (
              <div className="admin-rail__group" key={section.group}>
                <p className="admin-rail__group-label">{section.group}</p>
                {section.items.map((item) => {
                  const active = activeTab === item.id
                  return (
                    <button
                      key={item.id}
                      type="button"
                      className={`admin-nav-item${active ? ' is-active' : ''}`}
                      aria-current={active ? 'page' : undefined}
                      aria-label={item.label}
                      title={item.label}
                      onClick={() => {
                        setActiveTab(item.id)
                        setMobileOpen(false)
                      }}
                    >
                      <span className="admin-nav-item__icon">
                        <NavGlyph name={item.icon} />
                      </span>
                      <span className="admin-nav-item__text">{item.label}</span>
                    </button>
                  )
                })}
              </div>
            ))}
          </nav>
        </div>

        <div className="admin-rail__foot">
          <p className="admin-field__hint admin-rail__meta">
            Versi Konsol <code className="mono-chip">1.3.0</code>
          </p>
          <a
            href="/"
            className="admin-btn admin-btn--ghost admin-btn--sm"
            aria-label="Kembali ke situs utama LAMPOR"
            onClick={handleHomeLink}
          >
            <span>Situs Utama</span>
          </a>
        </div>
      </aside>

      <div className="admin-main">
        <header className="admin-topbar">
          <div className="admin-topbar__left">
            <button
              ref={mobileTriggerRef}
              type="button"
              className="admin-mobile-trigger"
              aria-expanded={mobileOpen}
              aria-controls="admin-nav-rail"
              aria-label={mobileOpen ? 'Tutup menu navigasi' : 'Buka menu navigasi'}
              onClick={() => setMobileOpen((prev) => !prev)}
            >
              <svg
                width="20"
                height="20"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="square"
                aria-hidden="true"
              >
                <line x1="4" y1="7" x2="20" y2="7" />
                <line x1="4" y1="12" x2="20" y2="12" />
                <line x1="4" y1="17" x2="20" y2="17" />
              </svg>
            </button>
            <div>
              <h1 className="admin-topbar__title">{currentItem.label}</h1>
              <p className="admin-topbar__sub">{currentItem.subtitle}</p>
            </div>
          </div>

          <div className="admin-topbar__right">
            <div className="admin-operator-badge" title={`Masuk sebagai ${admin.username}`}>
              <span className="admin-state-dot" aria-hidden="true" />
              <span>{admin.username}</span>
              <span className="admin-tag">{admin.role || 'admin'}</span>
            </div>

            <button
              type="button"
              className="admin-btn admin-btn--sm"
              onClick={() => setRefreshTick((t) => t + 1)}
            >
              Segarkan
            </button>

            <button
              type="button"
              className="admin-btn admin-btn--danger admin-btn--sm"
              onClick={handleLogout}
              disabled={loggingOut}
            >
              {loggingOut ? 'Keluar...' : 'Keluar'}
            </button>
          </div>
        </header>

        <main className="admin-content">
          {toast && (
            <div
              className={`admin-alert ${
                toast.type === 'error'
                  ? 'admin-alert--error'
                  : toast.type === 'warn'
                    ? 'admin-alert--warn'
                    : 'admin-alert--success'
              }`}
              role={toast.type === 'error' ? 'alert' : 'status'}
              aria-live="polite"
            >
              <span>{toast.text}</span>
              <button
                type="button"
                className="admin-btn admin-btn--ghost admin-btn--sm"
                aria-label="Tutup pemberitahuan"
                onClick={() => setToast(null)}
              >
                Tutup
              </button>
            </div>
          )}

          {activeTab === 'overview' && (
            <OverviewTab
              refreshTick={refreshTick}
              onNotify={showToast}
              onUnauthorized={handleUnauthorized}
            />
          )}
          {activeTab === 'users' && (
            <UsersTab
              refreshTick={refreshTick}
              onNotify={showToast}
              onUnauthorized={handleUnauthorized}
            />
          )}
          {activeTab === 'rooms' && (
            <RoomsTab
              refreshTick={refreshTick}
              onNotify={showToast}
              onUnauthorized={handleUnauthorized}
            />
          )}
          {activeTab === 'security' && (
            <SecurityTab
              refreshTick={refreshTick}
              onNotify={showToast}
              onUnauthorized={handleUnauthorized}
            />
          )}
        </main>
      </div>
    </div>
  )
}
