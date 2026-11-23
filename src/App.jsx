import { useEffect, useMemo, useRef, useState } from 'react'
import DownloadCard from './components/DownloadCard'
import DownloadModal from './components/DownloadModal'
import FeatherIcon from './components/FeatherIcon'
import { detectOS } from './lib/detectOS'
import { fetchDownloads } from './lib/releases'
import { GAME, RELEASES_URL, WEB_PLAY_URL } from './config'
import AdminApp from './admin/AdminApp'

const FEATURES = [
  [
    'eye',
    'AI Lampor',
    'Makhluk yang memburu Anda menembus gelap, dengan sistem kewarasan yang terus tergerus.',
  ],
  [
    'moon',
    'Tiga Babak Malam',
    'Dari menyalakan obor penolak bala hingga membakar benda ritual di tungku sebelum fajar.',
  ],
  [
    'zap',
    'Bertahan Hidup',
    'Kelola stamina, baterai senter, dan inventaris. Setiap keputusan berisiko.',
  ],
  [
    'sliders',
    'Desktop & Sentuh',
    'Kontrol keyboard-mouse di Windows dan joystick virtual yang dapat diatur di Android.',
  ],
]

const CHAPTERS = [
  ['I', 'Pertahanan Awal', '01.00 - 02.30', 'Nyalakan lima obor dan barikade tiga pintu rumah.'],
  ['II', 'Ritual Pemutus Kutukan', '02.30 - 04.00', 'Kumpulkan kemenyan, bunga tujuh rupa, keris pusaka, dan tanah kuburan.'],
  ['III', 'Klimaks Pembakaran', '04.00 - 05.00', 'Bakar semua benda ritual di tungku dan bertahan sampai fajar.'],
]

const OS_NAMES = { ios: 'iOS', mac: 'macOS', linux: 'Linux', unknown: 'perangkat ini' }

function CarvedLanternGlyph() {
  return (
    <svg
      width="28"
      height="28"
      viewBox="0 0 28 28"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.6"
      strokeLinecap="square"
      strokeLinejoin="miter"
      aria-hidden="true"
    >
      <path d="M10 4H18V7H10V4Z" />
      <path d="M7 9H21L19 22H9L7 9Z" />
      <path d="M14 12V19" />
      <path d="M11 15H17" />
      <path d="M9 24H19" />
    </svg>
  )
}

function MenuGlyph({ open }) {
  return (
    <svg
      width="22"
      height="22"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.8"
      strokeLinecap="square"
      aria-hidden="true"
    >
      {open ? (
        <>
          <line x1="6" y1="6" x2="18" y2="18" />
          <line x1="18" y1="6" x2="6" y2="18" />
        </>
      ) : (
        <>
          <line x1="4" y1="7" x2="20" y2="7" />
          <line x1="4" y1="12" x2="20" y2="12" />
          <line x1="4" y1="17" x2="20" y2="17" />
        </>
      )}
    </svg>
  )
}

function LandingPage({ onNavigate }) {
  const os = useMemo(detectOS, [])
  const [dl, setDl] = useState({ version: GAME.version, fallback: RELEASES_URL })
  const [activePlatform, setActivePlatform] = useState(null)
  const [menuOpen, setMenuOpen] = useState(false)
  const downloadTriggerRef = useRef(null)
  const navToggleRef = useRef(null)

  useEffect(() => {
    fetchDownloads().then(setDl)
  }, [])

  useEffect(() => {
    if (!menuOpen) return undefined
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        setMenuOpen(false)
        navToggleRef.current?.focus()
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [menuOpen])

  const handleDownload = (platform, triggerEl) => {
    downloadTriggerRef.current = triggerEl
    setActivePlatform(platform)
  }

  const handleCloseModal = () => {
    setActivePlatform(null)
  }

  const handleRouteLink = (e, path) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
    e.preventDefault()
    setMenuOpen(false)
    onNavigate(path)
  }

  const supported = os === 'windows' || os === 'android'
  const order = os === 'android' ? ['android', 'windows'] : ['windows', 'android']

  return (
    <div className="landing-shell">
      <header className="nav">
        <a className="brand" href="#top" onClick={() => setMenuOpen(false)}>
          <img src="/icon.png" alt="Lambang LAMPOR" width="32" height="32" />
          <span>LAMPOR</span>
        </a>

        <button
          ref={navToggleRef}
          type="button"
          className="nav__toggle"
          aria-expanded={menuOpen}
          aria-controls="site-nav"
          aria-label={menuOpen ? 'Tutup menu navigasi' : 'Buka menu navigasi'}
          onClick={() => setMenuOpen((prev) => !prev)}
        >
          <MenuGlyph open={menuOpen} />
        </button>

        <nav
          id="site-nav"
          className={`nav__menu${menuOpen ? ' is-open' : ''}`}
          aria-label="Navigasi utama"
        >
          <a href="#unduh" onClick={() => setMenuOpen(false)}>
            Unduh
          </a>
          <a href="#mode-online" onClick={() => setMenuOpen(false)}>
            Mode Online
          </a>
          <a href="#fitur" onClick={() => setMenuOpen(false)}>
            Fitur
          </a>
          <a href="#babak" onClick={() => setMenuOpen(false)}>
            Babak
          </a>
          <a
            href="/admin"
            className="nav__admin"
            onClick={(e) => handleRouteLink(e, '/admin')}
          >
            Admin
          </a>
        </nav>
      </header>

      <main id="top">
        <section className="hero">
          <div className="hero__crest" aria-hidden="true">
            <img src="/icon.png" alt="" width="56" height="56" fetchpriority="high" />
          </div>
          <h1>
            LAMPOR
            <span>Malam Jahanam</span>
          </h1>
          <p className="lead">
            Game survival horror 3D bertema folklor Indonesia, kini hadir dengan rilis{' '}
            <code className="mono-chip">v{dl.version}</code>. Bertahan seorang diri atau bersama
            rekan sebelum fajar tiba.
          </p>
          <div className="hero__actions">
            <a className="btn btn--lg" href="#unduh">
              Unduh v{dl.version}
            </a>
            <a className="btn btn--ghost" href="#mode-online">
              Lihat Fitur v1.3.0
            </a>
          </div>
          <p className="small">Windows (64-bit) · Android 7+ · Singleplayer, Co-op &amp; Sandbox</p>
        </section>

        <section id="unduh" className="section">
          <h2>Unduh Game</h2>
          {supported ? (
            <p className="sub">
              Sistem mendeteksi perangkat Anda menjalankan{' '}
              <strong>{os === 'windows' ? 'Windows' : 'Android'}</strong>.
            </p>
          ) : (
            <p className="notice">
              Paket instalasi belum tersedia untuk {OS_NAMES[os]}. Unduh dari Windows (64-bit) atau
              Android 7+.
            </p>
          )}
          <div className="cards">
            {order.map((k) => (
              <DownloadCard
                key={k}
                platform={k}
                data={dl[k]}
                fallback={dl.fallback}
                version={dl.version}
                detected={os === k}
                onDownload={handleDownload}
              />
            ))}
          </div>
          <p className="web-play">
            Atau mainkan langsung melalui peramban:{' '}
            <a href={WEB_PLAY_URL} target="_blank" rel="noopener noreferrer">
              Website Game LAMPOR
            </a>
          </p>
          <p className="small">
            Arsip rilis lengkap:{' '}
            <a href={RELEASES_URL} target="_blank" rel="noreferrer">
              GitHub Releases
            </a>
          </p>
        </section>

        <section id="mode-online" className="section section--online">
          <h2>Pembaruan v1.3.0: Malam Bersama</h2>
          <p className="sub">
            Mainkan Singleplayer dalam Mode Guest, atau masuk menggunakan Akun LAMPOR untuk membuka
            sesi Co-op dan ruang Sandbox.
          </p>

          <article className="online-flagship">
            <div className="online-flagship__head">
              <span className="online-glyph">
                <CarvedLanternGlyph />
              </span>
              <div>
                <h3>Multiplayer Co-op (1 hingga 4 Pemain)</h3>
                <p>
                  Buat room publik atau terkunci kata sandi dengan kode enam karakter, atur izin
                  pemakaian item toko oleh host, dan sinkronkan status obor, barikade pintu, benda
                  ritual, serta pergerakan Lampor secara serempak.
                </p>
              </div>
            </div>
            <ul className="online-ledger">
              <li>
                <span className="mono-chip">ROOM CODE</span>
                <span>Gabung cepat dengan kode 6 huruf atau daftar room aktif</span>
              </li>
              <li>
                <span className="mono-chip">SHOP RULE</span>
                <span>Host menentukan apakah Item Toko dan nyawa tambahan aktif di room</span>
              </li>
              <li>
                <span className="mono-chip">SYNC</span>
                <span>Keadaan obor, pintu rumah, benda ritual, dan status kewarasan terpantau real-time</span>
              </li>
            </ul>
          </article>

          <div className="online-split">
            <article className="online-panel">
              <h3>Mode Sandbox Host</h3>
              <p>
                Pemilik room Sandbox dapat membuka panel kendali dengan{' '}
                <code className="mono-chip">Ctrl+F5</code> di desktop atau tombol panel pada
                antarmuka sentuh Android untuk membekukan AI Lampor, mengatur jam malam, mencoba
                stamina atau baterai tanpa batas, serta mengelola peserta room.
              </p>
            </article>
            <article className="online-panel online-panel--secondary">
              <h3>Akun LAMPOR &amp; Cloud Sync</h3>
              <p>
                Koin, koleksi item toko, kemenangan, dan penukaran kode hadiah tersimpan pada basis
                data PostgreSQL yang dilindungi tantangan anti-bot dan pembatasan akses. Mode Guest
                tetap tersedia kapan saja untuk permainan Singleplayer offline.
              </p>
            </article>
          </div>
        </section>

        <section id="fitur" className="section">
          <h2>Mekanik Bertahan Hidup</h2>
          <div className="grid">
            {FEATURES.map(([i, t, d]) => (
              <div className="feat" key={t}>
                <span>
                  <FeatherIcon name={i} size={26} />
                </span>
                <h3>{t}</h3>
                <p>{d}</p>
              </div>
            ))}
          </div>
        </section>

        <section id="babak" className="section">
          <h2>Alur Tiga Babak Malam</h2>
          <ol className="chapters">
            {CHAPTERS.map(([n, t, time, d]) => (
              <li key={n}>
                <b>{n}</b>
                <div>
                  <h3>
                    {t} <small>{time}</small>
                  </h3>
                  <p>{d}</p>
                </div>
              </li>
            ))}
          </ol>
        </section>
      </main>

      <footer className="footer">
        <p>
          © {new Date().getFullYear()} {GAME.developer} · {GAME.name} · Lisensi MIT
        </p>
        <div className="footer__links">
          <a href={RELEASES_URL} target="_blank" rel="noreferrer">
            GitHub Releases
          </a>
          <a href={WEB_PLAY_URL} target="_blank" rel="noopener noreferrer">
            Main di Browser
          </a>
          <a href="/admin" onClick={(e) => handleRouteLink(e, '/admin')}>
            Konsol Admin
          </a>
        </div>
      </footer>

      <DownloadModal
        platform={activePlatform}
        data={activePlatform ? dl[activePlatform] : null}
        fallback={dl.fallback}
        version={dl.version}
        onClose={handleCloseModal}
        returnFocusTo={downloadTriggerRef}
      />
    </div>
  )
}

export default function App() {
  const [pathname, setPathname] = useState(() =>
    typeof window !== 'undefined' ? window.location.pathname : '/'
  )

  useEffect(() => {
    const onPopState = () => setPathname(window.location.pathname)
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  const isAdminRoute = pathname.startsWith('/admin')

  useEffect(() => {
    document.title = isAdminRoute
      ? 'LAMPOR Admin | Konsol Operasi Server'
      : 'LAMPOR: Malam Jahanam | Unduh Game'
  }, [isAdminRoute])

  const navigate = (to) => {
    if (window.location.pathname !== to) {
      window.history.pushState({}, '', to)
      setPathname(to)
      window.scrollTo({ top: 0, behavior: 'auto' })
    }
  }

  if (isAdminRoute) {
    return <AdminApp onNavigateHome={() => navigate('/')} />
  }

  return <LandingPage onNavigate={navigate} />
}
