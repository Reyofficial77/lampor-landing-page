import { useEffect, useMemo, useRef, useState } from 'react'
import FeatherIcon from './components/FeatherIcon'
import DownloadCard from './components/DownloadCard'
import DownloadModal from './components/DownloadModal'
import { detectOS } from './lib/detectOS'
import { fetchDownloads } from './lib/releases'
import { GAME, RELEASES_URL, WEB_PLAY_URL } from './config'
import AdminApp from './admin/AdminApp'

const FEATURES = [
  ['eye', 'AI Lampor', 'Makhluk yang memburu Anda menembus gelap, dengan sistem kewarasan yang terus tergerus.'],
  ['moon', 'Tiga Babak Malam', 'Dari menyalakan obor penolak bala hingga membakar benda ritual di tungku sebelum fajar.'],
  ['zap', 'Bertahan Hidup', 'Kelola stamina, senter, dan inventaris. Setiap keputusan berisiko.'],
  ['sliders', 'Desktop & Sentuh', 'Kontrol keyboard-mouse di Windows dan joystick virtual yang bisa diatur di Android.'],
]
const CHAPTERS = [
  ['I', 'Pertahanan Awal', '01.00–02.30', 'Nyalakan lima obor dan barikade tiga pintu rumah.'],
  ['II', 'Ritual Pemutus Kutukan', '02.30–04.00', 'Kumpulkan kemenyan, bunga tujuh rupa, keris pusaka, dan tanah kuburan.'],
  ['III', 'Klimaks Pembakaran', '04.00–05.00', 'Bakar semua di tungku dan bertahan sampai fajar.'],
]
const OS_NAMES = { ios: 'iOS', mac: 'macOS', linux: 'Linux', unknown: 'perangkat ini' }

function LandingPage() {
  const os = useMemo(detectOS, [])
  const [dl, setDl] = useState({ version: GAME.version, fallback: RELEASES_URL })
  const [activePlatform, setActivePlatform] = useState(null)
  const downloadTriggerRef = useRef(null)

  useEffect(() => { fetchDownloads().then(setDl) }, [])

  const handleDownload = (platform, triggerEl) => {
    downloadTriggerRef.current = triggerEl
    setActivePlatform(platform)
  }

  const handleCloseModal = () => {
    setActivePlatform(null)
  }

  // Fade-up saat elemen masuk viewport.
  useEffect(() => {
    const els = document.querySelectorAll(
      '.hero > *, .section > *, .cards > *, .grid > *, .chapters > li'
    )
    if (!('IntersectionObserver' in window)) return
    const io = new IntersectionObserver((entries) => {
      entries.forEach((e) => {
        if (e.isIntersecting) { e.target.classList.add('is-visible'); io.unobserve(e.target) }
      })
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' })
    els.forEach((el, i) => {
      el.classList.add('reveal')
      el.style.setProperty('--d', `${(i % 4) * 90}ms`)
      io.observe(el)
    })
    return () => io.disconnect()
  }, [])

  const supported = os === 'windows' || os === 'android'
  const order = os === 'android' ? ['android', 'windows'] : ['windows', 'android']

  return (
    <>
      <header className="nav">
        <a className="brand" href="#top"><img src="/icon.png" alt="" width="32" height="32" />LAMPOR</a>
        <nav>
          <a href="#fitur">Fitur</a>
          <a href="#babak">Babak</a>
          <a href="#unduh">Unduh</a>
        </nav>
      </header>

      <main id="top">
        <section className="hero">
          <p className="eyebrow">Horor Survival Folklor Indonesia</p>
          <h1>LAMPOR<span>Malam Jahanam</span></h1>
          <p className="lead">
            Bertahan dari malam, kumpulkan benda ritual, lalu bakar semuanya sebelum fajar.
          </p>
          <a className="btn btn--lg" href="#unduh">Unduh Sekarang</a>
          <p className="small">Windows (64-bit) · Android 7+ · Gratis</p>
        </section>

        <section id="unduh" className="section">
          <h2>Unduh Game</h2>
          {supported ? (
            <p className="sub">Kami mendeteksi Anda memakai <strong>{os === 'windows' ? 'Windows' : 'Android'}</strong>.</p>
          ) : (
            <p className="notice">
              Game ini belum tersedia untuk {OS_NAMES[os]}. Unduh dari Windows (64-bit) atau Android 7+.
            </p>
          )}
          <div className="cards">
            {order.map((k) => (
              <DownloadCard key={k} platform={k} data={dl[k]} fallback={dl.fallback}
                version={dl.version} detected={os === k} onDownload={handleDownload} />
            ))}
          </div>
          <p className="web-play">
            Atau mainkan dengan browser anda :{' '}
            <a href={WEB_PLAY_URL} target="_blank" rel="noopener noreferrer">
              Website Game LAMPOR
            </a>
          </p>
          <p className="small">Semua rilis: <a href={RELEASES_URL} target="_blank" rel="noreferrer">GitHub Releases</a></p>
        </section>

        <section id="fitur" className="section">
          <h2>Fitur</h2>
          <div className="grid">
            {FEATURES.map(([i, t, d]) => (
              <div className="feat" key={t}><span><FeatherIcon name={i} size={28} /></span><h3>{t}</h3><p>{d}</p></div>
            ))}
          </div>
        </section>

        <section id="babak" className="section">
          <h2>Alur Permainan</h2>
          <ol className="chapters">
            {CHAPTERS.map(([n, t, time, d]) => (
              <li key={n}><b>{n}</b><div><h3>{t} <small>{time}</small></h3><p>{d}</p></div></li>
            ))}
          </ol>
        </section>
      </main>

      <footer className="footer">
        <p>© {new Date().getFullYear()} {GAME.developer} · {GAME.name} · Lisensi MIT</p>
      </footer>

      <DownloadModal
        platform={activePlatform}
        data={activePlatform ? dl[activePlatform] : null}
        fallback={dl.fallback}
        version={dl.version}
        onClose={handleCloseModal}
        returnFocusTo={downloadTriggerRef}
      />
    </>
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
      : 'LAMPOR: Malam Jahanam — Unduh Game'
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

  return <LandingPage />
}
