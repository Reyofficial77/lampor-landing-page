import { useCallback, useEffect, useRef, useState } from 'react'
import {
  ApiError,
  fetchOverview,
  fetchServerSettings,
  formatTimestamp,
  normalizeServerSettings,
  saveServerSettings,
} from './adminApi'

export default function OverviewTab({ refreshTick, autoTick, onNotify, onUnauthorized }) {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [stats, setStats] = useState(null)
  const [meta, setMeta] = useState({ updatedAt: null, updatedBy: '' })
  const [form, setForm] = useState(() => normalizeServerSettings({}))
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState('')
  const inFlightRef = useRef(false)

  const loadData = useCallback(async (silent = false) => {
    if (inFlightRef.current) return
    inFlightRef.current = true
    if (!silent) {
      setLoading(true)
      setError('')
    }
    try {
      const overviewRes = await fetchOverview()
      setStats(overviewRes.stats || null)
      let settingsRaw = overviewRes.serverSettings
      if (!settingsRaw && !silent) {
        const srvRes = await fetchServerSettings()
        settingsRaw = srvRes.serverSettings || srvRes.settings || srvRes
      }
      if (!silent && settingsRaw) {
        setForm(normalizeServerSettings(settingsRaw))
      }
      if (settingsRaw) {
        setMeta({
          updatedAt: settingsRaw?.updatedAt || settingsRaw?.updated_at || null,
          updatedBy: settingsRaw?.updatedBy || settingsRaw?.updated_by || '',
        })
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized(err.message)
        return
      }
      if (!silent) {
        setError(err.message || 'Gagal memuat ringkasan server.')
      }
    } finally {
      inFlightRef.current = false
      if (!silent) {
        setLoading(false)
      }
    }
  }, [onUnauthorized])

  useEffect(() => {
    loadData(false)
  }, [loadData, refreshTick])

  useEffect(() => {
    if (!autoTick) return
    loadData(true)
  }, [loadData, autoTick])

  const handleSaveSettings = async (e) => {
    e.preventDefault()
    setFormError('')

    const maxRooms = Number(form.maxActiveRooms)
    if (!Number.isInteger(maxRooms) || maxRooms < 1 || maxRooms > 500) {
      setFormError('Batas room aktif harus berupa bilangan bulat antara 1 dan 500.')
      return
    }
    if (!form.minClientVersion.trim()) {
      setFormError('Versi klien minimum wajib diisi (contoh: 1.3.0).')
      return
    }

    setSaving(true)
    try {
      const payload = {
        maintenanceMode: Boolean(form.maintenanceMode),
        maintenanceMessage: form.maintenanceMessage.trim(),
        allowRegistration: Boolean(form.allowRegistration),
        allowMultiplayer: Boolean(form.allowMultiplayer),
        allowSandbox: Boolean(form.allowSandbox),
        maxActiveRooms: maxRooms,
        globalAnnouncement: form.globalAnnouncement.trim(),
        minClientVersion: form.minClientVersion.trim(),
      }
      const res = await saveServerSettings(payload)
      const updated = res.serverSettings || res.settings || payload
      setForm(normalizeServerSettings(updated))
      setMeta({
        updatedAt: updated.updatedAt || updated.updated_at || new Date().toISOString(),
        updatedBy: updated.updatedBy || updated.updated_by || '',
      })
      onNotify('success', 'Pengaturan server berhasil disimpan ke basis data.')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized(err.message)
        return
      }
      setFormError(err.message || 'Gagal menyimpan pengaturan server.')
    } finally {
      setSaving(false)
    }
  }

  if (loading) {
    return (
      <section className="admin-state-box" role="status" aria-live="polite">
        <h2>Memuat Telemetri Server</h2>
        <p>Mengambil statistik pengguna, room aktif, dan gerbang server langsung dari API...</p>
      </section>
    )
  }

  if (error) {
    return (
      <section className="admin-state-box" role="alert">
        <h2>Gagal Memuat Ringkasan Server</h2>
        <p>{error}</p>
        <button type="button" className="admin-btn admin-btn--primary" onClick={loadData}>
          Coba Muat Ulang
        </button>
      </section>
    )
  }

  if (!stats) {
    return (
      <section className="admin-state-box">
        <h2>Data Telemetri Belum Tersedia</h2>
        <p>
          Server tidak mengembalikan objek statistik ringkasan. Tekan tombol di bawah untuk
          meminta data ulang dari endpoint ringkasan.
        </p>
        <button type="button" className="admin-btn admin-btn--primary" onClick={loadData}>
          Ambil Ulang Ringkasan
        </button>
      </section>
    )
  }

  return (
    <>
      <div className="overview-pulse">
        <section className="admin-panel admin-panel--priority" aria-labelledby="pulse-heading">
          <div className="admin-panel__head">
            <h2 id="pulse-heading">Beban Operasional Saat Ini</h2>
            <span
              className={`admin-tag ${form.maintenanceMode ? 'admin-tag--brass' : 'admin-tag--sage'}`}
            >
              {form.maintenanceMode ? 'PEMELIHARAAN AKTIF' : 'SERVER TERBUKA'}
            </span>
          </div>

          <div className="overview-primary-grid">
            <div className="overview-metric">
              <span className="overview-metric__label">Room Co-op Aktif</span>
              <strong className="overview-metric__value">{stats.activeMultiplayerRooms ?? 0}</strong>
            </div>
            <div className="overview-metric">
              <span className="overview-metric__label">Room Sandbox Aktif</span>
              <strong className="overview-metric__value">{stats.activeSandboxRooms ?? 0}</strong>
            </div>
            <div className="overview-metric">
              <span className="overview-metric__label">Kejadian Keamanan (24j)</span>
              <strong className="overview-metric__value">{stats.securityEvents24h ?? 0}</strong>
            </div>
          </div>

          <p className="admin-panel__desc">
            Seluruh angka diambil langsung dari kueri PostgreSQL/server saat halaman dimuat atau
            disegarkan.
          </p>
        </section>

        <section className="admin-panel" aria-labelledby="ledger-heading">
          <div className="admin-panel__head">
            <h2 id="ledger-heading">Catatan Populasi &amp; Kesehatan</h2>
            <span className="admin-tag">{stats.dbLatencyMs ?? 0} ms DB</span>
          </div>

          <dl className="overview-ledger">
            <div className="overview-ledger__row">
              <dt>Total Akun Pemain</dt>
              <dd>{stats.totalUsers ?? 0}</dd>
            </div>
            <div className="overview-ledger__row">
              <dt>Akun Diblokir</dt>
              <dd>{stats.bannedUsers ?? 0}</dd>
            </div>
            <div className="overview-ledger__row">
              <dt>Sesi Login Aktif</dt>
              <dd>{stats.activeSessions ?? 0}</dd>
            </div>
            <div className="overview-ledger__row">
              <dt>Alamat IP Terblokir</dt>
              <dd>{stats.blockedIps ?? 0}</dd>
            </div>
          </dl>
        </section>
      </div>

      <section className="admin-panel" aria-labelledby="server-settings-heading">
        <div className="admin-panel__head">
          <div>
            <h2 id="server-settings-heading">Gerbang Server &amp; Pengumuman Global</h2>
            <p className="admin-panel__desc">
              Ubah akses registrasi, multiplayer, sandbox, batas room, dan siaran HUD untuk semua
              klien v{form.minClientVersion || '1.3.0'}.
            </p>
          </div>
          {meta.updatedAt && (
            <span className="admin-field__hint">
              Terakhir diubah: {formatTimestamp(meta.updatedAt)}
              {meta.updatedBy ? ` oleh ${meta.updatedBy}` : ''}
            </span>
          )}
        </div>

        <form className="admin-form" onSubmit={handleSaveSettings}>
          <div className="server-toggles">
            <label className="admin-checkbox-row" htmlFor="srv-maintenance-mode">
              <input
                id="srv-maintenance-mode"
                type="checkbox"
                checked={form.maintenanceMode}
                onChange={(e) => setForm({ ...form, maintenanceMode: e.target.checked })}
                disabled={saving}
              />
              <span>Mode Pemeliharaan (Tutup Akses Room)</span>
            </label>

            <label className="admin-checkbox-row" htmlFor="srv-allow-reg">
              <input
                id="srv-allow-reg"
                type="checkbox"
                checked={form.allowRegistration}
                onChange={(e) => setForm({ ...form, allowRegistration: e.target.checked })}
                disabled={saving}
              />
              <span>Izinkan Pendaftaran Akun Baru</span>
            </label>

            <label className="admin-checkbox-row" htmlFor="srv-allow-mp">
              <input
                id="srv-allow-mp"
                type="checkbox"
                checked={form.allowMultiplayer}
                onChange={(e) => setForm({ ...form, allowMultiplayer: e.target.checked })}
                disabled={saving}
              />
              <span>Izinkan Multiplayer Co-op</span>
            </label>

            <label className="admin-checkbox-row" htmlFor="srv-allow-sandbox">
              <input
                id="srv-allow-sandbox"
                type="checkbox"
                checked={form.allowSandbox}
                onChange={(e) => setForm({ ...form, allowSandbox: e.target.checked })}
                disabled={saving}
              />
              <span>Izinkan Mode Sandbox</span>
            </label>
          </div>

          <div className="server-form-grid">
            <div className="admin-field">
              <label htmlFor="srv-maintenance-msg">Pesan Mode Pemeliharaan</label>
              <input
                id="srv-maintenance-msg"
                type="text"
                className="admin-input"
                placeholder="Contoh: Server sedang dalam pemeliharaan berkala."
                value={form.maintenanceMessage}
                onChange={(e) => setForm({ ...form, maintenanceMessage: e.target.value })}
                disabled={saving}
              />
            </div>

            <div className="admin-field">
              <label htmlFor="srv-max-rooms">Maksimal Room Aktif</label>
              <input
                id="srv-max-rooms"
                type="number"
                min={1}
                max={500}
                className="admin-input admin-input--mono"
                value={form.maxActiveRooms}
                onChange={(e) => setForm({ ...form, maxActiveRooms: e.target.value })}
                disabled={saving}
                required
              />
            </div>

            <div className="admin-field">
              <label htmlFor="srv-min-version">Versi Klien Minimum</label>
              <input
                id="srv-min-version"
                type="text"
                className="admin-input admin-input--mono"
                placeholder="1.3.0"
                value={form.minClientVersion}
                onChange={(e) => setForm({ ...form, minClientVersion: e.target.value })}
                disabled={saving}
                required
              />
            </div>

            <div className="admin-field">
              <label htmlFor="srv-global-announcement">Pengumuman Global (Lobby &amp; HUD)</label>
              <textarea
                id="srv-global-announcement"
                className="admin-textarea"
                placeholder="Kosongkan jika tidak ada pengumuman yang disiarkan ke pemain"
                value={form.globalAnnouncement}
                onChange={(e) => setForm({ ...form, globalAnnouncement: e.target.value })}
                disabled={saving}
              />
            </div>
          </div>

          {formError && (
            <div className="admin-alert admin-alert--error" role="alert">
              <span>{formError}</span>
            </div>
          )}

          <div>
            <button type="submit" className="admin-btn admin-btn--primary" disabled={saving}>
              {saving ? 'Menyimpan Perubahan...' : 'Simpan Pengaturan Server'}
            </button>
          </div>
        </form>
      </section>
    </>
  )
}
