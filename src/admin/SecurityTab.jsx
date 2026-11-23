import { useCallback, useEffect, useRef, useState } from 'react'
import {
  ApiError,
  fetchRedeemCodes,
  fetchSecurity,
  formatTimestamp,
  normalizeRedeemCode,
  postRedeemAction,
  postSecurityAction,
  useDialogController,
} from './adminApi'

const SHOP_ITEM_OPTIONS = [
  { id: 'jamu', label: 'Jamu Tolak Bala (jamu)' },
  { id: 'baterai', label: 'Baterai Senter (baterai)' },
  { id: 'energy_drink', label: 'Minuman Energi (energy_drink)' },
  { id: 'kentongan', label: 'Kentongan Pengalih (kentongan)' },
]

export default function SecurityTab({ refreshTick, onNotify, onUnauthorized }) {
  const [subtab, setSubtab] = useState('ip_blocks')

  const [secLoading, setSecLoading] = useState(true)
  const [secError, setSecError] = useState('')
  const [securityLogs, setSecurityLogs] = useState([])
  const [auditLogs, setAuditLogs] = useState([])
  const [ipBlocks, setIpBlocks] = useState([])

  const [codesLoading, setCodesLoading] = useState(true)
  const [codesError, setCodesError] = useState('')
  const [codes, setCodes] = useState([])

  const [ipInput, setIpInput] = useState('')
  const [ipReason, setIpReason] = useState('')
  const [ipHours, setIpHours] = useState(24)
  const [ipSubmitting, setIpSubmitting] = useState(false)
  const [ipFormError, setIpFormError] = useState('')

  const [modal, setModal] = useState(null)
  const [redeemForm, setRedeemForm] = useState({
    code: '',
    rewardType: 'coins',
    itemId: 'jamu',
    quantity: 250,
    maxUses: 100,
    descriptionId: '',
    descriptionEn: '',
    isActive: true,
  })
  const [modalError, setModalError] = useState('')
  const [modalBusy, setModalBusy] = useState(false)
  const returnFocusRef = useRef(null)

  const closeModal = useCallback(() => {
    setModal(null)
    setModalError('')
    setModalBusy(false)
  }, [])

  const { dialogRef, onDialogClick, onDialogCancel } = useDialogController(
    Boolean(modal),
    closeModal,
    returnFocusRef
  )

  const loadSecurity = useCallback(async () => {
    setSecLoading(true)
    setSecError('')
    try {
      const res = await fetchSecurity()
      setSecurityLogs(Array.isArray(res.securityLogs) ? res.securityLogs : [])
      setAuditLogs(Array.isArray(res.auditLogs) ? res.auditLogs : [])
      setIpBlocks(Array.isArray(res.ipBlocks) ? res.ipBlocks : [])
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized(err.message)
        return
      }
      setSecError(err.message || 'Gagal memuat data keamanan dan audit server.')
    } finally {
      setSecLoading(false)
    }
  }, [onUnauthorized])

  const loadCodes = useCallback(async () => {
    setCodesLoading(true)
    setCodesError('')
    try {
      const res = await fetchRedeemCodes()
      const list = Array.isArray(res.codes) ? res.codes.map(normalizeRedeemCode) : []
      setCodes(list)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized(err.message)
        return
      }
      setCodesError(err.message || 'Gagal memuat daftar kode redeem.')
    } finally {
      setCodesLoading(false)
    }
  }, [onUnauthorized])

  useEffect(() => {
    loadSecurity()
    loadCodes()
  }, [loadSecurity, loadCodes, refreshTick])

  const handleBlockIpSubmit = async (e) => {
    e.preventDefault()
    setIpFormError('')

    const cleanIp = ipInput.trim()
    if (!cleanIp || cleanIp.length < 3) {
      setIpFormError('Masukkan alamat IP yang valid (IPv4 atau IPv6).')
      return
    }
    const cleanReason = ipReason.trim()
    if (cleanReason.length < 3) {
      setIpFormError('Tuliskan alasan pemblokiran IP minimal 3 karakter.')
      return
    }
    const hours = Number(ipHours)
    if (!Number.isFinite(hours) || hours < 0 || hours > 8760) {
      setIpFormError('Durasi jam blokir harus antara 0 (permanen) hingga 8760 jam.')
      return
    }

    setIpSubmitting(true)
    try {
      await postSecurityAction({
        action: 'block_ip',
        ipAddress: cleanIp,
        reason: cleanReason,
        expiresHours: hours,
      })
      setIpInput('')
      setIpReason('')
      onNotify('success', `Alamat IP ${cleanIp} berhasil ditambahkan ke daftar blokir.`)
      await loadSecurity()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized(err.message)
        return
      }
      setIpFormError(err.message || 'Gagal memblokir alamat IP.')
    } finally {
      setIpSubmitting(false)
    }
  }

  const handleUnblockIp = async (ipAddress) => {
    try {
      await postSecurityAction({
        action: 'unblock_ip',
        ipAddress,
      })
      onNotify('success', `Blokir untuk IP ${ipAddress} telah dibuka.`)
      await loadSecurity()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized(err.message)
        return
      }
      onNotify('error', err.message || 'Gagal membuka blokir IP.')
    }
  }

  const handleToggleCode = async (item) => {
    try {
      await postRedeemAction({
        action: 'toggle',
        code: item.code,
        isActive: !item.isActive,
      })
      onNotify(
        'success',
        `Kode ${item.code} kini ${!item.isActive ? 'diaktifkan' : 'dinonaktifkan'}.`
      )
      await loadCodes()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized(err.message)
        return
      }
      onNotify('error', err.message || 'Gagal mengubah status kode redeem.')
    }
  }

  const openModal = (type, item, triggerEl) => {
    returnFocusRef.current = triggerEl
    setModalError('')
    if (type === 'create_redeem') {
      setRedeemForm({
        code: '',
        rewardType: 'coins',
        itemId: 'jamu',
        quantity: 250,
        maxUses: 100,
        descriptionId: '',
        descriptionEn: '',
        isActive: true,
      })
    }
    setModal({ type, item })
  }

  const handleModalSubmit = async (e) => {
    e.preventDefault()
    if (!modal) return
    setModalError('')

    setModalBusy(true)
    try {
      if (modal.type === 'clear_rate_limits') {
        await postSecurityAction({ action: 'clear_rate_limits' })
        closeModal()
        onNotify('success', 'Seluruh catatan rate limit sementara telah dikosongkan.')
        await loadSecurity()
      } else if (modal.type === 'create_redeem') {
        const cleanCode = String(redeemForm.code || '')
          .trim()
          .toUpperCase()
        if (!/^[A-Z0-9]{3,32}$/.test(cleanCode)) {
          setModalError('Kode harus 3 hingga 32 karakter huruf kapital atau angka (tanpa spasi/simbol).')
          setModalBusy(false)
          return
        }
        const qty = Number(redeemForm.quantity)
        const rawMax = String(redeemForm.maxUses ?? '').trim()
        const maxUses = rawMax === '' ? null : Number(rawMax)
        if (!Number.isInteger(qty) || qty < 1) {
          setModalError('Jumlah hadiah harus bilangan bulat minimal 1.')
          setModalBusy(false)
          return
        }
        if (maxUses !== null && (!Number.isInteger(maxUses) || maxUses < 1)) {
          setModalError('Batas pemakaian maksimal harus bilangan bulat minimal 1 (atau kosongkan).')
          setModalBusy(false)
          return
        }
        await postRedeemAction({
          action: 'create',
          code: cleanCode,
          rewardType: redeemForm.rewardType,
          itemId: redeemForm.rewardType === 'item' ? redeemForm.itemId : undefined,
          quantity: qty,
          maxUses,
          descriptionId: redeemForm.descriptionId.trim() || `Hadiah ${cleanCode}`,
          descriptionEn: redeemForm.descriptionEn.trim() || `Reward ${cleanCode}`,
          isActive: Boolean(redeemForm.isActive),
        })
        closeModal()
        onNotify('success', `Kode redeem ${cleanCode} berhasil ditambahkan.`)
        await loadCodes()
      } else if (modal.type === 'delete_redeem') {
        await postRedeemAction({
          action: 'delete',
          code: modal.item.code,
        })
        closeModal()
        onNotify('success', `Kode redeem ${modal.item.code} berhasil dihapus.`)
        await loadCodes()
      }
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        closeModal()
        onUnauthorized(err.message)
        return
      }
      setModalError(err.message || 'Gagal menjalankan tindakan.')
    } finally {
      setModalBusy(false)
    }
  }

  return (
    <>
      <div className="subtabs" role="tablist" aria-label="Bagian Keamanan dan Redeem">
        <button
          type="button"
          role="tab"
          aria-selected={subtab === 'ip_blocks'}
          className={`subtab${subtab === 'ip_blocks' ? ' is-active' : ''}`}
          onClick={() => setSubtab('ip_blocks')}
        >
          Blokir IP &amp; Rate Limit ({ipBlocks.length})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={subtab === 'redeem'}
          className={`subtab${subtab === 'redeem' ? ' is-active' : ''}`}
          onClick={() => setSubtab('redeem')}
        >
          Kode Redeem ({codes.length})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={subtab === 'security_logs'}
          className={`subtab${subtab === 'security_logs' ? ' is-active' : ''}`}
          onClick={() => setSubtab('security_logs')}
        >
          Log Keamanan ({securityLogs.length})
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={subtab === 'audit_logs'}
          className={`subtab${subtab === 'audit_logs' ? ' is-active' : ''}`}
          onClick={() => setSubtab('audit_logs')}
        >
          Log Audit Admin ({auditLogs.length})
        </button>
      </div>

      {subtab === 'ip_blocks' && (
        <div role="tabpanel" className="security-grid">
          <section className="admin-panel" aria-labelledby="block-ip-heading">
            <div className="admin-panel__head">
              <h2 id="block-ip-heading">Blokir Alamat IP</h2>
              <button
                type="button"
                className="admin-btn admin-btn--danger admin-btn--sm"
                onClick={(e) => openModal('clear_rate_limits', null, e.currentTarget)}
              >
                Kosongkan Rate Limit
              </button>
            </div>
            <p className="admin-panel__desc">
              Tolak permintaan autentikasi dan API dari IP penyalahguna, atau bersihkan penghitung
              rate limit sementara.
            </p>

            <form className="admin-form" onSubmit={handleBlockIpSubmit}>
              <div className="admin-field">
                <label htmlFor="sec-ip-address">Alamat IP</label>
                <input
                  id="sec-ip-address"
                  type="text"
                  className="admin-input admin-input--mono"
                  placeholder="203.0.113.10"
                  value={ipInput}
                  onChange={(e) => setIpInput(e.target.value)}
                  disabled={ipSubmitting}
                  required
                />
              </div>

              <div className="admin-field">
                <label htmlFor="sec-ip-reason">Alasan Pemblokiran</label>
                <input
                  id="sec-ip-reason"
                  type="text"
                  className="admin-input"
                  placeholder="Contoh: Brute force login berulang"
                  value={ipReason}
                  onChange={(e) => setIpReason(e.target.value)}
                  disabled={ipSubmitting}
                  required
                />
              </div>

              <div className="admin-field">
                <label htmlFor="sec-ip-hours">Durasi (Jam, 0 untuk permanen)</label>
                <input
                  id="sec-ip-hours"
                  type="number"
                  min={0}
                  max={8760}
                  className="admin-input admin-input--mono"
                  value={ipHours}
                  onChange={(e) => setIpHours(e.target.value)}
                  disabled={ipSubmitting}
                  required
                />
              </div>

              {ipFormError && (
                <div className="admin-alert admin-alert--error" role="alert">
                  <span>{ipFormError}</span>
                </div>
              )}

              <div>
                <button
                  type="submit"
                  className="admin-btn admin-btn--danger"
                  disabled={ipSubmitting}
                >
                  {ipSubmitting ? 'Memblokir...' : 'Tambahkan ke Daftar Blokir'}
                </button>
              </div>
            </form>
          </section>

          <section className="admin-panel" aria-labelledby="ip-list-heading">
            <div className="admin-panel__head">
              <h2 id="ip-list-heading">Daftar Blokir IP Aktif</h2>
              <button type="button" className="admin-btn admin-btn--sm" onClick={loadSecurity}>
                Segarkan
              </button>
            </div>

            {secLoading ? (
              <div className="admin-state-box" role="status" aria-live="polite">
                <h3>Memuat Daftar Blokir</h3>
                <p>Mengambil daftar IP terblokir dari server...</p>
              </div>
            ) : secError ? (
              <div className="admin-state-box" role="alert">
                <h3>Gagal Memuat Data Keamanan</h3>
                <p>{secError}</p>
                <button type="button" className="admin-btn admin-btn--primary" onClick={loadSecurity}>
                  Coba Lagi
                </button>
              </div>
            ) : ipBlocks.length === 0 ? (
              <div className="admin-state-box">
                <h3>Tidak Ada IP yang Diblokir</h3>
                <p>
                  Daftar blokir IP kosong saat ini. Gunakan formulir di sebelah kiri jika Anda perlu
                  menolak akses dari alamat IP tertentu.
                </p>
              </div>
            ) : (
              <div className="admin-table-wrap">
                <table className="admin-table">
                  <thead>
                    <tr>
                      <th>Alamat IP &amp; Alasan</th>
                      <th>Berakhir</th>
                      <th>Aksi</th>
                    </tr>
                  </thead>
                  <tbody>
                    {ipBlocks.map((b) => (
                      <tr key={b.id || b.ipAddress}>
                        <td>
                          <div>
                            <span className="mono-chip">{b.ipAddress}</span>
                          </div>
                          <div className="admin-field__hint">{b.reason || 'Tanpa alasan'}</div>
                        </td>
                        <td>
                          <div>{b.expiresAt ? formatTimestamp(b.expiresAt) : 'Permanen'}</div>
                          <div className="admin-field__hint">Oleh {b.blockedBy || 'admin'}</div>
                        </td>
                        <td>
                          <button
                            type="button"
                            className="admin-btn admin-btn--sm"
                            onClick={() => handleUnblockIp(b.ipAddress)}
                          >
                            Buka Blokir
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        </div>
      )}

      {subtab === 'redeem' && (
        <section role="tabpanel" className="admin-panel" aria-labelledby="redeem-heading">
          <div className="admin-panel__head">
            <div>
              <h2 id="redeem-heading">Manajemen Kode Redeem</h2>
              <p className="admin-panel__desc">
                Buat, aktifkan, nonaktifkan, atau hapus kode hadiah yang dapat ditukarkan pemain
                pada menu utama game.
              </p>
            </div>
            <button
              type="button"
              className="admin-btn admin-btn--primary"
              onClick={(e) => openModal('create_redeem', null, e.currentTarget)}
            >
              Tambah Kode Redeem
            </button>
          </div>

          {codesLoading ? (
            <div className="admin-state-box" role="status" aria-live="polite">
              <h3>Memuat Kode Redeem</h3>
              <p>Mengambil daftar kode hadiah dari basis data...</p>
            </div>
          ) : codesError ? (
            <div className="admin-state-box" role="alert">
              <h3>Gagal Memuat Kode Redeem</h3>
              <p>{codesError}</p>
              <button type="button" className="admin-btn admin-btn--primary" onClick={loadCodes}>
                Coba Lagi
              </button>
            </div>
          ) : codes.length === 0 ? (
            <div className="admin-state-box">
              <h3>Belum Ada Kode Redeem</h3>
              <p>
                Tidak ada kode hadiah yang tersimpan. Tekan tombol Tambah Kode Redeem untuk membuat
                kode promosi baru bagi pemain.
              </p>
              <button
                type="button"
                className="admin-btn admin-btn--primary"
                onClick={(e) => openModal('create_redeem', null, e.currentTarget)}
              >
                Buat Kode Pertama
              </button>
            </div>
          ) : (
            <div className="admin-table-wrap">
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Kode</th>
                    <th>Hadiah</th>
                    <th>Pemakaian</th>
                    <th>Status</th>
                    <th>Aksi</th>
                  </tr>
                </thead>
                <tbody>
                  {codes.map((c) => (
                    <tr key={c.code}>
                      <td>
                        <span className="mono-chip">{c.code}</span>
                        {c.descriptionId && (
                          <div className="admin-field__hint">{c.descriptionId}</div>
                        )}
                      </td>
                      <td>
                        {c.rewardType === 'coins' && `${c.quantity} Koin`}
                        {c.rewardType === 'lives' && `${c.quantity} Nyawa Tambahan`}
                        {c.rewardType === 'item' && `${c.quantity}x ${c.itemId || 'item'}`}
                      </td>
                      <td>
                        <span className="mono-chip">
                          {c.usesCount} / {c.maxUses === null ? 'Tanpa batas' : c.maxUses}
                        </span>
                      </td>
                      <td>
                        <span
                          className={`admin-tag ${
                            c.isActive ? 'admin-tag--sage' : 'admin-tag--brass'
                          }`}
                        >
                          {c.isActive ? 'AKTIF' : 'NONAKTIF'}
                        </span>
                      </td>
                      <td>
                        <div className="admin-row-actions">
                          <button
                            type="button"
                            className="admin-btn admin-btn--sm"
                            onClick={() => handleToggleCode(c)}
                          >
                            {c.isActive ? 'Nonaktifkan' : 'Aktifkan'}
                          </button>
                          <button
                            type="button"
                            className="admin-btn admin-btn--danger admin-btn--sm"
                            onClick={(e) => openModal('delete_redeem', c, e.currentTarget)}
                          >
                            Hapus
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {subtab === 'security_logs' && (
        <section role="tabpanel" className="admin-panel" aria-labelledby="seclogs-heading">
          <div className="admin-panel__head">
            <h2 id="seclogs-heading">Catatan Kejadian Keamanan</h2>
            <button type="button" className="admin-btn admin-btn--sm" onClick={loadSecurity}>
              Segarkan Log
            </button>
          </div>

          {secLoading ? (
            <div className="admin-state-box" role="status" aria-live="polite">
              <h3>Memuat Log Keamanan</h3>
              <p>Mengambil kejadian anti-bot, gagal login, dan pembatasan akses...</p>
            </div>
          ) : secError ? (
            <div className="admin-state-box" role="alert">
              <h3>Gagal Memuat Log Keamanan</h3>
              <p>{secError}</p>
              <button type="button" className="admin-btn admin-btn--primary" onClick={loadSecurity}>
                Coba Lagi
              </button>
            </div>
          ) : securityLogs.length === 0 ? (
            <div className="admin-state-box">
              <h3>Belum Ada Kejadian Keamanan</h3>
              <p>
                Log keamanan masih kosong karena belum ada percobaan mencurigakan atau pelanggaran
                rate limit yang tercatat.
              </p>
            </div>
          ) : (
            <div className="admin-table-wrap">
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Waktu</th>
                    <th>Tipe Kejadian</th>
                    <th>Subjek &amp; IP</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {securityLogs.map((log, idx) => (
                    <tr key={log.id || `${log.createdAt}-${idx}`}>
                      <td>{formatTimestamp(log.createdAt)}</td>
                      <td>
                        <span
                          className={`admin-tag ${
                            log.severity === 'high' || log.severity === 'critical'
                              ? 'admin-tag--crimson'
                              : 'admin-tag--brass'
                          }`}
                        >
                          {log.eventType || 'event'}
                        </span>
                      </td>
                      <td>
                        <div>{log.username || 'Anonim'}</div>
                        {log.ipAddress && <span className="mono-chip">{log.ipAddress}</span>}
                      </td>
                      <td>
                        <div>{log.path || '-'}</div>
                        <div className="admin-field__hint">
                          {typeof log.details === 'string'
                            ? log.details
                            : log.details
                              ? JSON.stringify(log.details)
                              : ''}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {subtab === 'audit_logs' && (
        <section role="tabpanel" className="admin-panel" aria-labelledby="auditlogs-heading">
          <div className="admin-panel__head">
            <h2 id="auditlogs-heading">Riwayat Audit Administrator</h2>
            <button type="button" className="admin-btn admin-btn--sm" onClick={loadSecurity}>
              Segarkan Audit
            </button>
          </div>

          {secLoading ? (
            <div className="admin-state-box" role="status" aria-live="polite">
              <h3>Memuat Log Audit</h3>
              <p>Mengambil riwayat perubahan oleh administrator...</p>
            </div>
          ) : secError ? (
            <div className="admin-state-box" role="alert">
              <h3>Gagal Memuat Log Audit</h3>
              <p>{secError}</p>
              <button type="button" className="admin-btn admin-btn--primary" onClick={loadSecurity}>
                Coba Lagi
              </button>
            </div>
          ) : auditLogs.length === 0 ? (
            <div className="admin-state-box">
              <h3>Belum Ada Catatan Audit</h3>
              <p>
                Semua tindakan perubahan pada pengguna, room, pengaturan server, dan kode hadiah
                akan dicatat di sini secara otomatis.
              </p>
            </div>
          ) : (
            <div className="admin-table-wrap">
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Waktu</th>
                    <th>Administrator</th>
                    <th>Aksi &amp; Target</th>
                    <th>Detail</th>
                  </tr>
                </thead>
                <tbody>
                  {auditLogs.map((log, idx) => (
                    <tr key={log.id || `${log.createdAt}-${idx}`}>
                      <td>{formatTimestamp(log.createdAt)}</td>
                      <td>
                        <div>{log.adminUsername || log.adminUserId || 'admin'}</div>
                        {log.ipAddress && <span className="mono-chip">{log.ipAddress}</span>}
                      </td>
                      <td>
                        <span className="admin-tag">{log.action}</span>
                        <div className="admin-field__hint">
                          {log.targetType} {log.targetId ? `(${log.targetId})` : ''}
                        </div>
                      </td>
                      <td>
                        <div className="admin-field__hint">
                          {typeof log.details === 'string'
                            ? log.details
                            : log.details
                              ? JSON.stringify(log.details)
                              : '-'}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      <dialog
        ref={dialogRef}
        className="admin-dialog"
        aria-labelledby="security-dialog-title"
        onClick={onDialogClick}
        onCancel={onDialogCancel}
      >
        {modal && (
          <form className="admin-dialog__panel" onSubmit={handleModalSubmit}>
            <div className="admin-dialog__head">
              <h3 id="security-dialog-title">
                {modal.type === 'clear_rate_limits' && 'Kosongkan Penghitung Rate Limit'}
                {modal.type === 'create_redeem' && 'Tambah Kode Redeem Baru'}
                {modal.type === 'delete_redeem' && `Hapus Kode ${modal.item.code}`}
              </h3>
              <button
                type="button"
                className="admin-btn admin-btn--ghost admin-btn--sm"
                onClick={closeModal}
              >
                Batal
              </button>
            </div>

            {modal.type === 'clear_rate_limits' && (
              <p className="admin-panel__desc">
                Semua jendela pembatasan laju permintaan sementara akan dihapus. Daftar blokir IP
                tetap dipertahankan.
              </p>
            )}

            {modal.type === 'delete_redeem' && (
              <div className="admin-alert admin-alert--error">
                <span>
                  Kode <strong>{modal.item.code}</strong> akan dihapus permanen dan tidak bisa lagi
                  diklaim dari klien game.
                </span>
              </div>
            )}

            {modal.type === 'create_redeem' && (
              <>
                <div className="server-form-grid">
                  <div className="admin-field">
                    <label htmlFor="redeem-code-input">Kode Hadiah</label>
                    <input
                      id="redeem-code-input"
                      type="text"
                      className="admin-input admin-input--mono"
                      placeholder="LAMPOR2026"
                      value={redeemForm.code}
                      onChange={(e) =>
                        setRedeemForm({ ...redeemForm, code: e.target.value.toUpperCase() })
                      }
                      required
                    />
                  </div>
                  <div className="admin-field">
                    <label htmlFor="redeem-type-select">Jenis Hadiah</label>
                    <select
                      id="redeem-type-select"
                      className="admin-select"
                      value={redeemForm.rewardType}
                      onChange={(e) => setRedeemForm({ ...redeemForm, rewardType: e.target.value })}
                    >
                      <option value="coins">Koin (coins)</option>
                      <option value="item">Item Toko (item)</option>
                      <option value="lives">Nyawa Tambahan (lives)</option>
                    </select>
                  </div>
                </div>

                {redeemForm.rewardType === 'item' && (
                  <div className="admin-field">
                    <label htmlFor="redeem-item-id">ID Item Toko</label>
                    <select
                      id="redeem-item-id"
                      className="admin-select"
                      value={redeemForm.itemId}
                      onChange={(e) => setRedeemForm({ ...redeemForm, itemId: e.target.value })}
                    >
                      {SHOP_ITEM_OPTIONS.map((opt) => (
                        <option key={opt.id} value={opt.id}>
                          {opt.label}
                        </option>
                      ))}
                    </select>
                  </div>
                )}

                <div className="server-form-grid">
                  <div className="admin-field">
                    <label htmlFor="redeem-qty">Jumlah Hadiah</label>
                    <input
                      id="redeem-qty"
                      type="number"
                      min={1}
                      className="admin-input admin-input--mono"
                      value={redeemForm.quantity}
                      onChange={(e) => setRedeemForm({ ...redeemForm, quantity: e.target.value })}
                      required
                    />
                  </div>
                  <div className="admin-field">
                    <label htmlFor="redeem-max-uses">Batas Pemakaian (Opsional)</label>
                    <input
                      id="redeem-max-uses"
                      type="number"
                      min={1}
                      placeholder="Kosongkan jika tanpa batas"
                      className="admin-input admin-input--mono"
                      value={redeemForm.maxUses}
                      onChange={(e) => setRedeemForm({ ...redeemForm, maxUses: e.target.value })}
                    />
                  </div>
                </div>

                <div className="admin-field">
                  <label htmlFor="redeem-desc-id">Keterangan (Indonesia)</label>
                  <input
                    id="redeem-desc-id"
                    type="text"
                    className="admin-input"
                    placeholder="Contoh: Bonus koin perayaan v1.3.0"
                    value={redeemForm.descriptionId}
                    onChange={(e) =>
                      setRedeemForm({ ...redeemForm, descriptionId: e.target.value })
                    }
                  />
                </div>

                <div className="admin-field">
                  <label htmlFor="redeem-desc-en">Keterangan (English)</label>
                  <input
                    id="redeem-desc-en"
                    type="text"
                    className="admin-input"
                    placeholder="Example: v1.3.0 release celebration coins"
                    value={redeemForm.descriptionEn}
                    onChange={(e) =>
                      setRedeemForm({ ...redeemForm, descriptionEn: e.target.value })
                    }
                  />
                </div>

                <label className="admin-checkbox-row" htmlFor="redeem-is-active">
                  <input
                    id="redeem-is-active"
                    type="checkbox"
                    checked={redeemForm.isActive}
                    onChange={(e) => setRedeemForm({ ...redeemForm, isActive: e.target.checked })}
                  />
                  <span>Langsung aktifkan kode setelah dibuat</span>
                </label>
              </>
            )}

            {modalError && (
              <div className="admin-alert admin-alert--error" role="alert">
                <span>{modalError}</span>
              </div>
            )}

            <div className="admin-dialog__actions">
              <button
                type="button"
                className="admin-btn admin-btn--ghost"
                onClick={closeModal}
                disabled={modalBusy}
              >
                Batal
              </button>
              <button
                type="submit"
                className={`admin-btn ${
                  modal.type === 'delete_redeem' || modal.type === 'clear_rate_limits'
                    ? 'admin-btn--danger'
                    : 'admin-btn--primary'
                }`}
                disabled={modalBusy}
              >
                {modalBusy ? 'Menyimpan...' : 'Konfirmasi'}
              </button>
            </div>
          </form>
        )}
      </dialog>
    </>
  )
}
