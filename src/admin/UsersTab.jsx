import { useCallback, useEffect, useRef, useState } from 'react'
import VerifiedBadge from './VerifiedBadge'
import {
  ApiError,
  fetchUsers,
  formatTimestamp,
  normalizeUser,
  postUsersAction,
  useDialogController,
} from './adminApi'

const USERNAME_RE = /^[a-zA-Z0-9_]{3,24}$/

function validatePassword(pwd) {
  if (pwd.length < 8 || pwd.length > 72) {
    return 'Kata sandi harus terdiri dari 8 hingga 72 karakter.'
  }
  if (!/[a-zA-Z]/.test(pwd) || !/[0-9]/.test(pwd)) {
    return 'Kata sandi harus mengandung minimal satu huruf dan satu angka.'
  }
  return ''
}

export default function UsersTab({ refreshTick, autoTick, onNotify, onUnauthorized }) {
  const [searchInput, setSearchInput] = useState('')
  const [appliedSearch, setAppliedSearch] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [page, setPage] = useState(1)

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [users, setUsers] = useState([])
  const [total, setTotal] = useState(0)
  const [pageSize, setPageSize] = useState(20)

  const [modal, setModal] = useState(null)
  const [modalForm, setModalForm] = useState({})
  const [modalError, setModalError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const returnFocusRef = useRef(null)
  const inFlightRef = useRef(false)

  const closeModal = useCallback(() => {
    setModal(null)
    setModalError('')
    setSubmitting(false)
  }, [])

  const { dialogRef, onDialogClick, onDialogCancel } = useDialogController(
    Boolean(modal),
    closeModal,
    returnFocusRef
  )

  const loadUsers = useCallback(async (silent = false) => {
    if (inFlightRef.current) return
    inFlightRef.current = true
    if (!silent) {
      setLoading(true)
      setError('')
    }
    try {
      const res = await fetchUsers({
        search: appliedSearch,
        status: statusFilter,
        page,
      })
      const list = Array.isArray(res.users) ? res.users.map(normalizeUser) : []
      setUsers(list)
      setTotal(Number(res.total ?? list.length))
      setPageSize(Math.max(1, Number(res.pageSize ?? 20)))
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized(err.message)
        return
      }
      if (!silent) {
        setError(err.message || 'Gagal memuat daftar akun pemain.')
      }
    } finally {
      inFlightRef.current = false
      if (!silent) {
        setLoading(false)
      }
    }
  }, [appliedSearch, statusFilter, page, onUnauthorized])

  useEffect(() => {
    loadUsers(false)
  }, [loadUsers, refreshTick])

  useEffect(() => {
    if (!autoTick || modal) return
    loadUsers(true)
  }, [loadUsers, autoTick, modal])

  const openActionModal = (type, user, triggerEl) => {
    returnFocusRef.current = triggerEl
    setModalError('')
    setModal({ type, user })

    if (type === 'create') {
      setModalForm({
        username: '',
        password: '',
        role: 'player',
        coins: 0,
        extraLives: 0,
      })
    } else if (type === 'update' && user) {
      setModalForm({
        coins: user.coins,
        totalWins: user.totalWins,
        extraLives: user.extraLives,
        role: user.role || 'player',
        isVerified: Boolean(user.isVerified),
      })
    } else if (type === 'ban') {
      setModalForm({ reason: '' })
    } else if (type === 'reset_password') {
      setModalForm({ password: '', confirmPassword: '' })
    } else {
      setModalForm({})
    }
  }

  const handleSearchSubmit = (e) => {
    e.preventDefault()
    setPage(1)
    setAppliedSearch(searchInput.trim())
  }

  const handleResetFilters = () => {
    setSearchInput('')
    setAppliedSearch('')
    setStatusFilter('all')
    setPage(1)
  }

  const handleModalSubmit = async (e) => {
    e.preventDefault()
    if (!modal) return
    setModalError('')

    let payload = null
    let successMsg = ''

    if (modal.type === 'create') {
      const uname = String(modalForm.username || '').trim()
      const pwd = String(modalForm.password || '')
      if (!USERNAME_RE.test(uname)) {
        setModalError('Username harus 3 hingga 24 karakter (huruf, angka, atau garis bawah).')
        return
      }
      const pwdErr = validatePassword(pwd)
      if (pwdErr) {
        setModalError(pwdErr)
        return
      }
      const coins = Number(modalForm.coins ?? 0)
      const extraLives = Number(modalForm.extraLives ?? 0)
      if (!Number.isInteger(coins) || coins < 0 || coins > 999999999) {
        setModalError('Koin harus bilangan bulat antara 0 dan 999.999.999.')
        return
      }
      if (!Number.isInteger(extraLives) || extraLives < 0 || extraLives > 5) {
        setModalError('Nyawa tambahan harus bilangan bulat antara 0 dan 5.')
        return
      }
      payload = {
        action: 'create',
        username: uname,
        password: pwd,
        role: modalForm.role === 'admin' ? 'admin' : 'player',
        coins,
        extraLives,
      }
      successMsg = `Akun ${uname} berhasil dibuat.`
    } else if (modal.type === 'update') {
      const coins = Number(modalForm.coins ?? 0)
      const totalWins = Number(modalForm.totalWins ?? 0)
      const extraLives = Number(modalForm.extraLives ?? 0)
      if (!Number.isInteger(coins) || coins < 0 || coins > 999999999) {
        setModalError('Koin harus bilangan bulat antara 0 dan 999.999.999.')
        return
      }
      if (!Number.isInteger(totalWins) || totalWins < 0) {
        setModalError('Total menang harus bilangan bulat 0 atau lebih.')
        return
      }
      if (!Number.isInteger(extraLives) || extraLives < 0 || extraLives > 5) {
        setModalError('Nyawa tambahan harus bilangan bulat antara 0 dan 5.')
        return
      }
      payload = {
        action: 'update',
        userId: modal.user.id,
        coins,
        totalWins,
        extraLives,
        role: modalForm.role === 'admin' ? 'admin' : 'player',
        isVerified: Boolean(modalForm.isVerified),
      }
      successMsg = `Data akun ${modal.user.username} berhasil diperbarui.`
    } else if (modal.type === 'ban') {
      const reason = String(modalForm.reason || '').trim()
      if (reason.length < 3) {
        setModalError('Tuliskan alasan pemblokiran minimal 3 karakter.')
        return
      }
      payload = {
        action: 'ban',
        userId: modal.user.id,
        reason,
      }
      successMsg = `Akun ${modal.user.username} telah diblokir dan seluruh sesinya dihentikan.`
    } else if (modal.type === 'unban') {
      payload = {
        action: 'unban',
        userId: modal.user.id,
      }
      successMsg = `Pemblokiran akun ${modal.user.username} telah dicabut.`
    } else if (modal.type === 'reset_password') {
      const pwd = String(modalForm.password || '')
      const pwdErr = validatePassword(pwd)
      if (pwdErr) {
        setModalError(pwdErr)
        return
      }
      if (pwd !== String(modalForm.confirmPassword || '')) {
        setModalError('Konfirmasi kata sandi tidak cocok.')
        return
      }
      payload = {
        action: 'reset_password',
        userId: modal.user.id,
        password: pwd,
      }
      successMsg = `Kata sandi ${modal.user.username} berhasil diatur ulang.`
    } else if (modal.type === 'force_logout') {
      payload = {
        action: 'force_logout',
        userId: modal.user.id,
      }
      successMsg = `Semua sesi login ${modal.user.username} berhasil diputus.`
    } else if (modal.type === 'delete') {
      payload = {
        action: 'delete',
        userId: modal.user.id,
      }
      successMsg = `Akun ${modal.user.username} telah dihapus secara permanen.`
    }

    if (!payload) return

    setSubmitting(true)
    try {
      await postUsersAction(payload)
      closeModal()
      onNotify('success', successMsg)
      await loadUsers()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        closeModal()
        onUnauthorized(err.message)
        return
      }
      setModalError(err.message || 'Gagal menjalankan aksi terhadap akun pemain.')
    } finally {
      setSubmitting(false)
    }
  }

  const totalPages = Math.max(1, Math.ceil(total / pageSize))
  const hasFilters = Boolean(appliedSearch || statusFilter !== 'all')

  const handleToggleVerified = async (user) => {
    if (!user?.id || submitting) return
    const nextAction = user.isVerified ? 'unverify' : 'verify'
    try {
      await postUsersAction({ action: nextAction, userId: user.id })
      onNotify(
        'success',
        user.isVerified
          ? `Lencana verifikasi ${user.username} telah dicabut.`
          : `Akun ${user.username} kini terverifikasi.`
      )
      await loadUsers(true)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized(err.message)
        return
      }
      onNotify('error', err.message || 'Gagal mengubah status verifikasi akun.')
    }
  }

  return (
    <>
      <section className="admin-panel" aria-labelledby="users-toolbar-heading">
        <div className="admin-panel__head">
          <div>
            <h2 id="users-toolbar-heading">Direktori Akun Pemain</h2>
            <p className="admin-panel__desc">
              Cari akun, ubah progres koin atau nyawa, atur peran, atau lakukan moderasi akses.
            </p>
          </div>
          <button
            type="button"
            className="admin-btn admin-btn--primary"
            onClick={(e) => openActionModal('create', null, e.currentTarget)}
          >
            Buat Akun Baru
          </button>
        </div>

        <form className="admin-toolbar" onSubmit={handleSearchSubmit}>
          <div className="admin-field admin-toolbar__grow">
            <label htmlFor="users-search">Cari Username atau ID</label>
            <input
              id="users-search"
              type="search"
              className="admin-input"
              placeholder="Ketik username pemain..."
              value={searchInput}
              onChange={(e) => setSearchInput(e.target.value)}
            />
          </div>

          <div className="admin-field">
            <label htmlFor="users-status-filter">Status Akun</label>
            <select
              id="users-status-filter"
              className="admin-select"
              value={statusFilter}
              onChange={(e) => {
                setStatusFilter(e.target.value)
                setPage(1)
              }}
            >
              <option value="all">Semua Akun</option>
              <option value="active">Aktif</option>
              <option value="verified">Terverifikasi</option>
              <option value="banned">Diblokir (Ban)</option>
              <option value="locked">Terkunci Lockout</option>
              <option value="admin">Administrator</option>
            </select>
          </div>

          <button type="submit" className="admin-btn">
            Cari
          </button>

          {hasFilters && (
            <button
              type="button"
              className="admin-btn admin-btn--ghost"
              onClick={handleResetFilters}
            >
              Reset Filter
            </button>
          )}
        </form>
      </section>

      {loading ? (
        <section className="admin-state-box" role="status" aria-live="polite">
          <h3>Memuat Daftar Akun</h3>
          <p>Mengambil halaman {page} dari basis data pengguna LAMPOR...</p>
        </section>
      ) : error ? (
        <section className="admin-state-box" role="alert">
          <h3>Gagal Memuat Akun Pemain</h3>
          <p>{error}</p>
          <button type="button" className="admin-btn admin-btn--primary" onClick={loadUsers}>
            Coba Lagi
          </button>
        </section>
      ) : users.length === 0 ? (
        <section className="admin-state-box">
          <h3>{hasFilters ? 'Tidak Ada Akun yang Cocok' : 'Belum Ada Akun Pemain'}</h3>
          <p>
            {hasFilters
              ? 'Pencarian atau filter status saat ini tidak menemukan akun. Ubah kata kunci atau reset filter untuk melihat seluruh akun.'
              : 'Basis data pengguna belum memiliki akun selain administrator saat ini. Buat akun baru untuk menguji akses pemain.'}
          </p>
          {hasFilters ? (
            <button type="button" className="admin-btn" onClick={handleResetFilters}>
              Reset Filter
            </button>
          ) : (
            <button
              type="button"
              className="admin-btn admin-btn--primary"
              onClick={(e) => openActionModal('create', null, e.currentTarget)}
            >
              Buat Akun Pertama
            </button>
          )}
        </section>
      ) : (
        <section className="admin-panel" aria-label="Tabel akun pemain">
          <div className="admin-table-wrap">
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Akun &amp; Status</th>
                  <th>Progres Game</th>
                  <th>Login Terakhir</th>
                  <th>Tindakan Admin</th>
                </tr>
              </thead>
              <tbody>
                {users.map((u) => {
                  const locked =
                    u.lockedUntil && !Number.isNaN(Date.parse(u.lockedUntil))
                      ? Date.parse(u.lockedUntil) > Date.now()
                      : false
                  return (
                    <tr key={u.id || u.username}>
                      <td>
                        <div>
                          <strong>{u.username}</strong>
                          {u.isVerified && <VerifiedBadge />}{' '}
                          <span
                            className={`admin-tag ${
                              u.role === 'admin' ? 'admin-tag--brass' : ''
                            }`}
                          >
                            {u.role}
                          </span>{' '}
                          {u.isBanned ? (
                            <span className="admin-tag admin-tag--crimson">DIBLOKIR</span>
                          ) : (
                            <span className="admin-tag admin-tag--sage">AKTIF</span>
                          )}
                          {locked && <span className="admin-tag admin-tag--brass">TERKUNCI</span>}
                        </div>
                        {u.id && <div className="admin-field__hint mono-chip">{u.id}</div>}
                        {u.isBanned && u.banReason && (
                          <p className="admin-field__hint">Alasan: {u.banReason}</p>
                        )}
                      </td>
                      <td>
                        <div>Koin: {u.coins.toLocaleString('id-ID')}</div>
                        <div className="admin-field__hint">
                          Menang: {u.totalWins} | Nyawa Tambahan: {u.extraLives}
                        </div>
                      </td>
                      <td>
                        <div>{formatTimestamp(u.lastLoginAt)}</div>
                        <div className="admin-field__hint">
                          {u.lastLoginIp ? (
                            <span className="mono-chip">{u.lastLoginIp}</span>
                          ) : (
                            `Dibuat ${formatTimestamp(u.createdAt)}`
                          )}
                        </div>
                      </td>
                      <td>
                        <div className="admin-row-actions">
                          <button
                            type="button"
                            className="admin-btn admin-btn--sm"
                            onClick={(e) => openActionModal('update', u, e.currentTarget)}
                          >
                            Edit
                          </button>
                          <button
                            type="button"
                            className={`admin-btn admin-btn--sm${u.isVerified ? ' admin-btn--primary' : ''}`}
                            onClick={() => handleToggleVerified(u)}
                          >
                            {u.isVerified ? 'Cabut Centang' : 'Verifikasi'}
                          </button>
                          {u.isBanned ? (
                            <button
                              type="button"
                              className="admin-btn admin-btn--sm"
                              onClick={(e) => openActionModal('unban', u, e.currentTarget)}
                            >
                              Buka Ban
                            </button>
                          ) : (
                            <button
                              type="button"
                              className="admin-btn admin-btn--danger admin-btn--sm"
                              onClick={(e) => openActionModal('ban', u, e.currentTarget)}
                            >
                              Ban
                            </button>
                          )}
                          <button
                            type="button"
                            className="admin-btn admin-btn--sm"
                            onClick={(e) => openActionModal('reset_password', u, e.currentTarget)}
                          >
                            Reset Sandi
                          </button>
                          <button
                            type="button"
                            className="admin-btn admin-btn--sm"
                            onClick={(e) => openActionModal('force_logout', u, e.currentTarget)}
                          >
                            Putus Sesi
                          </button>
                          <button
                            type="button"
                            className="admin-btn admin-btn--danger admin-btn--sm"
                            onClick={(e) => openActionModal('delete', u, e.currentTarget)}
                          >
                            Hapus
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          <div className="admin-pagination">
            <span className="admin-field__hint">
              Halaman {page} dari {totalPages} ({total} akun)
            </span>
            <div className="admin-row-actions">
              <button
                type="button"
                className="admin-btn admin-btn--sm"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                Sebelumnya
              </button>
              <button
                type="button"
                className="admin-btn admin-btn--sm"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Berikutnya
              </button>
            </div>
          </div>
        </section>
      )}

      <dialog
        ref={dialogRef}
        className="admin-dialog"
        aria-labelledby="user-dialog-title"
        onClick={onDialogClick}
        onCancel={onDialogCancel}
      >
        {modal && (
          <form className="admin-dialog__panel" onSubmit={handleModalSubmit}>
            <div className="admin-dialog__head">
              <h3 id="user-dialog-title">
                {modal.type === 'create' && 'Buat Akun Pemain Baru'}
                {modal.type === 'update' && `Edit Akun: ${modal.user.username}`}
                {modal.type === 'ban' && `Blokir Akun: ${modal.user.username}`}
                {modal.type === 'unban' && `Cabut Blokir: ${modal.user.username}`}
                {modal.type === 'reset_password' && `Atur Ulang Sandi: ${modal.user.username}`}
                {modal.type === 'force_logout' && `Putus Sesi: ${modal.user.username}`}
                {modal.type === 'delete' && `Hapus Permanen: ${modal.user.username}`}
              </h3>
              <button
                type="button"
                className="admin-btn admin-btn--ghost admin-btn--sm"
                onClick={closeModal}
              >
                Batal
              </button>
            </div>

            {modal.type === 'create' && (
              <>
                <div className="admin-field">
                  <label htmlFor="modal-create-username">Username</label>
                  <input
                    id="modal-create-username"
                    type="text"
                    className="admin-input"
                    placeholder="Contoh: warga_desa01"
                    value={modalForm.username || ''}
                    onChange={(e) => setModalForm({ ...modalForm, username: e.target.value })}
                    required
                  />
                  <span className="admin-field__hint">3 hingga 24 huruf, angka, atau garis bawah.</span>
                </div>
                <div className="admin-field">
                  <label htmlFor="modal-create-password">Kata Sandi</label>
                  <input
                    id="modal-create-password"
                    type="password"
                    className="admin-input"
                    placeholder="Minimal 8 karakter dengan huruf & angka"
                    value={modalForm.password || ''}
                    onChange={(e) => setModalForm({ ...modalForm, password: e.target.value })}
                    required
                  />
                </div>
                <div className="server-form-grid">
                  <div className="admin-field">
                    <label htmlFor="modal-create-role">Peran</label>
                    <select
                      id="modal-create-role"
                      className="admin-select"
                      value={modalForm.role || 'player'}
                      onChange={(e) => setModalForm({ ...modalForm, role: e.target.value })}
                    >
                      <option value="player">player</option>
                      <option value="admin">admin</option>
                    </select>
                  </div>
                  <div className="admin-field">
                    <label htmlFor="modal-create-coins">Koin Awal</label>
                    <input
                      id="modal-create-coins"
                      type="number"
                      min={0}
                      max={999999999}
                      className="admin-input admin-input--mono"
                      value={modalForm.coins ?? 0}
                      onChange={(e) => setModalForm({ ...modalForm, coins: e.target.value })}
                    />
                  </div>
                </div>
                <div className="admin-field">
                  <label htmlFor="modal-create-lives">Nyawa Tambahan (0 hingga 5)</label>
                  <input
                    id="modal-create-lives"
                    type="number"
                    min={0}
                    max={5}
                    className="admin-input admin-input--mono"
                    value={modalForm.extraLives ?? 0}
                    onChange={(e) => setModalForm({ ...modalForm, extraLives: e.target.value })}
                  />
                </div>
              </>
            )}

            {modal.type === 'update' && (
              <>
                <div className="server-form-grid">
                  <div className="admin-field">
                    <label htmlFor="modal-upd-coins">Koin</label>
                    <input
                      id="modal-upd-coins"
                      type="number"
                      min={0}
                      max={999999999}
                      className="admin-input admin-input--mono"
                      value={modalForm.coins ?? 0}
                      onChange={(e) => setModalForm({ ...modalForm, coins: e.target.value })}
                      required
                    />
                  </div>
                  <div className="admin-field">
                    <label htmlFor="modal-upd-wins">Total Kemenangan</label>
                    <input
                      id="modal-upd-wins"
                      type="number"
                      min={0}
                      className="admin-input admin-input--mono"
                      value={modalForm.totalWins ?? 0}
                      onChange={(e) => setModalForm({ ...modalForm, totalWins: e.target.value })}
                      required
                    />
                  </div>
                  <div className="admin-field">
                    <label htmlFor="modal-upd-lives">Nyawa Tambahan (0 hingga 5)</label>
                    <input
                      id="modal-upd-lives"
                      type="number"
                      min={0}
                      max={5}
                      className="admin-input admin-input--mono"
                      value={modalForm.extraLives ?? 0}
                      onChange={(e) => setModalForm({ ...modalForm, extraLives: e.target.value })}
                      required
                    />
                  </div>
                  <div className="admin-field">
                    <label htmlFor="modal-upd-role">Peran Akun</label>
                    <select
                      id="modal-upd-role"
                      className="admin-select"
                      value={modalForm.role || 'player'}
                      onChange={(e) => setModalForm({ ...modalForm, role: e.target.value })}
                    >
                      <option value="player">player</option>
                      <option value="admin">admin</option>
                    </select>
                  </div>
                </div>
                <label className="admin-checkbox-row" htmlFor="modal-upd-verified">
                  <input
                    id="modal-upd-verified"
                    type="checkbox"
                    checked={Boolean(modalForm.isVerified)}
                    onChange={(e) => setModalForm({ ...modalForm, isVerified: e.target.checked })}
                  />
                  <span>Akun Terverifikasi (Lencana Centang Biru)</span>
                </label>
              </>
            )}

            {modal.type === 'ban' && (
              <div className="admin-field">
                <label htmlFor="modal-ban-reason">Alasan Pemblokiran</label>
                <textarea
                  id="modal-ban-reason"
                  className="admin-textarea"
                  placeholder="Tuliskan pelanggaran atau alasan pemblokiran akun..."
                  value={modalForm.reason || ''}
                  onChange={(e) => setModalForm({ ...modalForm, reason: e.target.value })}
                  required
                />
              </div>
            )}

            {modal.type === 'unban' && (
              <p className="admin-panel__desc">
                Akun <strong>{modal.user.username}</strong> akan diaktifkan kembali. Alasan blokir
                sebelumnya: {modal.user.banReason || 'Tidak tercatat'}.
              </p>
            )}

            {modal.type === 'reset_password' && (
              <>
                <div className="admin-field">
                  <label htmlFor="modal-reset-pwd">Kata Sandi Baru</label>
                  <input
                    id="modal-reset-pwd"
                    type="password"
                    className="admin-input"
                    placeholder="Minimal 8 karakter dengan huruf & angka"
                    value={modalForm.password || ''}
                    onChange={(e) => setModalForm({ ...modalForm, password: e.target.value })}
                    required
                  />
                </div>
                <div className="admin-field">
                  <label htmlFor="modal-reset-pwd2">Ulangi Kata Sandi Baru</label>
                  <input
                    id="modal-reset-pwd2"
                    type="password"
                    className="admin-input"
                    placeholder="Masukkan kata sandi baru yang sama"
                    value={modalForm.confirmPassword || ''}
                    onChange={(e) =>
                      setModalForm({ ...modalForm, confirmPassword: e.target.value })
                    }
                    required
                  />
                </div>
              </>
            )}

            {modal.type === 'force_logout' && (
              <p className="admin-panel__desc">
                Seluruh token sesi aktif untuk <strong>{modal.user.username}</strong> akan dicabut
                sehingga pemain harus masuk ulang dari klien game.
              </p>
            )}

            {modal.type === 'delete' && (
              <div className="admin-alert admin-alert--error">
                <span>
                  Tindakan ini menghapus permanen akun <strong>{modal.user.username}</strong> beserta
                  sesinya dan tidak dapat dibatalkan.
                </span>
              </div>
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
                disabled={submitting}
              >
                Batal
              </button>
              <button
                type="submit"
                className={`admin-btn ${
                  modal.type === 'ban' || modal.type === 'delete'
                    ? 'admin-btn--danger'
                    : 'admin-btn--primary'
                }`}
                disabled={submitting}
              >
                {submitting ? 'Memproses...' : 'Konfirmasi'}
              </button>
            </div>
          </form>
        )}
      </dialog>
    </>
  )
}
