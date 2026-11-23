import { useCallback, useEffect, useRef, useState } from 'react'
import {
  ApiError,
  fetchRooms,
  formatTimestamp,
  normalizeRoom,
  postRoomsAction,
  useDialogController,
} from './adminApi'

export default function RoomsTab({ refreshTick, onNotify, onUnauthorized }) {
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [rooms, setRooms] = useState([])
  const [modeFilter, setModeFilter] = useState('all')
  const [cleaning, setCleaning] = useState(false)

  const [modal, setModal] = useState(null)
  const [broadcastMsg, setBroadcastMsg] = useState('')
  const [modalError, setModalError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const returnFocusRef = useRef(null)

  const closeModal = useCallback(() => {
    setModal(null)
    setBroadcastMsg('')
    setModalError('')
    setSubmitting(false)
  }, [])

  const { dialogRef, onDialogClick, onDialogCancel } = useDialogController(
    Boolean(modal),
    closeModal,
    returnFocusRef
  )

  const loadRooms = useCallback(async () => {
    setLoading(true)
    setError('')
    try {
      const res = await fetchRooms()
      const list = Array.isArray(res.rooms) ? res.rooms.map(normalizeRoom) : []
      setRooms(list)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized(err.message)
        return
      }
      setError(err.message || 'Gagal memuat daftar room aktif.')
    } finally {
      setLoading(false)
    }
  }, [onUnauthorized])

  useEffect(() => {
    loadRooms()
  }, [loadRooms, refreshTick])

  const openModal = (type, room, player, triggerEl) => {
    returnFocusRef.current = triggerEl
    setModalError('')
    setBroadcastMsg('')
    setModal({ type, room, player })
  }

  const handleCleanupStale = async () => {
    setCleaning(true)
    try {
      const res = await postRoomsAction({ action: 'cleanup_stale' })
      const removed = res.closedCount ?? res.removedCount ?? res.cleaned ?? 0
      onNotify('success', `Pembersihan room tidak aktif selesai (${removed} room dibersihkan).`)
      await loadRooms()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized(err.message)
        return
      }
      onNotify('error', err.message || 'Gagal membersihkan room mati.')
    } finally {
      setCleaning(false)
    }
  }

  const handleModalSubmit = async (e) => {
    e.preventDefault()
    if (!modal) return
    setModalError('')

    let payload = null
    let successMsg = ''

    if (modal.type === 'broadcast_room') {
      const msg = broadcastMsg.trim()
      if (!msg) {
        setModalError('Isi pesan pengumuman room terlebih dahulu.')
        return
      }
      payload = {
        action: 'broadcast_room',
        roomId: modal.room.id,
        message: msg,
      }
      successMsg = `Pengumuman dikirim ke room ${modal.room.name}.`
    } else if (modal.type === 'close_room') {
      payload = {
        action: 'close_room',
        roomId: modal.room.id,
      }
      successMsg = `Room ${modal.room.name} (${modal.room.roomCode}) telah ditutup paksa.`
    } else if (modal.type === 'kick_player') {
      payload = {
        action: 'kick_player',
        roomId: modal.room.id,
        targetUserId: modal.player.userId,
      }
      successMsg = `Pemain ${modal.player.username} dikeluarkan dari room ${modal.room.name}.`
    }

    if (!payload) return

    setSubmitting(true)
    try {
      await postRoomsAction(payload)
      closeModal()
      onNotify('success', successMsg)
      await loadRooms()
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        closeModal()
        onUnauthorized(err.message)
        return
      }
      setModalError(err.message || 'Gagal menjalankan aksi pada room.')
    } finally {
      setSubmitting(false)
    }
  }

  const filteredRooms = rooms.filter((r) => modeFilter === 'all' || r.mode === modeFilter)

  return (
    <>
      <section className="admin-panel" aria-labelledby="rooms-toolbar-heading">
        <div className="admin-panel__head">
          <div>
            <h2 id="rooms-toolbar-heading">Pengawasan Room Multiplayer &amp; Sandbox</h2>
            <p className="admin-panel__desc">
              Pantau room aktif, kirim pesan langsung ke lobby atau HUD room, keluarkan pemain,
              atau tutup sesi bermasalah.
            </p>
          </div>
          <div className="admin-row-actions">
            <button
              type="button"
              className="admin-btn"
              onClick={handleCleanupStale}
              disabled={cleaning}
            >
              {cleaning ? 'Membersihkan...' : 'Bersihkan Room Mati'}
            </button>
          </div>
        </div>

        <div className="admin-toolbar">
          <div className="admin-field">
            <label htmlFor="rooms-mode-filter">Filter Mode</label>
            <select
              id="rooms-mode-filter"
              className="admin-select"
              value={modeFilter}
              onChange={(e) => setModeFilter(e.target.value)}
            >
              <option value="all">Semua Mode ({rooms.length})</option>
              <option value="multiplayer">Multiplayer Co-op</option>
              <option value="sandbox">Mode Sandbox</option>
            </select>
          </div>

          <button type="button" className="admin-btn" onClick={loadRooms}>
            Muat Ulang Room
          </button>
        </div>
      </section>

      {loading ? (
        <section className="admin-state-box" role="status" aria-live="polite">
          <h3>Memuat Daftar Room</h3>
          <p>Mengambil status lobby dan sesi permainan aktif dari server...</p>
        </section>
      ) : error ? (
        <section className="admin-state-box" role="alert">
          <h3>Gagal Memuat Daftar Room</h3>
          <p>{error}</p>
          <button type="button" className="admin-btn admin-btn--primary" onClick={loadRooms}>
            Coba Lagi
          </button>
        </section>
      ) : filteredRooms.length === 0 ? (
        <section className="admin-state-box">
          <h3>Tidak Ada Room Aktif</h3>
          <p>
            {modeFilter !== 'all'
              ? `Tidak ditemukan room untuk mode ${modeFilter}. Ubah filter ke Semua Mode atau segarkan daftar.`
              : 'Belum ada room Multiplayer maupun Sandbox yang aktif saat ini. Room akan muncul setelah pemain membuatnya dari klien LAMPOR v1.3.0.'}
          </p>
          {modeFilter !== 'all' ? (
            <button type="button" className="admin-btn" onClick={() => setModeFilter('all')}>
              Tampilkan Semua Mode
            </button>
          ) : (
            <button type="button" className="admin-btn admin-btn--primary" onClick={loadRooms}>
              Segarkan Daftar Room
            </button>
          )}
        </section>
      ) : (
        <div className="rooms-list">
          {filteredRooms.map((room) => (
            <article className="room-card" key={room.id || room.roomCode}>
              <div className="room-card__head">
                <div>
                  <h3>
                    {room.name} <span className="mono-chip">{room.roomCode}</span>
                  </h3>
                  <div className="room-card__meta">
                    <span
                      className={`admin-tag ${
                        room.mode === 'sandbox' ? 'admin-tag--brass' : 'admin-tag--sage'
                      }`}
                    >
                      {room.mode.toUpperCase()}
                    </span>
                    <span
                      className={`admin-tag ${
                        room.status === 'playing' ? 'admin-tag--crimson' : ''
                      }`}
                    >
                      {room.status.toUpperCase()}
                    </span>
                    <span className="admin-tag">{room.difficulty}</span>
                    <span className="admin-tag">
                      Pemain: {room.players.length || room.playerCount}/{room.maxPlayers}
                    </span>
                    <span className="admin-tag">
                      {room.hasPassword ? 'BERPASSWORD' : 'PUBLIK'}
                    </span>
                    <span className="admin-tag">
                      Item Toko: {room.canUseShopItems ? 'ON' : 'OFF'}
                    </span>
                  </div>
                  <p className="admin-field__hint">
                    Host: {room.hostUsername || room.hostUserId || 'Tidak diketahui'} | Aktivitas
                    terakhir: {formatTimestamp(room.lastActivityAt)}
                  </p>
                  {room.announcement && (
                    <p className="admin-field__hint">Pengumuman room: {room.announcement}</p>
                  )}
                </div>

                <div className="admin-row-actions">
                  <button
                    type="button"
                    className="admin-btn admin-btn--sm"
                    onClick={(e) => openModal('broadcast_room', room, null, e.currentTarget)}
                  >
                    Siarkan Pesan
                  </button>
                  <button
                    type="button"
                    className="admin-btn admin-btn--danger admin-btn--sm"
                    onClick={(e) => openModal('close_room', room, null, e.currentTarget)}
                  >
                    Tutup Room
                  </button>
                </div>
              </div>

              <div className="room-players">
                {room.players.length === 0 ? (
                  <p className="admin-field__hint">Tidak ada pemain terhubung di daftar room ini.</p>
                ) : (
                  room.players.map((p) => (
                    <div className="room-player-row" key={p.userId || p.username}>
                      <div>
                        <strong>{p.username}</strong>{' '}
                        {p.isHost && <span className="admin-tag admin-tag--brass">HOST</span>}{' '}
                        <span className={`admin-tag ${p.isReady ? 'admin-tag--sage' : ''}`}>
                          {p.isReady ? 'SIAP' : 'MENUNGGU'}
                        </span>
                      </div>
                      {!p.isHost ? (
                        <button
                          type="button"
                          className="admin-btn admin-btn--danger admin-btn--sm"
                          onClick={(e) => openModal('kick_player', room, p, e.currentTarget)}
                        >
                          Kick Pemain
                        </button>
                      ) : (
                        <span className="admin-field__hint">Gunakan Tutup Room untuk mengakhiri host</span>
                      )}
                    </div>
                  ))
                )}
              </div>
            </article>
          ))}
        </div>
      )}

      <dialog
        ref={dialogRef}
        className="admin-dialog"
        aria-labelledby="room-dialog-title"
        onClick={onDialogClick}
        onCancel={onDialogCancel}
      >
        {modal && (
          <form className="admin-dialog__panel" onSubmit={handleModalSubmit}>
            <div className="admin-dialog__head">
              <h3 id="room-dialog-title">
                {modal.type === 'broadcast_room' && `Siarkan Pesan ke ${modal.room.name}`}
                {modal.type === 'close_room' && `Tutup Paksa Room: ${modal.room.name}`}
                {modal.type === 'kick_player' && `Keluarkan ${modal.player.username}`}
              </h3>
              <button
                type="button"
                className="admin-btn admin-btn--ghost admin-btn--sm"
                onClick={closeModal}
              >
                Batal
              </button>
            </div>

            {modal.type === 'broadcast_room' && (
              <div className="admin-field">
                <label htmlFor="room-broadcast-msg">Pesan Pengumuman Admin</label>
                <textarea
                  id="room-broadcast-msg"
                  className="admin-textarea"
                  placeholder="Contoh: Server akan dimulai ulang dalam 5 menit."
                  value={broadcastMsg}
                  onChange={(e) => setBroadcastMsg(e.target.value)}
                  required
                />
              </div>
            )}

            {modal.type === 'close_room' && (
              <div className="admin-alert admin-alert--error">
                <span>
                  Menutup room <strong>{modal.room.name}</strong> ({modal.room.roomCode}) akan
                  memutus seluruh pemain di dalamnya kembali ke menu utama.
                </span>
              </div>
            )}

            {modal.type === 'kick_player' && (
              <p className="admin-panel__desc">
                Pemain <strong>{modal.player.username}</strong> akan langsung dikeluarkan dari room{' '}
                <strong>{modal.room.name}</strong>.
              </p>
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
                  modal.type === 'broadcast_room' ? 'admin-btn--primary' : 'admin-btn--danger'
                }`}
                disabled={submitting}
              >
                {submitting ? 'Memproses...' : 'Jalankan'}
              </button>
            </div>
          </form>
        )}
      </dialog>
    </>
  )
}
