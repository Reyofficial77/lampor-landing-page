import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import {
  ApiError,
  deleteAdminMessage,
  formatTimestamp,
  listAdminMessages,
  normalizePlayerMessage,
  sendAdminMessage,
} from './adminApi'

const HTTP_URL_RE = /^https?:\/\//i

function isSafeHttpUrl(rawUrl) {
  const trimmed = String(rawUrl || '').trim()
  if (!HTTP_URL_RE.test(trimmed)) return false
  try {
    const parsed = new URL(trimmed)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:'
  } catch {
    return false
  }
}

function renderInlineMarkdown(text, keyPrefix = 'in') {
  const source = String(text || '')
  const nodes = []
  let pos = 0
  let tokenIndex = 0

  while (pos < source.length) {
    let best = null

    const codeIdx = source.indexOf('`', pos)
    if (codeIdx !== -1) {
      const codeEnd = source.indexOf('`', codeIdx + 1)
      if (codeEnd !== -1 && codeEnd > codeIdx + 1) {
        best = { type: 'code', start: codeIdx, end: codeEnd + 1, inner: source.slice(codeIdx + 1, codeEnd) }
      }
    }

    const linkStart = source.indexOf('[', pos)
    if (linkStart !== -1 && (!best || linkStart < best.start)) {
      const closeBracket = source.indexOf(']', linkStart + 1)
      if (closeBracket !== -1 && source[closeBracket + 1] === '(') {
        const closeParen = source.indexOf(')', closeBracket + 2)
        if (closeParen !== -1 && closeBracket > linkStart + 1) {
          best = {
            type: 'link',
            start: linkStart,
            end: closeParen + 1,
            label: source.slice(linkStart + 1, closeBracket),
            url: source.slice(closeBracket + 2, closeParen).trim(),
          }
        }
      }
    }

    const boldIdx = source.indexOf('**', pos)
    if (boldIdx !== -1 && (!best || boldIdx < best.start)) {
      const boldEnd = source.indexOf('**', boldIdx + 2)
      if (boldEnd !== -1 && boldEnd > boldIdx + 2) {
        best = { type: 'bold', start: boldIdx, end: boldEnd + 2, inner: source.slice(boldIdx + 2, boldEnd) }
      }
    }

    const strikeIdx = source.indexOf('~~', pos)
    if (strikeIdx !== -1 && (!best || strikeIdx < best.start)) {
      const strikeEnd = source.indexOf('~~', strikeIdx + 2)
      if (strikeEnd !== -1 && strikeEnd > strikeIdx + 2) {
        best = { type: 'strike', start: strikeIdx, end: strikeEnd + 2, inner: source.slice(strikeIdx + 2, strikeEnd) }
      }
    }

    const italicIdx = source.indexOf('*', pos)
    if (italicIdx !== -1 && (!best || italicIdx < best.start)) {
      if (source[italicIdx + 1] !== '*') {
        let searchFrom = italicIdx + 1
        while (searchFrom < source.length) {
          const italicEnd = source.indexOf('*', searchFrom)
          if (italicEnd === -1) break
          if (source[italicEnd + 1] === '*') {
            searchFrom = italicEnd + 2
            continue
          }
          if (italicEnd > italicIdx + 1) {
            best = {
              type: 'italic',
              start: italicIdx,
              end: italicEnd + 1,
              inner: source.slice(italicIdx + 1, italicEnd),
            }
          }
          break
        }
      }
    }

    if (!best) {
      nodes.push(source.slice(pos))
      break
    }

    if (best.start > pos) {
      nodes.push(source.slice(pos, best.start))
    }

    const key = `${keyPrefix}-${tokenIndex}`
    tokenIndex += 1

    if (best.type === 'code') {
      nodes.push(<code key={key}>{best.inner}</code>)
    } else if (best.type === 'link') {
      if (isSafeHttpUrl(best.url)) {
        nodes.push(
          <a key={key} href={best.url} target="_blank" rel="noopener noreferrer">
            {renderInlineMarkdown(best.label, `${key}-l`)}
          </a>
        )
      } else {
        nodes.push(
          <Fragment key={key}>{`${best.label} (${best.url})`}</Fragment>
        )
      }
    } else if (best.type === 'bold') {
      nodes.push(<strong key={key}>{renderInlineMarkdown(best.inner, `${key}-b`)}</strong>)
    } else if (best.type === 'strike') {
      nodes.push(<del key={key}>{renderInlineMarkdown(best.inner, `${key}-s`)}</del>)
    } else if (best.type === 'italic') {
      nodes.push(<em key={key}>{renderInlineMarkdown(best.inner, `${key}-i`)}</em>)
    }

    pos = best.end
  }

  return nodes
}

function SafeMarkdown({ text }) {
  const lines = String(text || '').replace(/\r\n?/g, '\n').split('\n')
  const blocks = []
  let i = 0
  let blockKey = 0

  while (i < lines.length) {
    const line = lines[i]
    const trimmed = line.trim()

    if (!trimmed) {
      i += 1
      continue
    }

    if (trimmed.startsWith('```')) {
      const codeLines = []
      i += 1
      while (i < lines.length && !lines[i].trim().startsWith('```')) {
        codeLines.push(lines[i])
        i += 1
      }
      if (i < lines.length) i += 1
      blocks.push(
        <pre key={`b-${blockKey}`}>
          <code>{codeLines.join('\n')}</code>
        </pre>
      )
      blockKey += 1
      continue
    }

    if (/^---+$/.test(trimmed)) {
      blocks.push(<hr key={`b-${blockKey}`} />)
      blockKey += 1
      i += 1
      continue
    }

    const headingMatch = trimmed.match(/^(#{1,3})\s+(.+)$/)
    if (headingMatch) {
      const level = headingMatch[1].length
      const content = renderInlineMarkdown(headingMatch[2], `h-${blockKey}`)
      if (level === 1) {
        blocks.push(<h3 className="admin-md-h1" key={`b-${blockKey}`}>{content}</h3>)
      } else if (level === 2) {
        blocks.push(<h4 className="admin-md-h2" key={`b-${blockKey}`}>{content}</h4>)
      } else {
        blocks.push(<h5 className="admin-md-h3" key={`b-${blockKey}`}>{content}</h5>)
      }
      blockKey += 1
      i += 1
      continue
    }

    if (/^>\s?/.test(trimmed)) {
      const quoteLines = []
      while (i < lines.length && /^>\s?/.test(lines[i].trim())) {
        quoteLines.push(lines[i].trim().replace(/^>\s?/, ''))
        i += 1
      }
      blocks.push(
        <blockquote key={`b-${blockKey}`}>
          {quoteLines.map((ql, idx) => (
            <p key={idx}>{renderInlineMarkdown(ql, `q-${blockKey}-${idx}`)}</p>
          ))}
        </blockquote>
      )
      blockKey += 1
      continue
    }

    if (/^[-*]\s+/.test(trimmed)) {
      const items = []
      while (i < lines.length && /^[-*]\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^[-*]\s+/, ''))
        i += 1
      }
      blocks.push(
        <ul key={`b-${blockKey}`}>
          {items.map((item, idx) => (
            <li key={idx}>{renderInlineMarkdown(item, `ul-${blockKey}-${idx}`)}</li>
          ))}
        </ul>
      )
      blockKey += 1
      continue
    }

    if (/^\d+\.\s+/.test(trimmed)) {
      const items = []
      while (i < lines.length && /^\d+\.\s+/.test(lines[i].trim())) {
        items.push(lines[i].trim().replace(/^\d+\.\s+/, ''))
        i += 1
      }
      blocks.push(
        <ol key={`b-${blockKey}`}>
          {items.map((item, idx) => (
            <li key={idx}>{renderInlineMarkdown(item, `ol-${blockKey}-${idx}`)}</li>
          ))}
        </ol>
      )
      blockKey += 1
      continue
    }

    const paraLines = []
    while (i < lines.length) {
      const cur = lines[i].trim()
      if (
        !cur ||
        cur.startsWith('```') ||
        /^---+$/.test(cur) ||
        /^(#{1,3})\s+/.test(cur) ||
        /^>\s?/.test(cur) ||
        /^[-*]\s+/.test(cur) ||
        /^\d+\.\s+/.test(cur)
      ) {
        break
      }
      paraLines.push(lines[i])
      i += 1
    }

    blocks.push(
      <p key={`b-${blockKey}`}>
        {paraLines.map((pl, idx) => (
          <Fragment key={idx}>
            {idx > 0 && <br />}
            {renderInlineMarkdown(pl, `p-${blockKey}-${idx}`)}
          </Fragment>
        ))}
      </p>
    )
    blockKey += 1
  }

  return <div className="admin-md-body">{blocks}</div>
}

export default function MessagesTab({ refreshTick, autoTick, onNotify, onUnauthorized }) {
  const [scope, setScope] = useState('global')
  const [targetUsername, setTargetUsername] = useState('')
  const [title, setTitle] = useState('')
  const [bodyMarkdown, setBodyMarkdown] = useState('')
  const [formError, setFormError] = useState('')
  const [sending, setSending] = useState(false)

  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [messages, setMessages] = useState([])
  const [deletingId, setDeletingId] = useState('')

  const inFlightRef = useRef(false)

  const loadMessages = useCallback(async (silent = false) => {
    if (inFlightRef.current) return
    inFlightRef.current = true
    if (!silent) {
      setLoading(true)
      setError('')
    }
    try {
      const res = await listAdminMessages()
      const list = Array.isArray(res.messages) ? res.messages.map(normalizePlayerMessage) : []
      setMessages(list)
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized(err.message)
        return
      }
      if (!silent) {
        setError(err.message || 'Gagal memuat riwayat pesan pemain.')
      }
    } finally {
      inFlightRef.current = false
      if (!silent) {
        setLoading(false)
      }
    }
  }, [onUnauthorized])

  useEffect(() => {
    loadMessages(false)
  }, [loadMessages, refreshTick])

  useEffect(() => {
    if (!autoTick || autoTick % 5 !== 0 || sending || deletingId) return
    loadMessages(true)
  }, [loadMessages, autoTick, sending, deletingId])

  const handleSendSubmit = async (e) => {
    e.preventDefault()
    setFormError('')

    const cleanTarget = targetUsername.trim()
    const cleanTitle = title.trim()
    const cleanBody = bodyMarkdown.trim()

    if (scope === 'user' && !cleanTarget) {
      setFormError('Username tujuan wajib diisi jika pesan ditujukan ke pemain tertentu.')
      return
    }
    if (!cleanBody) {
      setFormError('Isi pesan Markdown tidak boleh kosong.')
      return
    }

    setSending(true)
    try {
      const res = await sendAdminMessage({
        scope,
        targetUsername: scope === 'user' ? cleanTarget : undefined,
        title: cleanTitle || undefined,
        bodyMarkdown: cleanBody,
      })

      if (Array.isArray(res.messages)) {
        setMessages(res.messages.map(normalizePlayerMessage))
      } else if (res.message) {
        setMessages((prev) => [normalizePlayerMessage(res.message), ...prev])
      } else {
        await loadMessages(true)
      }

      setTargetUsername('')
      setTitle('')
      setBodyMarkdown('')
      setFormError('')
      onNotify(
        'success',
        scope === 'global'
          ? 'Pesan global berhasil dikirim ke kotak masuk seluruh pemain.'
          : `Pesan berhasil dikirim ke kotak masuk @${cleanTarget}.`
      )
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized(err.message)
        return
      }
      const errMsg = err.message || 'Gagal mengirim pesan ke pemain.'
      setFormError(errMsg)
      onNotify('error', errMsg)
    } finally {
      setSending(false)
    }
  }

  const handleDeleteMessage = async (msg) => {
    if (!msg?.id || deletingId) return
    setDeletingId(msg.id)
    try {
      const res = await deleteAdminMessage(msg.id)
      if (Array.isArray(res.messages)) {
        setMessages(res.messages.map(normalizePlayerMessage))
      } else {
        setMessages((prev) => prev.filter((item) => item.id !== msg.id))
      }
      onNotify('success', 'Pesan berhasil dihapus dari riwayat kotak masuk pemain.')
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        onUnauthorized(err.message)
        return
      }
      onNotify('error', err.message || 'Gagal menghapus pesan.')
    } finally {
      setDeletingId('')
    }
  }

  return (
    <>
      <section className="admin-panel admin-panel--priority" aria-labelledby="compose-message-heading">
        <div className="admin-panel__head">
          <div>
            <h2 id="compose-message-heading">Kirim Pesan ke Pemain (Markdown)</h2>
            <p className="admin-panel__desc">
              Kirim pengumuman atau pesan langsung ke kotak masuk semua pemain atau akun tertentu.
            </p>
          </div>
        </div>

        <form className="admin-form" onSubmit={handleSendSubmit}>
          <div className="admin-field">
            <span className="admin-field__label" id="msg-scope-label">
              Jangkauan Penerima
            </span>
            <div className="admin-scope-toggle" role="group" aria-labelledby="msg-scope-label">
              <button
                type="button"
                className={`admin-scope-btn${scope === 'global' ? ' is-active' : ''}`}
                aria-pressed={scope === 'global'}
                disabled={sending}
                onClick={() => {
                  setScope('global')
                  setFormError('')
                }}
              >
                Global (Semua Player)
              </button>
              <button
                type="button"
                className={`admin-scope-btn${scope === 'user' ? ' is-active' : ''}`}
                aria-pressed={scope === 'user'}
                disabled={sending}
                onClick={() => {
                  setScope('user')
                  setFormError('')
                }}
              >
                Pemain Tertentu (Username)
              </button>
            </div>
          </div>

          {scope === 'user' && (
            <div className="admin-field">
              <label htmlFor="msg-target-username">Username Tujuan</label>
              <input
                id="msg-target-username"
                type="text"
                className="admin-input admin-input--mono"
                spellCheck={false}
                autoCapitalize="none"
                autoCorrect="off"
                maxLength={24}
                placeholder="Masukkan username pemain"
                value={targetUsername}
                onChange={(e) => setTargetUsername(e.target.value)}
                disabled={sending}
                required
              />
            </div>
          )}

          <div className="admin-field">
            <label htmlFor="msg-title">Judul Pesan (Opsional)</label>
            <input
              id="msg-title"
              type="text"
              className="admin-input"
              maxLength={120}
              placeholder="Contoh: Pemberitahuan Pembaruan"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              disabled={sending}
            />
          </div>

          <div className="admin-markdown-grid">
            <div className="admin-field">
              <div className="admin-field__head">
                <label htmlFor="msg-body-markdown">Isi Pesan (Markdown)</label>
                <span className="admin-field__hint mono-chip">{bodyMarkdown.length} / 4000</span>
              </div>
              <textarea
                id="msg-body-markdown"
                className="admin-textarea admin-textarea--markdown"
                rows={6}
                maxLength={4000}
                placeholder="Tulis isi pesan menggunakan format Markdown..."
                value={bodyMarkdown}
                onChange={(e) => setBodyMarkdown(e.target.value)}
                disabled={sending}
                required
              />
              <p className="admin-field__hint">
                Format: <code># Judul</code>, <code>**tebal**</code>, <code>*miring*</code>,{' '}
                <code>`kode`</code>, <code>~~coret~~</code>, <code>- daftar</code>,{' '}
                <code>&gt; kutipan</code>, <code>[tautan](https://...)</code>
              </p>
            </div>

            <div className="admin-field">
              <span className="admin-field__label" id="msg-preview-label">
                Pratinjau Markdown
              </span>
              <div className="admin-md-preview" aria-labelledby="msg-preview-label">
                {bodyMarkdown.trim() ? (
                  <SafeMarkdown text={bodyMarkdown} />
                ) : (
                  <p className="admin-md-preview__empty">
                    Pratinjau isi pesan akan muncul di sini saat Anda mulai menulis.
                  </p>
                )}
              </div>
            </div>
          </div>

          {formError && (
            <div className="admin-alert admin-alert--error" role="alert">
              <span>{formError}</span>
            </div>
          )}

          <div>
            <button type="submit" className="admin-btn admin-btn--primary" disabled={sending}>
              {sending ? 'Mengirim Pesan...' : 'Kirim Pesan'}
            </button>
          </div>
        </form>
      </section>

      <section className="admin-panel" aria-labelledby="sent-messages-heading">
        <div className="admin-panel__head">
          <div>
            <h2 id="sent-messages-heading">Riwayat Pesan Terkirim ({messages.length})</h2>
            <p className="admin-panel__desc">
              Daftar pesan aktif yang tersimpan di kotak masuk pemain.
            </p>
          </div>
          <button
            type="button"
            className="admin-btn admin-btn--sm"
            onClick={() => loadMessages(false)}
            disabled={loading}
          >
            Segarkan
          </button>
        </div>

        {loading ? (
          <div className="admin-state-box" role="status" aria-live="polite">
            <h3>Memuat Riwayat Pesan</h3>
            <p>Mengambil daftar pesan pemain yang telah dikirim dari server...</p>
          </div>
        ) : error ? (
          <div className="admin-state-box" role="alert">
            <h3>Gagal Memuat Riwayat Pesan</h3>
            <p>{error}</p>
            <button
              type="button"
              className="admin-btn admin-btn--primary"
              onClick={() => loadMessages(false)}
            >
              Coba Lagi
            </button>
          </div>
        ) : messages.length === 0 ? (
          <div className="admin-state-box">
            <h3>Belum Ada Pesan Terkirim</h3>
            <p>
              Belum ada pesan yang dikirim ke pemain. Gunakan formulir di atas untuk mengirim
              pengumuman global atau pesan pribadi ke username tertentu.
            </p>
          </div>
        ) : (
          <div className="admin-msg-list">
            {messages.map((msg) => {
              const isUserScope = msg.scope === 'user'
              const isDeleting = deletingId === msg.id
              return (
                <article className="admin-msg-card" key={msg.id}>
                  <div className="admin-msg-card__head">
                    <div className="admin-msg-card__info">
                      <div className="admin-msg-card__meta">
                        <span
                          className={`admin-tag ${
                            isUserScope ? 'admin-tag--sage' : 'admin-tag--brass'
                          }`}
                        >
                          {isUserScope
                            ? `@${msg.targetUsername || 'pemain'}`
                            : 'GLOBAL'}
                        </span>
                        <span className="admin-field__hint">
                          Oleh {msg.senderUsername || 'admin'} · {formatTimestamp(msg.createdAt)}
                        </span>
                      </div>
                      <h3 className="admin-msg-card__title">
                        {msg.title || 'Pesan Tanpa Judul'}
                      </h3>
                    </div>

                    <button
                      type="button"
                      className="admin-btn admin-btn--danger admin-btn--sm"
                      disabled={Boolean(deletingId)}
                      onClick={() => handleDeleteMessage(msg)}
                    >
                      {isDeleting ? 'Menghapus...' : 'Hapus Pesan'}
                    </button>
                  </div>

                  <div className="admin-msg-card__body">
                    <SafeMarkdown text={msg.bodyMarkdown} />
                  </div>
                </article>
              )
            })}
          </div>
        )}
      </section>
    </>
  )
}
