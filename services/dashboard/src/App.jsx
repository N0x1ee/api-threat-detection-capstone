import React, { useCallback, useEffect, useState } from 'react'

// Talks to the XAI service's dashboard API (services/xai/service.py). Polls every 3 s.
let csrf = null
async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) }
  if (csrf && opts.method && opts.method !== 'GET') headers['X-CSRF-Token'] = csrf
  const r = await fetch(path, { credentials: 'same-origin', ...opts, headers })
  const body = await r.json().catch(() => ({}))
  if (!r.ok) throw Object.assign(new Error(body.error || r.statusText), { status: r.status })
  return body
}

const fmt = (s) => (s === null || s === undefined ? '–' : Number(s).toFixed(2))
const time = (ts) => new Date(ts * 1000).toLocaleTimeString()

function Login({ onLogin }) {
  const [u, setU] = useState('')
  const [p, setP] = useState('')
  const [err, setErr] = useState('')
  const submit = async (e) => {
    e.preventDefault()
    try {
      const me = await api('/login', { method: 'POST', body: JSON.stringify({ username: u, password: p }) })
      csrf = me.csrf
      onLogin(me)
    } catch (x) { setErr(x.message) }
  }
  return (
    <form className="login" onSubmit={submit}>
      <h1>API Threat Monitor</h1>
      <input placeholder="Username" value={u} onChange={(e) => setU(e.target.value)} autoFocus />
      <input placeholder="Password" type="password" value={p} onChange={(e) => setP(e.target.value)} />
      <button>Sign in</button>
      {err && <p className="err">{err}</p>}
    </form>
  )
}

function Tiles({ stats }) {
  const v = stats.by_verdict || {}
  const r = stats.by_route || {}
  const total = stats.total || 0
  const tiles = [
    ['Requests', total],
    ['Allowed', v.ALLOW || 0],
    ['Flagged', v.FLAG || 0],
    ['Blocked', v.BLOCK || 0],
    ['Cleared by fast filter', total ? `${Math.round(100 * (r.fast_filter || 0) / total)}%` : '–'],
    ['Agent latency p95', stats.agent_latency_ms?.p95 ? `${stats.agent_latency_ms.p95.toFixed(1)} ms` : '–'],
    ['Degraded decisions', stats.degraded || 0],
  ]
  return <div className="tiles">{tiles.map(([k, val]) => <div className="tile" key={k}><span>{k}</span><b>{val}</b></div>)}</div>
}

function Bars({ title, data }) {
  const entries = Object.entries(data || {}).sort((a, b) => b[1] - a[1])
  const max = Math.max(1, ...entries.map((e) => e[1]))
  return (
    <div className="card">
      <h3>{title}</h3>
      {entries.length === 0 && <p className="muted">Nothing yet</p>}
      {entries.map(([k, n]) => (
        <div className="bar" key={k}><span>{k}</span><i style={{ width: `${(100 * n) / max}%` }} /><b>{n}</b></div>
      ))}
    </div>
  )
}

function Detail({ rid, onClose }) {
  const [d, setD] = useState(null)
  const [hist, setHist] = useState([])
  const [form, setForm] = useState({ outcome: 'malicious', justification: '', corrected_verdict: '' })
  const [msg, setMsg] = useState('')
  const load = useCallback(async () => {
    setD((await api(`/api/decisions/${rid}`)).decision)
    setHist((await api(`/api/decisions/${rid}/adjudications`)).adjudications)
  }, [rid])
  useEffect(() => { load() }, [load])
  const review = async (e) => {
    e.preventDefault()
    try {
      await api(`/api/decisions/${rid}/adjudicate`, {
        method: 'POST',
        body: JSON.stringify({ ...form, corrected_verdict: form.corrected_verdict || null }),
      })
      setMsg('Review saved')
      setForm({ ...form, justification: '' })
      load()
    } catch (x) { setMsg(x.message) }
  }
  if (!d) return <div className="detail">Loading…</div>
  const ex = d.explanation || {}
  return (
    <div className="detail">
      <button className="close" onClick={onClose}>×</button>
      <h2 className={`v-${d.verdict}`}>{d.verdict} · score {fmt(d.score)}</h2>
      <p>{ex.summary}</p>
      <p className="muted">{d.method} {d.path}{d.query ? `?${d.query}` : ''} · {d.ip} · {time(d.ts)} · route {d.route}</p>
      {ex.evidence?.length > 0 && <ul>{ex.evidence.map((e, i) => <li key={i}>{e}</li>)}</ul>}
      {d.agents && Object.keys(d.agents).length > 0 && (
        <table>
          <thead><tr><th>Agent</th><th>Score</th><th>Confidence</th><th>Weight</th></tr></thead>
          <tbody>{Object.entries(d.agents).map(([n, a]) => (
            <tr key={n}><td>{n}</td><td>{fmt(a.score)}</td><td>{fmt(a.confidence)}</td><td>{fmt(a.weight)}</td></tr>
          ))}</tbody>
        </table>
      )}
      {d.excluded && Object.keys(d.excluded).length > 0 && (
        <p className="warn">Missing: {Object.entries(d.excluded).map(([n, w]) => `${n} (${w})`).join('; ')}</p>
      )}
      <h3>Analyst review</h3>
      <form className="review" onSubmit={review}>
        <select value={form.outcome} onChange={(e) => setForm({ ...form, outcome: e.target.value })}>
          <option value="malicious">Malicious</option>
          <option value="benign">Benign</option>
          <option value="undetermined">Undetermined</option>
        </select>
        <select value={form.corrected_verdict} onChange={(e) => setForm({ ...form, corrected_verdict: e.target.value })}>
          <option value="">Keep verdict</option>
          <option value="ALLOW">Should be ALLOW</option>
          <option value="FLAG">Should be FLAG</option>
          <option value="BLOCK">Should be BLOCK</option>
        </select>
        <input required placeholder="Justification (required)" value={form.justification}
          onChange={(e) => setForm({ ...form, justification: e.target.value })} />
        <button>Save review</button>
      </form>
      {msg && <p className="muted">{msg}</p>}
      {hist.map((h, i) => (
        <p className="muted" key={i}>{time(h.ts)} · {h.analyst}: {h.outcome}{h.corrected_verdict ? ` → ${h.corrected_verdict}` : ''} — {h.justification}</p>
      ))}
    </div>
  )
}

export default function App() {
  const [me, setMe] = useState(undefined)
  const [stats, setStats] = useState({})
  const [feed, setFeed] = useState([])
  const [filter, setFilter] = useState('')
  const [open, setOpen] = useState(null)

  useEffect(() => {
    api('/api/me').then((m) => { csrf = m.csrf; setMe(m) }).catch(() => setMe(null))
  }, [])

  useEffect(() => {
    if (!me) return
    const tick = async () => {
      try {
        setStats(await api('/api/stats'))
        setFeed((await api(`/api/decisions?limit=60${filter ? `&verdict=${filter}` : ''}`)).decisions)
      } catch (x) { if (x.status === 401) setMe(null) }
    }
    tick()
    const t = setInterval(tick, 3000)
    return () => clearInterval(t)
  }, [me, filter])

  if (me === undefined) return null
  if (!me) return <Login onLogin={setMe} />
  const logout = async () => { await api('/logout', { method: 'POST' }); csrf = null; setMe(null) }

  return (
    <div className="app">
      <header>
        <h1>API Threat Monitor</h1>
        <span>{me.user} ({me.role}) <button onClick={logout}>Sign out</button></span>
      </header>
      <Tiles stats={stats} />
      <div className="grid">
        <div className="card feed">
          <h3>Live decisions
            <select value={filter} onChange={(e) => setFilter(e.target.value)}>
              <option value="">All</option><option>BLOCK</option><option>FLAG</option><option>ALLOW</option>
            </select>
          </h3>
          <table>
            <thead><tr><th>Time</th><th>Verdict</th><th>Score</th><th>Request</th><th>Type</th></tr></thead>
            <tbody>{feed.map((d) => (
              <tr key={d.request_id} onClick={() => setOpen(d.request_id)} className={open === d.request_id ? 'sel' : ''}>
                <td>{time(d.ts)}</td><td className={`v-${d.verdict}`}>{d.verdict}{d.degraded ? ' *' : ''}</td>
                <td>{fmt(d.score)}</td><td className="req">{d.method} {d.path}</td><td>{d.attack_type}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
        <div>
          <Bars title="Threats by type" data={stats.by_attack_type} />
          <Bars title="Agent weights" data={stats.weights ? Object.fromEntries(Object.entries(stats.weights).map(([k, v]) => [k, Number(v.toFixed(2))])) : { anomaly: 1, payload: 1, behavior: 1 }} />
        </div>
      </div>
      {open && <Detail rid={open} onClose={() => setOpen(null)} />}
    </div>
  )
}
