import { useEffect, useMemo, useState } from 'react'
import './App.css'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
const POLL_INTERVAL_MS = 2000
const TOPOLOGY_HOSTS = [
  { id: 'h1', ip: '10.0.0.1' },
  { id: 'h2', ip: '10.0.0.2' },
  { id: 'h3', ip: '10.0.0.3' },
]
const HOST_NODE_BY_IP = Object.fromEntries(TOPOLOGY_HOSTS.map((host) => [host.ip, host.id]))

const fetchJson = async (path) => {
  const response = await fetch(`${API_BASE_URL}${path}`)
  if (!response.ok) {
    throw new Error(`Request failed: ${response.status}`)
  }
  return response.json()
}

const formatTimestamp = (value) => {
  const date = new Date(value)
  if (Number.isNaN(date.getTime())) {
    return value
  }
  return date.toLocaleString()
}

const isSuspiciousPrediction = (prediction) => (prediction || '').trim().toLowerCase() !== 'normal'

function App() {
  const [flows, setFlows] = useState([])
  const [alerts, setAlerts] = useState([])
  const [stats, setStats] = useState({
    total_flows: 0,
    normal_flows: 0,
    suspicious_flows: 0,
    active_hosts: 0,
    class_distribution: {},
  })
  const [error, setError] = useState('')

  useEffect(() => {
    let mounted = true

    const loadDashboardData = async () => {
      try {
        const [flowData, alertData, statsData] = await Promise.all([
          fetchJson('/flows?limit=100'),
          fetchJson('/alerts?limit=20'),
          fetchJson('/stats'),
        ])
        if (!mounted) {
          return
        }
        setFlows(flowData)
        setAlerts(alertData)
        setStats(statsData)
        setError('')
      } catch (loadError) {
        if (!mounted) {
          return
        }
        setError(loadError instanceof Error ? loadError.message : 'Failed to load dashboard data.')
      }
    }

    loadDashboardData()
    const timer = setInterval(loadDashboardData, POLL_INTERVAL_MS)
    return () => {
      mounted = false
      clearInterval(timer)
    }
  }, [])

  const chartRows = useMemo(() => {
    const entries = Object.entries(stats.class_distribution || {})
    const maxValue = Math.max(1, ...entries.map(([, count]) => count))
    return entries.map(([label, count]) => ({
      label,
      count,
      percent: (count / maxValue) * 100,
    }))
  }, [stats.class_distribution])

  const topologyPairs = useMemo(() => {
    const pairs = new Map()
    for (const flow of flows) {
      const srcNode = HOST_NODE_BY_IP[flow.src_ip]
      const dstNode = HOST_NODE_BY_IP[flow.dst_ip]
      if (!srcNode || !dstNode || srcNode === dstNode) {
        continue
      }

      const pairKey = [srcNode, dstNode].sort().join('|')
      const suspicious = isSuspiciousPrediction(flow.prediction)
      const existing = pairs.get(pairKey)
      if (!existing) {
        pairs.set(pairKey, {
          pairKey,
          srcNode,
          dstNode,
          suspicious,
          prediction: flow.prediction,
        })
        continue
      }

      if (suspicious) {
        existing.suspicious = true
      }
    }

    return Array.from(pairs.values())
  }, [flows])

  const hostStatus = useMemo(() => {
    const statusMap = Object.fromEntries(TOPOLOGY_HOSTS.map((host) => [host.id, 'idle']))
    for (const pair of topologyPairs) {
      const status = pair.suspicious ? 'suspicious' : 'active'
      for (const hostId of [pair.srcNode, pair.dstNode]) {
        if (status === 'suspicious' || statusMap[hostId] === 'idle') {
          statusMap[hostId] = status
        }
      }
    }
    return statusMap
  }, [topologyPairs])

  const hasLiveEvents = flows.length > 0

  return (
    <main className="dashboard">
      <header className="dashboard-header">
        <div>
          <h1>Intelligent SDN IDS Dashboard</h1>
          <p>Backend: {API_BASE_URL}</p>
        </div>
        <span className="polling-tag">Polling every {POLL_INTERVAL_MS / 1000}s</span>
      </header>

      {error && <div className="error-banner">API error: {error}</div>}

      <section className="summary-grid">
        <article className="summary-card">
          <h2>Total Flows</h2>
          <strong>{stats.total_flows}</strong>
        </article>
        <article className="summary-card">
          <h2>Normal Flows</h2>
          <strong>{stats.normal_flows}</strong>
        </article>
        <article className="summary-card">
          <h2>Suspicious Flows</h2>
          <strong>{stats.suspicious_flows}</strong>
        </article>
        <article className="summary-card">
          <h2>Active Hosts</h2>
          <strong>{stats.active_hosts}</strong>
        </article>
      </section>

      <section className="layout-grid">
        <div className="panel">
          <h2>Class Distribution</h2>
          {chartRows.length === 0 ? (
            <p className="empty-message">No live flow events received yet.</p>
          ) : (
            <div className="bar-chart">
              {chartRows.map((item) => (
                <div className="bar-row" key={item.label}>
                  <span className="bar-label">{item.label}</span>
                  <div className="bar-track">
                    <div className="bar-fill" style={{ width: `${item.percent}%` }} />
                  </div>
                  <span className="bar-value">{item.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="panel">
          <h2>Alerts (Non-Normal)</h2>
          {alerts.length === 0 ? (
            <p className="empty-message">
              {hasLiveEvents ? 'No suspicious flows detected.' : 'No live flow events received yet.'}
            </p>
          ) : (
            <ul className="alerts-list">
              {alerts.map((alert, index) => (
                <li key={`${alert.timestamp}-${alert.src_ip}-${index}`}>
                  <strong>{alert.prediction}</strong>{' '}
                  <span>
                    {alert.src_ip}:{alert.src_port} → {alert.dst_ip}:{alert.dst_port}
                  </span>
                  <small>conf={alert.confidence.toFixed(3)}</small>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <section className="panel">
        <h2>Topology (Mininet single,3)</h2>
        <div className="topology-layout">
          <div className="topology-row">
            <div className="topology-node topology-switch">s1</div>
          </div>
          <div className="topology-link-row">
            {TOPOLOGY_HOSTS.map((host) => {
              const status = hostStatus[host.id]
              return (
                <div className={`topology-link ${status}`} key={`link-${host.id}`}>
                  {status === 'suspicious' ? 'suspicious' : status === 'active' ? 'active' : 'idle'}
                </div>
              )
            })}
          </div>
          <div className="topology-row topology-host-row">
            {TOPOLOGY_HOSTS.map((host) => (
              <div className={`topology-node topology-host ${hostStatus[host.id]}`} key={host.id}>
                <strong>{host.id}</strong>
                <small>{host.ip}</small>
              </div>
            ))}
          </div>
        </div>

        <h3 className="topology-subtitle">Active communication pairs</h3>
        {topologyPairs.length === 0 ? (
          <p className="empty-message">No live flow events received yet.</p>
        ) : (
          <ul className="topology-pairs">
            {topologyPairs.map((pair) => (
              <li key={pair.pairKey} className={pair.suspicious ? 'suspicious' : 'normal'}>
                <span>
                  {pair.srcNode} ↔ {pair.dstNode}
                </span>
                <small>{pair.suspicious ? 'Suspicious activity' : pair.prediction}</small>
              </li>
            ))}
          </ul>
        )}
      </section>

      <section className="panel">
        <h2>Live Flows</h2>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Source</th>
                <th>Destination</th>
                <th>Protocol</th>
                <th>Prediction</th>
                <th>Confidence</th>
              </tr>
            </thead>
            <tbody>
              {flows.map((flow, index) => (
                <tr key={`${flow.timestamp}-${flow.src_ip}-${flow.dst_ip}-${index}`}>
                  <td>{formatTimestamp(flow.timestamp)}</td>
                  <td>
                    {flow.src_ip}:{flow.src_port}
                  </td>
                  <td>
                    {flow.dst_ip}:{flow.dst_port}
                  </td>
                  <td>{flow.protocol}</td>
                  <td>
                    <span className={flow.prediction === 'Normal' ? 'tag-normal' : 'tag-alert'}>
                      {flow.prediction}
                    </span>
                  </td>
                  <td>{flow.confidence.toFixed(3)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {flows.length === 0 && <p className="empty-message">No live flow events received yet.</p>}
        </div>
      </section>
    </main>
  )
}

export default App
