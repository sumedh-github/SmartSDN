import { useEffect, useMemo, useState } from 'react'
import './App.css'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
const POLL_INTERVAL_MS = 2000

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
            <p className="empty-message">No data yet.</p>
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
            <p className="empty-message">No suspicious flows detected.</p>
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
          {flows.length === 0 && <p className="empty-message">No flow records available.</p>}
        </div>
      </section>
    </main>
  )
}

export default App
