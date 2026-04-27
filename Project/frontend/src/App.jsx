import { useCallback, useEffect, useMemo, useState } from 'react'
import './App.css'
import LoginGate from './LoginGate'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
const POLL_INTERVAL_MS = 2000

const MODE_META = {
  REAL_ML: { label: 'REAL ML MODE', description: 'Only live FT-Transformer controller inference is used.' },
  DEMO_SCENARIO: {
    label: 'DEMO / SCENARIO MODE',
    description: 'Controlled scenario logic is enabled for reliable demonstrations.',
  },
}

const SOURCE_LABEL = {
  ml: 'ML',
  demo: 'Demo',
  hybrid: 'Hybrid',
}

const MITIGATION_ACTIONS = [
  { value: 'block_flow', label: 'Block Flow' },
  { value: 'block_source', label: 'Block Source' },
  { value: 'isolate_port', label: 'Disable / Isolate Port' },
]

const fetchJson = async (path, options = {}) => {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  })
  if (!response.ok) {
    let detail = `Request failed: ${response.status}`
    try {
      const body = await response.json()
      if (body?.detail) {
        detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
      }
    } catch {
      // Keep default error message.
    }
    throw new Error(detail)
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

const nodeDisplay = (node) => {
  if (!node) {
    return ''
  }
  if (node.kind === 'host') {
    return node.metadata?.ip || node.label
  }
  return node.label
}

const labelSourceClass = (source) => {
  if (source === 'demo') {
    return 'source-pill source-demo'
  }
  if (source === 'hybrid') {
    return 'source-pill source-hybrid'
  }
  return 'source-pill source-ml'
}

function SocDashboard({ currentUser, onLogout }) {
  const [health, setHealth] = useState({
    status: 'ok',
    components: {
      backend: 'unknown',
      controller: 'unknown',
      topology: 'unknown',
      live_event_stream: 'idle',
      mode: 'REAL_ML',
      mitigation_automatic_enabled: false,
    },
  })
  const [modeStatus, setModeStatus] = useState({ mode: 'REAL_ML', description: MODE_META.REAL_ML.description })
  const [controllerStatus, setControllerStatus] = useState({
    running: false,
    polling_active: false,
    model_loaded: false,
    mode: 'REAL_ML',
    datapath_count: 0,
    stale: true,
  })
  const [flows, setFlows] = useState([])
  const [alerts, setAlerts] = useState([])
  const [sessions, setSessions] = useState([])
  const [topology, setTopology] = useState({
    generated_at: null,
    nodes: [],
    links: [],
    traffic_edges: [],
  })
  const [scenarios, setScenarios] = useState([])
  const [mitigationEvents, setMitigationEvents] = useState([])
  const [mitigationConfig, setMitigationConfig] = useState({
    enabled: false,
    suspicious_labels: ['DoS_DDoS', 'Other_Attack', 'Congestion'],
    min_confidence: 0.75,
    default_timeout_sec: 300,
    action_order: ['block_flow', 'block_source', 'isolate_port'],
  })
  const [mitigationDraft, setMitigationDraft] = useState({
    enabled: false,
    min_confidence: 0.75,
    default_timeout_sec: 300,
    primary_action: 'block_flow',
  })
  const [stats, setStats] = useState({
    total_flows: 0,
    normal_flows: 0,
    suspicious_flows: 0,
    active_hosts: 0,
    class_distribution: {},
    by_source: {},
    mitigated_flows: 0,
  })
  const [scenarioRepeat, setScenarioRepeat] = useState(3)
  const [manualAction, setManualAction] = useState({
    action: 'block_source',
    src_ip: '',
    flow_key: '',
    switch_id: '',
    port_id: '',
    reason: '',
    timeout_sec: 300,
  })
  const [actionBusy, setActionBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [actionMessage, setActionMessage] = useState('')
  const [error, setError] = useState('')

  const loadDashboardData = useCallback(async () => {
    const [
      healthData,
      modeData,
      controllerData,
      flowData,
      alertData,
      sessionData,
      topologyData,
      statsData,
      scenarioData,
      mitigationConfigData,
      mitigationEventData,
    ] = await Promise.all([
      fetchJson('/health'),
      fetchJson('/mode'),
      fetchJson('/controller/status'),
      fetchJson('/flows?limit=250'),
      fetchJson('/alerts?limit=100'),
      fetchJson('/sessions?limit=120'),
      fetchJson('/topology'),
      fetchJson('/stats'),
      fetchJson('/scenarios'),
      fetchJson('/mitigation/config'),
      fetchJson('/mitigation/events?limit=120'),
    ])
    setHealth(healthData)
    setModeStatus(modeData)
    setControllerStatus(controllerData)
    setFlows(flowData)
    setAlerts(alertData)
    setSessions(sessionData)
    setTopology(topologyData)
    setStats(statsData)
    setScenarios(scenarioData)
    setMitigationConfig(mitigationConfigData)
    setMitigationEvents(mitigationEventData)
    setMitigationDraft((previous) => ({
      ...previous,
      enabled: mitigationConfigData.enabled,
      min_confidence: mitigationConfigData.min_confidence,
      default_timeout_sec: mitigationConfigData.default_timeout_sec,
      primary_action: mitigationConfigData.action_order?.[0] || 'block_flow',
    }))
    setError('')
  }, [])

  useEffect(() => {
    let active = true
    const poll = async () => {
      try {
        await loadDashboardData()
      } catch (loadError) {
        if (!active) {
          return
        }
        setError(loadError instanceof Error ? loadError.message : 'Failed to load dashboard data.')
      } finally {
        if (active) {
          setLoading(false)
        }
      }
    }

    poll()
    const timer = setInterval(poll, POLL_INTERVAL_MS)
    return () => {
      active = false
      clearInterval(timer)
    }
  }, [loadDashboardData])

  const chartRows = useMemo(() => {
    const entries = Object.entries(stats.class_distribution || {})
    const maxValue = Math.max(1, ...entries.map(([, count]) => count))
    return entries.map(([label, count]) => ({
      label,
      count,
      percent: (count / maxValue) * 100,
    }))
  }, [stats.class_distribution])

  const graphLayout = useMemo(() => {
    const width = 1100
    const controllers = topology.nodes.filter((node) => node.kind === 'controller')
    const switches = topology.nodes.filter((node) => node.kind === 'switch')
    const hosts = topology.nodes.filter((node) => node.kind === 'host')
    const positions = {}

    controllers.forEach((node, index) => {
      const total = controllers.length || 1
      positions[node.id] = {
        x: ((index + 1) / (total + 1)) * width,
        y: 70,
      }
    })
    switches.forEach((node, index) => {
      const total = switches.length || 1
      positions[node.id] = {
        x: ((index + 1) / (total + 1)) * width,
        y: 230,
      }
    })
    const perRow = 6
    hosts.forEach((node, index) => {
      const row = Math.floor(index / perRow)
      const rowStart = row * perRow
      const rowCount = Math.min(perRow, hosts.length - rowStart)
      const col = index % perRow
      positions[node.id] = {
        x: ((col + 1) / (rowCount + 1)) * width,
        y: 390 + row * 110,
      }
    })
    const rows = Math.max(1, Math.ceil(hosts.length / perRow))
    return {
      width,
      height: 460 + rows * 110,
      positions,
    }
  }, [topology.nodes])

  const healthCards = useMemo(
    () => [
      { label: 'Backend', value: health.components?.backend || 'unknown' },
      { label: 'Frontend', value: 'ok' },
      { label: 'Controller', value: health.components?.controller || 'unknown' },
      { label: 'Topology', value: health.components?.topology || 'unknown' },
      { label: 'Live Stream', value: health.components?.live_event_stream || 'idle' },
      { label: 'Mode', value: modeStatus.mode },
      { label: 'Auto Mitigation', value: mitigationConfig.enabled ? 'enabled' : 'disabled' },
    ],
    [health.components, mitigationConfig.enabled, modeStatus.mode],
  )

  const modeMeta = MODE_META[modeStatus.mode] || MODE_META.REAL_ML

  const hasLiveEvents = flows.length > 0

  const runManualMitigation = async (payload) => {
    setActionBusy(true)
    setActionMessage('')
    try {
      await fetchJson('/mitigate', {
        method: 'POST',
        body: JSON.stringify(payload),
      })
      setActionMessage(`Mitigation accepted: ${payload.action}`)
      await loadDashboardData()
    } catch (requestError) {
      setActionMessage(requestError instanceof Error ? requestError.message : 'Mitigation request failed.')
    } finally {
      setActionBusy(false)
    }
  }

  const applyActionToFlow = async (flow, action) => {
    const payload = {
      action,
      flow_key: flow.flow_key,
      src_ip: flow.src_ip,
      dst_ip: flow.dst_ip,
      switch_id: flow.switch_id || null,
      reason: `Manual action from dashboard alert for ${flow.prediction}`,
      timeout_sec: mitigationDraft.default_timeout_sec,
      triggered_by: 'manual',
    }
    await runManualMitigation(payload)
  }

  const applyActionToSession = async (session, action) => {
    const latest = flows.find((flow) => {
      if (flow.protocol !== session.protocol) {
        return false
      }
      const pairA = [flow.src_ip, flow.dst_ip].sort().join('|')
      const pairB = [...session.endpoints].sort().join('|')
      return pairA === pairB
    })
    const payload = {
      action,
      flow_key: action === 'block_flow' ? latest?.flow_key || null : null,
      src_ip: latest?.src_ip || session.endpoints[0] || null,
      dst_ip: latest?.dst_ip || session.endpoints[1] || null,
      switch_id: latest?.switch_id || null,
      reason: `Manual session action for ${session.dominant_label}`,
      timeout_sec: mitigationDraft.default_timeout_sec,
      triggered_by: 'manual',
    }
    await runManualMitigation(payload)
  }

  const handleModeSwitch = async (mode) => {
    setActionBusy(true)
    setActionMessage('')
    try {
      const response = await fetchJson('/mode', {
        method: 'PUT',
        body: JSON.stringify({ mode }),
      })
      setModeStatus(response)
      setActionMessage(`${MODE_META[mode].label} enabled.`)
      await loadDashboardData()
    } catch (switchError) {
      setActionMessage(switchError instanceof Error ? switchError.message : 'Mode switch failed.')
    } finally {
      setActionBusy(false)
    }
  }

  const runScenario = async (scenario) => {
    setActionBusy(true)
    setActionMessage('')
    try {
      const response = await fetchJson('/scenarios/run', {
        method: 'POST',
        body: JSON.stringify({ scenario, repeat: scenarioRepeat }),
      })
      setActionMessage(`${response.generated_events} demo events generated for ${scenario}.`)
      await loadDashboardData()
    } catch (scenarioError) {
      setActionMessage(scenarioError instanceof Error ? scenarioError.message : 'Scenario run failed.')
    } finally {
      setActionBusy(false)
    }
  }

  const clearScenarioEvents = async () => {
    setActionBusy(true)
    setActionMessage('')
    try {
      const response = await fetchJson('/scenarios/clear', { method: 'POST' })
      setActionMessage(`Cleared ${response.generated_events} demo/scenario events.`)
      await loadDashboardData()
    } catch (clearError) {
      setActionMessage(clearError instanceof Error ? clearError.message : 'Clear demo state failed.')
    } finally {
      setActionBusy(false)
    }
  }

  const saveMitigationConfig = async () => {
    const primary = mitigationDraft.primary_action
    const order = [primary, ...MITIGATION_ACTIONS.map((item) => item.value).filter((value) => value !== primary)]
    setActionBusy(true)
    setActionMessage('')
    try {
      await fetchJson('/mitigation/config', {
        method: 'PUT',
        body: JSON.stringify({
          enabled: mitigationDraft.enabled,
          min_confidence: mitigationDraft.min_confidence,
          default_timeout_sec: mitigationDraft.default_timeout_sec,
          action_order: order,
        }),
      })
      setActionMessage('Automatic mitigation configuration saved.')
      await loadDashboardData()
    } catch (configError) {
      setActionMessage(configError instanceof Error ? configError.message : 'Failed to save mitigation config.')
    } finally {
      setActionBusy(false)
    }
  }

  const submitManualMitigationFromPanel = async (event) => {
    event.preventDefault()
    const payload = {
      action: manualAction.action,
      src_ip: manualAction.src_ip || null,
      flow_key: manualAction.flow_key || null,
      switch_id: manualAction.switch_id || null,
      port_id: manualAction.port_id ? Number(manualAction.port_id) : null,
      reason: manualAction.reason || 'Manual mitigation request from mitigation panel.',
      timeout_sec: Number(manualAction.timeout_sec) || mitigationDraft.default_timeout_sec,
      triggered_by: 'manual',
    }
    await runManualMitigation(payload)
  }

  if (loading) {
    return (
      <main className="soc-shell">
        <section className="panel loading-panel">
          <h1>Intelligent SDN SOC Platform</h1>
          <p>Connecting to backend and loading live controller state...</p>
        </section>
      </main>
    )
  }

  return (
    <main className="soc-shell">
      <header className="soc-header">
        <div>
          <h1>SDN Cyber/SOC Security Platform</h1>
          <p className="muted">
            Live stream from backend {API_BASE_URL} | Polling every {POLL_INTERVAL_MS / 1000}s
          </p>
        </div>
        <div className="header-actions">
          <span className="user-pill">{currentUser}</span>
          <button className="btn ghost" onClick={onLogout} type="button">
            Sign out
          </button>
        </div>
      </header>

      <section className={`mode-banner ${modeStatus.mode === 'REAL_ML' ? 'real' : 'demo'}`}>
        <div>
          <strong>{modeMeta.label}</strong>
          <p>{modeStatus.description || modeMeta.description}</p>
        </div>
        <div className="mode-buttons">
          <button
            type="button"
            className={`btn ${modeStatus.mode === 'REAL_ML' ? 'primary' : 'ghost'}`}
            disabled={actionBusy}
            onClick={() => handleModeSwitch('REAL_ML')}
          >
            REAL ML MODE
          </button>
          <button
            type="button"
            className={`btn ${modeStatus.mode === 'DEMO_SCENARIO' ? 'warning' : 'ghost'}`}
            disabled={actionBusy}
            onClick={() => handleModeSwitch('DEMO_SCENARIO')}
          >
            DEMO / SCENARIO MODE
          </button>
        </div>
      </section>

      {error && <div className="error-banner">API error: {error}</div>}
      {actionMessage && <div className="action-banner">{actionMessage}</div>}

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
        <article className="summary-card">
          <h2>Mitigated Flows</h2>
          <strong>{stats.mitigated_flows}</strong>
        </article>
      </section>

      <section className="panel">
        <div className="panel-title-row">
          <h2>System Health & Controller Visibility</h2>
          <span className="muted">Frontend status is local UI runtime.</span>
        </div>
        <div className="health-grid">
          {healthCards.map((item) => (
            <div key={item.label} className="health-card">
              <span>{item.label}</span>
              <strong className={`status-tag ${String(item.value).toLowerCase()}`}>{item.value}</strong>
            </div>
          ))}
        </div>
        <div className="controller-meta">
          <span>Controller running: {controllerStatus.running ? 'Yes' : 'No'}</span>
          <span>Polling active: {controllerStatus.polling_active ? 'Yes' : 'No'}</span>
          <span>Model loaded: {controllerStatus.model_loaded ? 'Yes' : 'No'}</span>
          <span>Datapaths connected: {controllerStatus.datapath_count}</span>
          <span>Controller state freshness: {controllerStatus.stale ? 'stale' : 'live'}</span>
        </div>
      </section>

      <section className="panel topology-panel">
        <div className="panel-title-row">
          <h2>Dynamic SDN Topology (Backend/Controller Driven)</h2>
          <span className="muted">
            Generated at {topology.generated_at ? formatTimestamp(topology.generated_at) : 'n/a'}
          </span>
        </div>
        {topology.nodes.length === 0 ? (
          <p className="empty-message">No topology nodes available yet. Waiting for live events.</p>
        ) : (
          <div className="graph-wrap">
            <svg viewBox={`0 0 ${graphLayout.width} ${graphLayout.height}`} role="img" aria-label="Topology graph">
              {topology.links.map((link) => {
                const source = graphLayout.positions[link.source]
                const target = graphLayout.positions[link.target]
                if (!source || !target) {
                  return null
                }
                return (
                  <line
                    key={link.id}
                    x1={source.x}
                    y1={source.y}
                    x2={target.x}
                    y2={target.y}
                    className={`link-line ${link.state}`}
                  />
                )
              })}
              {topology.traffic_edges.map((edge) => {
                const source = graphLayout.positions[edge.source]
                const target = graphLayout.positions[edge.target]
                if (!source || !target) {
                  return null
                }
                return (
                  <line
                    key={edge.id}
                    x1={source.x}
                    y1={source.y}
                    x2={target.x}
                    y2={target.y}
                    className={`traffic-line ${edge.state}`}
                  />
                )
              })}
              {topology.nodes.map((node) => {
                const position = graphLayout.positions[node.id]
                if (!position) {
                  return null
                }
                return (
                  <g key={node.id}>
                    <circle
                      cx={position.x}
                      cy={position.y}
                      r={node.kind === 'controller' ? 38 : node.kind === 'switch' ? 32 : 28}
                      className={`node-circle ${node.kind} ${node.status}`}
                    />
                    <text x={position.x} y={position.y - 4} textAnchor="middle" className="node-title">
                      {nodeDisplay(node)}
                    </text>
                    <text x={position.x} y={position.y + 12} textAnchor="middle" className="node-subtitle">
                      {node.kind}
                    </text>
                  </g>
                )
              })}
            </svg>
          </div>
        )}
        {topology.traffic_edges.length > 0 && (
          <div className="traffic-legend">
            <span className="legend-item normal">Normal traffic</span>
            <span className="legend-item suspicious">Suspicious traffic</span>
            <span className="legend-item blocked">Mitigated / Blocked</span>
          </div>
        )}
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
          <h2>Alerts (Suspicious Live Flows)</h2>
          {alerts.length === 0 ? (
            <p className="empty-message">
              {hasLiveEvents ? 'No suspicious flows detected.' : 'No live flow events received yet.'}
            </p>
          ) : (
            <ul className="alerts-list">
              {alerts.map((alert, index) => (
                <li key={`${alert.timestamp}-${alert.src_ip}-${index}`}>
                  <div className="alert-header">
                    <strong>{alert.prediction}</strong>
                    <span className={labelSourceClass(alert.classification_source)}>
                      {SOURCE_LABEL[alert.classification_source] || 'ML'}
                    </span>
                  </div>
                  <span>
                    {alert.src_ip}:{alert.src_port} → {alert.dst_ip}:{alert.dst_port}
                  </span>
                  <small>
                    conf={alert.confidence.toFixed(3)} | mitigation={alert.mitigation_state || 'none'}
                  </small>
                  <div className="inline-actions">
                    <button
                      className="btn tiny danger"
                      type="button"
                      disabled={actionBusy || !alert.flow_key}
                      onClick={() => applyActionToFlow(alert, 'block_flow')}
                    >
                      Block Flow
                    </button>
                    <button
                      className="btn tiny danger"
                      type="button"
                      disabled={actionBusy}
                      onClick={() => applyActionToFlow(alert, 'block_source')}
                    >
                      Block Source
                    </button>
                    <button
                      className="btn tiny"
                      type="button"
                      disabled={actionBusy}
                      onClick={() => applyActionToFlow(alert, 'isolate_port')}
                    >
                      Disable / Isolate Port
                    </button>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>

      <section className="layout-grid">
        <div className="panel">
          <div className="panel-title-row">
            <h2>Scenario Runner (Demo Reliability)</h2>
            <span className="muted">Available only in DEMO / SCENARIO MODE.</span>
          </div>
          <div className="scenario-controls">
            <label>
              Repeat:
              <input
                type="number"
                min={1}
                max={50}
                value={scenarioRepeat}
                onChange={(event) => setScenarioRepeat(Number(event.target.value) || 1)}
              />
            </label>
            <button className="btn ghost" type="button" disabled={actionBusy} onClick={clearScenarioEvents}>
              Clear / Reset Demo State
            </button>
          </div>
          <div className="scenario-grid">
            {scenarios.map((scenario) => (
              <article key={scenario.code} className="scenario-card">
                <h3>{scenario.name}</h3>
                <p>{scenario.description}</p>
                <p>
                  Label source: <span className={labelSourceClass(scenario.default_label_source)}>{scenario.default_label_source}</span>
                </p>
                <button
                  className="btn primary"
                  type="button"
                  disabled={actionBusy || modeStatus.mode !== 'DEMO_SCENARIO'}
                  onClick={() => runScenario(scenario.code)}
                >
                  Run Scenario
                </button>
              </article>
            ))}
          </div>
          {modeStatus.mode !== 'DEMO_SCENARIO' && (
            <p className="empty-message">Switch to DEMO / SCENARIO MODE to run controlled scenarios.</p>
          )}
        </div>

        <div className="panel">
          <h2>Mitigation Controls</h2>
          <div className="mitigation-config">
            <label>
              <span>Automatic mitigation enabled</span>
              <input
                type="checkbox"
                checked={mitigationDraft.enabled}
                onChange={(event) =>
                  setMitigationDraft((previous) => ({ ...previous, enabled: event.target.checked }))
                }
              />
            </label>
            <label>
              <span>Min confidence</span>
              <input
                type="number"
                min={0}
                max={1}
                step={0.01}
                value={mitigationDraft.min_confidence}
                onChange={(event) =>
                  setMitigationDraft((previous) => ({
                    ...previous,
                    min_confidence: Number(event.target.value),
                  }))
                }
              />
            </label>
            <label>
              <span>Default timeout (sec)</span>
              <input
                type="number"
                min={0}
                max={86400}
                value={mitigationDraft.default_timeout_sec}
                onChange={(event) =>
                  setMitigationDraft((previous) => ({
                    ...previous,
                    default_timeout_sec: Number(event.target.value),
                  }))
                }
              />
            </label>
            <label>
              <span>Primary auto action</span>
              <select
                value={mitigationDraft.primary_action}
                onChange={(event) =>
                  setMitigationDraft((previous) => ({ ...previous, primary_action: event.target.value }))
                }
              >
                {MITIGATION_ACTIONS.map((action) => (
                  <option key={action.value} value={action.value}>
                    {action.label}
                  </option>
                ))}
              </select>
            </label>
            <button className="btn primary" type="button" disabled={actionBusy} onClick={saveMitigationConfig}>
              Save Auto Mitigation Config
            </button>
          </div>

          <form className="manual-mitigation-form" onSubmit={submitManualMitigationFromPanel}>
            <h3>Manual Mitigation Panel</h3>
            <select
              value={manualAction.action}
              onChange={(event) => setManualAction((previous) => ({ ...previous, action: event.target.value }))}
            >
              {MITIGATION_ACTIONS.map((action) => (
                <option key={action.value} value={action.value}>
                  {action.label}
                </option>
              ))}
            </select>
            <input
              placeholder="Source IP (optional)"
              value={manualAction.src_ip}
              onChange={(event) => setManualAction((previous) => ({ ...previous, src_ip: event.target.value }))}
            />
            <input
              placeholder="Flow key (optional)"
              value={manualAction.flow_key}
              onChange={(event) => setManualAction((previous) => ({ ...previous, flow_key: event.target.value }))}
            />
            <input
              placeholder="Switch ID (optional)"
              value={manualAction.switch_id}
              onChange={(event) =>
                setManualAction((previous) => ({ ...previous, switch_id: event.target.value }))
              }
            />
            <input
              placeholder="Port (optional)"
              type="number"
              min={0}
              value={manualAction.port_id}
              onChange={(event) => setManualAction((previous) => ({ ...previous, port_id: event.target.value }))}
            />
            <input
              placeholder="Reason"
              value={manualAction.reason}
              onChange={(event) => setManualAction((previous) => ({ ...previous, reason: event.target.value }))}
            />
            <button className="btn danger" type="submit" disabled={actionBusy}>
              Submit Manual Mitigation
            </button>
          </form>
        </div>
      </section>

      <section className="layout-grid">
        <div className="panel">
          <h2>Grouped Sessions / Conversations</h2>
          {sessions.length === 0 ? (
            <p className="empty-message">No live sessions available yet.</p>
          ) : (
            <div className="session-grid">
              {sessions.map((session) => (
                <article key={session.session_id} className={`session-card ${session.suspicious ? 'suspicious' : 'normal'}`}>
                  <div className="session-top">
                    <strong>{session.endpoints.join(' ↔ ')}</strong>
                    <span className={labelSourceClass(session.dominant_label_source)}>
                      {SOURCE_LABEL[session.dominant_label_source] || 'ML'}
                    </span>
                  </div>
                  <p>
                    <span className={session.suspicious ? 'tag-alert' : 'tag-normal'}>{session.dominant_label}</span>
                    {'  '}protocol={session.protocol}
                  </p>
                  <p className="muted">
                    flows={session.flow_count} | confidence avg={session.confidence_avg.toFixed(3)} max=
                    {session.confidence_max.toFixed(3)}
                  </p>
                  <p className="muted">
                    mitigation={session.mitigation_state} | packets={session.total_packets} | bytes={session.total_bytes}
                  </p>
                  <div className="inline-actions">
                    <button
                      className="btn tiny danger"
                      type="button"
                      disabled={actionBusy}
                      onClick={() => applyActionToSession(session, 'block_flow')}
                    >
                      Block Flow
                    </button>
                    <button
                      className="btn tiny danger"
                      type="button"
                      disabled={actionBusy}
                      onClick={() => applyActionToSession(session, 'block_source')}
                    >
                      Block Source
                    </button>
                    <button
                      className="btn tiny"
                      type="button"
                      disabled={actionBusy}
                      onClick={() => applyActionToSession(session, 'isolate_port')}
                    >
                      Disable / Isolate Port
                    </button>
                  </div>
                </article>
              ))}
            </div>
          )}
        </div>

        <div className="panel">
          <h2>Mitigation Event Log (Live Memory)</h2>
          {mitigationEvents.length === 0 ? (
            <p className="empty-message">No mitigation events logged yet.</p>
          ) : (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Action</th>
                    <th>Triggered By</th>
                    <th>Reason</th>
                    <th>Target</th>
                    <th>Source</th>
                    <th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {mitigationEvents.map((event) => (
                    <tr key={event.mitigation_id}>
                      <td>{formatTimestamp(event.timestamp)}</td>
                      <td>{event.action}</td>
                      <td>{event.triggered_by}</td>
                      <td>{event.reason}</td>
                      <td>{event.flow_key || event.src_ip || event.switch_id || 'n/a'}</td>
                      <td>{event.source_label_origin || 'manual'}</td>
                      <td>{event.status}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      <section className="panel">
        <h2>Raw Directional Flows (Live)</h2>
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
                <th>Label Source</th>
                <th>Mode</th>
                <th>Mitigation</th>
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
                  <td>
                    <span className={labelSourceClass(flow.classification_source)}>
                      {SOURCE_LABEL[flow.classification_source] || 'ML'}
                    </span>
                  </td>
                  <td>{flow.mode}</td>
                  <td>{flow.mitigation_state || 'none'}</td>
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

function App() {
  const [session, setSession] = useState({
    loggedIn: false,
    user: '',
  })

  if (!session.loggedIn) {
    return (
      <LoginGate
        onSuccess={(identity) => {
          setSession({
            loggedIn: true,
            user: identity,
          })
        }}
      />
    )
  }

  return (
    <SocDashboard
      currentUser={session.user}
      onLogout={() =>
        setSession({
          loggedIn: false,
          user: '',
        })
      }
    />
  )
}

export default App
