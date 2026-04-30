import { useCallback, useEffect, useMemo, useState } from 'react'
import { NavLink, Navigate, Route, Routes, useNavigate } from 'react-router-dom'
import './App.css'
import LoginGate from './LoginGate'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
const POLL_INTERVAL_MS = 2000
const AUTH_STORAGE_KEY = 'soc.auth.session'

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
  { value: 'block_flow', label: 'Block Flow Pair' },
  { value: 'block_source', label: 'Block Source Host' },
  { value: 'isolate_port', label: 'Disable / Isolate Port' },
]

const MANUAL_PROTOCOL_OPTIONS = ['ALL', 'TCP', 'UDP', 'ICMP']

const NAV_ITEMS = [
  { to: '/dashboard/overview', label: 'Overview Dashboard' },
  { to: '/dashboard/topology', label: 'Topology' },
  { to: '/dashboard/raw-flows', label: 'Raw Flows' },
  { to: '/dashboard/sessions', label: 'Sessions' },
  { to: '/dashboard/alerts', label: 'Alerts' },
  { to: '/dashboard/scenarios', label: 'Scenarios' },
  { to: '/dashboard/mitigation', label: 'Mitigation' },
  { to: '/dashboard/health', label: 'System / Controller Health' },
]

class ApiError extends Error {
  constructor(message, status) {
    super(message)
    this.status = status
  }
}

const readStoredSession = () => {
  try {
    const raw = window.localStorage.getItem(AUTH_STORAGE_KEY)
    if (!raw) {
      return null
    }
    const parsed = JSON.parse(raw)
    if (!parsed?.token || !parsed?.user) {
      return null
    }
    return parsed
  } catch {
    return null
  }
}

const writeStoredSession = (session) => {
  window.localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify(session))
}

const clearStoredSession = () => {
  window.localStorage.removeItem(AUTH_STORAGE_KEY)
}

const parseApiError = async (response) => {
  let detail = `Request failed: ${response.status}`
  try {
    const body = await response.json()
    if (body?.detail) {
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail)
    } else if (body?.message) {
      detail = String(body.message)
    }
  } catch {
    // Keep default message.
  }
  return new ApiError(detail, response.status)
}

const requestJson = async (path, { token, method = 'GET', body } = {}) => {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  })
  if (!response.ok) {
    throw await parseApiError(response)
  }
  if (response.status === 204) {
    return null
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

const statusClass = (value) => String(value || '').toLowerCase().replace(/\s+/g, '_')

const alertItemKey = (alert) =>
  [
    alert.event_id || 'event',
    alert.flow_key || 'flow',
    alert.timestamp || 'time',
    alert.src_ip || 'src',
    alert.src_port ?? 'sp',
    alert.dst_ip || 'dst',
    alert.dst_port ?? 'dp',
    alert.protocol || 'proto',
  ].join('|')

const mitigationPreview = (payload) => {
  if (payload.action === 'block_flow') {
    return [
      'Action: Block Flow Pair',
      `Source IP: ${payload.src_ip || 'n/a'}`,
      `Destination IP: ${payload.dst_ip || 'n/a'}`,
      `Protocol: ${payload.protocol || 'ALL'}`,
    ].join('\n')
  }
  if (payload.action === 'block_source') {
    return [
      'Action: Block Source Host',
      `Source IP: ${payload.src_ip || 'n/a'}`,
      `Protocol scope: ${payload.protocol || 'ALL (TCP/UDP/ICMP)'}`,
      'Scope: all IPv4 traffic from source host (ARP not blocked)',
    ].join('\n')
  }
  return [
    'Action: Disable / Isolate Port (Switch Isolation)',
    `Switch: ${payload.switch_id || 's1'}`,
    'Scope: all data ports on selected switch',
  ].join('\n')
}

function ProtectedRoute({ authenticated, children }) {
  if (!authenticated) {
    return <Navigate to="/login" replace />
  }
  return children
}

function OverviewSection({ stats, chartRows }) {
  return (
    <section className="section-stack">
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
      </section>
    </section>
  )
}

function TopologySection({ topology, graphLayout }) {
  return (
    <section className="panel topology-panel">
      <div className="panel-title-row">
        <h2>Network Map</h2>
        <span className="muted">Generated at {topology.generated_at ? formatTimestamp(topology.generated_at) : 'n/a'}</span>
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
      <div className="traffic-legend">
        <span className="legend-item normal">Normal traffic</span>
        <span className="legend-item suspicious">Suspicious traffic</span>
        <span className="legend-item blocked">Mitigated / Blocked traffic</span>
        <span className="legend-item disabled">Disabled link/port</span>
        <span className="legend-item controller">Controller node</span>
        <span className="legend-item switch">Switch node</span>
        <span className="legend-item host">Host node</span>
      </div>
    </section>
  )
}

function RawFlowsSection({ flows }) {
  return (
    <section className="panel">
      <h2>Raw Directional Flows (Technical Detail)</h2>
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
                  <span className={flow.prediction === 'Normal' ? 'tag-normal' : 'tag-alert'}>{flow.prediction}</span>
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
  )
}

function SessionsSection({ sessions, onAction, actionBusy }) {
  return (
    <section className="panel">
      <h2>Grouped Sessions / Conversations (Primary Operator View)</h2>
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
                <span className={session.suspicious ? 'tag-alert' : 'tag-normal'}>{session.dominant_label}</span>{' '}
                protocol={session.protocol}
              </p>
              <p className="muted">
                flows={session.flow_count} | confidence avg={session.confidence_avg.toFixed(3)} max=
                {session.confidence_max.toFixed(3)}
              </p>
              <p className="muted">
                traffic={session.source_entity} → {session.destination_entity} | mitigation={session.mitigation_state}
              </p>
              <div className="inline-actions">
                <button
                  className="btn tiny danger"
                  type="button"
                  disabled={actionBusy}
                  onClick={() => onAction(session, 'block_flow')}
                >
                  Block Flow Pair
                </button>
                <button
                  className="btn tiny danger"
                  type="button"
                  disabled={actionBusy}
                  onClick={() => onAction(session, 'block_source')}
                >
                  Block Source Host
                </button>
                <button
                  className="btn tiny"
                  type="button"
                  disabled={actionBusy}
                  onClick={() => onAction(session, 'isolate_port')}
                >
                  Disable / Isolate Port
                </button>
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  )
}

function AlertsSection({ alerts, hasLiveEvents, onAction, actionBusy }) {
  return (
    <section className="panel">
      <h2>Alerts (Suspicious Live Flows)</h2>
      {alerts.length === 0 ? (
        <p className="empty-message">
          {hasLiveEvents ? 'No suspicious flows detected.' : 'No live flow events received yet.'}
        </p>
      ) : (
        <ul className="alerts-list">
          {alerts.map((alert) => (
            <li key={alertItemKey(alert)}>
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
                protocol={alert.protocol} | conf={alert.confidence.toFixed(3)} | mitigation={alert.mitigation_state || 'none'}
              </small>
              <div className="inline-actions">
                <button
                  className="btn tiny danger"
                  type="button"
                  disabled={actionBusy}
                  onClick={() => onAction(alert, 'block_flow')}
                >
                  Block Flow Pair
                </button>
                <button
                  className="btn tiny danger"
                  type="button"
                  disabled={actionBusy}
                  onClick={() => onAction(alert, 'block_source')}
                >
                  Block Source Host
                </button>
                <button
                  className="btn tiny"
                  type="button"
                  disabled={actionBusy}
                  onClick={() => onAction(alert, 'isolate_port')}
                >
                  Disable / Isolate Port
                </button>
                <button
                  className="btn tiny ghost"
                  type="button"
                  disabled={actionBusy}
                  onClick={() => onAction(alert, 'mark_normal')}
                >
                  Mark as Normal (False Positive)
                </button>
                <button
                  className="btn tiny ghost"
                  type="button"
                  disabled={actionBusy}
                  onClick={() => onAction(alert, 'mark_mitigated')}
                >
                  Flow Mitigated
                </button>
              </div>
            </li>
          ))}
        </ul>
      )}
    </section>
  )
}

function ScenariosSection({
  modeStatus,
  scenarios,
  scenarioDraft,
  setScenarioDraft,
  actionBusy,
  runScenario,
  clearScenarioEvents,
}) {
  return (
    <section className="panel">
      <div className="panel-title-row">
        <h2>Host-Targeted Scenario Runner</h2>
        <span className="muted">Use DEMO / SCENARIO MODE for controlled demonstration labels.</span>
      </div>

      <div className="scenario-controls">
        <label>
          Source host(s)
          <input
            value={scenarioDraft.source_hosts}
            onChange={(event) => setScenarioDraft((prev) => ({ ...prev, source_hosts: event.target.value }))}
            placeholder="h1,h3"
          />
        </label>
        <label>
          Destination host
          <input
            value={scenarioDraft.destination_host}
            onChange={(event) => setScenarioDraft((prev) => ({ ...prev, destination_host: event.target.value }))}
            placeholder="h2"
          />
        </label>
        <label>
          Repeat
          <input
            type="number"
            min={1}
            max={200}
            value={scenarioDraft.repeat}
            onChange={(event) => setScenarioDraft((prev) => ({ ...prev, repeat: Number(event.target.value) || 1 }))}
          />
        </label>
        <label>
          Intensity
          <input
            type="number"
            min={1}
            max={100}
            value={scenarioDraft.intensity}
            onChange={(event) => setScenarioDraft((prev) => ({ ...prev, intensity: Number(event.target.value) || 1 }))}
          />
        </label>
        <label>
          Packet size (bytes)
          <input
            type="number"
            min={64}
            max={65535}
            value={scenarioDraft.packet_size}
            onChange={(event) => setScenarioDraft((prev) => ({ ...prev, packet_size: Number(event.target.value) || 512 }))}
          />
        </label>
        <label>
          Concurrency
          <input
            type="number"
            min={1}
            max={64}
            value={scenarioDraft.concurrency}
            onChange={(event) => setScenarioDraft((prev) => ({ ...prev, concurrency: Number(event.target.value) || 1 }))}
          />
        </label>
        <label className="checkbox-row">
          <span>Use real helper command (when configured)</span>
          <input
            type="checkbox"
            checked={scenarioDraft.use_real_helpers}
            onChange={(event) => setScenarioDraft((prev) => ({ ...prev, use_real_helpers: event.target.checked }))}
          />
        </label>
        <button className="btn ghost" type="button" disabled={actionBusy} onClick={clearScenarioEvents}>
          Reset / Clear Demo State
        </button>
      </div>

      <div className="scenario-grid">
        {scenarios.map((scenario) => (
          <article key={scenario.code} className="scenario-card">
            <h3>{scenario.name}</h3>
            <p>{scenario.description}</p>
            <p>
              Label source:{' '}
              <span className={labelSourceClass(scenario.default_label_source)}>{scenario.default_label_source}</span>
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
    </section>
  )
}

function MitigationSection({
  mitigationDraft,
  mitigationConfig,
  setMitigationDraft,
  setMitigationDraftDirty,
  onAutoMitigationToggle,
  saveMitigationConfig,
  manualAction,
  setManualAction,
  submitManualMitigationFromPanel,
  activeMitigations,
  rollbackMitigation,
  mitigationEvents,
  actionBusy,
}) {
  const isBlockFlow = manualAction.action === 'block_flow'
  const isIsolatePort = manualAction.action === 'isolate_port'
  const protocolOptions = isIsolatePort ? [] : MANUAL_PROTOCOL_OPTIONS
  return (
    <section className="section-stack">
      <section className="panel">
        <h2>Automatic Mitigation</h2>
        <div className="mitigation-config">
          <label className="toggle-row">
            <span>Automatic mitigation enabled</span>
            <button
              type="button"
              className={`toggle-switch ${mitigationDraft.enabled ? 'on' : 'off'}`}
              onClick={() => onAutoMitigationToggle(!mitigationDraft.enabled)}
              disabled={actionBusy}
              aria-pressed={mitigationDraft.enabled}
            >
              <span className="toggle-knob" />
            </button>
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
                {
                  setMitigationDraftDirty(true)
                  setMitigationDraft((prev) => ({ ...prev, min_confidence: Number(event.target.value) }))
                }
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
                {
                  setMitigationDraftDirty(true)
                  setMitigationDraft((prev) => ({ ...prev, default_timeout_sec: Number(event.target.value) }))
                }
              }
            />
          </label>
          <label>
            <span>Escalate after count</span>
            <input
              type="number"
              min={1}
              max={1000}
              value={mitigationDraft.escalate_after_count}
              onChange={(event) =>
                {
                  setMitigationDraftDirty(true)
                  setMitigationDraft((prev) => ({ ...prev, escalate_after_count: Number(event.target.value) || 1 }))
                }
              }
            />
          </label>
          <label>
            <span>Primary auto action</span>
            <select
              value={mitigationDraft.primary_action}
              onChange={(event) => {
                setMitigationDraftDirty(true)
                setMitigationDraft((prev) => ({ ...prev, primary_action: event.target.value }))
              }}
            >
              {MITIGATION_ACTIONS.map((action) => (
                <option key={action.value} value={action.value}>
                  {action.label}
                </option>
              ))}
            </select>
          </label>
          <button className="btn primary" type="button" disabled={actionBusy || mitigationDraft.enabled} onClick={saveMitigationConfig}>
            Save Auto Mitigation Config
          </button>
          {mitigationDraft.enabled && (
            <p className="empty-message">
              Auto mitigation is ON. Disable it to edit thresholds/actions, then save and re-enable.
            </p>
          )}
          {!mitigationDraft.enabled && (
            <p className="empty-message">
              Editing draft values only. Click "Save Auto Mitigation Config" to apply changes.
            </p>
          )}
          {mitigationConfig.enabled !== mitigationDraft.enabled && (
            <p className="empty-message">
              Unsaved toggle state detected. Current backend state: {mitigationConfig.enabled ? 'enabled' : 'disabled'}.
            </p>
          )}
        </div>
      </section>

      <section className="panel">
        <form className="manual-mitigation-form" onSubmit={submitManualMitigationFromPanel}>
          <h3>Manual Mitigation (with explicit target confirmation)</h3>
          <select
            value={manualAction.action}
            onChange={(event) =>
              setManualAction((prev) => ({
                ...prev,
                action: event.target.value,
                protocol: event.target.value === 'isolate_port' ? 'ALL' : prev.protocol || 'ALL',
                port_id: event.target.value === 'isolate_port' ? 'ALL' : prev.port_id,
              }))
            }
          >
            {MITIGATION_ACTIONS.map((action) => (
              <option key={action.value} value={action.value}>
                {action.label}
              </option>
            ))}
          </select>
          {!isIsolatePort && (
            <input
              placeholder="Source IP (required for block_flow/block_source)"
              value={manualAction.src_ip}
              onChange={(event) => setManualAction((prev) => ({ ...prev, src_ip: event.target.value }))}
            />
          )}
          {isBlockFlow && (
            <input
              placeholder="Destination IP (required for block_flow)"
              value={manualAction.dst_ip}
              onChange={(event) => setManualAction((prev) => ({ ...prev, dst_ip: event.target.value }))}
            />
          )}
          {!isIsolatePort && (
            <select
              value={manualAction.protocol}
              onChange={(event) => setManualAction((prev) => ({ ...prev, protocol: event.target.value }))}
            >
              {protocolOptions.map((protocol) => (
                <option key={protocol} value={protocol}>
                  {protocol === 'ALL' ? 'ALL (TCP + UDP + ICMP)' : protocol}
                </option>
              ))}
            </select>
          )}
          {isIsolatePort && (
            <input
              placeholder="Switch ID (required for switch isolation)"
              value={manualAction.switch_id}
              onChange={(event) => setManualAction((prev) => ({ ...prev, switch_id: event.target.value }))}
            />
          )}
          {!isIsolatePort && (
            <input
              placeholder="Switch ID (required for isolate_port)"
              value={manualAction.switch_id}
              onChange={(event) => setManualAction((prev) => ({ ...prev, switch_id: event.target.value }))}
            />
          )}
          {isIsolatePort && <p className="empty-message">Switch isolation will disable all data ports on this switch.</p>}
          <input
            placeholder="Reason"
            value={manualAction.reason}
            onChange={(event) => setManualAction((prev) => ({ ...prev, reason: event.target.value }))}
          />
          <button className="btn danger" type="submit" disabled={actionBusy}>
            Submit Manual Mitigation
          </button>
        </form>
      </section>

      <section className="panel">
        <h2>Active Mitigations</h2>
        {activeMitigations.length === 0 ? (
          <p className="empty-message">No active mitigations.</p>
        ) : (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Source</th>
                  <th>Reason</th>
                  <th>Status</th>
                  <th>Rollback</th>
                </tr>
              </thead>
              <tbody>
                {activeMitigations.map((event) => (
                  <tr key={event.mitigation_id}>
                    <td>{event.action}</td>
                    <td>{event.target_summary}</td>
                    <td>{event.triggered_by}</td>
                    <td>{event.reason}</td>
                    <td>{event.status}</td>
                    <td>
                      <button
                        className="btn tiny ghost"
                        type="button"
                        disabled={actionBusy}
                        onClick={() => rollbackMitigation(event)}
                      >
                        Retract
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel">
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
                  <th>Source</th>
                  <th>Target</th>
                  <th>Reason</th>
                  <th>Status</th>
                  <th>Enforcement</th>
                </tr>
              </thead>
              <tbody>
                {mitigationEvents.map((event) => (
                  <tr key={event.mitigation_id}>
                    <td>{formatTimestamp(event.timestamp)}</td>
                    <td>{event.action}</td>
                    <td>{event.triggered_by}</td>
                    <td>{event.target_summary}</td>
                    <td>{event.reason}</td>
                    <td>{event.status}</td>
                    <td>{event.enforcement_status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </section>
  )
}

function HealthSection({ healthCards, controllerStatus }) {
  return (
    <section className="panel">
      <div className="panel-title-row">
        <h2>System Health & Controller Visibility</h2>
        <span className="muted">Frontend health is local UI runtime.</span>
      </div>
      <div className="health-grid">
        {healthCards.map((item) => (
          <div key={item.label} className="health-card">
            <span>{item.label}</span>
            <strong className={`status-tag ${statusClass(item.value)}`}>{item.value}</strong>
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
  )
}

function SocDashboard({ token, currentUser, onLogout, onSessionExpired }) {
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
  const [activeMitigations, setActiveMitigations] = useState([])
  const [mitigationConfig, setMitigationConfig] = useState({
    enabled: false,
    suspicious_labels: ['DoS_DDoS', 'Other_Attack', 'Congestion'],
    min_confidence: 0.75,
    default_timeout_sec: 300,
    action_order: ['block_flow', 'block_source', 'isolate_port'],
    escalate_after_count: 3,
  })
  const [mitigationDraft, setMitigationDraft] = useState({
    enabled: false,
    min_confidence: 0.75,
    default_timeout_sec: 300,
    primary_action: 'block_flow',
    escalate_after_count: 3,
  })
  const [mitigationDraftDirty, setMitigationDraftDirty] = useState(false)
  const [stats, setStats] = useState({
    total_flows: 0,
    normal_flows: 0,
    suspicious_flows: 0,
    active_hosts: 0,
    class_distribution: {},
    by_source: {},
    mitigated_flows: 0,
  })
  const [scenarioDraft, setScenarioDraft] = useState({
    source_hosts: 'h1',
    destination_host: 'h2',
    repeat: 3,
    intensity: 5,
    packet_size: 1024,
    concurrency: 2,
    use_real_helpers: true,
  })
  const [manualAction, setManualAction] = useState({
    action: 'block_source',
    src_ip: '',
    dst_ip: '',
    protocol: 'ALL',
    switch_id: 's1',
    port_id: 'ALL',
    reason: '',
    timeout_sec: 300,
  })
  const [actionBusy, setActionBusy] = useState(false)
  const [loading, setLoading] = useState(true)
  const [actionMessage, setActionMessage] = useState('')
  const [error, setError] = useState('')

  const authedRequest = useCallback(
    async (path, options) => {
      try {
        return await requestJson(path, { ...options, token })
      } catch (requestError) {
        if (requestError instanceof ApiError && requestError.status === 401) {
          onSessionExpired()
        }
        throw requestError
      }
    },
    [onSessionExpired, token],
  )

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
      activeMitigationsData,
    ] = await Promise.all([
      authedRequest('/health'),
      authedRequest('/mode'),
      authedRequest('/controller/status'),
      authedRequest('/flows?limit=250'),
      authedRequest('/alerts?limit=100'),
      authedRequest('/sessions?limit=120'),
      authedRequest('/topology'),
      authedRequest('/stats'),
      authedRequest('/scenarios'),
      authedRequest('/mitigation/config'),
      authedRequest('/mitigation/events?limit=120'),
      authedRequest('/mitigations/active'),
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
    setActiveMitigations(activeMitigationsData)
    if (!mitigationDraftDirty) {
      setMitigationDraft((previous) => ({
        ...previous,
        enabled: mitigationConfigData.enabled,
        min_confidence: mitigationConfigData.min_confidence,
        default_timeout_sec: mitigationConfigData.default_timeout_sec,
        primary_action: mitigationConfigData.action_order?.[0] || 'block_flow',
        escalate_after_count: mitigationConfigData.escalate_after_count || 3,
      }))
    }
    setError('')
  }, [authedRequest, mitigationDraftDirty])

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
    const timer = window.setInterval(poll, POLL_INTERVAL_MS)
    return () => {
      active = false
      window.clearInterval(timer)
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

  const runManualMitigation = async (payload) => {
    if (!window.confirm(`Confirm mitigation target:\n\n${mitigationPreview(payload)}`)) {
      return
    }
    setActionBusy(true)
    setActionMessage('')
    try {
      const response = await authedRequest('/mitigations/apply', {
        method: 'POST',
        body: payload,
      })
      if (response.status === 'accepted') {
        setActionMessage(`Mitigation enforced: ${response.event.target_summary}`)
      } else {
        setActionMessage(`Mitigation failed: ${response.event.enforcement_message || 'enforcement error'}`)
      }
      await loadDashboardData()
    } catch (requestError) {
      setActionMessage(requestError instanceof Error ? requestError.message : 'Mitigation request failed.')
    } finally {
      setActionBusy(false)
    }
  }

  const applyActionToAlert = async (flow, action) => {
    if (action === 'mark_mitigated') {
      setActionBusy(true)
      setActionMessage('')
      try {
        await authedRequest('/alerts/mark-mitigated', {
          method: 'POST',
          body: {
            flow_key: flow.flow_key || null,
            src_ip: flow.src_ip,
            dst_ip: flow.dst_ip,
            protocol: flow.protocol,
            timestamp: flow.timestamp || null,
            reason: 'Operator dismissed alert as already mitigated from alerts panel.',
          },
        })
        setActionMessage(`Alert dismissed as mitigated for ${flow.src_ip} -> ${flow.dst_ip} (${flow.protocol}).`)
        await loadDashboardData()
      } catch (dismissError) {
        setActionMessage(dismissError instanceof Error ? dismissError.message : 'Failed to dismiss alert.')
      } finally {
        setActionBusy(false)
      }
      return
    }

    if (action === 'mark_normal') {
      setActionBusy(true)
      setActionMessage('')
      try {
        await authedRequest('/alerts/mark-normal', {
          method: 'POST',
          body: {
            flow_key: flow.flow_key || null,
            src_ip: flow.src_ip,
            dst_ip: flow.dst_ip,
            protocol: flow.protocol,
            timestamp: flow.timestamp || null,
            reason: 'Operator marked as false positive from alerts panel.',
          },
        })
        setActionMessage(`Alert marked as normal for ${flow.src_ip} -> ${flow.dst_ip} (${flow.protocol}).`)
        await loadDashboardData()
      } catch (markError) {
        setActionMessage(markError instanceof Error ? markError.message : 'Failed to mark alert as normal.')
      } finally {
        setActionBusy(false)
      }
      return
    }

    if (action === 'isolate_port') {
      await runManualMitigation({
        action,
        src_ip: null,
        switch_id: flow.switch_id || 's1',
        port_id: 0,
        reason: `Manual alert action for ${flow.prediction}`,
        timeout_sec: mitigationDraft.default_timeout_sec,
        triggered_by: 'manual',
      })
      return
    }

    if (action === 'block_flow') {
      await runManualMitigation({
        action,
        src_ip: flow.src_ip,
        dst_ip: flow.dst_ip,
        protocol: flow.protocol,
        reason: `Manual alert action for ${flow.prediction}`,
        timeout_sec: mitigationDraft.default_timeout_sec,
        triggered_by: 'manual',
      })
      return
    }

    await runManualMitigation({
      action,
      src_ip: flow.src_ip,
      reason: `Manual alert action for ${flow.prediction}`,
      timeout_sec: mitigationDraft.default_timeout_sec,
      triggered_by: 'manual',
    })
  }

  const applyActionToSession = async (session, action) => {
    if (action === 'isolate_port') {
      const switchInput = window.prompt('Enter switch ID to isolate:', 's1')
      if (!switchInput || !switchInput.trim()) {
        setActionMessage('Switch isolation requires a valid switch ID.')
        return
      }
      await runManualMitigation({
        action,
        src_ip: null,
        switch_id: switchInput.trim(),
        port_id: 0,
        reason: `Manual session action for ${session.dominant_label}`,
        timeout_sec: mitigationDraft.default_timeout_sec,
        triggered_by: 'manual',
      })
      return
    }

    if (action === 'block_flow') {
      await runManualMitigation({
        action,
        src_ip: session.source_entity,
        dst_ip: session.destination_entity,
        protocol: session.protocol,
        reason: `Manual session action for ${session.dominant_label}`,
        timeout_sec: mitigationDraft.default_timeout_sec,
        triggered_by: 'manual',
      })
      return
    }

    await runManualMitigation({
      action,
      src_ip: session.source_entity,
      reason: `Manual session action for ${session.dominant_label}`,
      timeout_sec: mitigationDraft.default_timeout_sec,
      triggered_by: 'manual',
    })
  }

  const handleModeSwitch = async (mode) => {
    setActionBusy(true)
    setActionMessage('')
    try {
      const response = await authedRequest('/mode', {
        method: 'PUT',
        body: { mode },
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
      const sourceHosts = scenarioDraft.source_hosts
        .split(',')
        .map((value) => value.trim())
        .filter(Boolean)
      const response = await authedRequest('/scenarios/run', {
        method: 'POST',
        body: {
          scenario,
          source_hosts: sourceHosts,
          destination_host: scenarioDraft.destination_host.trim(),
          repeat: scenarioDraft.repeat,
          intensity: scenarioDraft.intensity,
          packet_size: scenarioDraft.packet_size,
          concurrency: scenarioDraft.concurrency,
          use_real_helpers: scenarioDraft.use_real_helpers,
        },
      })
      const helperNote = response.helper_invoked
        ? ` helper=${response.helper_output || 'executed'}`
        : ` helper=${response.helper_output || 'not configured'}`
      setActionMessage(`${response.generated_events} scenario events generated for ${scenario}.${helperNote}`)
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
      const response = await authedRequest('/scenarios/reset', { method: 'POST' })
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
      await authedRequest('/mitigation/config', {
        method: 'PUT',
        body: {
          enabled: mitigationDraft.enabled,
          min_confidence: mitigationDraft.min_confidence,
          default_timeout_sec: mitigationDraft.default_timeout_sec,
          action_order: order,
          escalate_after_count: mitigationDraft.escalate_after_count,
        },
      })
      setMitigationDraftDirty(false)
      setActionMessage('Automatic mitigation configuration saved.')
      await loadDashboardData()
    } catch (configError) {
      setActionMessage(configError instanceof Error ? configError.message : 'Failed to save mitigation config.')
    } finally {
      setActionBusy(false)
    }
  }

  const toggleAutoMitigation = async (nextEnabled) => {
    const verb = nextEnabled ? 'enable' : 'disable'
    if (!window.confirm(`Are you sure you want to ${verb} automatic mitigation?`)) {
      return
    }
    const primary = mitigationDraft.primary_action
    const order = [primary, ...MITIGATION_ACTIONS.map((item) => item.value).filter((value) => value !== primary)]
    setActionBusy(true)
    setActionMessage('')
    try {
      await authedRequest('/mitigation/config', {
        method: 'PUT',
        body: {
          enabled: nextEnabled,
          min_confidence: mitigationDraft.min_confidence,
          default_timeout_sec: mitigationDraft.default_timeout_sec,
          action_order: order,
          escalate_after_count: mitigationDraft.escalate_after_count,
        },
      })
      setMitigationDraft((prev) => ({ ...prev, enabled: nextEnabled }))
      setMitigationDraftDirty(false)
      setActionMessage(
        `Automatic mitigation ${nextEnabled ? 'enabled' : 'disabled'} with primary action ${primary}.`,
      )
      await loadDashboardData()
    } catch (toggleError) {
      setActionMessage(toggleError instanceof Error ? toggleError.message : 'Failed to update automatic mitigation.')
    } finally {
      setActionBusy(false)
    }
  }

  const submitManualMitigationFromPanel = async (event) => {
    event.preventDefault()
    const normalizedProtocol = manualAction.action === 'isolate_port' || manualAction.protocol === 'ALL'
      ? null
      : manualAction.protocol
    const normalizedPortId =
      manualAction.action !== 'isolate_port'
        ? null
        : 0
    await runManualMitigation({
      action: manualAction.action,
      src_ip: manualAction.action === 'isolate_port' ? null : manualAction.src_ip || null,
      dst_ip: manualAction.action === 'isolate_port' ? null : manualAction.dst_ip || null,
      protocol: normalizedProtocol,
      switch_id: manualAction.switch_id || null,
      port_id: Number.isFinite(normalizedPortId) ? normalizedPortId : null,
      reason: manualAction.reason || 'Manual mitigation request from mitigation panel.',
      timeout_sec: Number(manualAction.timeout_sec) || mitigationDraft.default_timeout_sec,
      triggered_by: 'manual',
    })
  }

  const rollbackMitigation = async (mitigationEvent) => {
    if (
      !window.confirm(
        `Rollback mitigation?\n\n${mitigationEvent.target_summary}\nAction: ${mitigationEvent.action}\nSource: ${mitigationEvent.triggered_by}`,
      )
    ) {
      return
    }
    setActionBusy(true)
    setActionMessage('')
    try {
      const response = await authedRequest('/mitigations/retract', {
        method: 'POST',
        body: {
          mitigation_id: mitigationEvent.mitigation_id,
          reason: 'Operator rollback from dashboard',
        },
      })
      setActionMessage(response.message)
      await loadDashboardData()
    } catch (rollbackError) {
      setActionMessage(rollbackError instanceof Error ? rollbackError.message : 'Rollback failed.')
    } finally {
      setActionBusy(false)
    }
  }

  if (loading) {
    return (
      <main className="soc-shell">
        <section className="panel loading-panel">
          <h1>smartSDN</h1>
          <p>Connecting to backend and loading authenticated live controller state...</p>
        </section>
      </main>
    )
  }

  return (
    <main className="soc-shell">
      <header className="soc-header">
        <div>
          <h1>smartSDN</h1>
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

      <nav className="dashboard-nav" aria-label="Dashboard sections">
        {NAV_ITEMS.map((item) => (
          <NavLink key={item.to} to={item.to} className={({ isActive }) => `nav-pill ${isActive ? 'active' : ''}`}>
            {item.label}
          </NavLink>
        ))}
      </nav>

      <Routes>
        <Route path="/" element={<Navigate to="overview" replace />} />
        <Route path="overview" element={<OverviewSection stats={stats} chartRows={chartRows} />} />
        <Route path="topology" element={<TopologySection topology={topology} graphLayout={graphLayout} />} />
        <Route path="raw-flows" element={<RawFlowsSection flows={flows} />} />
        <Route
          path="sessions"
          element={<SessionsSection sessions={sessions} onAction={applyActionToSession} actionBusy={actionBusy} />}
        />
        <Route
          path="alerts"
          element={
            <AlertsSection
              alerts={alerts}
              hasLiveEvents={flows.length > 0}
              onAction={applyActionToAlert}
              actionBusy={actionBusy}
            />
          }
        />
        <Route
          path="scenarios"
          element={
            <ScenariosSection
              modeStatus={modeStatus}
              scenarios={scenarios}
              scenarioDraft={scenarioDraft}
              setScenarioDraft={setScenarioDraft}
              actionBusy={actionBusy}
              runScenario={runScenario}
              clearScenarioEvents={clearScenarioEvents}
            />
          }
        />
        <Route
          path="mitigation"
          element={
            <MitigationSection
              mitigationDraft={mitigationDraft}
              mitigationConfig={mitigationConfig}
              setMitigationDraft={setMitigationDraft}
              setMitigationDraftDirty={setMitigationDraftDirty}
              onAutoMitigationToggle={toggleAutoMitigation}
              saveMitigationConfig={saveMitigationConfig}
              manualAction={manualAction}
              setManualAction={setManualAction}
              submitManualMitigationFromPanel={submitManualMitigationFromPanel}
              activeMitigations={activeMitigations}
              rollbackMitigation={rollbackMitigation}
              mitigationEvents={mitigationEvents}
              actionBusy={actionBusy}
            />
          }
        />
        <Route path="health" element={<HealthSection healthCards={healthCards} controllerStatus={controllerStatus} />} />
        <Route path="*" element={<Navigate to="overview" replace />} />
      </Routes>
    </main>
  )
}

function App() {
  const navigate = useNavigate()
  const [session, setSession] = useState({
    status: 'checking',
    token: '',
    user: null,
    error: '',
  })
  const [loginBusy, setLoginBusy] = useState(false)

  const setLoggedOut = useCallback(() => {
    clearStoredSession()
    setSession({
      status: 'unauthenticated',
      token: '',
      user: null,
      error: '',
    })
    navigate('/login', { replace: true })
  }, [navigate])

  const verifyStoredToken = useCallback(async () => {
    const stored = readStoredSession()
    if (!stored?.token) {
      setSession({
        status: 'unauthenticated',
        token: '',
        user: null,
        error: '',
      })
      return
    }
    try {
      const me = await requestJson('/auth/me', { token: stored.token })
      const persisted = {
        token: stored.token,
        user: me.user,
        expires_at: stored.expires_at || null,
      }
      writeStoredSession(persisted)
      setSession({
        status: 'authenticated',
        token: stored.token,
        user: me.user,
        error: '',
      })
    } catch {
      setLoggedOut()
    }
  }, [setLoggedOut])

  useEffect(() => {
    verifyStoredToken()
  }, [verifyStoredToken])

  const handleLogin = async ({ identifier, password }) => {
    setLoginBusy(true)
    setSession((previous) => ({ ...previous, error: '' }))
    try {
      const response = await requestJson('/auth/login', {
        method: 'POST',
        body: { identifier, password },
      })
      const persisted = {
        token: response.token,
        user: response.user,
        expires_at: response.expires_at,
      }
      writeStoredSession(persisted)
      setSession({
        status: 'authenticated',
        token: response.token,
        user: response.user,
        error: '',
      })
      navigate('/dashboard/overview', { replace: true })
    } catch (loginError) {
      setSession({
        status: 'unauthenticated',
        token: '',
        user: null,
        error: loginError instanceof Error ? loginError.message : 'Login failed.',
      })
    } finally {
      setLoginBusy(false)
    }
  }

  const handleLogout = async () => {
    const stored = readStoredSession()
    if (stored?.token) {
      try {
        await requestJson('/auth/logout', { token: stored.token, method: 'POST' })
      } catch {
        // Best effort logout for stateless tokens.
      }
    }
    setLoggedOut()
  }

  if (session.status === 'checking') {
    return (
      <main className="login-shell">
        <section className="login-card">
          <h1>Loading secure dashboard session...</h1>
          <p>Validating local token with backend auth service.</p>
        </section>
      </main>
    )
  }

  return (
    <Routes>
      <Route
        path="/login"
        element={
          session.status === 'authenticated' ? (
            <Navigate to="/dashboard/overview" replace />
          ) : (
            <LoginGate onLogin={handleLogin} loading={loginBusy} backendError={session.error} />
          )
        }
      />
      <Route
        path="/dashboard/*"
        element={
          <ProtectedRoute authenticated={session.status === 'authenticated'}>
            <SocDashboard
              token={session.token}
              currentUser={session.user?.username || 'admin'}
              onLogout={handleLogout}
              onSessionExpired={setLoggedOut}
            />
          </ProtectedRoute>
        }
      />
      <Route
        path="*"
        element={
          <Navigate to={session.status === 'authenticated' ? '/dashboard/overview' : '/login'} replace />
        }
      />
    </Routes>
  )
}

export default App
