import { useState } from 'react'

function LoginGate({ onLogin, loading, backendError }) {
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [validationError, setValidationError] = useState('')

  const handleSubmit = async (event) => {
    event.preventDefault()
    setValidationError('')

    const trimmed = identifier.trim()
    if (!trimmed) {
      setValidationError('Username or email is required.')
      return
    }
    if (!password.trim()) {
      setValidationError('Password is required.')
      return
    }
    if (password.length < 4) {
      setValidationError('Password must be at least 4 characters.')
      return
    }

    onLogin({ identifier: trimmed, password })
  }

  return (
    <main className="login-shell">
      <section className="login-layout">
        <aside className="login-hero">
          <p className="login-kicker">AI-SDN</p>
          <h1>AI-SDN</h1>
          <p className="muted">
            Observe live controller telemetry, investigate suspicious sessions, and orchestrate mitigation from a
            single operator console.
          </p>
          <ul className="login-capability-list">
            <li>
              <strong>Live topology intelligence</strong>
              <span>Controller, switch, and host visibility with stateful traffic overlays.</span>
            </li>
            <li>
              <strong>Explainable threat response</strong>
              <span>Operator-driven and automatic mitigations with enforcement detail trails.</span>
            </li>
            <li>
              <strong>Scenario simulation lab</strong>
              <span>Controlled replay for demonstrations, testing, and SOC training flow.</span>
            </li>
          </ul>
        </aside>

        <section className="login-card">
          <div className="login-badge">SECURE OPERATOR ACCESS</div>
          <h1>Sign in</h1>
          <p>Authenticate with the configured admin identity to open the workspace.</p>
          <form className="login-form" onSubmit={handleSubmit}>
            <label htmlFor="login-identifier">Username or email</label>
            <input
              id="login-identifier"
              name="identifier"
              placeholder="soc.demo@local"
              autoComplete="username"
              value={identifier}
              onChange={(event) => setIdentifier(event.target.value)}
              disabled={loading}
            />

            <label htmlFor="login-password">Password</label>
            <div className="password-row">
              <input
                id="login-password"
                name="password"
                placeholder="Enter password"
                type={showPassword ? 'text' : 'password'}
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                disabled={loading}
              />
              <button
                className="btn ghost tiny"
                type="button"
                onClick={() => setShowPassword((value) => !value)}
                disabled={loading}
              >
                {showPassword ? 'Hide' : 'Show'}
              </button>
            </div>

            {validationError || backendError ? (
              <div className="form-error">{validationError || backendError}</div>
            ) : (
              <div className="form-hint">Credentials are validated by backend /auth/login.</div>
            )}

            <button className="btn primary login-btn" type="submit" disabled={loading}>
              {loading ? 'Signing in...' : 'Enter workspace'}
            </button>
          </form>
        </section>
      </section>
    </main>
  )
}

export default LoginGate
