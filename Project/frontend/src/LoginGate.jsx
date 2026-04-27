import { useState } from 'react'

function LoginGate({ onSuccess }) {
  const [identifier, setIdentifier] = useState('')
  const [password, setPassword] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (event) => {
    event.preventDefault()
    setError('')

    const trimmed = identifier.trim()
    if (!trimmed) {
      setError('Username or email is required.')
      return
    }
    if (!password.trim()) {
      setError('Password is required.')
      return
    }
    if (password.length < 4) {
      setError('Password must be at least 4 characters.')
      return
    }

    setLoading(true)
    await new Promise((resolve) => {
      window.setTimeout(resolve, 650)
    })
    setLoading(false)
    onSuccess(trimmed)
  }

  return (
    <main className="login-shell">
      <section className="login-card">
        <div className="login-badge">SDN SOC SECURITY PLATFORM</div>
        <h1>Sign in to Live Dashboard</h1>
        <p>UI access gate for local demo sessions. Real authentication is not enabled.</p>
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

          {error ? <div className="form-error">{error}</div> : <div className="form-hint">Demo-only login gate.</div>}

          <button className="btn primary login-btn" type="submit" disabled={loading}>
            {loading ? 'Signing in...' : 'Login'}
          </button>
        </form>
      </section>
    </main>
  )
}

export default LoginGate
