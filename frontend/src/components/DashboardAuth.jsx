import { useEffect, useState } from 'react'
import { AuthError, clearLegacyAuth, loginDashboard, validateSession } from '../api'

export default function DashboardAuth({ onSuccess }) {
  const [user, setUser] = useState('')
  const [pass, setPass] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    clearLegacyAuth()
  }, [])

  const submit = async (e) => {
    e.preventDefault()
    if (!user || !pass) {
      setError('Enter username and password')
      return
    }
    setLoading(true)
    setError('')
    try {
      await loginDashboard(user, pass)
      const valid = await validateSession()
      if (!valid) throw new AuthError('Session could not be established')
      onSuccess()
    } catch (err) {
      if (err instanceof AuthError) {
        setError('Invalid credentials')
      } else {
        setError('Unable to reach threat API')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-surface flex items-center justify-center p-4">
      <form onSubmit={submit} autoComplete="off" className="bg-surface-light border border-surface-border rounded-xl p-8 w-full max-w-sm">
        <h1 className="text-lg font-bold text-white mb-1">Security Operations</h1>
        <p className="text-xs text-slate-500 mb-2">Threat intelligence console</p>
        {error && <p className="text-xs text-red-400 mb-3">{error}</p>}
        <input
          type="text"
          placeholder="Username"
          value={user}
          onChange={(e) => setUser(e.target.value)}
          className="w-full px-3 py-2 mb-3 text-sm bg-surface border border-surface-border rounded-md text-slate-300"
          autoComplete="off"
          name="dashboard-user"
        />
        <input
          type="password"
          placeholder="Password"
          value={pass}
          onChange={(e) => setPass(e.target.value)}
          className="w-full px-3 py-2 mb-4 text-sm bg-surface border border-surface-border rounded-md text-slate-300"
          autoComplete="new-password"
          name="dashboard-pass"
        />
        <button
          type="submit"
          disabled={loading}
          className="w-full py-2 text-sm font-medium bg-accent text-surface rounded-md hover:opacity-90 disabled:opacity-50"
        >
          {loading ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}