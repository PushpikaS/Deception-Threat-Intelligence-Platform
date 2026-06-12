import { useMemo } from 'react'
import { tagLabel } from '../api'
import Card from './Card'

const FLOW = [
  { step: '1', label: 'Request logged', detail: 'Auth, admin, API, or recon surface' },
  { step: '2', label: 'Behavior classified', detail: 'sqli_attempt, env_leak, brute_force, benign_session…' },
  { step: '3', label: 'MITRE map applied', detail: 'Per-event threats and IP-wide context mapped to technique IDs' },
  { step: '4', label: 'Dashboard updated', detail: 'Technique tags on profiles and event feed' },
]

const EXAMPLES = [
  { behavior: 'env_leak', trigger: 'GET /.env', mitre: 'T1552.001', name: 'Credentials In Files' },
  { behavior: 'brute_force', trigger: '3+ login POSTs or weak password', mitre: 'T1110.001', name: 'Password Guessing' },
  { behavior: 'sqli_attempt', trigger: 'union select in payload', mitre: 'T1190', name: 'Exploit Public-Facing Application' },
  { behavior: 'benign_session', trigger: 'Normal login → MFA → admin', mitre: '—', name: 'No MITRE tag (safe)' },
]

export default function MitreGuide({ mitreMap, loading }) {
  const byTactic = useMemo(() => {
    if (!mitreMap) return {}
    const groups = {}
    for (const [classification, techniques] of Object.entries(mitreMap)) {
      for (const t of techniques) {
        if (!groups[t.tactic]) groups[t.tactic] = []
        groups[t.tactic].push({ ...t, classification })
      }
    }
    return groups
  }, [mitreMap])

  return (
    <Card title="MITRE ATT&CK — How Labels Work">
      {loading ? (
        <p className="text-slate-500 text-sm">Loading mapping…</p>
      ) : (
        <div className="space-y-5">
          <p className="text-xs text-slate-400 leading-relaxed">
            MITRE ATT&CK is a public catalog of real-world attacker techniques. Each tag is assigned by matching observed behavior to the platform classification catalog.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2">
            {FLOW.map((f) => (
              <div key={f.step} className="bg-surface rounded-lg p-3 border border-surface-border">
                <span className="text-[10px] text-purple-400 font-bold">Step {f.step}</span>
                <p className="text-xs text-slate-200 font-medium mt-1">{f.label}</p>
                <p className="text-[10px] text-slate-500 mt-0.5">{f.detail}</p>
              </div>
            ))}
          </div>

          <div>
            <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-2">Real examples from this deployment</p>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-slate-500 uppercase tracking-wider">
                    <th className="pb-2 pr-3">If you see…</th>
                    <th className="pb-2 pr-3">Trigger</th>
                    <th className="pb-2 pr-3">MITRE ID</th>
                    <th className="pb-2">Technique</th>
                  </tr>
                </thead>
                <tbody>
                  {EXAMPLES.map((ex) => (
                    <tr key={ex.behavior} className="border-t border-surface-border">
                      <td className="py-2 pr-3 text-slate-400">{tagLabel(ex.behavior)}</td>
                      <td className="py-2 pr-3 text-slate-500">{ex.trigger}</td>
                      <td className="py-2 pr-3 mono text-purple-400">{ex.mitre}</td>
                      <td className="py-2 text-slate-300">{ex.name}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {Object.keys(byTactic).length > 0 && (
            <div>
              <p className="text-[10px] text-slate-500 uppercase tracking-wider mb-2">Full mapping by tactic ({Object.keys(mitreMap || {}).length} behaviors)</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 max-h-48 overflow-y-auto">
                {Object.entries(byTactic).map(([tactic, items]) => (
                  <div key={tactic} className="bg-surface rounded-lg p-3 border border-surface-border">
                    <p className="text-[10px] text-purple-300 uppercase tracking-wider mb-2">{tactic}</p>
                    <div className="flex flex-wrap gap-1">
                      {items.map((t) => (
                        <span key={`${t.id}-${t.classification}`} className="px-1.5 py-0.5 bg-purple-500/10 text-purple-400 rounded text-[10px] tooltip">
                          {t.id}
                          <span className="tooltip-text">{tagLabel(t.classification)} → {t.name}</span>
                        </span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </Card>
  )
}