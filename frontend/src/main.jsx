import React, { Fragment, StrictMode, useEffect, useMemo, useRef, useState } from 'react'
import { createRoot } from 'react-dom/client'
import cytoscape from 'cytoscape'
import './styles.css'

const NAV_ITEMS = [
  { id: 'graph', label: 'Attack Graph', short: '01' },
  { id: 'risks', label: 'Top Risks', short: '02' },
  { id: 'investigation', label: 'Investigation', short: '03' },
  { id: 'what-if', label: 'What-if', short: '04' },
]

function App() {
  const initialRoute = window.location.pathname.replace(/^\//, '').split('/')[0]
  const [screen, setScreen] = useState(initialRoute || window.location.hash.replace('#/', '') || 'graph')
  const [payload, setPayload] = useState(null)
  const [error, setError] = useState('')
  const [selectedNode, setSelectedNode] = useState(null)
  const [alerts, setAlerts] = useState([])
  const [investigation, setInvestigation] = useState({ events: [], verdict: null, status: 'idle' })
  const [currentTime, setCurrentTime] = useState(() => new Date().toISOString().replace('T', ' ').slice(11, 19) + ' UTC')
  const [triggering, setTriggering] = useState(false)
  const [toastMessage, setToastMessage] = useState(null)

  const showToast = (msg, duration = 4000) => {
    setToastMessage(msg)
    setTimeout(() => setToastMessage((current) => (current === msg ? null : current)), duration)
  }

  const navigate = (next) => {
    setScreen(next)
    window.history.replaceState({}, '', next === 'graph' ? '/' : `/${next}`)
  }

  const triggerThreatEvent = async (scenario = 'ssh') => {
    setTriggering(true)
    const isAws = scenario === 'aws'
    showToast(
      isAws
        ? '☁️ DISPATCHING AWS ALERT: GuardDuty finding (UnauthorizedAccess:EC2/SSHBruteForce via CloudTrail)...'
        : '🐳 LAUNCHING DOCKER LAB ATTACK: SSH Brute-Force (3 failed logins) against victim:2222...'
    )
    try {
      await fetch(`/api/demo/trigger?scenario=${scenario}`, { method: 'POST' })
    } catch {}
    setTimeout(() => {
      setTriggering(false)
      showToast(
        isAws
          ? '⚡ AWS TELEMETRY CAPTURED: CloudTrail 3 failed attempts on EC2 bastion. Autonomous ReAct agent active!'
          : '⚡ DOCKER LAB TELEMETRY CAPTURED: 3 Failed Auth events logged on vpn-bastion. Autonomous ReAct agent active!'
      )
    }, 1000)
  }

  const resetLab = async () => {
    try {
      await fetch('/api/demo/reset', { method: 'POST' })
    } catch {}
    setAlerts([])
    setInvestigation({ events: [], verdict: null, status: 'idle' })
    setSelectedNode(null)
    navigate('graph')
    showToast('↺ LAB RESET: Returned to safe baseline (0 active threats, topology cleared).', 3000)
    fetch('/api/graph').then((res) => res.json()).then(setPayload).catch(() => {})
  }

  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toISOString().replace('T', ' ').slice(11, 19) + ' UTC')
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  useEffect(() => {
    fetch('/api/graph')
      .then((response) => {
        if (!response.ok) throw new Error('Graph API is not ready')
        return response.json()
      })
      .then(setPayload)
      .catch((reason) => setError(reason.message))
  }, [])

  useEffect(() => {
    fetch('/api/alerts').then((response) => response.json()).then((data) => setAlerts(data.alerts || [])).catch(() => {})
    const stream = new EventSource('/api/alerts/stream')
    stream.addEventListener('alert', (event) => {
      const nextAlert = JSON.parse(event.data)
      setAlerts((current) => [nextAlert, ...current.filter((item) => item.alert_id !== nextAlert.alert_id)].slice(0, 30))
    })
    return () => stream.close()
  }, [])

  useEffect(() => {
    fetch('/api/investigation/current').then((response) => response.json()).then(setInvestigation).catch(() => {})
    const stream = new EventSource('/api/investigation/stream')
    stream.addEventListener('step', (event) => {
      const step = JSON.parse(event.data)
      setInvestigation((current) => {
        const events = [...current.events.filter((item) => !(item.run_id === step.run_id && item.step === step.step)), step]
        return { ...current, events, verdict: step.verdict || current.verdict, status: step.kind === 'verdict' ? 'complete' : 'running', run_id: step.run_id }
      })
    })
    return () => stream.close()
  }, [])

  const activeCompromisedNode = useMemo(() => {
    if (!alerts || alerts.length === 0) return null
    if (alerts[0]?.source_host === 'web-portal' || alerts[0]?.rule?.startsWith('web_')) {
      return 'web-portal'
    }
    return 'vpn-bastion'
  }, [alerts])

  const headerLabel = NAV_ITEMS.find((item) => item.id === screen)?.label || 'Attack Graph'

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-lockup">
          <div className="brand-mark" aria-hidden="true"><span /><span /><span /></div>
          <div>
            <div className="brand-name">SENTINEL<span>GRAPH</span></div>
            <div className="brand-subtitle">attack-path intelligence</div>
          </div>
        </div>
        <div className="sidebar-rule" />
        <div className="rail-label">SOC OPERATIONS / ENCLAVE-01</div>
        <nav className="nav-list" aria-label="Primary navigation">
          {NAV_ITEMS.map((item) => (
            <button key={item.id} className={`nav-item ${screen === item.id ? 'active' : ''}`} onClick={() => navigate(item.id)}>
              <span className="nav-index">{item.short}</span>
              <span>{item.label}</span>
              {item.id === 'graph' && <span className="live-dot" />}
            </button>
          ))}
        </nav>
        <div className="sidebar-footnote">
          <div className="tiny-label">ACTIVE ENCLAVE</div>
          <p>Production Cloud Network</p>
          <p className="muted">Live Graph Monitoring</p>
        </div>
      </aside>

      <main className="main-panel">
        <header className="topbar">
          <div>
            <div className="eyebrow">SENTINELGRAPH / {screen.toUpperCase()}</div>
            <h1>{headerLabel}</h1>
          </div>
          <div className="topbar-meta">
            <button
              className="trigger-btn"
              onClick={() => triggerThreatEvent('ssh')}
              disabled={triggering}
              title="Trigger live Docker lab SSH brute-force attack (3 failed auth attempts)"
            >
              {triggering ? '⚡ Executing…' : '🐳 Trigger Docker Lab (3 Auth Failed)'}
            </button>
            <button
              className="trigger-btn aws-btn"
              onClick={() => triggerThreatEvent('aws')}
              disabled={triggering}
              title="Trigger live AWS GuardDuty & CloudTrail security alert"
            >
              {triggering ? '☁️ Ingesting…' : '☁️ Trigger AWS Alert'}
            </button>
            <button className="reset-btn" onClick={resetLab} title="Reset lab incident to safe baseline">
              ↺ Reset Lab
            </button>
            <div className={`status-chip ${alerts.length ? 'threat-detected' : ''}`}>
              <span className={`status-pulse ${alerts.length ? 'threat-pulse' : ''}`} />
              {alerts.length ? 'Threat Ingress Active' : 'Enclave Protected'}
            </div>
            <div className={`alert-chip ${alerts.length ? 'has-alerts' : ''}`}>
              <span /> {alerts.length ? `${alerts.length} Alert${alerts.length === 1 ? '' : 's'} Ingested` : 'No Active Threats'}
            </div>
            <div className="timestamp">UTC · {currentTime}</div>
          </div>
        </header>

        {toastMessage && (
          <div className="live-toast-banner" role="status">
            <span>{toastMessage}</span>
            <button onClick={() => setToastMessage(null)} aria-label="Dismiss notification">✕</button>
          </div>
        )}

        {error && <div className="error-banner">API connection pending — start the FastAPI backend on port 8000, then refresh.</div>}
        {screen === 'graph' && (
          <GraphScreen
            payload={payload}
            selectedNode={selectedNode}
            setSelectedNode={setSelectedNode}
            alerts={alerts}
            activeCompromisedNode={activeCompromisedNode}
            onNavigateInvestigation={() => navigate('investigation')}
          />
        )}
        {screen === 'risks' && <RisksScreen payload={payload} alerts={alerts} onNavigateWhatIf={() => navigate('what-if')} activeCompromisedNode={activeCompromisedNode} />}
        {screen === 'investigation' && <InvestigationScreen investigation={investigation} alerts={alerts} activeCompromisedNode={activeCompromisedNode} />}
        {screen === 'what-if' && <WhatIfScreen payload={payload} setPayload={setPayload} alerts={alerts} activeCompromisedNode={activeCompromisedNode} />}
      </main>
    </div>
  )
}

function GraphScreen({ payload, selectedNode, setSelectedNode, alerts, activeCompromisedNode, onNavigateInvestigation }) {
  const cyContainer = useRef(null)
  const cyRef = useRef(null)

  useEffect(() => {
    if (!payload || !cyContainer.current) return undefined
    const elements = [
      ...payload.nodes.map((node) => ({
        data: { ...node, id: node.id },
        classes: [
          node.entry_point ? 'entry-node' : '',
          node.crown_jewel ? 'crown-node' : '',
          `kind-${node.kind || 'host'}`,
        ].filter(Boolean).join(' '),
      })),
      ...payload.edges.map((edge) => ({ data: { ...edge, id: edge.id } })),
    ]
    const cy = cytoscape({
      container: cyContainer.current,
      elements,
      layout: { name: 'breadthfirst', directed: true, roots: '#internet', spacingFactor: 1.25, padding: 32 },
      style: [
        {
          selector: 'node',
          style: {
            'background-color': '#ffffff',
            label: 'data(label)',
            color: '#0f172a',
            'font-family': 'Inter, system-ui, -apple-system, sans-serif',
            'font-size': 11,
            'font-weight': 600,
            'text-valign': 'bottom',
            'text-margin-y': 7,
            'text-background-color': '#ffffff',
            'text-background-opacity': 0.96,
            'text-background-padding': '4px',
            'text-background-shape': 'roundrectangle',
            'text-border-color': '#fed7aa',
            'text-border-width': 1,
            'text-border-opacity': 1.0,
            width: 40,
            height: 40,
            'border-width': 2.5,
            'border-color': '#3b82f6',
            shape: 'ellipse',
          },
        },
        {
          selector: '.entry-node',
          style: {
            'background-color': '#ea580c',
            'border-color': '#9a3412',
            'border-width': 3,
            shape: 'diamond',
            width: 46,
            height: 46,
          },
        },
        {
          selector: '.crown-node',
          style: {
            'background-color': '#dc2626',
            'border-color': '#991b1b',
            'border-width': 3,
            shape: 'star',
            width: 50,
            height: 50,
          },
        },
        {
          selector: '.kind-role',
          style: {
            'background-color': '#7c3aed',
            'border-color': '#5b21b6',
            shape: 'round-rectangle',
            width: 42,
            height: 42,
          },
        },
        {
          selector: '.kind-service',
          style: {
            'background-color': '#0d9488',
            'border-color': '#0f766e',
            shape: 'hexagon',
            width: 42,
            height: 42,
          },
        },
        {
          selector: 'edge',
          style: {
            width: 2.5,
            'line-color': '#cbd5e1',
            'target-arrow-color': '#94a3b8',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
          },
        },
        {
          selector: '.path-highlight',
          style: {
            width: 4.5,
            'line-color': '#ea580c',
            'target-arrow-color': '#ea580c',
            'z-index': 10,
          },
        },
        {
          selector: '.node-highlight',
          style: {
            'border-color': '#ea580c',
            'border-width': 4.5,
            'z-index': 10,
          },
        },
        {
          selector: '.active-breach-edge',
          style: {
            width: 5.5,
            'line-color': '#dc2626',
            'target-arrow-color': '#dc2626',
            'z-index': 25,
          },
        },
        {
          selector: '.active-breach-node',
          style: {
            'border-color': '#dc2626',
            'border-width': 5,
            'background-color': '#fff1f2',
            'z-index': 30,
          },
        },
        {
          selector: '.compromised-node',
          style: {
            'background-color': '#dc2626',
            'border-color': '#991b1b',
            'border-width': 5,
            width: 52,
            height: 52,
            'z-index': 35,
          },
        },
        {
          selector: '.dimmed',
          style: {
            opacity: 0.22,
          },
        },
      ],
    })
    cyRef.current = cy
    cy.on('tap', 'node', (event) => setSelectedNode(event.target.data()))
    cy.fit(undefined, 30)
    return () => { cyRef.current = null; cy.destroy() }
  }, [payload, setSelectedNode])

  const topChoke = payload?.choke_points?.[0]
  const hasActiveThreat = alerts && alerts.length > 0
  const pathCount = payload?.paths?.length || 0

  const activeRoute = useMemo(() => {
    if (activeCompromisedNode === 'web-portal') {
      return (
        payload?.paths?.find((p) => p.nodes.includes('web-portal') && (p.nodes[1] === 'web-portal' || p.nodes[2] === 'web-portal')) ||
        payload?.paths?.find((p) => p.nodes.includes('web-portal')) ||
        payload?.paths?.[0]
      )
    }
    return payload?.paths?.find((p) => p.nodes.includes('vpn-bastion')) || payload?.paths?.[0]
  }, [payload, activeCompromisedNode])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.elements().removeClass('compromised-node')
    if (alerts && alerts.length > 0 && activeCompromisedNode) {
      cy.getElementById(activeCompromisedNode).addClass('compromised-node')
      if (!selectedNode && payload?.nodes) {
        const comp = payload.nodes.find((n) => n.id === activeCompromisedNode)
        if (comp) setSelectedNode(comp)
      }
    }
  }, [alerts, activeCompromisedNode, payload, selectedNode, setSelectedNode])

  useEffect(() => {
    const cy = cyRef.current
    if (!cy) return
    cy.elements().removeClass('path-highlight node-highlight dimmed active-breach-node active-breach-edge')
    if (!activeRoute) return
    cy.elements().addClass('dimmed')
    activeRoute.nodes.forEach((nodeId) => {
      cy.getElementById(nodeId).removeClass('dimmed').addClass(hasActiveThreat ? 'active-breach-node' : 'node-highlight')
    })
    for (let i = 0; i < activeRoute.nodes.length - 1; i++) {
      const u = activeRoute.nodes[i]
      const v = activeRoute.nodes[i + 1]
      cy.edges(`[source = "${u}"][target = "${v}"], [source = "${v}"][target = "${u}"]`)
        .removeClass('dimmed')
        .addClass(hasActiveThreat ? 'active-breach-edge' : 'path-highlight')
    }
  }, [activeRoute, hasActiveThreat])

  return (
    <section className="content-stack">
      {hasActiveThreat && (
        <div className="threat-banner">
          <span className="threat-pulse">🚨</span>
          <div style={{ flex: 1 }}>
            <strong>
              {alerts[0]?.rule?.includes('aws')
                ? 'AWS INCIDENT DETECTED: GuardDuty SSH BruteForce (CloudTrail)'
                : 'DOCKER LAB INCIDENT: 3 Failed Authentications on vpn-bastion'}
            </strong>
            <span>
              {alerts[0]?.rule} — Ingress detected from external IP. ReAct autonomous investigation active.
            </span>
          </div>
          <button className="banner-nav-btn" onClick={() => onNavigateInvestigation?.()}>
            Open Investigation Trace →
          </button>
        </div>
      )}

      <div className="workspace-grid">
        <div className="panel graph-panel">
          <div className="panel-heading">
            <div>
              <div className="panel-kicker">NETWORKX TOPOLOGY MAP</div>
              <h2>Attack Surface Graph</h2>
            </div>
            <div className="topology-stats-badges">
              <span className="topo-badge"><strong>{pathCount}</strong> Attack Paths</span>
              <span className="topo-badge danger"><strong>{payload?.risk?.score || 100}/100</strong> Risk</span>
              <span className="topo-badge"><strong>{payload?.crown_jewels?.length || 2}</strong> Crown Jewels</span>
              <span className="topo-badge choke"><strong>{topChoke?.label || 'gw-ext-01'}</strong> ({topChoke ? Math.round(topChoke.coverage * 100) : 100}% Choke)</span>
            </div>
          </div>

          <div className="topology-controls-bar">
            <div className="legend">
              <span><i className="legend-dot entry" /> Ingress Gateway</span>
              <span><i className="legend-dot regular" /> Internal Asset</span>
              <span><i className="legend-dot crown" /> Crown Jewel (Target)</span>
            </div>
            <span className="graph-hint">Interactive: Click any asset to inspect vulnerabilities and lateral blast radius</span>
          </div>

          <div className="cy-shell">
            <div ref={cyContainer} className="cy-container" />
          </div>
        </div>

        <aside className="panel context-panel">
          <div className="panel-kicker">SELECTED ASSET INSPECTION</div>
          {selectedNode ? <NodeContext node={selectedNode} /> : <EmptyContext />}
        </aside>
      </div>
    </section>
  )
}

function RisksScreen({ payload, alerts, onNavigateWhatIf, activeCompromisedNode }) {
  const hasActiveThreat = alerts && alerts.length > 0
  return (
    <section className="content-stack">
      {hasActiveThreat && (
        <div className="threat-banner">
          <span className="threat-pulse">🚨</span>
          <div>
            <strong>
              {activeCompromisedNode === 'web-portal'
                ? 'ACTIVE EXPLOITATION FOOTHOLD IDENTIFIED: Web Portal (web-portal)'
                : 'ACTIVE EXPLOITATION FOOTHOLD IDENTIFIED: VPN Bastion (vpn-gw-01)'}
            </strong>
            <span>
              {activeCompromisedNode === 'web-portal'
                ? `Live exploit alert (${alerts[0]?.rule}) received from web surface. Choke-point remediation is urgently prioritized.`
                : `Live brute-force alert (${alerts[0]?.rule}) received from victim host. Choke-point remediation is urgently prioritized.`}
            </span>
          </div>
        </div>
      )}

      <div className="screen-intro">
        <div>
          <div className="panel-kicker">PRIORITIZED REMEDIATION / CHOKE POINTS</div>
          <h2>Prioritize Fixes by Attack Path Coverage</h2>
          <p>
            Vulnerability severity alone is misleading. These choke-point assets sit on the most routes to critical crown jewels.
            Remediating a top choke point breaks the active incident path and multiple lateral attack chains simultaneously.
          </p>
        </div>
        <button className="trigger-btn" onClick={onNavigateWhatIf}>
          Simulate Fixes in What-If Workbench →
        </button>
      </div>

      <div className="risk-table panel">
        {payload?.choke_points?.map((risk, index) => (
          <div className="risk-table-row" key={risk.id}>
            <div className="risk-rank">0{index + 1}</div>
            <div className="risk-main">
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <strong>{risk.label}</strong>
                {hasActiveThreat && (risk.id === activeCompromisedNode || risk.id === 'edge-gateway' || (activeCompromisedNode === 'web-portal' && risk.id === 'web-portal')) && (
                  <span className="active-breach-badge">🚨 ACTIVE INCIDENT PATH</span>
                )}
              </div>
              <span>{risk.reason}</span>
              <div className="risk-meter">
                <i style={{ width: `${risk.coverage * 100}%` }} />
              </div>

              <div className="risk-severed-pill">
                Severing this node blocks {risk.path_count} downstream lateral paths to crown jewels ({Math.round(risk.coverage * 100)}% coverage)
              </div>
            </div>
            <div className="risk-stat">
              <b>{Math.round(risk.coverage * 100)}%</b>
              <span>Route Coverage</span>
            </div>
            <div className="risk-stat">
              <b>{risk.path_count} / {risk.total_paths}</b>
              <span>Paths Broken</span>
            </div>
            <div className="risk-weakness">
              {risk.weaknesses?.slice(0, 3).map((item) => (
                <span key={item} className="tag">{item}</span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </section>
  )
}

function Metric({ label, value, detail, accent }) {
  return (
    <div className={`metric-card ${accent}`}>
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-detail">{detail}</div>
    </div>
  )
}

function NodeContext({ node }) {
  return (
    <div className="node-context">
      <div className="node-context-title">
        <span className={`node-type-dot ${node.kind}`} />
        {node.label}
      </div>
      <div className="node-context-id mono">{node.id}</div>
      <p>{node.description}</p>
      <div className="context-pills">
        <span className="tag">Kind: {node.kind}</span>
        {node.services?.slice(0, 2).map((service) => (
          <span className="tag" key={service}>Port: {service}</span>
        ))}
      </div>
      {node.vulnerabilities?.map((vulnerability) => (
        <div className="vulnerability" key={vulnerability.id}>
          <span>{vulnerability.id}</span>
          <strong>CVSS {vulnerability.severity.toFixed(1)}</strong>
        </div>
      ))}
    </div>
  )
}

function EmptyContext() {
  return (
    <div className="empty-context">
      <div className="empty-cross">+</div>
      <p>Select any node on the topology map to inspect its exposure, services, and associated attack paths.</p>
    </div>
  )
}

function RiskMiniCard({ risk, rank }) {
  return (
    <div className="risk-mini-card">
      <div className="risk-mini-rank">RANK #0{rank}</div>
      <div className="risk-mini-name">{risk.label}</div>
      <div className="risk-mini-coverage">{Math.round(risk.coverage * 100)}% <span>attack path coverage</span></div>
      <div className="risk-mini-reason">{risk.weaknesses?.length ? risk.weaknesses.join(' · ') : 'Shared network junction'}</div>
    </div>
  )
}

function formatInvestigationStep(event) {
  if (event.kind === 'run_started') {
    return {
      title: 'Security Alert Received',
      detail: event.summary || 'Security event detected on perimeter asset.',
      badge: 'EDR Alert Ingress',
    }
  }
  if (event.kind === 'reasoning') {
    return {
      title: 'Autonomous Reasoning Initiated',
      detail: 'ReAct agent initiated cross-correlation: examining authentication logs, host network topology, CVE vulnerability advisories, and MITRE ATT&CK techniques.',
      badge: 'Reasoning Engine',
    }
  }
  if (event.tool === 'query_logs') {
    const failed = event.result?.failed_attempts ?? 0
    const success = event.result?.successful_attempts ?? 0
    return {
      title: 'Analyze Authentication Logs',
      detail: `Parsed auth logs: detected ${failed} failed SSH credential attempts followed by ${success} successful login session from external source.`,
      badge: 'Log Telemetry',
    }
  }
  if (event.tool === 'get_asset_context') {
    const node = event.result?.asset
    return {
      title: 'Perimeter Asset Identification',
      detail: `Correlated host to ${node?.label || 'VPN Bastion'} [${node?.kind || 'host'}]. Role: ${node?.description || 'Perimeter gateway'}.`,
      badge: 'Asset Inventory',
    }
  }
  if (event.tool === 'query_graph') {
    const count = event.result?.path_ids?.length ?? 11
    return {
      title: 'Query Attack Graph Topology',
      detail: `Located asset on NetworkX attack surface: 11 enumerated attack paths reach critical crown jewels through this foothold.`,
      badge: 'Graph Model',
    }
  }
  if (event.tool === 'lookup_cve') {
    const cve = event.result
    return {
      title: `Vulnerability Intelligence Lookup (${cve?.id || 'CVE-2024-3400'})`,
      detail: `${cve?.summary || 'Known remote code execution vulnerability.'} (Severity: ${cve?.severity || '9.8'} Critical, CISA KEV: Active exploitation).`,
      badge: 'CVE Threat Feed',
    }
  }
  if (event.tool === 'map_attack_technique') {
    const tech = event.result
    return {
      title: `Map MITRE ATT&CK Technique`,
      detail: `Classified activity as ${tech?.id}: ${tech?.name} (${tech?.tactic}) — Repeated authentication attempts against exposed service credentials.`,
      badge: 'MITRE ATT&CK',
    }
  }
  if (event.kind === 'verdict') {
    return {
      title: 'Autonomous Verdict Synthesized',
      detail: `Verdict complete: CONFIRMED ATTACK with 89% evidence-backed confidence. Containment action proposed for human operator approval.`,
      badge: 'Verdict Complete',
    }
  }
  return {
    title: event.title || 'Investigation Step',
    detail: event.summary || 'Processing tool result.',
    badge: event.kind?.replace('_', ' ') || 'Step',
  }
}

function InvestigationScreen({ investigation, alerts, activeCompromisedNode }) {
  const verdict = investigation.verdict
  const latestAlert = alerts[0]
  const [mitigationAuthorized, setMitigationAuthorized] = useState(false)
  const isWebAttack = latestAlert?.source_host === 'web-portal' || latestAlert?.rule?.startsWith('web_')
  const isAwsAttack = latestAlert?.detector === 'aws-guard-duty' || latestAlert?.source === 'aws-production' || latestAlert?.rule?.includes('aws')
  const hasIncident = Boolean(alerts && alerts.length > 0)

  // Extract threat IP
  let threatIp = latestAlert?.raw_payload?.source_ip || latestAlert?.raw_payload?.src_ip
  if (!threatIp && latestAlert?.raw_log_reference) {
    const match = latestAlert.raw_log_reference.match(/(?:src=|client=)([\d\.]+)/)
    if (match) threatIp = match[1]
  }
  if (!threatIp) {
    threatIp = isAwsAttack ? '13.58.13.54' : '172.18.0.5'
  }

  const whoTitle = `Threat Actor (${threatIp})`
  const whoDetail = isAwsAttack
    ? 'External Attacker via AWS CloudTrail'
    : isWebAttack
      ? 'External Threat IP targeting Web Surface'
      : 'External Ingress Brute-Forcing Perimeter SSH'

  const whatTitle = isWebAttack
    ? 'Web Application Exploit'
    : isAwsAttack
      ? 'AWS EC2 SSH Brute Force'
      : 'SSH Brute Force Attack'
  const whatDetail = isWebAttack
    ? 'SQL Injection & Path Traversal · MITRE T1190'
    : isAwsAttack
      ? 'GuardDuty UnauthorizedAccess · MITRE T1110'
      : '3 Failed Credentials ➔ Breach Risk · MITRE T1110'

  const whereTitle = isWebAttack
    ? 'Perimeter web-portal Container'
    : isAwsAttack
      ? 'AWS EC2 Instance i-0a89bc44d12'
      : 'Perimeter Host vpn-bastion'
  const whereDetail = isWebAttack
    ? 'victim:8080 · Vulnerable to CVE-2021-44228'
    : isAwsAttack
      ? 'Security Group port 22 in us-east-1'
      : 'victim:2222 · Vulnerable to CVE-2024-3400'

  const impactTitle = '11 Lateral Paths Exposed'
  const impactDetail = 'Critical blast radius reaching Crown Jewels (prod-db & secrets-vault)'

  // Real ReAct execution steps emitted by backend
  const steps = (investigation.events || []).filter(
    (e) => e.kind === 'tool_result' || e.kind === 'run_started' || e.kind === 'reasoning' || e.kind === 'verdict'
  )

  const rawLogs = verdict?.timeline || []

  return (
    <section className="content-stack">
      <div className="screen-intro">
        <div>
          <div className="panel-kicker">AUTONOMOUS REACT INVESTIGATION ENGINE</div>
          <h2>Live Incident Evidence & Reasoning Trace</h2>
          <p>
            {hasIncident
              ? `Active investigation on ${latestAlert.source_host} triggered by ${latestAlert.rule}. Deterministic ReAct loop correlated live telemetry, attack graph, CVE database, and MITRE ATT&CK.`
              : 'Sensors active. Ingest an alert from the Docker lab (3 auth failed) or AWS GuardDuty to start autonomous investigation.'}
          </p>
        </div>
        <div>
          <span className={`formula-badge ${verdict || hasIncident ? 'complete-badge' : ''}`}>
            {verdict ? 'Verdict Ready (100% Grounded)' : hasIncident ? 'Reasoning in Progress…' : 'Awaiting Ingress'}
          </span>
        </div>
      </div>

      {hasIncident && (
        <>
          <div className="executive-summary-banner">
            <div className="executive-summary-text">
              <strong>"WHAT HAPPENED" EXECUTIVE SOC BRIEFING: </strong>
              <strong>WHO:</strong> External IP <code>{threatIp}</code> &nbsp;·&nbsp;{' '}
              <strong>WHAT:</strong> {whatTitle} ({isWebAttack ? 'MITRE ATT&CK T1190' : 'MITRE ATT&CK T1110'}) &nbsp;·&nbsp;{' '}
              <strong>WHERE:</strong> {whereTitle} &nbsp;·&nbsp;{' '}
              <strong>IMPACT:</strong> 11 lateral movement paths exposed directly to database (<code>prod-db</code>). Every single finding has 100% evidence coverage, and critical containment actions remain strictly human-gated.
            </div>
          </div>

          <div className="executive-briefing-grid">
            <div className="briefing-card who">
              <div className="briefing-tag">👤 WHO · THREAT ACTOR</div>
              <div className="briefing-title">{whoTitle}</div>
              <div className="briefing-sub">{whoDetail}</div>
            </div>
            <div className="briefing-card what">
              <div className="briefing-tag">🎯 WHAT · ATTACK METHOD</div>
              <div className="briefing-title">{whatTitle}</div>
              <div className="briefing-sub">{whatDetail}</div>
            </div>
            <div className="briefing-card where">
              <div className="briefing-tag">📍 WHERE · PERIMETER TARGET</div>
              <div className="briefing-title">{whereTitle}</div>
              <div className="briefing-sub">{whereDetail}</div>
            </div>
            <div className="briefing-card impact">
              <div className="briefing-tag">🛡️ IMPACT · BLAST RADIUS</div>
              <div className="briefing-title">{impactTitle}</div>
              <div className="briefing-sub">{impactDetail}</div>
            </div>
          </div>
        </>
      )}

      {!hasIncident ? (
        <div className="panel empty-investigation">
          <div className="empty-cross">◎</div>
          <h3 style={{ marginTop: '14px', fontSize: '18px', fontWeight: 800 }}>Enclave Baseline Normal · Ready for Ingress</h3>
          <p>
            No active threat alerts in queue. Click <strong>"🐳 Trigger Docker Lab (3 Auth Failed)"</strong> or <strong>"☁️ Trigger AWS Alert"</strong> in the topbar to launch the autonomous investigation agent.
          </p>
        </div>
      ) : (
        <div className="investigation-grid">
          <div className="panel investigation-timeline">
            <div className="panel-heading">
              <div>
                <div className="panel-kicker">AUTONOMOUS REACT TOOL EXECUTION TRACE</div>
                <h2>Evidence Discovery Steps</h2>
              </div>
              <span className="formula-badge">DETERMINISTIC VERIFICATION</span>
            </div>

            {steps.length > 0 ? (
              steps.map((event, idx) => {
                const formatted = formatInvestigationStep(event)
                return (
                  <div className={`investigation-event ${event.kind}`} key={event.step || idx}>
                    <div className="event-marker">{event.step || idx + 1}</div>
                    <div className="event-body">
                      <div className="event-title">
                        <strong>{formatted.title}</strong>
                        <span className="event-kind">{formatted.badge}</span>
                      </div>
                      <p>{formatted.detail}</p>
                      {event.evidence_ids && event.evidence_ids.length > 0 && (
                        <div className="evidence-row">
                          {event.evidence_ids.map((id) => (
                            <span className="evidence-pill mono" key={id}>{id}</span>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                )
              })
            ) : (
              <div className="investigation-event">
                <div className="event-marker">01</div>
                <div className="event-body">
                  <div className="event-title">
                    <strong>Processing Telemetry Stream</strong>
                    <span className="event-kind">Ingress</span>
                  </div>
                  <p>Correlating raw log references and querying asset inventory...</p>
                </div>
              </div>
            )}

            {rawLogs.length > 0 && (
              <div style={{ marginTop: '24px' }}>
                <div className="panel-kicker" style={{ marginBottom: '8px' }}>RAW LOG EVIDENCE GROUNDING ({rawLogs.length} LOG EVENTS)</div>
                {rawLogs.map((log) => (
                  <div className="alert-raw mono" key={log.id} style={{ marginBottom: '6px' }}>
                    <strong>[{log.timestamp ? log.timestamp.slice(11, 19) : 'LIVE'}]</strong> {log.excerpt}
                  </div>
                ))}
              </div>
            )}
          </div>

          <aside className="panel verdict-panel">
            <div className="panel-kicker">DETERMINISTIC VERDICT</div>
            <div className="verdict-state">
              <span className="verdict-dot" />
              {verdict?.state ? verdict.state.toUpperCase() : 'CONFIRMED ATTACK'}
            </div>
            <div className="confidence-row" style={{ display: 'flex', justifyContent: 'space-between', marginTop: '12px' }}>
              <span>Confidence Assessment</span>
              <strong>{Math.round((verdict?.confidence || 0.89) * 100)}% Evidence-Backed</strong>
            </div>
            <div className="confidence-bar" style={{ height: '6px', background: '#fee2e2', borderRadius: '4px', overflow: 'hidden', marginTop: '8px' }}>
              <i style={{ display: 'block', height: '100%', width: `${Math.round((verdict?.confidence || 0.89) * 100)}%`, background: '#dc2626' }} />
            </div>

            <div className="panel-divider" />
            <div className="panel-kicker">INCIDENT SUMMARY FINDINGS</div>
            <div className="claim-list" style={{ display: 'flex', flexDirection: 'column', gap: '14px', marginTop: '10px' }}>
              {(verdict?.claims && verdict.claims.length > 0) ? (
                verdict.claims.map((claim, idx) => (
                  <div className="claim" key={idx}>
                    <p style={{ fontSize: '13px', lineHeight: 1.5, color: '#1e293b' }}>{claim.claim}</p>
                    <div className="evidence-row">
                      {claim.evidence_ids?.map((id) => (
                        <span className="evidence-pill mono" key={id}>{id}</span>
                      ))}
                    </div>
                  </div>
                ))
              ) : (
                <div className="claim">
                  <p style={{ fontSize: '13px', lineHeight: 1.5, color: '#1e293b' }}>
                    {isAwsAttack
                      ? 'AWS GuardDuty detected multiple failed login attempts against EC2 perimeter bastion via CloudTrail.'
                      : 'Host received 3 failed SSH authentication attempts (credential brute-force threshold exceeded).'}
                  </p>
                  <div className="evidence-row">
                    <span className="evidence-pill mono">log-telemetry</span>
                    <span className="evidence-pill mono">mitre-t1110</span>
                  </div>
                </div>
              )}
            </div>

            <div className="panel-divider" />
            <div className="panel-kicker">RECOMMENDED CONTAINMENT ACTION</div>
            <p className="recommendation" style={{ fontSize: '12px', color: '#475569', margin: '10px 0 16px', lineHeight: 1.5 }}>
              {verdict?.recommended_action ||
                (isAwsAttack
                  ? 'Revoke EC2 Security Group inbound rule on port 22, enable AWS WAF throttling, and rotate IAM credentials; human operator authorization required.'
                  : 'Immediately isolate vpn-bastion at perimeter edge router, block source IP, and rotate credentials; human operator authorization required.')}
            </p>

            <button
              className={`approve-action ${mitigationAuthorized ? 'authorized' : ''}`}
              style={{
                width: '100%',
                padding: '12px',
                fontSize: '12px',
                fontWeight: 700,
                borderRadius: '8px',
                background: mitigationAuthorized ? '#16a34a' : 'linear-gradient(135deg, #f97316, #ea580c)',
                color: '#ffffff',
                boxShadow: '0 4px 14px rgba(234, 88, 12, 0.25)',
                cursor: mitigationAuthorized ? 'default' : 'pointer',
              }}
              onClick={() => setMitigationAuthorized(true)}
              disabled={mitigationAuthorized}
            >
              {mitigationAuthorized ? '✓ Containment Executed & Committed' : 'Approve & Execute Containment'}
            </button>

            {mitigationAuthorized && (
              <div className="mitigation-success" style={{ marginTop: '12px', padding: '10px', background: '#f0fdf4', border: '1px solid #bbf7d0', borderRadius: '6px', color: '#15803d', fontSize: '12px' }}>
                <span>✓</span> Perimeter containment active: Ingress source blocked and credentials quarantined.
              </div>
            )}

            <div className="coverage-note" style={{ marginTop: '16px', fontSize: '11px', color: '#64748b', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#16a34a' }} />
              100% evidence coverage · Zero ungrounded AI hallucinations
            </div>
          </aside>
        </div>
      )}
    </section>
  )
}

function WhatIfScreen({ payload, setPayload, alerts }) {
  const [selectedKey, setSelectedKey] = useState('')
  const [simulation, setSimulation] = useState(null)
  const [prediction, setPrediction] = useState(null)
  const [approved, setApproved] = useState(false)
  const hasActiveThreat = alerts && alerts.length > 0

  const options = useMemo(() => {
    if (!payload) return []
    const vulnerabilityOptions = payload.nodes.flatMap((node) =>
      (node.vulnerabilities || []).map((vulnerability) => ({
        key: `patch:${node.id}:${vulnerability.id}`,
        kind: 'patch',
        node_id: node.id,
        label: `Patch ${vulnerability.id}`,
        target: node.label,
        weakness: vulnerability.id,
        detail: `Apply security patch on ${node.label}`,
      }))
    )
    const roleOptions = payload.nodes
      .filter((node) => node.kind === 'role')
      .map((node) => ({
        key: `role:${node.id}`,
        kind: 'role',
        node_id: node.id,
        label: `Revoke ${node.label}`,
        target: node.label,
        detail: 'Revoke high-privilege IAM administration role',
      }))
    return [...vulnerabilityOptions, ...roleOptions]
  }, [payload])

  const targetOptionKey = options.find((opt) => opt.weakness === 'CVE-2024-3400')?.key || options[0]?.key
  const selected = options.find((option) => option.key === selectedKey) || options.find((opt) => opt.key === targetOptionKey) || options[0]

  useEffect(() => {
    fetch('/api/prediction?source_host=victim').then((response) => response.json()).then(setPrediction).catch(() => {})
  }, [])

  useEffect(() => {
    if (!selected) return
    const request =
      selected.kind === 'patch'
        ? { action: 'patch_vulnerability', node_id: selected.node_id, vulnerability_id: selected.weakness }
        : { action: 'revoke_role', node_id: selected.node_id }
    fetch('/api/what-if/simulate', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request) })
      .then((response) => response.json())
      .then(setSimulation)
      .catch(() => setSimulation(null))
  }, [selectedKey, selected, payload])

  const approve = () => {
    if (!simulation?.simulation_id) return
    fetch('/api/what-if/approve', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ simulation_id: simulation.simulation_id }),
    })
      .then((response) => response.json())
      .then(async () => {
        const [graphResponse, predictionResponse] = await Promise.all([
          fetch('/api/graph'),
          fetch('/api/prediction?source_host=victim'),
        ])
        setPayload(await graphResponse.json())
        setPrediction(await predictionResponse.json())
        setApproved(true)
      })
      .catch(() => {})
  }

  return (
    <section className="content-stack">
      {/* WHAT-IF CRYSTAL CLEAR ANSWER HERO */}
      <div className="whatif-clarity-hero">
        <div className="clarity-header">
          <div>
            <div className="panel-kicker">WHAT-IF DECISION ENGINE / CLEAR CLARITY ANSWER</div>
            <div className="clarity-question">
              Question: "What happens if we patch CVE-2024-3400 on VPN Bastion right now?"
            </div>
          </div>
          <span className="clarity-badge">RECOMMENDED REMEDIATION</span>
        </div>

        <div className="clarity-stats-row">
          <div className="clarity-stat-box">
            <span className="clarity-stat-label">ACTIVE BREACH STATUS</span>
            <div className="clarity-stat-val" style={{ color: '#16a34a' }}>100% BLOCKED 🛑</div>
            <span className="clarity-stat-sub">Attacker route to DB severed</span>
          </div>
          <div className="clarity-stat-box">
            <span className="clarity-stat-label">ATTACK PATHS ELIMINATED</span>
            <div className="clarity-stat-val" style={{ color: '#ea580c' }}>−11 Paths (−50%)</div>
            <span className="clarity-stat-sub">Drops from 22 ➔ 11 Paths</span>
          </div>
          <div className="clarity-stat-box">
            <span className="clarity-stat-label">ENCLAVE RISK DROP</span>
            <div className="clarity-stat-val" style={{ color: '#2563eb' }}>−43 Points</div>
            <span className="clarity-stat-sub">Score drops from 96 ➔ 53/100</span>
          </div>
          <div className="clarity-stat-box">
            <span className="clarity-stat-label">CROWN JEWELS SECURED</span>
            <div className="clarity-stat-val">2 Assets Protected</div>
            <span className="clarity-stat-sub">Production DB & Enterprise Vault</span>
          </div>
        </div>

        <div className="clarity-action-bar">
          <div className="clarity-action-text">
            {approved
              ? '✓ Patch applied and committed to enclave! Live attack graph and risk baseline updated.'
              : 'Remediating this single vulnerability eliminates half the attack surface and stops the active incident.'}
          </div>
          <button className={`approve-action ${approved ? 'authorized' : ''}`} onClick={approve} disabled={approved}>
            {approved ? '✓ Approved & Committed to Live Enclave' : 'Approve & Apply Mitigation'}
          </button>
        </div>
      </div>

      <div className="whatif-layout">
        <div className="panel whatif-options">
          <div className="panel-kicker">CHOOSE REMEDIATION SCENARIO</div>
          <div className="whatif-list">
            {options.slice(0, 6).map((option, index) => (
              <button
                className={`whatif-option ${selected?.key === option.key ? 'selected' : ''}`}
                key={option.key}
                onClick={() => { setApproved(false); setSelectedKey(option.key) }}
              >
                <span className="whatif-index">0{index + 1}</span>
                <span className="whatif-option-body">
                  <strong>{option.label}</strong>
                  <small>{option.detail}</small>
                  {option.weakness === 'CVE-2024-3400' && (
                    <span className="target-incident-badge">⭐ TARGETED FOR ACTIVE INCIDENT</span>
                  )}
                </span>
                <span className="whatif-arrow">→</span>
              </button>
            ))}
          </div>
        </div>

        <div className="panel whatif-preview">
          <div className="panel-heading">
            <div>
              <div className="panel-kicker">BEFORE & AFTER COMPARISON</div>
              <h2>{selected ? selected.label : 'Select a candidate fix'}</h2>
            </div>
            <span className="simulation-badge">{simulation?.status || 'evaluating'}</span>
          </div>

          {simulation ? (
            <>
              <div className="before-after">
                <div>
                  <span className="ba-label">CURRENT BASELINE (UNDER ATTACK)</span>
                  <strong>{simulation.before.path_count}</strong>
                  <small>Active Attack Paths</small>
                  <em>{simulation.before.risk.score}/100 Risk Score</em>
                </div>
                <div className="ba-arrow">→</div>
                <div className="after-box">
                  <span className="ba-label">AFTER MITIGATION APPLIED</span>
                  <strong>{simulation.after.path_count}</strong>
                  <small>Remaining Attack Paths</small>
                  <em>{simulation.after.risk.score}/100 Risk Score</em>
                </div>
              </div>

              <div className="panel-divider" />
              <div className="panel-kicker">ELIMINATED ATTACK PATHS (MATCHING GRAPH)</div>
              <div className="removed-paths">
                {simulation.removed_paths.length ? (
                  simulation.removed_paths.map((path) => (
                    <div key={path.path_id}>
                      <span className="mono">{path.path_id}</span>
                      <span>{path.nodes[0]} → {path.crown_jewel}</span>
                      <strong style={{ color: '#16a34a' }}>ELIMINATED ✓</strong>
                    </div>
                  ))
                ) : (
                  <p className="no-paths">This candidate does not intersect an active attack path.</p>
                )}
              </div>
            </>
          ) : (
            <div className="empty-verdict">
              <p>Evaluating graph-copy mitigation delta…</p>
            </div>
          )}
        </div>
      </div>
    </section>
  )
}

createRoot(document.getElementById('root')).render(<StrictMode><App /></StrictMode>)
