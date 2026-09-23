'use client'

import { FormEvent, useEffect, useMemo, useRef, useState } from 'react'
import { Check, ChevronDown, ChevronUp, Download, FileCode2, Gauge, LogOut, ShieldCheck, Sparkles, UploadCloud } from 'lucide-react'

type View = 'login' | 'upload' | 'processing' | 'results'

type Finding = {
  severity: 'Critical' | 'High' | 'Medium' | 'Low'
  title: string
  category: string
  explanation: string
  detected: string
  recommended: string
}

type ScanResult = {
  reportId: string
  scanName: string
  fileName: string
  analyzedAt: string
  score: number
  grade: string
  severityCounts: {
    Critical: number
    High: number
    Medium: number
    Low: number
  }
  aiSummary: string
  findings: Finding[]
  technicalDetails: string
}

const defaultFindings: Finding[] = [
  { severity: 'Critical', title: 'Weak pre-shared key detected', category: 'Authentication', explanation: 'The configured key is short enough to be exposed to practical dictionary and brute-force attacks.', detected: 'vpn-key-2024', recommended: 'Use a 32+ character random secret' },
  { severity: 'High', title: 'Aggressive mode is enabled', category: 'IKE negotiation', explanation: 'Aggressive mode reveals identity information during IKE phase 1 and reduces negotiation privacy.', detected: 'aggressive-mode', recommended: 'Use main mode with IKEv2' },
  { severity: 'Medium', title: 'Legacy encryption proposal', category: 'Cryptography', explanation: '3DES remains enabled in the proposal set and should be removed from modern deployments.', detected: '3des-sha1', recommended: 'AES-256-GCM with SHA-256' },
  { severity: 'Low', title: 'DPD interval is conservative', category: 'Availability', explanation: 'The dead peer detection interval may delay recovery when a tunnel endpoint becomes unavailable.', detected: '180 seconds', recommended: 'Set interval to 30–60 seconds' },
]

const severityStyles: Record<string, string> = {
  Critical: 'border-[#e58a78]/35 bg-[#e58a78]/10 text-[#f1ad9d]',
  High: 'border-[#d9a06a]/35 bg-[#d9a06a]/10 text-[#f0bd86]',
  Medium: 'border-[#c1b276]/35 bg-[#c1b276]/10 text-[#d8ca91]',
  Low: 'border-[#93a56f]/35 bg-[#93a56f]/10 text-[#c1d19d]',
}

function Backdrop() {
  return (
    <>
      <div className="pointer-events-none fixed inset-0 bg-[#111310]" />
      <div className="pointer-events-none fixed -left-40 -top-40 size-[36rem] rounded-full bg-[#b47a45]/[0.13] blur-[130px]" />
      <div className="pointer-events-none fixed -bottom-56 -right-40 size-[38rem] rounded-full bg-[#68755a]/[0.14] blur-[140px]" />
      <div className="pointer-events-none fixed inset-0 opacity-[0.035] [background-image:linear-gradient(rgba(242,240,233,.7)_1px,transparent_1px),linear-gradient(90deg,rgba(242,240,233,.7)_1px,transparent_1px)] [background-size:42px_42px]" />
    </>
  )
}

function Brand() {
  return (
    <div className="flex items-center gap-3">
      <div className="grid size-10 place-items-center rounded-xl border border-[#d59a61]/30 bg-[#d59a61]/[0.1] text-[#e0a66d]">
        <ShieldCheck className="size-5" />
      </div>
      <div>
        <p className="text-sm font-semibold text-[#f5f1e8]">IPsec Analyzer</p>
        <p className="text-xs text-[#858a7e]">Security workspace</p>
      </div>
    </div>
  )
}

function Topbar({ onLogout }: { onLogout: () => void }) {
  return (
    <header className="relative z-10 flex items-center justify-between border-b border-[#e4d7c2]/[0.12] pb-5">
      <Brand />
      <button
        onClick={onLogout}
        className="flex items-center gap-2 rounded-lg border border-[#e4d7c2]/[0.16] px-3 py-2 text-xs font-medium text-[#c9c7bd] transition hover:border-[#d9a06a]/50 hover:text-[#f0bd86]"
      >
        <LogOut className="size-3.5" /> Sign out
      </button>
    </header>
  )
}

function Login({ onSuccess }: { onSuccess: () => void }) {
  const [error, setError] = useState('')
  const form = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    const data = new FormData(event.currentTarget)
    if (data.get('localId') === '100' && data.get('password') === 'ABC') {
      onSuccess()
    } else {
      setError('Use demo ID 100 and password ABC.')
    }
  }

  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden px-5 py-10 text-[#f2f0e9]">
      <Backdrop />
      <section className="animate-login-in relative z-10 w-full max-w-[430px] rounded-[1.35rem] border border-[#e4d7c2]/[0.14] bg-[#1a1d18]/95 p-7 shadow-[0_26px_90px_rgba(0,0,0,.42)] sm:p-9">
        <div className="mb-8 flex justify-between">
          <Brand />
          <span className="h-fit rounded-full border border-[#aeb69f]/20 bg-[#aeb69f]/[0.08] px-3 py-1 text-[10px] font-medium uppercase tracking-[0.16em] text-[#bfc7ae]">
            Secure access
          </span>
        </div>
        <h1 className="text-[27px] font-semibold tracking-[-0.04em]">Welcome back</h1>
        <p className="mt-2 text-sm leading-6 text-[#a8aaa0]">
          Sign in to continue to your IPsec security workspace.
        </p>
        <form onSubmit={form} className="mt-8 space-y-5">
          <label className="block text-xs font-medium text-[#d0cec4]">
            Local ID
            <input
              name="localId"
              required
              inputMode="numeric"
              placeholder="Enter your local ID"
              className="login-input mt-2 h-12 w-full rounded-xl border border-[#e4d7c2]/[0.14] bg-[#111310]/80 px-4 text-sm text-[#f5f1e8] outline-none placeholder:text-[#6f746a]"
            />
          </label>
          <label className="block text-xs font-medium text-[#d0cec4]">
            Password
            <input
              name="password"
              required
              type="password"
              placeholder="Enter your password"
              className="login-input mt-2 h-12 w-full rounded-xl border border-[#e4d7c2]/[0.14] bg-[#111310]/80 px-4 text-sm text-[#f5f1e8] outline-none placeholder:text-[#6f746a]"
            />
          </label>
          <button className="login-button h-12 w-full rounded-xl bg-[#c88750] text-sm font-semibold text-[#20160f] transition hover:bg-[#dda16a]">
            Sign in to workspace
          </button>
          {error && (
            <p role="alert" className="rounded-xl border border-[#c87862]/30 bg-[#c87862]/[0.08] px-4 py-3 text-center text-xs text-[#e6aa98]">
              {error}
            </p>
          )}
          <p className="text-center text-xs text-[#8f9688]">
            Demo credentials: ID <b className="text-[#d9a06a]">100</b> · password <b className="text-[#d9a06a]">ABC</b>
          </p>
        </form>
      </section>
    </main>
  )
}

function Upload({
  onStart,
  onLogout,
  error,
}: {
  onStart: (file: File, scanName: string) => void
  onLogout: () => void
  error?: string | null
}) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [scanName, setScanName] = useState('')
  const input = useRef<HTMLInputElement>(null)

  const choose = (f?: File) => {
    if (f) setSelectedFile(f)
  }

  return (
    <main className="relative min-h-screen overflow-hidden px-5 py-8 text-[#f2f0e9] sm:px-8">
      <Backdrop />
      <div className="relative z-10 mx-auto max-w-5xl">
        <Topbar onLogout={onLogout} />
        <section className="mx-auto max-w-3xl py-14 text-center sm:py-20">
          <p className="mb-4 text-xs font-medium uppercase tracking-[0.2em] text-[#bfc7ae]">
            Configuration intelligence
          </p>
          <h1 className="text-4xl font-semibold tracking-[-0.055em] text-[#f5f1e8] sm:text-6xl">
            New <span className="text-[#d9a06a]">Security Analysis</span>
          </h1>
          <p className="mx-auto mt-5 max-w-xl text-sm leading-6 text-[#a8aaa0]">
            Upload a packet capture or IPsec configuration and let the analyzer surface the risks that matter.
          </p>

          {error && (
            <div className="mt-8 rounded-2xl border border-[#e58a78]/40 bg-[#e58a78]/10 p-4 text-center text-sm text-[#f1ad9d]">
              {error}
            </div>
          )}

          <div
            onDragOver={(e) => e.preventDefault()}
            onDrop={(e) => {
              e.preventDefault()
              if (e.dataTransfer.files[0]) choose(e.dataTransfer.files[0])
            }}
            onClick={() => input.current?.click()}
            className={`upload-zone mt-10 cursor-pointer rounded-3xl border p-10 text-center transition sm:p-16 ${
              selectedFile
                ? 'border-[#93a56f]/60 bg-[#93a56f]/[0.08]'
                : 'border-[#d9a06a]/35 bg-[#1a1d18]/75 hover:border-[#d9a06a]/70 hover:bg-[#d9a06a]/[0.06]'
            }`}
          >
            <input
              ref={input}
              type="file"
              accept=".pcap,.pcapng,.conf,.cfg,.txt"
              className="hidden"
              onChange={(e) => choose(e.target.files?.[0])}
            />
            {selectedFile ? (
              <div className="animate-file-in">
                <div className="mx-auto grid size-16 place-items-center rounded-2xl bg-[#93a56f]/15 text-[#c1d19d]">
                  <Check className="size-8" />
                </div>
                <p className="mt-5 text-lg font-semibold text-[#f5f1e8]">{selectedFile.name}</p>
                <p className="mt-2 text-sm text-[#9da991]">
                  {(selectedFile.size / 1024).toFixed(1)} KB · Ready for secure analysis · Click to replace
                </p>
              </div>
            ) : (
              <>
                <div className="upload-icon mx-auto grid size-20 place-items-center rounded-3xl border border-[#d9a06a]/30 bg-[#d9a06a]/[0.1] text-[#e0a66d]">
                  <UploadCloud className="size-9" />
                </div>
                <p className="mt-7 text-2xl font-semibold text-[#f5f1e8]">Drag & drop your file here</p>
                <p className="mt-3 text-sm text-[#a8aaa0]">
                  or <span className="font-semibold text-[#e0a66d]">click to browse</span> · PCAP, CFG, CONF
                </p>
              </>
            )}
          </div>

          <div className="mt-4 flex justify-center">
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                const sampleText = `# Sample StrongSwan / Libreswan IPsec Configuration for Testing
conn production-vpn
    authby=secret
    keyexchange=ikev1
    ike=3des-sha1-modp1024
    esp=aes256-sha1
    aggressive=yes
    dpddelay=180s
    dpdaction=restart
    ikelifetime=8h
    keylife=1h
    left=192.168.1.1
    leftsubnet=10.0.0.0/24
    right=203.0.113.5
    rightsubnet=10.1.0.0/24
    auto=start
`
                const sampleFile = new File([sampleText], 'sample-ipsec.conf', { type: 'text/plain' })
                choose(sampleFile)
                if (!scanName) {
                  setScanName('Sample Production VPN Audit')
                }
              }}
              className="inline-flex items-center gap-2 rounded-xl border border-[#d9a06a]/30 bg-[#d9a06a]/[0.08] px-4 py-2 text-xs font-semibold text-[#f0bd86] transition hover:border-[#d9a06a]/60 hover:bg-[#d9a06a]/[0.18]"
            >
              <Sparkles className="size-3.5" />
              Load Sample IPsec Configuration (.conf)
            </button>
          </div>

          <label className="mt-6 block text-left text-xs font-medium text-[#d0cec4]">
            Scan name
            <input
              id="scan-name"
              value={scanName}
              onChange={(e) => setScanName(e.target.value)}
              placeholder="e.g. Production VPN review"
              className="login-input mt-2 h-14 w-full rounded-xl border border-[#e4d7c2]/[0.14] bg-[#1a1d18]/80 px-4 text-base text-[#f5f1e8] outline-none placeholder:text-[#6f746a]"
            />
          </label>

          <button
            disabled={!selectedFile}
            onClick={() => selectedFile && onStart(selectedFile, scanName)}
            className="mt-6 h-14 w-full rounded-xl bg-[#c88750] text-sm font-semibold text-[#20160f] shadow-[0_10px_30px_rgba(200,135,80,.18)] transition hover:scale-[1.01] hover:bg-[#dda16a] disabled:cursor-not-allowed disabled:opacity-35"
          >
            Run Analysis <span className="ml-2">→</span>
          </button>
        </section>
      </div>
    </main>
  )
}

function Processing() {
  const [status, setStatus] = useState(0)
  const statuses = [
    'Parsing protocol structure...',
    'Checking security parameters...',
    'Running AI analysis...',
    'Finalizing report...',
  ]

  useEffect(() => {
    const timer = setInterval(() => {
      setStatus((s) => (s < 3 ? s + 1 : s))
    }, 1200)
    return () => clearInterval(timer)
  }, [])

  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden px-5 text-center text-[#f2f0e9]">
      <Backdrop />
      <section className="relative z-10">
        <div className="radar mx-auto grid size-56 place-items-center rounded-full border border-[#d9a06a]/25">
          <div className="grid size-36 place-items-center rounded-full border border-[#93a56f]/30 bg-[#1a1d18]/80 shadow-[0_0_70px_rgba(217,160,106,.16)]">
            <Gauge className="size-14 text-[#e0a66d]" />
          </div>
        </div>
        <h1 className="mt-12 text-3xl font-semibold tracking-[-0.04em] sm:text-4xl">
          Analyzing your configuration<span className="text-[#d9a06a]">...</span>
        </h1>
        <p className="mt-4 h-6 text-sm text-[#a8aaa0]">{statuses[status]}</p>
        <div className="mx-auto mt-8 h-1.5 w-64 overflow-hidden rounded-full bg-[#e4d7c2]/10">
          <div
            className="progress-bar h-full rounded-full bg-[#c88750]"
            style={{ width: `${(status + 1) * 25}%` }}
          />
        </div>
        <p className="mt-4 text-xs uppercase tracking-[0.2em] text-[#777d72]">
          Secure processing · {Math.min((status + 1) * 25, 100)}%
        </p>
      </section>
    </main>
  )
}

function Results({
  data,
  onNew,
  onLogout,
}: {
  data: ScanResult
  onNew: () => void
  onLogout: () => void
}) {
  const [filter, setFilter] = useState('All')
  const [open, setOpen] = useState<number | null>(0)

  const findingsList = data.findings && data.findings.length > 0 ? data.findings : defaultFindings
  const visible = useMemo(
    () => (filter === 'All' ? findingsList : findingsList.filter((f) => f.severity === filter)),
    [filter, findingsList]
  )

  const downloadUrl = `/api/reports/${data.reportId}.pdf`

  return (
    <main className="relative min-h-screen overflow-hidden px-5 py-8 text-[#f2f0e9] sm:px-8">
      <Backdrop />
      <div className="relative z-10 mx-auto max-w-6xl">
        <Topbar onLogout={onLogout} />

        <div className="flex flex-col justify-between gap-5 py-10 sm:flex-row sm:items-end">
          <div>
            <p className="text-xs uppercase tracking-[0.18em] text-[#bfc7ae]">
              Analysis complete · {data.analyzedAt}
            </p>
            <h1 className="mt-3 text-3xl font-semibold tracking-[-0.05em] sm:text-5xl">
              {data.scanName}
            </h1>
            <p className="mt-2 text-sm text-[#a8aaa0]">
              {data.fileName} · AI security assessment
            </p>
          </div>
          <div className="flex gap-3">
            <a
              href={downloadUrl}
              target="_blank"
              rel="noopener noreferrer"
              download
              className="flex items-center gap-2 rounded-xl bg-[#c88750] px-4 py-3 text-xs font-semibold text-[#20160f] transition hover:bg-[#dda16a]"
            >
              <Download className="size-4" /> Download PDF
            </a>
            <button
              onClick={onNew}
              className="rounded-xl border border-[#e4d7c2]/20 px-4 py-3 text-xs font-semibold text-[#e2e0d7] transition hover:border-[#d9a06a]/50"
            >
              New Analysis
            </button>
          </div>
        </div>

        <section className="grid gap-5 lg:grid-cols-[280px_1fr]">
          <div className="rounded-3xl border border-[#e4d7c2]/[0.14] bg-[#1a1d18]/80 p-7 text-center">
            <div
              className="score-ring mx-auto grid size-48 place-items-center rounded-full"
              style={{
                background: `conic-gradient(#c88750 0 ${data.score}%, rgba(228,215,194,.09) ${data.score}% 100%)`,
              }}
            >
              <div className="grid size-36 place-items-center rounded-full bg-[#151713]">
                <div>
                  <p className="text-5xl font-semibold text-[#f5f1e8]">{data.score}</p>
                  <p className="text-xs uppercase tracking-[0.18em] text-[#d9a06a]">{data.grade}</p>
                </div>
              </div>
            </div>
            <div className="mt-7 grid grid-cols-2 gap-2 text-left">
              {(['Critical', 'High', 'Medium', 'Low'] as const).map((s) => (
                <div key={s} className={`rounded-xl border p-3 ${severityStyles[s]}`}>
                  <p className="text-[10px] uppercase tracking-wider opacity-75">{s}</p>
                  <p className="mt-1 text-xl font-semibold">{data.severityCounts?.[s] ?? 0}</p>
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-3xl border border-[#d9a06a]/25 bg-gradient-to-br from-[#d9a06a]/[0.09] to-[#1a1d18]/80 p-7">
            <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-[0.16em] text-[#e0a66d]">
              <Sparkles className="size-4" /> AI assessment
            </div>
            <p className="mt-6 max-w-2xl text-xl leading-9 text-[#eee9dd]">
              {data.aiSummary}
            </p>
          </div>
        </section>

        <section className="mt-12">
          <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-center">
            <h2 className="text-2xl font-semibold">
              Findings <span className="text-[#777d72]">({visible.length})</span>
            </h2>
            <div className="flex flex-wrap gap-2">
              {['All', 'Critical', 'High', 'Medium', 'Low'].map((f) => (
                <button
                  key={f}
                  onClick={() => setFilter(f)}
                  className={`rounded-full border px-3 py-1.5 text-xs font-semibold transition ${
                    filter === f
                      ? 'border-[#d9a06a]/60 bg-[#d9a06a]/15 text-[#f0bd86] shadow-[0_0_18px_rgba(217,160,106,.12)]'
                      : 'border-[#e4d7c2]/15 text-[#858a7e] hover:text-[#e2e0d7]'
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>

          <div className="mt-5 space-y-3">
            {visible.map((finding) => {
              const index = findingsList.indexOf(finding)
              const isOpen = open === index
              return (
                <article
                  key={`${finding.title}-${index}`}
                  className="rounded-2xl border border-[#e4d7c2]/[0.13] bg-[#1a1d18]/75 transition hover:-translate-y-0.5 hover:border-[#d9a06a]/35"
                >
                  <button
                    onClick={() => setOpen(isOpen ? null : index)}
                    className="flex w-full items-center gap-4 p-5 text-left"
                  >
                    <span className={`rounded-full border px-2.5 py-1 text-[10px] font-semibold uppercase tracking-wider ${severityStyles[finding.severity]}`}>
                      {finding.severity}
                    </span>
                    <span className="flex-1 font-semibold text-[#f2f0e9]">
                      {finding.title}
                      <span className="ml-3 text-xs font-normal text-[#858a7e]">{finding.category}</span>
                    </span>
                    {isOpen ? <ChevronUp className="size-4 text-[#858a7e]" /> : <ChevronDown className="size-4 text-[#858a7e]" />}
                  </button>
                  {isOpen && (
                    <div className="border-t border-[#e4d7c2]/10 px-5 pb-5 pt-4 text-sm leading-6 text-[#a8aaa0]">
                      <p>{finding.explanation}</p>
                      <div className="mt-4 grid gap-3 sm:grid-cols-2">
                        <div className="rounded-xl bg-[#111310]/70 p-4">
                          <p className="text-[10px] uppercase tracking-wider text-[#777d72]">Detected</p>
                          <p className="mt-1 font-mono text-[#e0a66d]">{finding.detected}</p>
                        </div>
                        <div className="rounded-xl bg-[#111310]/70 p-4">
                          <p className="text-[10px] uppercase tracking-wider text-[#777d72]">Recommended</p>
                          <p className="mt-1 font-mono text-[#c1d19d]">{finding.recommended}</p>
                        </div>
                      </div>
                    </div>
                  )}
                </article>
              )
            })}
          </div>
        </section>

        {data.technicalDetails && (
          <section className="mt-10 rounded-2xl border border-[#e4d7c2]/[0.14] bg-[#1a1d18]/75 p-5">
            <div className="flex items-center gap-3 text-sm font-semibold">
              <FileCode2 className="size-4 text-[#d9a06a]" /> Technical details
            </div>
            <pre className="mt-4 overflow-auto rounded-xl bg-[#0d0f0c] p-4 font-mono text-xs leading-6 text-[#a8aaa0]">
              {data.technicalDetails}
            </pre>
          </section>
        )}
      </div>
    </main>
  )
}

export default function Page() {
  const [view, setView] = useState<View>('login')
  const [scanResult, setScanResult] = useState<ScanResult | null>(null)
  const [uploadError, setUploadError] = useState<string | null>(null)

  const handleStartAnalysis = async (file: File, scanName: string) => {
    setUploadError(null)
    setView('processing')
    const startTime = Date.now()

    const formData = new FormData()
    formData.append('file', file)
    if (scanName && scanName.trim()) {
      formData.append('scanName', scanName.trim())
    }

    try {
      let response: Response | null = null

      // 1. Try Next.js rewrites proxy (/api/analyze)
      try {
        const proxyRes = await fetch('/api/analyze', {
          method: 'POST',
          body: formData,
        })
        if (proxyRes.ok) {
          response = proxyRes
        } else if (proxyRes.status !== 502 && proxyRes.status !== 504 && proxyRes.status !== 500) {
          response = proxyRes
        }
      } catch (proxyErr) {
        console.warn('Next.js proxy route failed, attempting direct backend connection...', proxyErr)
      }

      // 2. If proxy was unreachable or failed, try direct FastAPI backend at http://127.0.0.1:8000
      if (!response || !response.ok) {
        try {
          const directRes = await fetch('http://127.0.0.1:8000/api/analyze', {
            method: 'POST',
            body: formData,
          })
          if (directRes.ok || !response) {
            response = directRes
          }
        } catch (directErr) {
          console.warn('Direct backend connection failed:', directErr)
        }
      }

      if (!response) {
        throw new Error(
          'Failed to fetch: Cannot connect to the IPsec backend on port 8000. Please start the backend by running start_backend.bat or start_all.bat.'
        )
      }

      if (!response.ok) {
        const err = await response.json().catch(() => ({}))
        throw new Error(err.detail || `Server error during analysis (${response.status})`)
      }

      const data: ScanResult = await response.json()

      // Allow at least 1.6s for the radar progress animation to present smoothly
      const elapsed = Date.now() - startTime
      const delay = Math.max(0, 1600 - elapsed)

      setTimeout(() => {
        setScanResult(data)
        setView('results')
      }, delay)
    } catch (err: any) {
      console.error('Scan error:', err)
      const errorMsg =
        err.message?.includes('Failed to fetch') || err.message?.includes('NetworkError')
          ? 'Backend offline: Cannot reach http://127.0.0.1:8000. Please launch the backend server using start_backend.bat or start_all.bat.'
          : err.message || 'Failed to connect to backend at http://127.0.0.1:8000. Is the server running?'
      setUploadError(errorMsg)
      setView('upload')
    }
  }

  if (view === 'login') return <Login onSuccess={() => setView('upload')} />
  if (view === 'upload') {
    return (
      <Upload
        error={uploadError}
        onStart={handleStartAnalysis}
        onLogout={() => {
          setUploadError(null)
          setView('login')
        }}
      />
    )
  }
  if (view === 'processing') return <Processing />
  if (view === 'results' && scanResult) {
    return (
      <Results
        data={scanResult}
        onNew={() => setView('upload')}
        onLogout={() => {
          setScanResult(null)
          setView('login')
        }}
      />
    )
  }

  return (
    <Upload
      error={uploadError}
      onStart={handleStartAnalysis}
      onLogout={() => setView('login')}
    />
  )
}
