import { useState, useEffect, useMemo, useCallback } from 'react'
import './App.css'

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000'

// Login Component - Full Screen
function LoginPage({ onLogin }) {
  const [credentials, setCredentials] = useState({ username: '', password: '' })
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState('')

  const handleLogin = async (e) => {
    e.preventDefault()
    setIsLoading(true)
    setError('')
    try {
      const response = await fetch(`${API_BASE_URL}/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(credentials)
      })

      if (!response.ok) {
        const data = await response.json().catch(() => ({}))
        throw new Error(data.error || 'Authentication failed')
      }

      const data = await response.json()
      onLogin(data.token, data.username, data.expires_in)
    } catch (err) {
      setError(err.message || 'Unable to authenticate')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-primary-900 to-indigo-900 flex items-center justify-center relative overflow-hidden">
      {/* Animated background elements */}
      <div className="absolute inset-0">
        <div className="absolute top-0 left-0 w-72 h-72 bg-primary-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-blob"></div>
        <div className="absolute top-0 right-0 w-72 h-72 bg-purple-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-blob animation-delay-2000"></div>
        <div className="absolute -bottom-8 left-20 w-72 h-72 bg-indigo-500 rounded-full mix-blend-multiply filter blur-xl opacity-20 animate-blob animation-delay-4000"></div>
      </div>
      
      <div className="relative z-10 w-full max-w-md px-6">
        <div className="bg-white/95 backdrop-blur-xl rounded-2xl shadow-2xl border border-white/20 p-8 animate-slide-up">
          {/* Logo and header */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-gradient-to-br from-primary-500 to-primary-600 rounded-2xl mb-4 shadow-lg animate-glow">
              <svg className="w-8 h-8 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 2.676-1.148 6-4.178 6-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <h1 className="text-3xl font-bold bg-gradient-to-r from-primary-600 to-indigo-600 bg-clip-text text-transparent mb-2">
              Sentinel Security
            </h1>
            <p className="text-secondary-600 font-medium">Advanced Network Protection</p>
          </div>
          
          {/* Login form */}
          <form onSubmit={handleLogin} className="space-y-6">
            <div className="space-y-4">
              <div className="relative">
                <label className="block text-sm font-medium text-secondary-700 mb-2">Username</label>
                <input
                  type="text"
                  value={credentials.username}
                  onChange={(e) => setCredentials({...credentials, username: e.target.value})}
                  className="w-full px-4 py-3 bg-secondary-50 border border-secondary-200 rounded-xl focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-all duration-300 placeholder-secondary-400"
                  placeholder="Enter your username"
                  required
                />
              </div>
              <div className="relative">
                <label className="block text-sm font-medium text-secondary-700 mb-2">Password</label>
                <input
                  type="password"
                  value={credentials.password}
                  onChange={(e) => setCredentials({...credentials, password: e.target.value})}
                  className="w-full px-4 py-3 bg-secondary-50 border border-secondary-200 rounded-xl focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-all duration-300 placeholder-secondary-400"
                  placeholder="Enter your password"
                  required
                />
              </div>
            </div>
            
            <button
              type="submit"
              disabled={isLoading}
              className="w-full bg-gradient-to-r from-primary-500 to-primary-600 text-white font-semibold py-3 px-6 rounded-xl hover:from-primary-600 hover:to-primary-700 focus:ring-4 focus:ring-primary-200 transition-all duration-300 disabled:opacity-50 transform hover:scale-[1.02] shadow-lg"
            >
              {isLoading ? (
                <div className="flex items-center justify-center">
                  <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                  </svg>
                  Authenticating...
                </div>
              ) : (
                'Access Security Platform'
              )}
            </button>
          </form>
          
          {/* Footer */}
          <div className="mt-8 pt-6 border-t border-secondary-200 text-center">
            <p className="text-xs text-secondary-500">
              Secure • Professional • Advanced Monitoring
            </p>
            {error && (
              <p className="text-xs text-red-500 mt-3">
                {error}
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

// Landing Page - Full Screen
function LandingPage({ onEnterDashboard, currentUser }) {
  const [currentTime, setCurrentTime] = useState(new Date())

  useEffect(() => {
    const timer = setInterval(() => setCurrentTime(new Date()), 1000)
    return () => clearInterval(timer)
  }, [])

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900 text-white relative overflow-hidden">
      {/* Animated background */}
      <div className="absolute inset-0">
        <div className="absolute top-0 left-0 w-96 h-96 bg-primary-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-blob"></div>
        <div className="absolute top-0 right-0 w-96 h-96 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-blob animation-delay-2000"></div>
        <div className="absolute -bottom-32 left-32 w-96 h-96 bg-indigo-500 rounded-full mix-blend-multiply filter blur-3xl opacity-10 animate-blob animation-delay-4000"></div>
      </div>
      
      {/* Grid pattern overlay */}
      <div className="absolute inset-0 opacity-20" style={{
        backgroundImage: `url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%239C92AC' fill-opacity='0.03'%3E%3Ccircle cx='30' cy='30' r='1'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E")`
      }}></div>
      
      <div className="relative z-10 flex flex-col items-center justify-center min-h-screen px-6">
        <div className="text-center max-w-4xl animate-fade-in">
          {/* Logo */}
          <div className="inline-flex items-center justify-center w-20 h-20 bg-gradient-to-br from-primary-500 to-primary-600 rounded-3xl mb-8 shadow-2xl animate-glow">
            <svg className="w-10 h-10 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 2.676-1.148 6-4.178 6-11.622 0-1.042-.133-2.052-.382-3.016z" />
            </svg>
          </div>
          
          {/* Main heading */}
          <h1 className="text-5xl md:text-7xl font-bold mb-6 bg-gradient-to-r from-white via-primary-200 to-primary-300 bg-clip-text text-transparent animate-slide-up">
            Sentinel Security Platform
          </h1>
          
          <p className="text-xl md:text-2xl text-secondary-300 mb-4 max-w-3xl mx-auto leading-relaxed animate-slide-up">
            Enterprise-grade network threat detection with real-time monitoring, 
            advanced anomaly detection, and comprehensive security analysis.
          </p>
          {currentUser && (
            <p className="text-sm text-secondary-400 mb-8 animate-slide-up">
              Authenticated as <span className="text-secondary-100 font-semibold">{currentUser}</span>
            </p>
          )}
          
          {/* System time display */}
          <div className="inline-block bg-white/5 backdrop-blur-xl border border-white/10 rounded-2xl p-6 mb-10 animate-slide-up">
            <div className="flex items-center space-x-4">
              <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
              <div className="text-2xl font-mono font-bold text-primary-200">
                {currentTime.toLocaleString()}
              </div>
              <div className="text-sm text-secondary-400">SYSTEM TIME</div>
            </div>
          </div>
          
          {/* CTA Button */}
          <button
            onClick={onEnterDashboard}
            className="inline-flex items-center bg-gradient-to-r from-primary-500 to-primary-600 hover:from-primary-600 hover:to-primary-700 text-white font-semibold px-8 py-4 rounded-2xl text-lg transition-all duration-300 transform hover:scale-105 shadow-2xl hover:shadow-primary-500/25 animate-slide-up group"
          >
            <span>Enter Security Dashboard</span>
            <svg className="w-5 h-5 ml-2 group-hover:translate-x-1 transition-transform duration-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 7l5 5m0 0l-5 5m5-5H6" />
            </svg>
          </button>
          
          {/* Features grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mt-16 max-w-4xl mx-auto animate-slide-up">
            <div className="bg-white/5 backdrop-blur-xl border border-white/10 rounded-2xl p-6 text-center hover:bg-white/10 transition-all duration-300 group">
              <div className="w-12 h-12 bg-gradient-to-br from-green-400 to-emerald-500 rounded-xl mx-auto mb-4 flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
              <h3 className="text-2xl font-bold text-green-400 mb-2">24/7</h3>
              <p className="text-secondary-400 font-medium">Continuous Monitoring</p>
            </div>
            
            <div className="bg-white/5 backdrop-blur-xl border border-white/10 rounded-2xl p-6 text-center hover:bg-white/10 transition-all duration-300 group">
              <div className="w-12 h-12 bg-gradient-to-br from-purple-400 to-purple-500 rounded-xl mx-auto mb-4 flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
                </svg>
              </div>
              <h3 className="text-2xl font-bold text-purple-400 mb-2">AI</h3>
              <p className="text-secondary-400 font-medium">Smart Detection</p>
            </div>
            
            <div className="bg-white/5 backdrop-blur-xl border border-white/10 rounded-2xl p-6 text-center hover:bg-white/10 transition-all duration-300 group">
              <div className="w-12 h-12 bg-gradient-to-br from-indigo-400 to-indigo-500 rounded-xl mx-auto mb-4 flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                </svg>
              </div>
              <h3 className="text-2xl font-bold text-indigo-400 mb-2">PGP</h3>
              <p className="text-secondary-400 font-medium">End-to-End Encrypted</p>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// Dashboard - Full Screen No Padding
function Dashboard({ token, username, onLogout }) {
  const [alerts, setAlerts] = useState([])
  const [status, setStatus] = useState(null)
  const [logs, setLogs] = useState([])
  const [config, setConfig] = useState(null)
  const [isLoading, setIsLoading] = useState(false)
  const [scanTarget, setScanTarget] = useState('127.0.0.1')
  const [scanPorts, setScanPorts] = useState('')
  const [customArgs, setCustomArgs] = useState('-sV -O -Pn')
  const [showScanForm, setShowScanForm] = useState(false)
  const [scanResult, setScanResult] = useState(null)
  const [showUserMenu, setShowUserMenu] = useState(false)
  const [showSettings, setShowSettings] = useState(false)
  const [showReports, setShowReports] = useState(false)
  const [showAdvancedTools, setShowAdvancedTools] = useState(false)
  const [scanType, setScanType] = useState('quick')
  const [timingTemplate, setTimingTemplate] = useState('T3')
  const [detectOS, setDetectOS] = useState(false)
  const [detectVersion, setDetectVersion] = useState(true)
  const [scriptScan, setScriptScan] = useState(false)
  const [toolResult, setToolResult] = useState(null)
  const [deviceIP, setDeviceIP] = useState('')
  const [networkToolInputs, setNetworkToolInputs] = useState({
    ping: '',
    traceroute: '',
    whois: '',
    dns: ''
  })
  const [reports, setReports] = useState([])
  const [encryptedReports, setEncryptedReports] = useState([])
  const [selectedReport, setSelectedReport] = useState(null)
  const [selectedEncryptedReport, setSelectedEncryptedReport] = useState(null)
  const [reportResult, setReportResult] = useState(null)
  const [reportError, setReportError] = useState('')
  const [reportBusy, setReportBusy] = useState(false)

  const authHeaders = useMemo(() => {
    if (!token) return {}
    return {
      Authorization: `Bearer ${token}`
    }
  }, [token])

  const getDeviceIP = async () => {
    try {
      const response = await fetch('https://api.ipify.org?format=json')
      const data = await response.json()
      return data.ip
    } catch (error) {
      console.error('Error getting device IP:', error)
      return '127.0.0.1' // fallback to localhost
    }
  }

  const fetchData = async () => {
    if (!token) return
    try {
      const [alertsRes, statusRes, logsRes, configRes, reportsRes] = await Promise.all([
        fetch(`${API_BASE_URL}/alerts`, { headers: authHeaders }),
        fetch(`${API_BASE_URL}/status`, { headers: authHeaders }),
        fetch(`${API_BASE_URL}/logs`, { headers: authHeaders }),
        fetch(`${API_BASE_URL}/config`, { headers: authHeaders }),
        fetch(`${API_BASE_URL}/reports`, { headers: authHeaders })
      ])

      if ([alertsRes, statusRes, logsRes, configRes, reportsRes].some(res => res.status === 401)) {
        onLogout()
        return
      }
      
      if (alertsRes.ok) setAlerts(await alertsRes.json())
      if (statusRes.ok) setStatus(await statusRes.json())
      if (logsRes.ok) setLogs(await logsRes.json())
      if (configRes.ok) {
        const configData = await configRes.json()
        setConfig(configData)
        setCustomArgs(configData.scan_args || '-sV -O -Pn')
      }
      if (reportsRes.ok) {
        const reportData = await reportsRes.json()
        setReports(reportData.reports || [])
        setEncryptedReports(reportData.encrypted_reports || [])
      }

      // Get device IP and set as default for network tools
      const ip = await getDeviceIP()
      setDeviceIP(ip)
      setNetworkToolInputs({
        ping: ip,
        traceroute: ip,
        whois: ip,
        dns: 'example.com' // DNS lookup works better with domain names
      })
      
      // Set device IP as default target for scans if not already set
      if (scanTarget === '127.0.0.1') setScanTarget(ip)
    } catch (error) {
      console.error('Error fetching data:', error)
    }
  }

  const runCustomScan = async () => {
    setIsLoading(true)
    setScanResult(null)
    try {
      const response = await fetch(`${API_BASE_URL}/scan_target`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders
        },
        body: JSON.stringify({
          target: scanTarget,
          ports: scanPorts,
          scan_args: buildScanArgs(),
          send_alert: true
        })
      })
      
      if (response.ok) {
        const result = await response.json()
        setScanResult(result)
        await fetchData()
      } else {
        const error = await response.json()
        alert('Scan failed: ' + error.error)
      }
    } catch (error) {
      console.error('Error running scan:', error)
      alert('Scan failed: ' + error.message)
    }
    setIsLoading(false)
  }

  const setDefaultConfig = () => {
    setScanTarget('127.0.0.1')
    setScanPorts('22,80,443,3389,21,25,53,110,143,993,995')
    setCustomArgs('-sV -O -Pn')
    setScanType('quick')
    setTimingTemplate('T3')
    setDetectOS(false)
    setDetectVersion(true)
    setScriptScan(false)
  }

  const saveTemplate = () => {
    const template = {
      scanTarget,
      scanPorts,
      customArgs,
      scanType,
      timingTemplate,
      detectOS,
      detectVersion,
      scriptScan
    }
    localStorage.setItem('sentinel_scan_template', JSON.stringify(template))
    alert('Scan template saved successfully!')
  }

  const loadTemplate = () => {
    const saved = localStorage.getItem('sentinel_scan_template')
    if (saved) {
      const template = JSON.parse(saved)
      setScanTarget(template.scanTarget || '127.0.0.1')
      setScanPorts(template.scanPorts || '')
      setCustomArgs(template.customArgs || '-sV -O -Pn')
      setScanType(template.scanType || 'quick')
      setTimingTemplate(template.timingTemplate || 'T3')
      setDetectOS(template.detectOS || false)
      setDetectVersion(template.detectVersion || true)
      setScriptScan(template.scriptScan || false)
    }
  }

  const buildScanArgs = () => {
    let args = ''
    
    switch (scanType) {
      case 'quick':
        args = '-sV -T4'
        break
      case 'comprehensive':
        args = '-sS -sV -O -A -T4'
        break
      case 'stealth':
        args = '-sS -T1 -f'
        break
      case 'vulnerability':
        args = '-sV --script vuln'
        break
      case 'custom':
        args = customArgs
        break
      default:
        args = customArgs
    }

    if (detectOS && scanType !== 'custom') args += ' -O'
    if (detectVersion && scanType !== 'custom') args += ' -sV'
    if (scriptScan && scanType !== 'custom') args += ' -sC'
    if (timingTemplate !== 'T3' && scanType !== 'custom') args += ` -${timingTemplate}`

    return args
  }

  const runNetworkTool = async (tool, customTarget = null) => {
    const targetToUse = customTarget || networkToolInputs[tool] || scanTarget
    
    if (!targetToUse) {
      alert('Please enter a target address first')
      return
    }

    setIsLoading(true)
    try {
      let endpoint = ''
      let body = { target: targetToUse }

      switch (tool) {
        case 'ping':
          endpoint = 'ping'
          break
        case 'traceroute':
          endpoint = 'traceroute'
          break
        case 'whois':
          endpoint = 'whois'
          break
        case 'dns':
          endpoint = 'dns_lookup'
          break
        default:
          return
      }

      const response = await fetch(`${API_BASE_URL}/${endpoint}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders
        },
        body: JSON.stringify(body)
      })
      
      if (response.ok) {
        const result = await response.json()
        setToolResult({ tool, result, target: targetToUse })
        await fetchData()
      } else {
        const error = await response.json()
        alert(`${tool} failed: ${error.error}`)
      }
    } catch (error) {
      console.error(`Error running ${tool}:`, error)
      alert(`${tool} failed: ${error.message}`)
    }
    setIsLoading(false)
  }

  const runQuickScan = async () => {
    setIsLoading(true)
    try {
      const response = await fetch(`${API_BASE_URL}/scan`, {
        method: 'POST',
        headers: authHeaders
      })
      if (response.ok) {
        await fetchData()
      }
    } catch (error) {
      console.error('Error running scan:', error)
    }
    setIsLoading(false)
  }

  const refreshReports = async () => {
    if (!token) return
    try {
      const response = await fetch(`${API_BASE_URL}/reports`, { headers: authHeaders })
      if (response.ok) {
        const data = await response.json()
        setReports(data.reports || [])
        setEncryptedReports(data.encrypted_reports || [])
      }
    } catch (error) {
      console.error('Error refreshing reports:', error)
    }
  }

  const handleEncryptReport = async () => {
    if (!selectedReport) {
      setReportError('Select a report to encrypt')
      return
    }
    setReportBusy(true)
    setReportError('')
    setReportResult(null)
    try {
      const payload = {
        report_type: selectedReport.type,
        filename: selectedReport.filename
      }
      const response = await fetch(`${API_BASE_URL}/reports/encrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders
        },
        body: JSON.stringify(payload)
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) {
        throw new Error(data.error || 'Failed to encrypt report')
      }
      setReportResult({ action: 'encrypt', data })
      setSelectedEncryptedReport(data.encrypted_file ? { filename: data.encrypted_file } : null)
      await refreshReports()
    } catch (error) {
      setReportError(error.message || 'Unable to encrypt report')
    } finally {
      setReportBusy(false)
    }
  }

  const handleDecryptReport = async () => {
    if (!selectedEncryptedReport) {
      setReportError('Select an encrypted report to decrypt')
      return
    }
    setReportBusy(true)
    setReportError('')
    setReportResult(null)
    try {
      const response = await fetch(`${API_BASE_URL}/reports/decrypt`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...authHeaders
        },
        body: JSON.stringify({ encrypted_file: selectedEncryptedReport.filename || selectedEncryptedReport })
      })
      const data = await response.json().catch(() => ({}))
      if (!response.ok) {
        throw new Error(data.error || 'Failed to decrypt report')
      }
      setReportResult({ action: 'decrypt', data })
      await refreshReports()
    } catch (error) {
      setReportError(error.message || 'Unable to decrypt report')
    } finally {
      setReportBusy(false)
    }
  }

  const handleLogoutClick = async () => {
    if (token) {
      try {
        await fetch(`${API_BASE_URL}/logout`, {
          method: 'POST',
          headers: authHeaders
        })
      } catch (error) {
        console.warn('Error logging out:', error)
      }
    }
    onLogout()
  }

  useEffect(() => {
    if (!token) {
      setAlerts([])
      setStatus(null)
      setLogs([])
      setConfig(null)
      setReports([])
      setEncryptedReports([])
      return
    }
    fetchData()
    const interval = setInterval(fetchData, 30000)
    return () => clearInterval(interval)
  }, [token])

  useEffect(() => {
    if (showReports && token) {
      refreshReports()
    }
  }, [showReports, token])

  if (!token) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-secondary-50 to-secondary-100">
        <div className="text-center bg-white/80 border border-secondary-200 rounded-2xl px-8 py-12 shadow-lg">
          <h2 className="text-2xl font-semibold text-secondary-800 mb-2">Authentication Required</h2>
          <p className="text-secondary-600">Your session has expired. Please log in again.</p>
          <button
            onClick={onLogout}
            className="mt-6 px-4 py-2 text-sm font-semibold rounded-xl text-white bg-primary-500 hover:bg-primary-600 transition-all duration-200"
          >
            Return to Login
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-secondary-50 to-secondary-100 flex flex-col">
      {/* Header */}
      <header className="bg-white/80 backdrop-blur-xl border-b border-secondary-200 shadow-lg sticky top-0 z-50">
        <div className="px-6 py-4">
          <div className="flex justify-between items-center">
            <div className="flex items-center space-x-4 animate-slide-right">
              <div className="w-10 h-10 bg-gradient-to-br from-primary-500 to-primary-600 rounded-xl flex items-center justify-center shadow-lg">
                <svg className="w-5 h-5 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 2.676-1.148 6-4.178 6-11.622 0-1.042-.133-2.052-.382-3.016z" />
                </svg>
              </div>
              <div>
                <h1 className="text-xl font-bold bg-gradient-to-r from-secondary-800 to-secondary-700 bg-clip-text text-transparent">
                  Sentinel Security Dashboard
                </h1>
                <p className="text-sm text-secondary-600 font-medium">Real-time Network Monitoring & Threat Detection</p>
              </div>
            </div>
            <div className="flex items-center space-x-3 animate-slide-left">
              <button
                onClick={() => setShowScanForm(!showScanForm)}
                className="inline-flex items-center px-4 py-2 border-2 border-primary-500 text-sm font-semibold rounded-xl text-primary-600 bg-white hover:bg-primary-50 transition-all duration-300 transform hover:scale-105 shadow-sm"
              >
                <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                </svg>
                Custom Scan
              </button>
              <button
                onClick={runQuickScan}
                disabled={isLoading}
                className="inline-flex items-center px-6 py-2 text-sm font-semibold rounded-xl text-white bg-gradient-to-r from-primary-500 to-primary-600 hover:from-primary-600 hover:to-primary-700 disabled:opacity-50 transition-all duration-300 transform hover:scale-105 shadow-lg"
              >
                {isLoading ? (
                  <>
                    <svg className="animate-spin -ml-1 mr-3 h-4 w-4 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Scanning Network...
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                    </svg>
                    Quick Scan
                  </>
                )}
              </button>
              
              {/* User menu dropdown */}
              <div className="relative">
                <button
                  onClick={() => setShowUserMenu(!showUserMenu)}
                  className="flex items-center space-x-2 px-3 py-2 text-sm font-medium text-secondary-700 bg-white rounded-xl border border-secondary-200 hover:bg-secondary-50 transition-all duration-300 shadow-sm"
                >
                  <div className="w-8 h-8 bg-gradient-to-br from-secondary-400 to-secondary-500 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z" />
                    </svg>
                  </div>
                  <span>{username || 'User'}</span>
                  <svg className={`w-4 h-4 transition-transform duration-200 ${showUserMenu ? 'rotate-180' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                  </svg>
                </button>
                
                {showUserMenu && (
                  <div className="absolute right-0 mt-2 w-48 bg-white rounded-xl shadow-lg border border-secondary-200 z-50 animate-slide-down">
                    <div className="py-2">
                      <button
                        onClick={() => setShowSettings(!showSettings)}
                        className="flex items-center w-full px-4 py-2 text-sm text-secondary-700 hover:bg-secondary-50 transition-colors duration-200"
                      >
                        <svg className="w-4 h-4 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                        </svg>
                        Settings
                      </button>
                      <button
                        onClick={() => setShowReports(!showReports)}
                        className="flex items-center w-full px-4 py-2 text-sm text-secondary-700 hover:bg-secondary-50 transition-colors duration-200"
                      >
                        <svg className="w-4 h-4 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                        </svg>
                        Reports
                      </button>
                      <div className="border-t border-secondary-200 my-2"></div>
                      <button
                        onClick={handleLogoutClick}
                        className="flex items-center w-full px-4 py-2 text-sm text-red-600 hover:bg-red-50 transition-colors duration-200"
                      >
                        <svg className="w-4 h-4 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                        </svg>
                        Logout
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </header>

      {/* Custom Scan Form */}
      {showScanForm && (
        <div className="bg-white/90 backdrop-blur-xl border-b border-secondary-200 shadow-lg animate-slide-down">
          <div className="px-6 py-4">
            <div className="space-y-6">
              {/* Basic Scan Configuration */}
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <div className="animate-slide-up">
                  <label className="block text-sm font-semibold text-secondary-700 mb-2">Target Address</label>
                  <input
                    type="text"
                    value={scanTarget}
                    onChange={(e) => setScanTarget(e.target.value)}
                    placeholder="127.0.0.1 or 192.168.1.0/24"
                    className="w-full px-4 py-3 bg-secondary-50 border border-secondary-200 rounded-xl focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-all duration-300 placeholder-secondary-400"
                  />
                </div>
                <div className="animate-slide-up">
                  <label className="block text-sm font-semibold text-secondary-700 mb-2">Port Range</label>
                  <input
                    type="text"
                    value={scanPorts}
                    onChange={(e) => setScanPorts(e.target.value)}
                    placeholder="80,443,22 or 1-1000"
                    className="w-full px-4 py-3 bg-secondary-50 border border-secondary-200 rounded-xl focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-all duration-300 placeholder-secondary-400"
                  />
                </div>
                <div className="animate-slide-up">
                  <label className="block text-sm font-semibold text-secondary-700 mb-2">Scan Type</label>
                  <select
                    value={scanType}
                    onChange={(e) => setScanType(e.target.value)}
                    className="w-full px-4 py-3 bg-secondary-50 border border-secondary-200 rounded-xl focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-all duration-300"
                  >
                    <option value="quick">Quick Scan</option>
                    <option value="comprehensive">Comprehensive Scan</option>
                    <option value="stealth">Stealth Scan</option>
                    <option value="vulnerability">Vulnerability Scan</option>
                    <option value="custom">Custom Arguments</option>
                  </select>
                </div>
              </div>

              {/* Advanced Options */}
              <div className="border-t border-secondary-200 pt-4">
                <button
                  onClick={() => setShowAdvancedTools(!showAdvancedTools)}
                  className="flex items-center space-x-2 text-sm font-semibold text-secondary-700 hover:text-primary-600 transition-colors duration-200"
                >
                  <svg className={`w-4 h-4 transition-transform duration-200 ${showAdvancedTools ? 'rotate-90' : ''}`} fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                  </svg>
                  <span>Advanced Options</span>
                </button>
                
                {showAdvancedTools && (
                  <div className="mt-4 grid grid-cols-1 lg:grid-cols-2 gap-4 animate-slide-down">
                    <div>
                      <label className="block text-sm font-semibold text-secondary-700 mb-2">Timing Template</label>
                      <select
                        value={timingTemplate}
                        onChange={(e) => setTimingTemplate(e.target.value)}
                        className="w-full px-4 py-3 bg-secondary-50 border border-secondary-200 rounded-xl focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-all duration-300"
                      >
                        <option value="T0">Paranoid (T0) - Very Slow</option>
                        <option value="T1">Sneaky (T1) - Slow</option>
                        <option value="T2">Polite (T2) - Normal</option>
                        <option value="T3">Normal (T3) - Default</option>
                        <option value="T4">Aggressive (T4) - Fast</option>
                        <option value="T5">Insane (T5) - Very Fast</option>
                      </select>
                    </div>
                    <div>
                      <label className="block text-sm font-semibold text-secondary-700 mb-2">Detection Options</label>
                      <div className="space-y-2">
                        <label className="flex items-center">
                          <input
                            type="checkbox"
                            checked={detectOS}
                            onChange={(e) => setDetectOS(e.target.checked)}
                            className="mr-2 rounded border-secondary-300 text-primary-600 focus:ring-primary-500"
                          />
                          <span className="text-sm text-secondary-700">OS Detection</span>
                        </label>
                        <label className="flex items-center">
                          <input
                            type="checkbox"
                            checked={detectVersion}
                            onChange={(e) => setDetectVersion(e.target.checked)}
                            className="mr-2 rounded border-secondary-300 text-primary-600 focus:ring-primary-500"
                          />
                          <span className="text-sm text-secondary-700">Version Detection</span>
                        </label>
                        <label className="flex items-center">
                          <input
                            type="checkbox"
                            checked={scriptScan}
                            onChange={(e) => setScriptScan(e.target.checked)}
                            className="mr-2 rounded border-secondary-300 text-primary-600 focus:ring-primary-500"
                          />
                          <span className="text-sm text-secondary-700">Script Scanning</span>
                        </label>
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Custom Arguments (shown when scan type is custom) */}
              {scanType === 'custom' && (
                <div className="animate-slide-up">
                  <label className="block text-sm font-semibold text-secondary-700 mb-2">Custom Nmap Arguments</label>
                  <input
                    type="text"
                    value={customArgs}
                    onChange={(e) => setCustomArgs(e.target.value)}
                    placeholder="-sV -O -Pn --script vuln"
                    className="w-full px-4 py-3 bg-secondary-50 border border-secondary-200 rounded-xl focus:ring-2 focus:ring-primary-500 focus:border-primary-500 transition-all duration-300 placeholder-secondary-400"
                  />
                  <p className="text-xs text-secondary-500 mt-1">Enter custom nmap arguments for advanced scanning</p>
                </div>
              )}

              {/* Action Buttons */}
              <div className="flex flex-col sm:flex-row space-y-2 sm:space-y-0 sm:space-x-3 pt-4 border-t border-secondary-200">
                <button
                  onClick={setDefaultConfig}
                  className="flex-1 px-4 py-3 border-2 border-secondary-300 text-sm font-semibold rounded-xl text-secondary-700 bg-white hover:bg-secondary-50 transition-all duration-300 transform hover:scale-105"
                >
                  Reset Defaults
                </button>
                <button
                  onClick={loadTemplate}
                  className="flex-1 px-4 py-3 border-2 border-purple-300 text-sm font-semibold rounded-xl text-purple-700 bg-white hover:bg-purple-50 transition-all duration-300 transform hover:scale-105"
                >
                  Load Template
                </button>
                <button
                  onClick={saveTemplate}
                  className="flex-1 px-4 py-3 border-2 border-indigo-300 text-sm font-semibold rounded-xl text-indigo-700 bg-white hover:bg-indigo-50 transition-all duration-300 transform hover:scale-105"
                >
                  Save Template
                </button>
                <button
                  onClick={runCustomScan}
                  disabled={isLoading}
                  className="flex-2 px-6 py-3 text-sm font-semibold rounded-xl text-white bg-gradient-to-r from-emerald-500 to-emerald-600 hover:from-emerald-600 hover:to-emerald-700 disabled:opacity-50 transition-all duration-300 transform hover:scale-105 shadow-lg"
                >
                  {isLoading ? (
                    <>
                      <svg className="animate-spin -ml-1 mr-3 h-4 w-4 text-white inline" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                      </svg>
                      Scanning Network...
                    </>
                  ) : (
                    <>
                      <svg className="w-4 h-4 mr-2 inline" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                      </svg>
                      Start Advanced Scan
                    </>
                  )}
                </button>
              </div>
            </div>


          </div>
        </div>
      )}

      {showReports && (
        <div className="bg-white/90 backdrop-blur-xl border-b border-secondary-200 shadow-lg animate-slide-down">
          <div className="px-6 py-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-secondary-900 flex items-center">
                <svg className="w-5 h-5 mr-2 text-primary-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5h6m2 0h1a1 1 0 011 1v2m0 0v10a2 2 0 01-2 2H7a2 2 0 01-2-2V8m0 0V6a1 1 0 011-1h1m0 0V4a1 1 0 011-1h6a1 1 0 011 1v1" />
                </svg>
                Report Encryption Console
              </h2>
              <div className="flex items-center space-x-3">
                <button
                  onClick={refreshReports}
                  disabled={reportBusy}
                  className="inline-flex items-center px-4 py-2 text-sm font-semibold rounded-xl text-secondary-700 bg-white border border-secondary-200 hover:bg-secondary-50 transition-all duration-200 disabled:opacity-50"
                >
                  <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582M20 20v-5h-.581M5.582 9A7.977 7.977 0 0112 4c2.21 0 4.208.894 5.658 2.342M18.418 15A7.977 7.977 0 0112 20c-2.21 0-4.208-.894-5.657-2.343" />
                  </svg>
                  Refresh
                </button>
                <button
                  onClick={() => {
                    setSelectedReport(null)
                    setSelectedEncryptedReport(null)
                    setReportResult(null)
                    setReportError('')
                  }}
                  className="inline-flex items-center px-4 py-2 text-sm font-semibold rounded-xl text-secondary-600 bg-white border border-secondary-200 hover:bg-secondary-50 transition-all duration-200"
                >
                  Clear
                </button>
              </div>
            </div>

            {reportError && (
              <div className="mb-4 rounded-xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                {reportError}
              </div>
            )}

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="bg-secondary-50 rounded-2xl border border-secondary-200 p-4">
                <h3 className="text-sm font-semibold text-secondary-700 flex items-center mb-3">
                  <span className="w-2 h-2 rounded-full bg-primary-500 mr-2"></span>
                  Available Reports
                </h3>
                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                  {reports.length > 0 ? (
                    reports.map((report) => (
                      <button
                        key={`${report.type}-${report.filename}`}
                        onClick={() => {
                          setSelectedReport(report)
                          setReportResult(null)
                          setReportError('')
                        }}
                        className={`w-full text-left px-3 py-2 rounded-xl border transition-all duration-200 ${
                          selectedReport?.filename === report.filename && selectedReport?.type === report.type
                            ? 'border-primary-400 bg-primary-50 text-primary-700'
                            : 'border-secondary-200 bg-white text-secondary-700 hover:border-primary-200 hover:bg-primary-50/50'
                        }`}
                      >
                        <div className="text-sm font-semibold">{report.filename}</div>
                        <div className="text-xs text-secondary-500 capitalize">
                          {report.type} • {new Date(report.modified_at).toLocaleString()}
                        </div>
                        {report.encrypted_available && (
                          <div className="mt-1 inline-flex items-center text-[11px] text-emerald-600 bg-emerald-100 px-2 py-0.5 rounded-full">
                            <svg className="w-3 h-3 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4" />
                            </svg>
                            Encrypted copy available
                          </div>
                        )}
                      </button>
                    ))
                  ) : (
                    <div className="text-sm text-secondary-500">No reports available.</div>
                  )}
                </div>
                <button
                  onClick={handleEncryptReport}
                  disabled={reportBusy || !selectedReport}
                  className="mt-4 w-full inline-flex items-center justify-center px-4 py-2 text-sm font-semibold rounded-xl text-white bg-gradient-to-r from-primary-500 to-primary-600 hover:from-primary-600 hover:to-primary-700 disabled:opacity-50 transition-all duration-200"
                >
                  <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 11V3m0 0l-3 3m3-3l3 3m4 4h1a1 1 0 011 1v7a2 2 0 01-2 2H6a2 2 0 01-2-2v-7a1 1 0 011-1h1" />
                  </svg>
                  Encrypt Selected Report
                </button>
              </div>

              <div className="bg-secondary-50 rounded-2xl border border-secondary-200 p-4">
                <h3 className="text-sm font-semibold text-secondary-700 flex items-center mb-3">
                  <span className="w-2 h-2 rounded-full bg-purple-500 mr-2"></span>
                  Encrypted Reports
                </h3>
                <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
                  {encryptedReports.length > 0 ? (
                    encryptedReports.map((report) => (
                      <button
                        key={report.filename}
                        onClick={() => {
                          setSelectedEncryptedReport(report)
                          setReportResult(null)
                          setReportError('')
                        }}
                        className={`w-full text-left px-3 py-2 rounded-xl border transition-all duration-200 ${
                          selectedEncryptedReport?.filename === report.filename
                            ? 'border-purple-400 bg-purple-50 text-purple-700'
                            : 'border-secondary-200 bg-white text-secondary-700 hover:border-purple-200 hover:bg-purple-50/50'
                        }`}
                      >
                        <div className="text-sm font-semibold">{report.filename}</div>
                        <div className="text-xs text-secondary-500">
                          {new Date(report.modified_at).toLocaleString()}
                        </div>
                      </button>
                    ))
                  ) : (
                    <div className="text-sm text-secondary-500">No encrypted reports yet.</div>
                  )}
                </div>
                <button
                  onClick={handleDecryptReport}
                  disabled={reportBusy || !selectedEncryptedReport}
                  className="mt-4 w-full inline-flex items-center justify-center px-4 py-2 text-sm font-semibold rounded-xl text-white bg-gradient-to-r from-purple-500 to-purple-600 hover:from-purple-600 hover:to-purple-700 disabled:opacity-50 transition-all duration-200"
                >
                  <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 13v8m0 0l3-3m-3 3l-3-3m9-5h1a1 1 0 001-1V8a2 2 0 00-2-2H6a2 2 0 00-2 2v4a1 1 0 001 1h1" />
                  </svg>
                  Decrypt Selected Report
                </button>
              </div>

              <div className="bg-white rounded-2xl border border-secondary-200 p-4">
                <h3 className="text-sm font-semibold text-secondary-700 mb-3">Action Output</h3>
                {reportBusy && (
                  <div className="flex items-center space-x-3 text-secondary-600 text-sm">
                    <svg className="animate-spin h-5 w-5 text-primary-500" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V2C5.373 2 2 5.373 2 10h2zm2 5.291A7.962 7.962 0 014 12H2c0 3.042 1.135 5.824 3 7.938l1-1.647z"></path>
                    </svg>
                    <span>Processing...</span>
                  </div>
                )}
                {!reportBusy && reportResult && (
                  <div className="text-xs text-secondary-700 space-y-3">
                    <div className="text-sm font-semibold text-secondary-900 capitalize">
                      {reportResult.action === 'encrypt' ? 'Encryption Details' : 'Decryption Output'}
                    </div>
                    <pre className="bg-secondary-900 text-green-300 rounded-xl p-3 max-h-64 overflow-y-auto whitespace-pre-wrap">
                      {JSON.stringify(reportResult.data, null, 2)}
                    </pre>
                  </div>
                )}
                {!reportBusy && !reportResult && (
                  <div className="text-sm text-secondary-500">
                    Select a report and choose an action to view results.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main Content */}
      <main className="flex-1 p-6 space-y-6">
        {/* Enhanced Stats Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 xl:grid-cols-5 gap-6">
          <div className="bg-white/70 backdrop-blur-xl rounded-2xl border border-white/20 p-6 shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-300 animate-fade-in">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-secondary-600 uppercase tracking-wide">System Status</p>
                <p className="text-2xl font-bold text-secondary-900 mt-1">
                  {status ? 'Active' : 'Initializing'}
                </p>
              </div>
              <div className="w-12 h-12 bg-gradient-to-br from-green-400 to-emerald-500 rounded-xl flex items-center justify-center shadow-lg animate-glow">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
            </div>
            <div className={`mt-3 inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${status ? 'bg-green-100 text-green-800' : 'bg-yellow-100 text-yellow-800'}`}>
              <div className={`w-2 h-2 rounded-full mr-2 ${status ? 'bg-green-400' : 'bg-yellow-400'} animate-pulse`}></div>
              {status ? 'Online' : 'Starting'}
            </div>
          </div>

          <div className="bg-white/70 backdrop-blur-xl rounded-2xl border border-white/20 p-6 shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-300 animate-fade-in">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-secondary-600 uppercase tracking-wide">Total Scans</p>
                <p className="text-2xl font-bold text-secondary-900 mt-1">{logs.length}</p>
              </div>
              <div className="w-12 h-12 bg-gradient-to-br from-primary-400 to-primary-500 rounded-xl flex items-center justify-center shadow-lg">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
                </svg>
              </div>
            </div>
            <div className="mt-3 text-sm text-secondary-600">
              Last 24 hours: {logs.filter(log => new Date(log.timestamp) > new Date(Date.now() - 24*60*60*1000)).length}
            </div>
          </div>

          <div className="bg-white/70 backdrop-blur-xl rounded-2xl border border-white/20 p-6 shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-300 animate-fade-in">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-secondary-600 uppercase tracking-wide">Security Alerts</p>
                <p className="text-2xl font-bold text-secondary-900 mt-1">{alerts.length}</p>
              </div>
              <div className={`w-12 h-12 bg-gradient-to-br ${alerts.length > 0 ? 'from-red-400 to-red-500' : 'from-green-400 to-green-500'} rounded-xl flex items-center justify-center shadow-lg`}>
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                </svg>
              </div>
            </div>
            <div className={`mt-3 inline-flex items-center px-3 py-1 rounded-full text-xs font-medium ${alerts.length > 0 ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`}>
              {alerts.length > 0 ? `${alerts.length} Active` : 'All Clear'}
            </div>
          </div>

          <div className="bg-white/70 backdrop-blur-xl rounded-2xl border border-white/20 p-6 shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-300 animate-fade-in">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-secondary-600 uppercase tracking-wide">Current Target</p>
                <p className="text-lg font-bold text-secondary-900 mt-1 font-mono">
                  {status?.target || config?.targets?.[0] || 'No Target'}
                </p>
              </div>
              <div className="w-12 h-12 bg-gradient-to-br from-purple-400 to-purple-500 rounded-xl flex items-center justify-center shadow-lg">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
              </div>
            </div>
            <div className="mt-3 text-sm text-secondary-600">
              Primary scan target
            </div>
          </div>

          <div className="bg-white/70 backdrop-blur-xl rounded-2xl border border-white/20 p-6 shadow-lg hover:shadow-xl transform hover:scale-105 transition-all duration-300 animate-fade-in">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-secondary-600 uppercase tracking-wide">Uptime</p>
                <p className="text-2xl font-bold text-secondary-900 mt-1">
                  {Math.floor((Date.now() - (status?.startTime || Date.now())) / 3600000)}h
                </p>
              </div>
              <div className="w-12 h-12 bg-gradient-to-br from-indigo-400 to-indigo-500 rounded-xl flex items-center justify-center shadow-lg">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
              </div>
            </div>
            <div className="mt-3 text-sm text-secondary-600">
              System running time
            </div>
          </div>
        </div>

        {/* Quick Network Tools */}
        <div className="bg-white/70 backdrop-blur-xl rounded-2xl border border-white/20 p-6 shadow-lg animate-fade-in">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-bold text-secondary-900 flex items-center">
              <svg className="w-5 h-5 mr-2 text-primary-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
              </svg>
              Quick Network Tools
            </h3>
            <div className="text-sm text-secondary-600">Instant network diagnostics</div>
          </div>
          
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {/* Ping Tool */}
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <div className="w-6 h-6 bg-blue-500 rounded-lg flex items-center justify-center">
                  <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                  </svg>
                </div>
                <span className="text-sm font-semibold text-blue-800">Ping Test</span>
              </div>
              <input
                type="text"
                value={networkToolInputs.ping}
                onChange={(e) => setNetworkToolInputs({...networkToolInputs, ping: e.target.value})}
                placeholder="Enter IP address"
                className="w-full px-3 py-2 text-sm border border-blue-200 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              />
              <button
                onClick={() => runNetworkTool('ping')}
                className="w-full py-2 px-3 bg-gradient-to-r from-blue-500 to-blue-600 text-white text-sm font-medium rounded-lg hover:from-blue-600 hover:to-blue-700 transition-all duration-200 transform hover:scale-105"
              >
                Run Ping
              </button>
            </div>

            {/* Traceroute Tool */}
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <div className="w-6 h-6 bg-green-500 rounded-lg flex items-center justify-center">
                  <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 20l-5.447-2.724A1 1 0 013 16.382V5.618a1 1 0 011.447-.894L9 7m0 13l6-3m-6 3V7m6 10l4.553 2.276A1 1 0 0021 18.382V7.618a1 1 0 00-.553-.894L15 4m0 13V4m0 0L9 7" />
                  </svg>
                </div>
                <span className="text-sm font-semibold text-green-800">Traceroute</span>
              </div>
              <input
                type="text"
                value={networkToolInputs.traceroute}
                onChange={(e) => setNetworkToolInputs({...networkToolInputs, traceroute: e.target.value})}
                placeholder="Enter IP address"
                className="w-full px-3 py-2 text-sm border border-green-200 rounded-lg focus:ring-2 focus:ring-green-500 focus:border-transparent"
              />
              <button
                onClick={() => runNetworkTool('traceroute')}
                className="w-full py-2 px-3 bg-gradient-to-r from-green-500 to-green-600 text-white text-sm font-medium rounded-lg hover:from-green-600 hover:to-green-700 transition-all duration-200 transform hover:scale-105"
              >
                Run Traceroute
              </button>
            </div>

            {/* WHOIS Tool */}
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <div className="w-6 h-6 bg-purple-500 rounded-lg flex items-center justify-center">
                  <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                  </svg>
                </div>
                <span className="text-sm font-semibold text-purple-800">WHOIS</span>
              </div>
              <input
                type="text"
                value={networkToolInputs.whois}
                onChange={(e) => setNetworkToolInputs({...networkToolInputs, whois: e.target.value})}
                placeholder="Enter domain or IP"
                className="w-full px-3 py-2 text-sm border border-purple-200 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent"
              />
              <button
                onClick={() => runNetworkTool('whois')}
                className="w-full py-2 px-3 bg-gradient-to-r from-purple-500 to-purple-600 text-white text-sm font-medium rounded-lg hover:from-purple-600 hover:to-purple-700 transition-all duration-200 transform hover:scale-105"
              >
                Run WHOIS
              </button>
            </div>

            {/* DNS Lookup Tool */}
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <div className="w-6 h-6 bg-orange-500 rounded-lg flex items-center justify-center">
                  <svg className="w-3 h-3 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 01-9 9m9-9a9 9 0 00-9-9m9 9H3m9 9a9 9 0 01-9-9m9 9c1.657 0 3-4.03 3-9s-1.343-9-3-9m0 18c-1.657 0-3-4.03-3-9s-1.343-9 3-9m-9 9a9 9 0 019-9" />
                  </svg>
                </div>
                <span className="text-sm font-semibold text-orange-800">DNS Lookup</span>
              </div>
              <input
                type="text"
                value={networkToolInputs.dns}
                onChange={(e) => setNetworkToolInputs({...networkToolInputs, dns: e.target.value})}
                placeholder="Enter domain name"
                className="w-full px-3 py-2 text-sm border border-orange-200 rounded-lg focus:ring-2 focus:ring-orange-500 focus:border-transparent"
              />
              <button
                onClick={() => runNetworkTool('dns')}
                className="w-full py-2 px-3 bg-gradient-to-r from-orange-500 to-orange-600 text-white text-sm font-medium rounded-lg hover:from-orange-600 hover:to-orange-700 transition-all duration-200 transform hover:scale-105"
              >
                Run DNS Lookup
              </button>
            </div>
          </div>
        </div>

        {/* Scan Result */}
        {scanResult && (
          <div className="bg-white/70 backdrop-blur-xl rounded-2xl border border-white/20 p-6 shadow-lg animate-slide-up">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-bold text-secondary-900">Latest Scan Result</h3>
              <div className="flex items-center space-x-2">
                <div className="w-3 h-3 bg-green-400 rounded-full animate-pulse"></div>
                <span className="text-sm text-secondary-600 font-medium">Completed</span>
              </div>
            </div>
            
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div className="space-y-4">
                <div className="bg-secondary-50 rounded-xl p-4">
                  <h4 className="text-sm font-semibold text-secondary-700 mb-3">Scan Overview</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-secondary-600">Target:</span>
                      <span className="text-sm font-mono font-semibold text-secondary-900">{scanResult.target}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-secondary-600">Hosts Found:</span>
                      <span className="text-sm font-semibold text-secondary-900">{Object.keys(scanResult.scan_result.hosts).length}</span>
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-secondary-600">Anomalies:</span>
                      <span className={`text-sm font-semibold ${scanResult.anomalies.length > 0 ? 'text-amber-600' : 'text-green-600'}`}>
                        {scanResult.anomalies.length}
                      </span>
                    </div>
                  </div>
                </div>
              </div>
              
              <div className="space-y-4">
                <div className="bg-secondary-50 rounded-xl p-4">
                  <h4 className="text-sm font-semibold text-secondary-700 mb-3">Host Status</h4>
                  <div className="space-y-2 max-h-32 overflow-y-auto">
                    {Object.entries(scanResult.scan_result.hosts).map(([host, data]) => (
                      <div key={host} className="flex justify-between items-center py-1">
                        <span className="text-sm font-mono text-secondary-700">{host}</span>
                        <span className={`px-3 py-1 rounded-full text-xs font-semibold ${data.state === 'up' ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}`}>
                          {data.state}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
            
            {scanResult.anomalies.length > 0 && (
              <div className="mt-6">
                <div className="bg-amber-50 border border-amber-200 rounded-xl p-4">
                  <h4 className="text-sm font-semibold text-amber-800 mb-3 flex items-center">
                    <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                    </svg>
                    Security Anomalies Detected
                  </h4>
                  <div className="space-y-1 max-h-24 overflow-y-auto">
                    {scanResult.anomalies.map((anomaly, index) => (
                      <div key={index} className="text-sm text-amber-800 animate-fade-in" style={{ animationDelay: `${index * 0.1}s` }}>
                        • {anomaly}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Network Tool Result */}
        {toolResult && (
          <div className="bg-white/70 backdrop-blur-xl rounded-2xl border border-white/20 p-6 shadow-lg animate-slide-up">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-bold text-secondary-900 capitalize">{toolResult.tool} Result</h3>
                {toolResult.target && (
                  <p className="text-sm text-secondary-600 font-mono">Target: {toolResult.target}</p>
                )}
              </div>
              <button
                onClick={() => setToolResult(null)}
                className="text-secondary-400 hover:text-secondary-600 transition-colors duration-200"
              >
                <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                </svg>
              </button>
            </div>
            
            <div className="bg-secondary-900 rounded-xl p-4 font-mono text-sm text-green-400 max-h-64 overflow-y-auto">
              <pre className="whitespace-pre-wrap">{JSON.stringify(toolResult.result, null, 2)}</pre>
            </div>
          </div>
        )}

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          {/* Security Alerts */}
          <div className="bg-white/70 backdrop-blur-xl rounded-2xl border border-white/20 shadow-lg animate-slide-right">
            <div className="p-6 border-b border-secondary-200">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 bg-gradient-to-br from-red-400 to-red-500 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L4.082 16.5c-.77.833.192 2.5 1.732 2.5z" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-bold text-secondary-900">Security Alerts</h3>
                </div>
                <div className={`px-3 py-1 rounded-full text-xs font-semibold ${alerts.length > 0 ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`}>
                  {alerts.length} {alerts.length === 1 ? 'Alert' : 'Alerts'}
                </div>
              </div>
            </div>
            <div className="p-6 max-h-96 overflow-y-auto">
              <div className="space-y-3">
                {alerts.length > 0 ? (
                  alerts.slice(0, 20).map((alert, index) => (
                    <div key={index} className="flex items-start space-x-4 p-4 bg-secondary-50/50 rounded-xl hover:bg-secondary-100/50 transition-all duration-300 animate-fade-in" style={{ animationDelay: `${index * 0.05}s` }}>
                      <div className="w-3 h-3 bg-red-400 rounded-full mt-1.5 animate-pulse flex-shrink-0"></div>
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-semibold text-secondary-900">{alert.target}</p>
                        <p className="text-sm text-secondary-700 mt-1">{alert.message}</p>
                        <p className="text-xs text-secondary-500 mt-2">{new Date(alert.timestamp).toLocaleString()}</p>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-12">
                    <div className="w-16 h-16 bg-green-100 rounded-full flex items-center justify-center mx-auto mb-4">
                      <svg className="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
                      </svg>
                    </div>
                    <p className="text-lg font-semibold text-secondary-900 mb-2">All Clear</p>
                    <p className="text-sm text-secondary-600">No security alerts detected</p>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Scan History */}
          <div className="bg-white/70 backdrop-blur-xl rounded-2xl border border-white/20 shadow-lg animate-slide-left">
            <div className="p-6 border-b border-secondary-200">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <div className="w-8 h-8 bg-gradient-to-br from-primary-400 to-primary-500 rounded-lg flex items-center justify-center">
                    <svg className="w-4 h-4 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5H7a2 2 0 00-2 2v10a2 2 0 002 2h8a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2" />
                    </svg>
                  </div>
                  <h3 className="text-lg font-bold text-secondary-900">Scan History</h3>
                </div>
                <div className="px-3 py-1 bg-primary-100 text-primary-800 rounded-full text-xs font-semibold">
                  {logs.length} {logs.length === 1 ? 'Scan' : 'Scans'}
                </div>
              </div>
            </div>
            <div className="p-6 max-h-96 overflow-y-auto">
              <div className="space-y-3">
                {logs.length > 0 ? (
                  logs.slice(0, 20).map((log, index) => (
                    <div key={index} className="flex items-start space-x-4 p-4 bg-secondary-50/50 rounded-xl hover:bg-secondary-100/50 transition-all duration-300 animate-fade-in" style={{ animationDelay: `${index * 0.05}s` }}>
                      <div className={`w-3 h-3 rounded-full mt-1.5 animate-pulse flex-shrink-0 ${log.anomalies.length > 0 ? 'bg-amber-400' : 'bg-green-400'}`}></div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between">
                          <p className="text-sm font-semibold text-secondary-900">{log.target}</p>
                          <span className={`px-2 py-1 rounded-full text-xs font-semibold ${log.anomalies.length > 0 ? 'bg-amber-100 text-amber-800' : 'bg-green-100 text-green-800'}`}>
                            {log.anomalies.length > 0 ? `${log.anomalies.length} Issues` : 'Clean'}
                          </span>
                        </div>
                        <p className="text-sm text-secondary-700 mt-1">
                          {log.anomalies.length > 0 ? `${log.anomalies.length} anomalies detected` : 'Scan completed successfully - no issues found'}
                        </p>
                        <p className="text-xs text-secondary-500 mt-2">{new Date(log.timestamp).toLocaleString()}</p>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-12">
                    <div className="w-16 h-16 bg-primary-100 rounded-full flex items-center justify-center mx-auto mb-4">
                      <svg className="w-8 h-8 text-primary-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
                      </svg>
                    </div>
                    <p className="text-lg font-semibold text-secondary-900 mb-2">No Scans Yet</p>
                    <p className="text-sm text-secondary-600">Run your first network scan to see results here</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  )
}

// Main App Component
function App() {
  const [currentView, setCurrentView] = useState('login') // 'login', 'landing', 'dashboard'
  const [authToken, setAuthToken] = useState(null)
  const [currentUser, setCurrentUser] = useState(null)
  const [sessionExpiry, setSessionExpiry] = useState(null)
  const resetSession = useCallback(() => {
    setAuthToken(null)
    setCurrentUser(null)
    setSessionExpiry(null)
    setCurrentView('login')
  }, [])

  const handleLogin = (token, username, expiresIn) => {
    setAuthToken(token)
    setCurrentUser(username)
    setSessionExpiry(expiresIn ? Date.now() + expiresIn * 1000 : null)
    setCurrentView('landing')
  }

  const handleEnterDashboard = () => {
    if (authToken) {
      setCurrentView('dashboard')
    } else {
      setCurrentView('login')
    }
  }

  useEffect(() => {
    if (!sessionExpiry) return
    const now = Date.now()
    const remaining = sessionExpiry - now
    if (remaining <= 0) {
      resetSession()
      return
    }
    const timer = setTimeout(() => {
      resetSession()
    }, remaining)
    return () => clearTimeout(timer)
  }, [sessionExpiry, resetSession])

  if (currentView === 'login') {
    return <LoginPage onLogin={handleLogin} />
  }

  if (currentView === 'landing') {
    return <LandingPage onEnterDashboard={handleEnterDashboard} currentUser={currentUser} />
  }

  return <Dashboard token={authToken} username={currentUser} onLogout={resetSession} />
}

export default App