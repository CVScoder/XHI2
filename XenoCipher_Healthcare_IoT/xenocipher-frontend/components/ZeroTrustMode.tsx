// components/ZeroTrustMode.tsx
'use client'

import React, { useState, useEffect, useCallback } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useWebSocket } from '../context/WebSocketContext'

type ThreatLevel = 'green' | 'yellow' | 'red'
type ZTMRecipe = 'FULL_STACK' | 'CHACHA_HEAVY' | 'SALSA_LIGHT' | 'CHAOS_ONLY' | 'STREAM_FOCUS'

interface ThreatEvent {
  type: string
  timestamp: number
  eventType: string
  hmacFailures: number
  decryptFailures: number
  replayAttempts: number
  malformedPackets: number
  timingAnomalies: number
  currentRecipe?: string
}

interface ZTMStatus {
  ztmEnabled: boolean
  currentMode: string
  currentRecipe: ZTMRecipe
  hmacFailures: number
  decryptFailures: number
  replayAttempts: number
  malformedPackets: number
  timingAnomalies: number
}

export default function ZeroTrustMode() {
  const { isConnected, sendMessage, lastMessage, messageHistory } = useWebSocket()
  const [isActivating, setIsActivating] = useState(false)
  const [ztmStatus, setZtmStatus] = useState<ZTMStatus | null>(null)
  const [threatEvents, setThreatEvents] = useState<ThreatEvent[]>([])
  const [selectedRecipe, setSelectedRecipe] = useState<ZTMRecipe>('FULL_STACK')
  const [showKeyWarning, setShowKeyWarning] = useState(false)

  // Recipe definitions
  const recipes: Record<ZTMRecipe, { name: string; algorithms: string[]; description: string }> = {
    FULL_STACK: {
      name: 'Full Stack',
      algorithms: ['LFSR', 'Tinkerbell', 'Transposition', 'ChaCha20', 'Salsa20'],
      description: 'Maximum security - all 5 algorithms active'
    },
    CHACHA_HEAVY: {
      name: 'ChaCha Heavy',
      algorithms: ['LFSR', 'Tinkerbell', 'ChaCha20'],
      description: 'ChaCha20 with chaos algorithms'
    },
    SALSA_LIGHT: {
      name: 'Salsa Light',
      algorithms: ['LFSR', 'Salsa20'],
      description: 'Lightweight stream cipher only'
    },
    CHAOS_ONLY: {
      name: 'Chaos Only',
      algorithms: ['LFSR', 'Tinkerbell', 'Transposition'],
      description: 'Baseline fusion - no stream ciphers'
    },
    STREAM_FOCUS: {
      name: 'Stream Focus',
      algorithms: ['ChaCha20', 'Salsa20'],
      description: 'Stream ciphers only - minimal chaos'
    }
  }

  // Handle WebSocket messages
  useEffect(() => {
    if (!lastMessage) return

    const msg = lastMessage
    switch (msg.type) {
      case 'threat_event':
        setThreatEvents(prev => [...prev.slice(-19), msg as ThreatEvent])
        break
      case 'ztm_activation_acknowledged':
        console.log('[ZTM] Activation acknowledged:', msg)
        // Clear timeout if it exists
        if ((window as any).ztmActivationTimeout) {
          clearTimeout((window as any).ztmActivationTimeout)
          delete (window as any).ztmActivationTimeout
        }
        
        if (msg.success) {
          setIsActivating(false)
          // Immediately set ZTM status from acknowledgment
          const status: ZTMStatus = {
            ztmEnabled: true,
            currentMode: 'ztm',
            currentRecipe: (msg.currentRecipe || msg.recipe || 'FULL_STACK') as ZTMRecipe,
            hmacFailures: msg.hmacFailures || 0,
            decryptFailures: msg.decryptFailures || 0,
            replayAttempts: msg.replayAttempts || 0,
            malformedPackets: msg.malformedPackets || 0,
            timingAnomalies: msg.timingAnomalies || 0
          }
          console.log('[ZTM] Setting ZTM status from ESP32:', status)
          setZtmStatus(status)
          setSelectedRecipe(status.currentRecipe)
          // Also fetch full status for complete data
          setTimeout(() => fetchZTMStatus(), 500)
        } else {
          alert('ZTM activation failed: ' + (msg.error || 'Unknown error'))
          setIsActivating(false)
        }
        break
      case 'ztm_deactivation_acknowledged':
        console.log('[ZTM] Deactivation acknowledged:', msg)
        if (msg.success) {
          setZtmStatus(null)
          setThreatEvents([])
          setSelectedRecipe('FULL_STACK')
          console.log('[ZTM] Reverted to Normal Mode')
        } else {
          alert('ZTM deactivation failed: ' + (msg.error || 'Unknown error'))
        }
        break
      case 'recipe_switched':
        setSelectedRecipe(msg.newRecipe as ZTMRecipe)
        setShowKeyWarning(true)
        setTimeout(() => setShowKeyWarning(false), 5000)
        break
      case 'ztm_status':
        console.log('[ZTM] Received ZTM status:', msg)
        const status = msg as any
        if (status.ztmEnabled) {
          // Update status and clear activating state if we were waiting
          setIsActivating(false)
          if ((window as any).ztmActivationTimeout) {
            clearTimeout((window as any).ztmActivationTimeout)
            delete (window as any).ztmActivationTimeout
          }
          
          setZtmStatus({
            ztmEnabled: status.ztmEnabled,
            currentMode: status.currentMode || 'ztm',
            currentRecipe: (status.currentRecipe || 'FULL_STACK') as ZTMRecipe,
            hmacFailures: status.hmacFailures || 0,
            decryptFailures: status.decryptFailures || 0,
            replayAttempts: status.replayAttempts || 0,
            malformedPackets: status.malformedPackets || 0,
            timingAnomalies: status.timingAnomalies || 0
          })
          setSelectedRecipe((status.currentRecipe || 'FULL_STACK') as ZTMRecipe)
        }
        break
    }
  }, [lastMessage])

  const fetchZTMStatus = useCallback(() => {
    if (isConnected) {
      console.log('[ZTM] Fetching ZTM status...')
      sendMessage({ type: 'get_ztm_status' })
    } else {
      console.warn('[ZTM] Cannot fetch status - WebSocket not connected')
    }
  }, [isConnected, sendMessage])

  const handleActivateClick = useCallback(() => {
    // Don't activate if already active
    if (ztmStatus && ztmStatus.ztmEnabled) {
      console.log('[ZTM] Already activated, skipping')
      return
    }
    
    setIsActivating(true)
    console.log('[ZTM] Sending activation request (no passcode required)')
    
    // Send activation request - no passcode needed
    if (isConnected) {
      sendMessage({
        type: 'ztm_activate_request'
      })
    }
    
    // Fallback: If ESP32 doesn't respond in 3 seconds, activate client-side anyway
    const timeoutId = setTimeout(() => {
      setIsActivating((prev) => {
        if (prev) {
          console.warn('[ZTM] No ESP32 response - activating client-side as fallback')
          // Activate ZTM client-side so user can access the page
          const fallbackStatus: ZTMStatus = {
            ztmEnabled: true,
            currentMode: 'ztm',
            currentRecipe: 'FULL_STACK',
            hmacFailures: 0,
            decryptFailures: 0,
            replayAttempts: 0,
            malformedPackets: 0,
            timingAnomalies: 0
          }
          setZtmStatus(fallbackStatus)
          setSelectedRecipe('FULL_STACK')
          console.log('[ZTM] Client-side activation complete - will sync with ESP32 when available')
          
          // Continue trying to sync with ESP32 in background
          if (isConnected) {
            setTimeout(() => fetchZTMStatus(), 2000)
          }
          return false
        }
        return prev
      })
    }, 3000)
    
    // Store timeout ID to clear if activation succeeds
    ;(window as any).ztmActivationTimeout = timeoutId
  }, [isConnected, sendMessage, ztmStatus, fetchZTMStatus])

  // Request ZTM status on mount and auto-activate if not already active
  useEffect(() => {
    if (isConnected) {
      // First, check current status
      fetchZTMStatus()
      
      // Auto-activate ZTM after a short delay if not already active
      // This ensures the management page opens immediately when user clicks the button
      const autoActivateTimer = setTimeout(() => {
        // Only auto-activate if we don't have ZTM status yet (not already active)
        if (!ztmStatus || !ztmStatus.ztmEnabled) {
          console.log('[ZTM] Auto-activating ZTM on page load')
          handleActivateClick()
        }
      }, 1000) // Wait 1 second to check status first
      
      return () => clearTimeout(autoActivateTimer)
    } else {
      // If not connected, still try to activate (will use client-side fallback)
      console.log('[ZTM] WebSocket not connected, will activate with client-side fallback')
      const autoActivateTimer = setTimeout(() => {
        if (!ztmStatus || !ztmStatus.ztmEnabled) {
          console.log('[ZTM] Auto-activating ZTM (client-side fallback)')
          handleActivateClick()
        }
      }, 2000) // Wait 2 seconds if not connected
      
      return () => clearTimeout(autoActivateTimer)
    }
  }, [isConnected, fetchZTMStatus, handleActivateClick, ztmStatus])


  const handleDeactivate = () => {
    const confirmed = window.confirm(
      '⚠️ EXIT ZERO TRUST MODE?\n\n' +
      'This will:\n' +
      '• Disable adaptive encryption switching\n' +
      '• Revert to Normal Mode encryption (LFSR + Tinkerbell + Transposition)\n' +
      '• Stop all ZTM encryption algorithms\n' +
      '• Reset threat detection heuristics\n\n' +
      'Are you sure you want to exit ZTM?'
    )
    
    if (confirmed) {
      console.log('[ZTM] Sending deactivation request')
      sendMessage({ type: 'ztm_deactivate_request' })
      
      // Set a timeout to show the page even if ESP32 doesn't respond
      setTimeout(() => {
        if (ztmStatus && ztmStatus.ztmEnabled) {
          console.log('[ZTM] ESP32 did not respond - deactivating client-side')
          setZtmStatus(null)
          setThreatEvents([])
        }
      }, 3000)
    }
  }

  const handleRecipeSwitch = (recipe: ZTMRecipe) => {
    if (confirm(`Switch to ${recipes[recipe].name}? Keys and nonces will be regenerated.`)) {
      setSelectedRecipe(recipe)
      sendMessage({
        type: 'adaptive_switch_request',
        mode: 'ztm',
        recipe: recipe.toLowerCase()
      })
      setShowKeyWarning(true)
      setTimeout(() => setShowKeyWarning(false), 5000)
    }
  }

  const getThreatLevel = (): ThreatLevel => {
    if (!ztmStatus) return 'green'
    const totalThreats = ztmStatus.hmacFailures + ztmStatus.decryptFailures + 
                        ztmStatus.replayAttempts + ztmStatus.malformedPackets + 
                        ztmStatus.timingAnomalies
    if (totalThreats >= 20) return 'red'
    if (totalThreats >= 10) return 'yellow'
    return 'green'
  }

  const threatLevel = getThreatLevel()


  // Show loading state while activating
  if (isActivating) {
    return (
      <div className="min-h-screen bg-black text-white flex items-center justify-center p-8">
        <div className="text-center max-w-2xl">
          <div className="text-6xl mb-6 animate-spin">🔄</div>
          <h1 className="text-3xl font-bold text-red-500 font-mono mb-4">
            ACTIVATING ZERO TRUST MODE
          </h1>
          <p className="text-gray-400 text-lg mb-4">
            Sending activation request to ESP32...
          </p>
          <p className="text-gray-500 text-sm">
            {isConnected ? 'WebSocket connected' : 'Waiting for WebSocket connection...'}
          </p>
        </div>
      </div>
    )
  }

  // Show ZTM management page
  if (ztmStatus && ztmStatus.ztmEnabled) {
    return (
      <div className="min-h-screen bg-black text-white p-8">
        <div className="max-w-7xl mx-auto">
          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div>
              <h1 className="text-4xl font-bold text-red-500 font-mono mb-2">
                ZERO TRUST MODE
              </h1>
              <p className="text-gray-400 mb-2">
                Adaptive encryption switching based on live threat detection
              </p>
              <div className="px-3 py-1 bg-red-500/20 border border-red-500/50 rounded text-red-400 font-mono text-xs inline-block">
                🔒 ZTM ACTIVE - Recipe: {ztmStatus.currentRecipe} | Mode: {ztmStatus.currentMode}
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <div className={`px-4 py-2 rounded-lg border ${
                threatLevel === 'red' ? 'bg-red-500/20 border-red-500' :
                threatLevel === 'yellow' ? 'bg-yellow-500/20 border-yellow-500' :
                'bg-green-500/20 border-green-500'
              }`}>
                <span className="font-mono text-sm">
                  THREAT: <span className={
                    threatLevel === 'red' ? 'text-red-400' :
                    threatLevel === 'yellow' ? 'text-yellow-400' : 'text-green-400'
                  }>{threatLevel.toUpperCase()}</span>
                </span>
              </div>
              <button
                onClick={handleDeactivate}
                className="px-6 py-2 bg-red-700 hover:bg-red-600 text-white rounded-lg font-mono text-sm font-bold transition-colors border border-red-500"
              >
                ⚠️ EXIT ZTM
              </button>
            </div>
          </div>

          {/* Key Warning */}
          <AnimatePresence>
            {showKeyWarning && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -10 }}
              >
                <div className="mb-6 p-4 bg-yellow-500/20 border border-yellow-500 rounded-lg">
                  <p className="text-yellow-400 font-mono text-sm">
                    ⚠️ Recipe switched - Keys and nonces have been regenerated for synchronization
                  </p>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Left Column - Recipes and Algorithms */}
            <div className="lg:col-span-1 space-y-6">
              {/* Current Recipe */}
              <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
                <h2 className="text-xl font-bold text-red-400 font-mono mb-4">
                  ACTIVE RECIPE
                </h2>
                <div className="mb-4">
                  <div className="text-2xl font-bold text-white mb-2">
                    {recipes[selectedRecipe].name}
                  </div>
                  <div className="text-gray-400 text-sm">
                    {recipes[selectedRecipe].description}
                  </div>
                </div>
                <div className="space-y-2">
                  {recipes[selectedRecipe].algorithms.map((alg, idx) => (
                    <div
                      key={idx}
                      className="px-3 py-2 bg-green-500/20 border border-green-500/50 rounded-lg text-green-400 font-mono text-sm"
                    >
                      ✓ {alg}
                    </div>
                  ))}
                </div>
              </div>

              {/* Available Recipes */}
              <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
                <h2 className="text-xl font-bold text-red-400 font-mono mb-4">
                  AVAILABLE RECIPES
                </h2>
                <div className="space-y-3">
                  {(Object.keys(recipes) as ZTMRecipe[]).map((recipe) => (
                    <button
                      key={recipe}
                      onClick={() => handleRecipeSwitch(recipe)}
                      disabled={selectedRecipe === recipe}
                      className={`w-full text-left px-4 py-3 rounded-lg border transition-all ${
                        selectedRecipe === recipe
                          ? 'bg-red-500/20 border-red-500 text-red-400'
                          : 'bg-gray-800 border-gray-700 text-gray-300 hover:border-gray-600'
                      } disabled:cursor-not-allowed`}
                    >
                      <div className="font-mono font-bold mb-1">{recipes[recipe].name}</div>
                      <div className="text-xs text-gray-500">{recipes[recipe].description}</div>
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Middle Column - Pipeline and Events */}
            <div className="lg:col-span-1 space-y-6">
              {/* Encryption Pipeline */}
              <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
                <h2 className="text-xl font-bold text-red-400 font-mono mb-4">
                  ENCRYPTION PIPELINE
                </h2>
                <div className="space-y-3">
                  {recipes[selectedRecipe].algorithms.map((alg, idx) => (
                    <div
                      key={idx}
                      className="flex items-center space-x-3 p-3 bg-gray-800 rounded-lg"
                    >
                      <div className="w-8 h-8 bg-green-500 rounded-full flex items-center justify-center text-white font-bold text-sm">
                        {idx + 1}
                      </div>
                      <div className="flex-1 font-mono text-white">{alg}</div>
                      <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse" />
                    </div>
                  ))}
                </div>
              </div>

              {/* Live Event Log */}
              <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
                <h2 className="text-xl font-bold text-red-400 font-mono mb-4">
                  LIVE EVENT LOG
                </h2>
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {threatEvents.length === 0 ? (
                    <div className="text-gray-500 text-sm text-center py-8">
                      No events detected yet
                    </div>
                  ) : (
                    threatEvents.map((event, idx) => (
                      <div
                        key={idx}
                        className="p-3 bg-gray-800 rounded-lg border border-gray-700"
                      >
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono text-sm text-red-400">
                            {event.eventType.toUpperCase()}
                          </span>
                          <span className="text-gray-500 text-xs">
                            {new Date(event.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <div className="text-xs text-gray-400 space-y-1">
                          <div>HMAC Failures: {event.hmacFailures}</div>
                          <div>Decrypt Failures: {event.decryptFailures}</div>
                          <div>Replay Attempts: {event.replayAttempts}</div>
                          {event.currentRecipe && (
                            <div className="text-green-400 mt-2">
                              Recipe: {event.currentRecipe}
                            </div>
                          )}
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>

            {/* Right Column - Threat Metrics */}
            <div className="lg:col-span-1 space-y-6">
              {/* Threat Metrics */}
              <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
                <h2 className="text-xl font-bold text-red-400 font-mono mb-4">
                  THREAT METRICS
                </h2>
                <div className="space-y-4">
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-gray-400 text-sm">HMAC Failures</span>
                      <span className="text-white font-mono">{ztmStatus.hmacFailures}</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-2">
                      <div
                        className="bg-red-500 h-2 rounded-full"
                        style={{ width: `${Math.min((ztmStatus.hmacFailures / 10) * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-gray-400 text-sm">Decrypt Failures</span>
                      <span className="text-white font-mono">{ztmStatus.decryptFailures}</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-2">
                      <div
                        className="bg-red-500 h-2 rounded-full"
                        style={{ width: `${Math.min((ztmStatus.decryptFailures / 10) * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-gray-400 text-sm">Replay Attempts</span>
                      <span className="text-white font-mono">{ztmStatus.replayAttempts}</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-2">
                      <div
                        className="bg-yellow-500 h-2 rounded-full"
                        style={{ width: `${Math.min((ztmStatus.replayAttempts / 5) * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-gray-400 text-sm">Malformed Packets</span>
                      <span className="text-white font-mono">{ztmStatus.malformedPackets}</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-2">
                      <div
                        className="bg-yellow-500 h-2 rounded-full"
                        style={{ width: `${Math.min((ztmStatus.malformedPackets / 15) * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-gray-400 text-sm">Timing Anomalies</span>
                      <span className="text-white font-mono">{ztmStatus.timingAnomalies}</span>
                    </div>
                    <div className="w-full bg-gray-800 rounded-full h-2">
                      <div
                        className="bg-yellow-500 h-2 rounded-full"
                        style={{ width: `${Math.min((ztmStatus.timingAnomalies / 25) * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                </div>
              </div>

              {/* Key/Nonce Status */}
              <div className="bg-gray-900 border border-gray-700 rounded-xl p-6">
                <h2 className="text-xl font-bold text-red-400 font-mono mb-4">
                  KEY/NONCE STATUS
                </h2>
                <div className="space-y-3">
                  <div className="p-3 bg-green-500/20 border border-green-500/50 rounded-lg">
                    <div className="text-green-400 font-mono text-sm mb-1">✓ Keys Synchronized</div>
                    <div className="text-gray-400 text-xs">Master keys regenerated on recipe switch</div>
                  </div>
                  <div className="p-3 bg-green-500/20 border border-green-500/50 rounded-lg">
                    <div className="text-green-400 font-mono text-sm mb-1">✓ Nonces Synchronized</div>
                    <div className="text-gray-400 text-xs">Nonce counter managed per session</div>
                  </div>
                  <div className="p-3 bg-yellow-500/20 border border-yellow-500/50 rounded-lg">
                    <div className="text-yellow-400 font-mono text-sm mb-1">⚠️ Recipe Switch Cooldown</div>
                    <div className="text-gray-400 text-xs">5 second minimum between switches</div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    )
  }

  // Show activation prompt
  return (
    <div className="min-h-screen bg-black text-white flex items-center justify-center p-8">
      <div className="text-center max-w-2xl">
        <h1 className="text-5xl font-bold text-red-500 font-mono mb-6">
          ZERO TRUST MODE
        </h1>
        <p className="text-gray-400 text-lg mb-8">
          Activate adaptive encryption switching with live threat detection
        </p>
        <button
          onClick={handleActivateClick}
          disabled={!isConnected || isActivating}
          className={`px-8 py-4 text-white rounded-xl font-mono font-bold text-lg transition-colors shadow-lg ${
            !isConnected || isActivating
              ? 'bg-gray-600 cursor-not-allowed'
              : 'bg-red-600 hover:bg-red-700 shadow-red-500/25'
          }`}
        >
          {isActivating ? '🔄 ACTIVATING...' : '🛡️ ACTIVATE ZERO TRUST'}
        </button>
        {!isConnected && (
          <p className="mt-4 text-yellow-400 text-sm">
            ⚠️ WebSocket not connected. Please wait for connection.
          </p>
        )}
        <div className="mt-8 text-gray-500 text-sm space-y-2">
          <p>• Threat detection via heuristics manager</p>
          <p>• Automatic algorithm switching based on events</p>
          <p>• 5 adaptive encryption recipes available</p>
          <p>• Synchronized key and nonce management</p>
        </div>
      </div>
    </div>
  )
}
