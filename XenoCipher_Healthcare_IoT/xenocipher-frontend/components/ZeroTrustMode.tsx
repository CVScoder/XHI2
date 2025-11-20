// components/ZeroTrustMode.tsx
'use client'

import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react'
import { motion, AnimatePresence } from 'framer-motion'

// ===== ZERO TRUST CONTEXT (Embedded) =====
type ThreatLevel = 'green' | 'yellow' | 'red'

interface ZeroTrustContextType {
  isZeroTrustMode: boolean
  enableZeroTrust: () => void
  disableZeroTrust: () => void
  zeroTrustData: {
    sessionKey?: string
    ephemeralIdentity?: string
    threatLevel: ThreatLevel
  }
}

const ZeroTrustContext = createContext<ZeroTrustContextType | undefined>(undefined)

function ZeroTrustProvider({ children }: { children: ReactNode }) {
  const [isZeroTrustMode, setIsZeroTrustMode] = useState(true) // Start in Zero Trust mode
  const [zeroTrustData, setZeroTrustData] = useState<{
    sessionKey?: string
    ephemeralIdentity?: string
    threatLevel: ThreatLevel
  }>({
    threatLevel: 'green'
  })

  const enableZeroTrust = useCallback(() => {
    console.log('[Zero Trust] 🚀 Activating Zero Trust Mode...')
    
    const sessionKey = Array.from({ length: 32 }, () => 
      Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
    ).join('')
    
    const words = ['quantum', 'lattice', 'cipher', 'void', 'neon', 'trust', 'zero', 'burn']
    const ephemeralIdentity = Array.from({ length: 4 }, () => 
      words[Math.floor(Math.random() * words.length)]
    ).join('-')
    
    setZeroTrustData({
      sessionKey,
      ephemeralIdentity,
      threatLevel: 'yellow'
    })
    setIsZeroTrustMode(true)
    
    setTimeout(() => {
      setZeroTrustData(prev => ({ ...prev, threatLevel: 'green' }))
    }, 5000)
  }, [])

  const disableZeroTrust = useCallback(() => {
    console.log('[Zero Trust] 🗑️ Deactivating Zero Trust Mode...')
    setZeroTrustData({ threatLevel: 'green' })
    setIsZeroTrustMode(false)
  }, [])

  // Auto-enable Zero Trust when component mounts
  useEffect(() => {
    enableZeroTrust()
  }, [enableZeroTrust])

  const value: ZeroTrustContextType = {
    isZeroTrustMode,
    enableZeroTrust,
    disableZeroTrust,
    zeroTrustData
  }

  return (
    <ZeroTrustContext.Provider value={value}>
      {children}
    </ZeroTrustContext.Provider>
  )
}

function useZeroTrust(): ZeroTrustContextType {
  const context = useContext(ZeroTrustContext)
  if (!context) {
    throw new Error('useZeroTrust must be used within ZeroTrustProvider')
  }
  return context
}

// ===== MAIN ZERO TRUST COMPONENT =====
function ZeroTrustContent() {
  const [currentStep, setCurrentStep] = useState(0)
  // FIX: Add enableZeroTrust to the destructuring
  const { disableZeroTrust, enableZeroTrust, isZeroTrustMode, zeroTrustData } = useZeroTrust()

  const steps = [
    {
      title: 'ACTIVATING ZERO TRUST',
      description: 'Initializing secure environment',
      icon: '🛡️',
      color: 'text-red-500'
    },
    {
      title: 'GENERATING EPHEMERAL IDENTITY', 
      description: 'Creating quantum-resistant key pair',
      icon: '🔑',
      color: 'text-yellow-500'
    },
    {
      title: 'SECURE HANDSHAKE',
      description: 'Establishing encrypted connection',
      icon: '⚡',
      color: 'text-green-500'
    },
    {
      title: 'ZERO TRUST ACTIVE',
      description: 'All communications secured',
      icon: '✅',
      color: 'text-cyan-500'
    }
  ]

  // Auto-advance steps for demo
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentStep(prev => (prev < steps.length - 1 ? prev + 1 : prev))
    }, 2000)

    return () => clearInterval(timer)
  }, [steps.length])

  const handleExit = () => {
    if (confirm('Leaving Zero Trust Mode will destroy all ephemeral data. Continue?')) {
      disableZeroTrust()
      // Redirect to home or show message
      alert('Zero Trust Mode deactivated. Returning to standard mode.')
    }
  }

  // Show loading state if Zero Trust mode is not properly activated
  if (!isZeroTrustMode) {
    return (
      <div className="min-h-screen bg-black text-white flex items-center justify-center">
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="text-center"
        >
          <div className="text-6xl mb-4">🔄</div>
          <h1 className="text-2xl font-bold text-red-500 font-mono mb-4">
            ZERO TRUST MODE DEACTIVATED
          </h1>
          <p className="text-gray-400">Returning to standard mode...</p>
          {/* FIX: enableZeroTrust is now available */}
          <button
            onClick={enableZeroTrust}
            className="mt-4 px-4 py-2 bg-red-600 text-white rounded-lg font-mono text-sm hover:bg-red-700"
          >
            Reactivate Zero Trust
          </button>
        </motion.div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-black text-white p-8">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: -50 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center mb-16"
        >
          <h1 className="text-5xl font-bold text-red-500 font-mono mb-4 tracking-tighter">
            ZERO TRUST MODE
          </h1>
          <p className="text-gray-400 text-lg">
            No history. No contacts. Nothing persists. Nothing is trusted.
          </p>
        </motion.div>

        {/* Progress Steps */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-16">
          {steps.map((step, index) => (
            <motion.div
              key={index}
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: index * 0.3 }}
              className={`p-6 rounded-xl border-2 transition-all ${
                index <= currentStep 
                  ? 'border-red-500 bg-red-500/10 shadow-lg shadow-red-500/25' 
                  : 'border-gray-700 bg-gray-800/30'
              }`}
            >
              <div className="text-4xl mb-4">{step.icon}</div>
              <div className={`font-mono text-sm font-bold mb-2 ${step.color}`}>
                {step.title}
              </div>
              <div className="text-gray-400 text-xs">
                {step.description}
              </div>
            </motion.div>
          ))}
        </div>

        {/* Current Step Display */}
        <motion.div
          key={currentStep}
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-center bg-gray-900/50 rounded-2xl p-12 border border-gray-700"
        >
          <motion.div
            className="text-8xl mb-8"
            animate={{ scale: [1, 1.1, 1] }}
            transition={{ duration: 2, repeat: Infinity }}
          >
            {steps[currentStep].icon}
          </motion.div>
          
          <h2 className={`text-3xl font-bold font-mono mb-4 ${steps[currentStep].color}`}>
            {steps[currentStep].title}
          </h2>
          
          <p className="text-gray-300 text-xl mb-8">
            {steps[currentStep].description}
          </p>

          {/* Progress Bar */}
          <div className="w-full bg-gray-700 rounded-full h-3 mb-4">
            <motion.div 
              className="h-3 bg-gradient-to-r from-red-500 to-green-500 rounded-full"
              initial={{ width: 0 }}
              animate={{ width: `${((currentStep + 1) / steps.length) * 100}%` }}
              transition={{ duration: 1 }}
            />
          </div>
          
          <div className="text-gray-400 font-mono">
            Step {currentStep + 1} of {steps.length}
          </div>

          {/* Ephemeral Identity Display */}
          {zeroTrustData.ephemeralIdentity && currentStep >= 1 && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="mt-6 p-4 bg-green-500/10 border border-green-500/30 rounded-lg"
            >
              <div className="font-mono text-green-400 text-sm">
                EPHEMERAL IDENTITY: {zeroTrustData.ephemeralIdentity}
              </div>
            </motion.div>
          )}
        </motion.div>

        {/* Status Bar */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 1 }}
          className="fixed bottom-6 left-6 bg-red-500/20 border border-red-500/30 rounded-lg p-4 font-mono text-sm"
        >
          <div className="flex items-center space-x-3">
            <motion.div 
              className={`w-3 h-3 rounded-full ${
                zeroTrustData.threatLevel === 'green' ? 'bg-green-500' :
                zeroTrustData.threatLevel === 'yellow' ? 'bg-yellow-500' : 'bg-red-500'
              }`}
              animate={{ scale: [1, 1.2, 1] }}
              transition={{ duration: 2, repeat: Infinity }}
            />
            <span className="text-red-400">ZERO TRUST ACTIVE</span>
            <span className="text-gray-400">•</span>
            <span className={
              zeroTrustData.threatLevel === 'green' ? 'text-green-400' :
              zeroTrustData.threatLevel === 'yellow' ? 'text-yellow-400' : 'text-red-400'
            }>
              THREAT: {zeroTrustData.threatLevel.toUpperCase()}
            </span>
          </div>
        </motion.div>

        {/* Exit Button */}
        <motion.button
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 2 }}
          onClick={handleExit}
          className="fixed bottom-6 right-6 px-4 py-2 bg-gray-800 text-white rounded-lg border border-gray-600 font-mono text-sm hover:bg-gray-700 transition-colors"
        >
          ← Exit Zero Trust
        </motion.button>

        {/* Demo Controls */}
        {currentStep === steps.length - 1 && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center mt-8"
          >
            <p className="text-gray-500 text-sm mb-4">
              Zero Trust Mode is now active. All communications are secured.
            </p>
            <motion.button
              whileHover={{ scale: 1.05 }}
              whileTap={{ scale: 0.95 }}
              onClick={() => setCurrentStep(0)}
              className="px-4 py-2 bg-red-600 text-white rounded-lg font-mono text-sm"
            >
              Restart Demo
            </motion.button>
          </motion.div>
        )}
      </div>
    </div>
  )
}

// ===== MAIN EXPORT =====
export default function ZeroTrustMode() {
  return (
    <ZeroTrustProvider>
      <ZeroTrustContent />
    </ZeroTrustProvider>
  )
}