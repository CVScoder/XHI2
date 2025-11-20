// components/XenoCipherDashboard.tsx
'use client'

import { useState } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import EnhancedPipelineVisualization from './EnhancedPipelineVisualization'
import ZeroTrustMode from './ZeroTrustMode'

export default function XenoCipherDashboard() {
  const [isZeroTrustActive, setIsZeroTrustActive] = useState(false)

  const handleZeroTrustToggle = () => {
    setIsZeroTrustActive(true)
  }

  const handleExitZeroTrust = () => {
    setIsZeroTrustActive(false)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-blue-900/20 to-purple-900/20">
      <AnimatePresence mode="wait">
        {isZeroTrustActive ? (
          <motion.div
            key="zero-trust-mode"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="min-h-screen"
          >
            <ZeroTrustMode />
            <button
              onClick={handleExitZeroTrust}
              className="fixed top-6 right-6 z-50 px-5 py-2.5 bg-white/10 backdrop-blur-sm text-white rounded-xl border border-white/20 font-medium text-sm hover:bg-white/20 transition-all shadow-lg"
            >
              ← Back to Dashboard
            </button>
          </motion.div>
        ) : (
          <motion.div
            key="pipeline-dashboard"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="min-h-screen"
          >
            <EnhancedPipelineVisualization onZeroTrustToggle={handleZeroTrustToggle} />
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}