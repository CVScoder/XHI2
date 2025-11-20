// components/ZeroTrustStatus.tsx
'use client'

import { motion } from 'framer-motion'
import { useZeroTrust } from '../context/ZeroTrustContext'

export function ZeroTrustStatus() {
  const { isZeroTrustMode, zeroTrustData } = useZeroTrust()

  if (!isZeroTrustMode) return null

  return (
    <motion.div
      className="fixed top-20 right-4 z-40"
      initial={{ opacity: 0, x: 100 }}
      animate={{ opacity: 1, x: 0 }}
      exit={{ opacity: 0, x: 100 }}
    >
      <div className="bg-black/80 backdrop-blur-lg border border-red-500/30 rounded-lg p-4 font-mono">
        <div className="flex items-center space-x-2 mb-2">
          <div className={`w-2 h-2 rounded-full ${
            zeroTrustData.threatLevel === 'green' ? 'bg-green-500' :
            zeroTrustData.threatLevel === 'yellow' ? 'bg-yellow-500' : 'bg-red-500'
          }`} />
          <span className="text-red-400 text-sm">ZERO TRUST ACTIVE</span>
        </div>
        <div className="text-xs text-gray-400">
          Threat Level: <span className="text-white">{zeroTrustData.threatLevel.toUpperCase()}</span>
        </div>
        {zeroTrustData.ephemeralIdentity && (
          <div className="text-xs text-gray-400 mt-1">
            Identity: <span className="text-green-400">{zeroTrustData.ephemeralIdentity}</span>
          </div>
        )}
      </div>
    </motion.div>
  )
}