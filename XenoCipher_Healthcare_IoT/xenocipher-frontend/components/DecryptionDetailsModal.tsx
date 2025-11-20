// components/DecryptionDetailsModal.tsx
'use client'

import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { DecryptionDetails } from '../types/pipeline'

interface DecryptionDetailsModalProps {
  isOpen: boolean
  onClose: () => void
  details: DecryptionDetails | null
}

export default function DecryptionDetailsModal({ isOpen, onClose, details }: DecryptionDetailsModalProps) {
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  // Prevent background scrolling when modal is open
  React.useEffect(() => {
    if (isOpen) {
      document.body.style.overflow = 'hidden'
    } else {
      document.body.style.overflow = 'unset'
    }
    
    return () => {
      document.body.style.overflow = 'unset'
    }
  }, [isOpen])

  if (!details) return null

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          className="fixed inset-0 bg-black/80 backdrop-blur-sm z-[9999] flex items-center justify-center p-4"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose} // Close when clicking backdrop
        >
          <motion.div
            className="bg-gray-900 border border-green-500/30 rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden"
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.9, opacity: 0 }}
            onClick={(e) => e.stopPropagation()} // Prevent closing when clicking modal content
          >
            {/* Header */}
            <div className="border-b border-green-500/20 p-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-2xl font-bold text-green-400">Decryption Pipeline Details</h2>
                  <p className="text-gray-400">Step-by-step decryption process and verification</p>
                </div>
                <button
                  onClick={onClose}
                  className="text-gray-400 hover:text-white transition-colors p-2 rounded-lg hover:bg-gray-800 cursor-pointer"
                  style={{ pointerEvents: 'auto' }}
                >
                  <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
                  </svg>
                </button>
              </div>
            </div>

            {/* Content */}
            <div className="p-6 overflow-y-auto max-h-[70vh]">
              <div className="space-y-6">
                {/* Step 1: Encrypted Packet */}
                <div className="bg-gray-800/50 rounded-xl p-4 border border-red-500/20">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-lg font-semibold text-red-400">1. Encrypted Packet</h3>
                    <button
                      onClick={() => copyToClipboard(details.encryptedPacket)}
                      className="text-xs bg-red-600 hover:bg-red-700 px-3 py-2 rounded transition-colors cursor-pointer active:scale-95"
                      style={{ pointerEvents: 'auto' }}
                    >
                      Copy
                    </button>
                  </div>
                  <pre className="text-red-300 font-mono text-sm bg-black/40 p-3 rounded-lg overflow-x-auto">
                    {details.encryptedPacket}
                  </pre>
                </div>

                {/* Step 2: Reverse Transposition */}
                <div className="bg-gray-800/50 rounded-xl p-4 border border-yellow-500/20">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-lg font-semibold text-yellow-400">2. Reverse Transposition</h3>
                    <button
                      onClick={() => copyToClipboard(details.reversedTransposition)}
                      className="text-xs bg-yellow-600 hover:bg-yellow-700 px-3 py-2 rounded transition-colors cursor-pointer active:scale-95"
                      style={{ pointerEvents: 'auto' }}
                    >
                      Copy
                    </button>
                  </div>
                  <pre className="text-yellow-300 font-mono text-sm bg-black/40 p-3 rounded-lg overflow-x-auto">
                    {details.reversedTransposition}
                  </pre>
                </div>

                {/* Step 3: Reverse Chaos Map */}
                <div className="bg-gray-800/50 rounded-xl p-4 border border-purple-500/20">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-lg font-semibold text-purple-400">3. Reverse Chaos Map</h3>
                    <button
                      onClick={() => copyToClipboard(details.reversedChaosMap)}
                      className="text-xs bg-purple-600 hover:bg-purple-700 px-3 py-2 rounded transition-colors cursor-pointer active:scale-95"
                      style={{ pointerEvents: 'auto' }}
                    >
                      Copy
                    </button>
                  </div>
                  <pre className="text-purple-300 font-mono text-sm bg-black/40 p-3 rounded-lg overflow-x-auto">
                    {details.reversedChaosMap}
                  </pre>
                </div>

                {/* Step 4: Reverse LFSR */}
                <div className="bg-gray-800/50 rounded-xl p-4 border border-blue-500/20">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-lg font-semibold text-blue-400">4. Reverse LFSR</h3>
                    <button
                      onClick={() => copyToClipboard(details.reversedLFSR)}
                      className="text-xs bg-blue-600 hover:bg-blue-700 px-3 py-2 rounded transition-colors cursor-pointer active:scale-95"
                      style={{ pointerEvents: 'auto' }}
                    >
                      Copy
                    </button>
                  </div>
                  <pre className="text-blue-300 font-mono text-sm bg-black/40 p-3 rounded-lg overflow-x-auto">
                    {details.reversedLFSR}
                  </pre>
                </div>

                {/* Step 5: Final Plaintext */}
                <div className="bg-gray-800/50 rounded-xl p-4 border border-green-500/20">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-lg font-semibold text-green-400">5. Final Plaintext</h3>
                    <button
                      onClick={() => copyToClipboard(details.finalPlaintext)}
                      className="text-xs bg-green-600 hover:bg-green-700 px-3 py-2 rounded transition-colors cursor-pointer active:scale-95"
                      style={{ pointerEvents: 'auto' }}
                    >
                      Copy
                    </button>
                  </div>
                  <pre className="text-green-300 font-mono text-sm bg-black/40 p-3 rounded-lg overflow-x-auto">
                    {details.finalPlaintext}
                  </pre>
                </div>

                {/* Verification Results */}
                <div className="bg-gray-800/50 rounded-xl p-4 border border-cyan-500/20">
                  <h3 className="text-lg font-semibold text-cyan-400 mb-3">Integrity Verification</h3>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div className="flex items-center space-x-2">
                      <div className={`w-3 h-3 rounded-full ${details.verification.hmacValid ? 'bg-green-500' : 'bg-red-500'}`} />
                      <span>HMAC Validation: {details.verification.hmacValid ? 'PASS' : 'FAIL'}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className={`w-3 h-3 rounded-full ${details.verification.integrityCheck ? 'bg-green-500' : 'bg-red-500'}`} />
                      <span>Integrity Check: {details.verification.integrityCheck ? 'PASS' : 'FAIL'}</span>
                    </div>
                    <div className="flex items-center space-x-2">
                      <div className={`w-3 h-3 rounded-full ${details.verification.timestampValid ? 'bg-green-500' : 'bg-red-500'}`} />
                      <span>Timestamp Valid: {details.verification.timestampValid ? 'PASS' : 'FAIL'}</span>
                    </div>
                  </div>
                </div>

                {/* Timing Stats */}
                <div className="bg-gray-800/50 rounded-xl p-4 border border-purple-500/20">
                  <h3 className="text-lg font-semibold text-purple-400 mb-3">Performance Timing</h3>
                  <div className="grid grid-cols-3 gap-4 text-sm">
                    <div>
                      <span className="text-gray-400">Total Time:</span>
                      <div className="text-purple-300 font-mono">{details.timing.totalTime}ms</div>
                    </div>
                    <div>
                      <span className="text-gray-400">Decryption:</span>
                      <div className="text-purple-300 font-mono">{details.timing.decryptionTime}ms</div>
                    </div>
                    <div>
                      <span className="text-gray-400">Verification:</span>
                      <div className="text-purple-300 font-mono">{details.timing.verificationTime}ms</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="border-t border-green-500/20 p-4 bg-gray-800/50">
              <div className="flex justify-end">
                <button
                  onClick={onClose}
                  className="px-6 py-3 bg-green-600 hover:bg-green-700 rounded-lg transition-colors cursor-pointer active:scale-95 font-medium"
                  style={{ pointerEvents: 'auto' }}
                >
                  Close
                </button>
              </div>
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  )
}