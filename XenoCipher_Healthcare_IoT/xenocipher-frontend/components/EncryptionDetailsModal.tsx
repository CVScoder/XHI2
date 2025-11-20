// components/EncryptionDetailsModal.tsx
'use client'

import React from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { EncryptionDetails } from '../types/pipeline'

interface EncryptionDetailsModalProps {
  isOpen: boolean
  onClose: () => void
  details: EncryptionDetails | null
}

export default function EncryptionDetailsModal({ isOpen, onClose, details }: EncryptionDetailsModalProps) {
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
            className="bg-gray-900 border border-cyan-500/30 rounded-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden"
            initial={{ scale: 0.9, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.9, opacity: 0 }}
            onClick={(e) => e.stopPropagation()} // Prevent closing when clicking modal content
          >
            {/* Header */}
            <div className="border-b border-cyan-500/20 p-6">
              <div className="flex items-center justify-between">
                <div>
                  <h2 className="text-2xl font-bold text-cyan-400">Encryption Pipeline Details</h2>
                  <p className="text-gray-400">Step-by-step encryption process</p>
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
                {/* Step 1: Plaintext Input */}
                <div className="bg-gray-800/50 rounded-xl p-4 border border-green-500/20">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-lg font-semibold text-green-400">1. Plaintext Input</h3>
                    <button
                      onClick={() => copyToClipboard(details.plaintext)}
                      className="text-xs bg-green-600 hover:bg-green-700 px-3 py-2 rounded transition-colors cursor-pointer active:scale-95"
                      style={{ pointerEvents: 'auto' }}
                    >
                      Copy
                    </button>
                  </div>
                  <pre className="text-green-300 font-mono text-sm bg-black/40 p-3 rounded-lg overflow-x-auto">
                    {details.plaintext}
                  </pre>
                </div>

                {/* Step 2: LFSR Encryption */}
                <div className="bg-gray-800/50 rounded-xl p-4 border border-blue-500/20">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-lg font-semibold text-blue-400">2. LFSR Stream Cipher</h3>
                    <button
                      onClick={() => copyToClipboard(details.lfsrOutput)}
                      className="text-xs bg-blue-600 hover:bg-blue-700 px-3 py-2 rounded transition-colors cursor-pointer active:scale-95"
                      style={{ pointerEvents: 'auto' }}
                    >
                      Copy
                    </button>
                  </div>
                  <pre className="text-blue-300 font-mono text-sm bg-black/40 p-3 rounded-lg overflow-x-auto">
                    {details.lfsrOutput}
                  </pre>
                </div>

                {/* Step 3: Chaos Map */}
                <div className="bg-gray-800/50 rounded-xl p-4 border border-purple-500/20">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-lg font-semibold text-purple-400">3. Tinkerbell Chaos Map</h3>
                    <button
                      onClick={() => copyToClipboard(details.chaosMapOutput)}
                      className="text-xs bg-purple-600 hover:bg-purple-700 px-3 py-2 rounded transition-colors cursor-pointer active:scale-95"
                      style={{ pointerEvents: 'auto' }}
                    >
                      Copy
                    </button>
                  </div>
                  <pre className="text-purple-300 font-mono text-sm bg-black/40 p-3 rounded-lg overflow-x-auto">
                    {details.chaosMapOutput}
                  </pre>
                </div>

                {/* Step 4: Transposition */}
                <div className="bg-gray-800/50 rounded-xl p-4 border border-yellow-500/20">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-lg font-semibold text-yellow-400">4. Transposition Cipher</h3>
                    <button
                      onClick={() => copyToClipboard(details.transpositionOutput)}
                      className="text-xs bg-yellow-600 hover:bg-yellow-700 px-3 py-2 rounded transition-colors cursor-pointer active:scale-95"
                      style={{ pointerEvents: 'auto' }}
                    >
                      Copy
                    </button>
                  </div>
                  <pre className="text-yellow-300 font-mono text-sm bg-black/40 p-3 rounded-lg overflow-x-auto">
                    {details.transpositionOutput}
                  </pre>
                </div>

                {/* Step 5: Final Encrypted Packet */}
                <div className="bg-gray-800/50 rounded-xl p-4 border border-red-500/20">
                  <div className="flex items-center justify-between mb-3">
                    <h3 className="text-lg font-semibold text-red-400">5. Final Encrypted Packet</h3>
                    <button
                      onClick={() => copyToClipboard(details.finalEncryptedPacket)}
                      className="text-xs bg-red-600 hover:bg-red-700 px-3 py-2 rounded transition-colors cursor-pointer active:scale-95"
                      style={{ pointerEvents: 'auto' }}
                    >
                      Copy
                    </button>
                  </div>
                  <pre className="text-red-300 font-mono text-sm bg-black/40 p-3 rounded-lg overflow-x-auto">
                    {details.finalEncryptedPacket}
                  </pre>
                </div>

                {/* Metadata */}
                <div className="bg-gray-800/50 rounded-xl p-4 border border-cyan-500/20">
                  <h3 className="text-lg font-semibold text-cyan-400 mb-3">Cryptographic Metadata</h3>
                  <div className="grid grid-cols-2 gap-4 text-sm">
                    <div>
                      <span className="text-gray-400">Salt:</span>
                      <div className="font-mono text-cyan-300 truncate">{details.metadata.salt}</div>
                    </div>
                    <div>
                      <span className="text-gray-400">Key:</span>
                      <div className="font-mono text-cyan-300 truncate">{details.metadata.key}</div>
                    </div>
                    <div>
                      <span className="text-gray-400">IV:</span>
                      <div className="font-mono text-cyan-300 truncate">{details.metadata.iv}</div>
                    </div>
                    <div>
                      <span className="text-gray-400">Auth Tag:</span>
                      <div className="font-mono text-cyan-300 truncate">{details.metadata.authTag}</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Footer */}
            <div className="border-t border-cyan-500/20 p-4 bg-gray-800/50">
              <div className="flex justify-end">
                <button
                  onClick={onClose}
                  className="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 rounded-lg transition-colors cursor-pointer active:scale-95 font-medium"
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