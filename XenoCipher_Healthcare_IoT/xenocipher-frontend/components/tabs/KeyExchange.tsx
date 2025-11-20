// components/tabs/KeyExchange.tsx
'use client'

import * as React from 'react'
import { useState } from 'react'
import { motion } from 'framer-motion'
import { usePipeline } from '../../context/PipelineContext'
import { useWebSocket } from '../../context/WebSocketContext'

export default function KeyExchange() {
  const { pipelineData, updatePipelineData } = usePipeline()
  const { sendMessage, isConnected } = useWebSocket()
  const [isExchanging, setIsExchanging] = useState(false)

  const simulateKeyExchange = async () => {
    if (!isConnected) {
      alert('WebSocket not connected. Please check server connection.')
      return
    }

    setIsExchanging(true)
    updatePipelineData({ handshakeStatus: 'in-progress' })

    // Simulate NTRU key exchange
    await new Promise(resolve => setTimeout(resolve, 1000))
    updatePipelineData({ publicKeyReceived: true })

    // Simulate master key establishment
    await new Promise(resolve => setTimeout(resolve, 1500))
    updatePipelineData({ 
      masterKeyEstablished: true,
      handshakeStatus: 'completed'
    })

    setIsExchanging(false)
  }

  const keySteps = [
    {
      step: 1,
      name: 'NTRU Key Pair Generation',
      status: pipelineData.publicKeyReceived ? 'completed' : 'pending',
      description: 'Generate quantum-resistant NTRU key pair'
    },
    {
      step: 2,
      name: 'Public Key Exchange',
      status: pipelineData.publicKeyReceived ? 'completed' : 'pending',
      description: 'Exchange public keys with server'
    },
    {
      step: 3,
      name: 'Master Key Encryption',
      status: pipelineData.masterKeyEstablished ? 'completed' : 'pending',
      description: 'Encrypt 256-bit master key using NTRU'
    },
    {
      step: 4,
      name: 'Key Derivation',
      status: pipelineData.masterKeyEstablished ? 'completed' : 'pending',
      description: 'Derive session keys from master key'
    }
  ]

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="grid grid-cols-1 lg:grid-cols-2 gap-6"
      >
        {/* Key Exchange Process */}
        <div className="bg-gray-800/50 rounded-xl border border-cyan-500/20 p-6">
          <h2 className="text-2xl font-bold text-cyan-400 mb-4">Quantum Key Exchange</h2>
          <p className="text-gray-300 mb-6">
            XenoCipher uses NTRU, a quantum-resistant cryptographic system, 
            to establish secure session keys without vulnerability to quantum attacks.
          </p>

          <div className="space-y-4">
            {keySteps.map((keyStep) => (
              <motion.div
                key={keyStep.step}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: keyStep.step * 0.1 }}
                className={`p-4 rounded-lg border ${
                  keyStep.status === 'completed' 
                    ? 'border-green-500 bg-green-500/10' 
                    : 'border-gray-600 bg-gray-700/30'
                }`}
              >
                <div className="flex items-center space-x-4">
                  <div className={`w-8 h-8 rounded-full flex items-center justify-center ${
                    keyStep.status === 'completed' 
                      ? 'bg-green-500 text-white' 
                      : 'bg-gray-600 text-gray-300'
                  }`}>
                    {keyStep.status === 'completed' ? '✓' : keyStep.step}
                  </div>
                  <div className="flex-1">
                    <h3 className="font-semibold text-white">{keyStep.name}</h3>
                    <p className="text-sm text-gray-300">{keyStep.description}</p>
                  </div>
                </div>
              </motion.div>
            ))}
          </div>

          <motion.button
            whileHover={{ scale: 1.05 }}
            whileTap={{ scale: 0.95 }}
            onClick={simulateKeyExchange}
            disabled={isExchanging || !isConnected}
            className={`w-full mt-6 py-3 px-4 rounded-lg font-mono font-bold transition-all ${
              isExchanging || !isConnected
                ? 'bg-gray-600 cursor-not-allowed'
                : 'bg-cyan-600 hover:bg-cyan-700 cyber-glow'
            }`}
          >
            {!isConnected ? 'WebSocket Disconnected' :
             isExchanging ? 'Exchanging Keys...' : 
             'Simulate Key Exchange'}
          </motion.button>
        </div>

        {/* Key Information */}
        <div className="space-y-6">
          {/* Connection Status */}
          <motion.div 
            className="bg-gray-800/50 rounded-xl border border-cyan-500/20 p-6"
            whileHover={{ scale: 1.02 }}
          >
            <h3 className="text-lg font-bold text-cyan-400 mb-4">Connection Status</h3>
            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-gray-300">WebSocket</span>
                <span className={isConnected ? 'text-green-400' : 'text-red-400'}>
                  {isConnected ? 'Connected' : 'Disconnected'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-300">Handshake</span>
                <span className={
                  pipelineData.handshakeStatus === 'completed' ? 'text-green-400' :
                  pipelineData.handshakeStatus === 'in-progress' ? 'text-yellow-400' : 'text-red-400'
                }>
                  {pipelineData.handshakeStatus?.toUpperCase() || 'IDLE'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-300">Public Key</span>
                <span className={pipelineData.publicKeyReceived ? 'text-green-400' : 'text-red-400'}>
                  {pipelineData.publicKeyReceived ? 'Received' : 'Pending'}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-300">Master Key</span>
                <span className={pipelineData.masterKeyEstablished ? 'text-green-400' : 'text-red-400'}>
                  {pipelineData.masterKeyEstablished ? 'Established' : 'Pending'}
                </span>
              </div>
            </div>
          </motion.div>

          {/* Security Features */}
          <motion.div 
            className="bg-gray-800/50 rounded-xl border border-green-500/20 p-6"
            whileHover={{ scale: 1.02 }}
          >
            <h3 className="text-lg font-bold text-green-400 mb-4">Quantum Security Features</h3>
            <ul className="space-y-2 text-sm text-gray-300">
              <li>• NTRU-based key exchange (quantum-resistant)</li>
              <li>• 256-bit master key encryption</li>
              <li>• Forward secrecy enabled</li>
              <li>• Post-quantum cryptography</li>
              <li>• Adaptive key rotation</li>
              <li>• Side-channel attack protection</li>
            </ul>
          </motion.div>
        </div>
      </motion.div>
    </div>
  )
}