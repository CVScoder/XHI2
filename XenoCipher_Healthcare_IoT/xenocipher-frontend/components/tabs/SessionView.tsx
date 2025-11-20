// components/tabs/SessionView.tsx
'use client'

import React from 'react'
import { motion } from 'framer-motion'
import { usePipeline } from '../../context/PipelineContext'

export default function SessionView() {
  const { pipelineData } = usePipeline()

  const sessionEvents = [
    {
      phase: 'Key Exchange',
      status: pipelineData.masterKeyEstablished ? 'completed' : 'pending',
      timestamp: '12:30:45',
      details: 'NTRU Key Pair Established'
    },
    {
      phase: 'Master Key Derivation',
      status: pipelineData.masterKeyEstablished ? 'completed' : 'pending',
      timestamp: '12:30:46',
      details: '256-bit Master Key Secured'
    },
    {
      phase: 'Health Data Encryption',
      status: pipelineData.finalPacket ? 'completed' : 'pending',
      timestamp: pipelineData.finalPacket ? '12:30:47' : '--:--:--',
      details: pipelineData.finalPacket ? 'Data Encrypted & Transmitted' : 'Awaiting Data'
    },
    {
      phase: 'Server Decryption',
      status: pipelineData.finalPlaintext ? 'completed' : 'pending',
      timestamp: pipelineData.finalPlaintext ? '12:30:48' : '--:--:--',
      details: pipelineData.finalPlaintext ? 'Data Decrypted Successfully' : 'Awaiting Processing'
    },
    {
      phase: 'Database Storage',
      status: pipelineData.sessionSummary?.dataStored ? 'completed' : 'pending',
      timestamp: pipelineData.sessionSummary?.dataStored ? '12:30:49' : '--:--:--',
      details: pipelineData.sessionSummary?.dataStored ? 'Data Securely Stored' : 'Ready for Storage'
    }
  ]

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="grid grid-cols-1 lg:grid-cols-2 gap-6"
      >
        {/* Session Timeline */}
        <motion.div 
          className="bg-gray-800/50 rounded-xl border border-cyan-500/20 p-6"
          whileHover={{ scale: 1.02 }}
        >
          <h2 className="text-xl font-bold text-cyan-400 mb-4">Session Timeline</h2>
          <div className="space-y-4">
            {sessionEvents.map((event, index) => (
              <motion.div
                key={event.phase}
                initial={{ opacity: 0, x: -20 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: index * 0.1 }}
                className={`flex items-center space-x-4 p-3 rounded-lg border ${
                  event.status === 'completed' 
                    ? 'border-green-500/50 bg-green-500/10' 
                    : 'border-gray-600/50 bg-gray-700/20'
                }`}
              >
                <div className={`w-3 h-3 rounded-full ${
                  event.status === 'completed' ? 'bg-green-500' : 'bg-gray-500'
                }`}></div>
                <div className="flex-1">
                  <div className="flex justify-between items-center">
                    <span className="font-semibold text-white">{event.phase}</span>
                    <span className="text-sm text-cyan-300">{event.timestamp}</span>
                  </div>
                  <p className="text-sm text-gray-300 mt-1">{event.details}</p>
                </div>
              </motion.div>
            ))}
          </div>
        </motion.div>

        {/* Cryptographic Data Flow */}
        <motion.div 
          className="bg-gray-800/50 rounded-xl border border-cyan-500/20 p-6"
          whileHover={{ scale: 1.02 }}
        >
          <h2 className="text-xl font-bold text-cyan-400 mb-4">Data Transformation</h2>
          
          <div className="space-y-4">
            {/* Original Data */}
            <div className="p-4 bg-gray-700/30 rounded-lg border border-green-500/30">
              <label className="text-green-400 text-sm font-mono">Original Health Data</label>
              <div className="mt-2 p-3 bg-black/40 rounded border border-green-500/20">
                <code className="text-green-300 font-mono text-sm">
                  {pipelineData.plaintext || 'HR-81 SPO2-99 STEPS-6403'}
                </code>
              </div>
            </div>

            {/* Encrypted Data */}
            <div className="p-4 bg-gray-700/30 rounded-lg border border-cyan-500/30">
              <label className="text-cyan-400 text-sm font-mono">Encrypted Packet</label>
              <div className="mt-2 p-3 bg-black/40 rounded border border-cyan-500/20">
                <code className="text-cyan-300 font-mono text-sm break-all">
                  {pipelineData.finalPacket || 'ENC_DATA:a1b2c3d4e5f6...'}
                </code>
              </div>
            </div>

            {/* Decrypted Data */}
            <div className="p-4 bg-gray-700/30 rounded-lg border border-purple-500/30">
              <label className="text-purple-400 text-sm font-mono">Decrypted Result</label>
              <div className="mt-2 p-3 bg-black/40 rounded border border-purple-500/20">
                <code className="text-purple-300 font-mono text-sm">
                  {pipelineData.finalPlaintext || 'Awaiting decryption...'}
                </code>
              </div>
            </div>
          </div>
        </motion.div>
      </motion.div>

      {/* Performance Metrics */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gray-800/50 rounded-xl border border-cyan-500/20 p-6"
      >
        <h2 className="text-xl font-bold text-cyan-400 mb-4">Session Performance</h2>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="text-center p-4 bg-gray-700/30 rounded-lg">
            <div className="text-2xl font-bold text-green-400">
              {pipelineData.encryptionTime?.toFixed(2) || '0.00'}ms
            </div>
            <div className="text-gray-300 text-sm">Encryption Time</div>
          </div>
          <div className="text-center p-4 bg-gray-700/30 rounded-lg">
            <div className="text-2xl font-bold text-cyan-400">
              {pipelineData.decryptionTime?.toFixed(2) || '0.00'}ms
            </div>
            <div className="text-gray-300 text-sm">Decryption Time</div>
          </div>
          <div className="text-center p-4 bg-gray-700/30 rounded-lg">
            <div className="text-2xl font-bold text-purple-400">
              {((pipelineData.encryptionTime || 0) + (pipelineData.decryptionTime || 0)).toFixed(2)}ms
            </div>
            <div className="text-gray-300 text-sm">Total Processing</div>
          </div>
        </div>
      </motion.div>
    </div>
  )
}