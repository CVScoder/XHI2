// components/tabs/PipelineVisualization.tsx
'use client'

import React from 'react'
import { motion } from 'framer-motion'
import { usePipeline } from '../../context/PipelineContext'

const pipelineStages = [
  { id: 'original', name: 'Original Data', color: 'green' },
  { id: 'salt', name: 'Salt Addition', color: 'blue' },
  { id: 'lfsr', name: 'LFSR Encryption', color: 'purple' },
  { id: 'tinkerbell', name: 'Tinkerbell Map', color: 'pink' },
  { id: 'transposition', name: 'Transposition', color: 'yellow' },
  { id: 'encrypted', name: 'Encrypted Packet', color: 'cyan' }
]

export default function PipelineVisualization() {
  const { pipelineData } = usePipeline()

  const getStageData = (stageId: string) => {
    switch (stageId) {
      case 'original': return pipelineData.plaintext
      case 'salt': return pipelineData.afterSalt
      case 'lfsr': return pipelineData.afterLFSR
      case 'tinkerbell': return pipelineData.afterTinkerbell
      case 'transposition': return pipelineData.afterTransposition
      case 'encrypted': return pipelineData.finalPacket
      default: return ''
    }
  }

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="bg-gray-800/50 rounded-xl border border-cyan-500/20 p-6"
      >
        <h2 className="text-2xl font-bold text-cyan-400 mb-6">Cryptographic Pipeline</h2>
        
        {/* Pipeline Flow */}
        <div className="relative">
          {/* Connection Lines */}
          <div className="absolute top-1/2 left-0 right-0 h-0.5 bg-cyan-500/30 -translate-y-1/2"></div>
          
          <div className="grid grid-cols-6 gap-4 relative z-10">
            {pipelineStages.map((stage, index) => (
              <motion.div
                key={stage.id}
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: index * 0.1 }}
                className="text-center"
              >
                {/* Stage Circle */}
                <div className={`
                  w-16 h-16 rounded-full border-4 mx-auto mb-3
                  flex items-center justify-center text-white font-bold
                  ${getStageData(stage.id) 
                    ? `border-${stage.color}-500 bg-${stage.color}-500/20 cyber-glow` 
                    : 'border-gray-600 bg-gray-700/50'
                  }
                `}>
                  {index + 1}
                </div>
                
                {/* Stage Label */}
                <h3 className={`font-semibold text-sm ${
                  getStageData(stage.id) ? `text-${stage.color}-400` : 'text-gray-500'
                }`}>
                  {stage.name}
                </h3>
                
                {/* Stage Data Preview */}
                <div className="mt-2 p-2 bg-black/40 rounded border border-gray-600">
                  <code className="text-xs text-gray-300 break-all">
                    {getStageData(stage.id) ? formatHex(getStageData(stage.id)!) : 'Waiting...'}
                  </code>
                </div>
              </motion.div>
            ))}
          </div>
        </div>
      </motion.div>

      {/* Detailed Stage Information */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="grid grid-cols-1 lg:grid-cols-2 gap-6"
      >
        {/* Encryption Pipeline */}
        <div className="bg-gray-800/50 rounded-xl border border-green-500/20 p-6">
          <h3 className="text-lg font-bold text-green-400 mb-4">Encryption Pipeline (ESP32)</h3>
          <div className="space-y-3">
            {pipelineStages.map(stage => (
              <div key={stage.id} className="flex items-center justify-between p-3 bg-gray-700/30 rounded">
                <span className="text-gray-300">{stage.name}</span>
                <code className="text-xs text-green-300">
                  {getStageData(stage.id) ? '✓ Complete' : '⏳ Pending'}
                </code>
              </div>
            ))}
          </div>
        </div>

        {/* Decryption Pipeline */}
        <div className="bg-gray-800/50 rounded-xl border border-purple-500/20 p-6">
          <h3 className="text-lg font-bold text-purple-400 mb-4">Decryption Pipeline (Server)</h3>
          <div className="space-y-3">
            <div className="flex items-center justify-between p-3 bg-gray-700/30 rounded">
              <span className="text-gray-300">Encrypted Packet Received</span>
              <code className="text-xs text-purple-300">
                {pipelineData.encryptedPacket ? '✓ Complete' : '⏳ Waiting'}
              </code>
            </div>
            <div className="flex items-center justify-between p-3 bg-gray-700/30 rounded">
              <span className="text-gray-300">HMAC Verification</span>
              <code className="text-xs text-purple-300">
                {pipelineData.finalPlaintext ? '✓ Valid' : '⏳ Pending'}
              </code>
            </div>
            <div className="flex items-center justify-between p-3 bg-gray-700/30 rounded">
              <span className="text-gray-300">Inverse Transposition</span>
              <code className="text-xs text-purple-300">
                {pipelineData.afterTransposition ? '✓ Applied' : '⏳ Pending'}
              </code>
            </div>
            <div className="flex items-center justify-between p-3 bg-gray-700/30 rounded">
              <span className="text-gray-300">Tinkerbell XOR</span>
              <code className="text-xs text-purple-300">
                {pipelineData.afterTinkerbellDecryption ? '✓ Applied' : '⏳ Pending'}
              </code>
            </div>
            <div className="flex items-center justify-between p-3 bg-gray-700/30 rounded">
              <span className="text-gray-300">LFSR Decryption</span>
              <code className="text-xs text-purple-300">
                {pipelineData.afterLFSRDecryption ? '✓ Applied' : '⏳ Pending'}
              </code>
            </div>
            <div className="flex items-center justify-between p-3 bg-gray-700/30 rounded">
              <span className="text-gray-300">Salt Removal</span>
              <code className="text-xs text-purple-300">
                {pipelineData.afterDepad ? '✓ Removed' : '⏳ Pending'}
              </code>
            </div>
          </div>
        </div>
      </motion.div>
    </div>
  )
}

function formatHex(data: string): string {
  if (data.length > 20) {
    return data.substring(0, 20) + '...'
  }
  return data
}