// components/tabs/SecurityMetrics.tsx
'use client'

import React from 'react'
import { motion } from 'framer-motion'
import { usePipeline } from '../../context/PipelineContext'

export default function SecurityMetrics() {
  const { pipelineData } = usePipeline()
  const metrics = pipelineData.securityMetrics

  const securityLevels = [
    { name: 'Encryption Strength', value: 95, color: 'green' },
    { name: 'Key Security', value: 98, color: 'green' },
    { name: 'HMAC Integrity', value: 92, color: 'green' },
    { name: 'Replay Protection', value: 96, color: 'green' },
    { name: 'Side-Channel Resistance', value: 88, color: 'yellow' },
  ]

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="grid grid-cols-1 lg:grid-cols-3 gap-6"
      >
        {/* Live Metrics */}
        <div className="col-span-2 grid grid-cols-2 gap-4">
          <motion.div 
            className="bg-gray-800/50 rounded-xl border border-red-500/20 p-4"
            whileHover={{ scale: 1.02 }}
          >
            <h3 className="text-red-400 font-semibold">Decryption Failures</h3>
            <p className="text-3xl font-bold text-white mt-2">{metrics?.decrypt_failures || 0}</p>
            <p className="text-gray-400 text-sm">Last 24 hours</p>
          </motion.div>

          <motion.div 
            className="bg-gray-800/50 rounded-xl border border-yellow-500/20 p-4"
            whileHover={{ scale: 1.02 }}
          >
            <h3 className="text-yellow-400 font-semibold">HMAC Failures</h3>
            <p className="text-3xl font-bold text-white mt-2">{metrics?.hmac_failures || 0}</p>
            <p className="text-gray-400 text-sm">Integrity checks failed</p>
          </motion.div>

          <motion.div 
            className="bg-gray-800/50 rounded-xl border border-purple-500/20 p-4"
            whileHover={{ scale: 1.02 }}
          >
            <h3 className="text-purple-400 font-semibold">Replay Attempts</h3>
            <p className="text-3xl font-bold text-white mt-2">{metrics?.replay_attempts || 0}</p>
            <p className="text-gray-400 text-sm">Attack attempts blocked</p>
          </motion.div>

          <motion.div 
            className="bg-gray-800/50 rounded-xl border border-cyan-500/20 p-4"
            whileHover={{ scale: 1.02 }}
          >
            <h3 className="text-cyan-400 font-semibold">Requests/Minute</h3>
            <p className="text-3xl font-bold text-white mt-2">{metrics?.requests_per_minute || 0}</p>
            <p className="text-gray-400 text-sm">Current load</p>
          </motion.div>
        </div>

        {/* System Status */}
        <motion.div 
          className="bg-gray-800/50 rounded-xl border border-green-500/20 p-6"
          whileHover={{ scale: 1.02 }}
        >
          <h3 className="text-green-400 font-semibold text-lg mb-4">System Status</h3>
          <div className="space-y-3">
            <div className="flex justify-between">
              <span className="text-gray-300">Encryption Engine</span>
              <span className="text-green-400">● Operational</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-300">Key Management</span>
              <span className="text-green-400">● Secure</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-300">HMAC Verification</span>
              <span className="text-green-400">● Active</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-300">Nonce Tracking</span>
              <span className="text-green-400">● Enabled</span>
            </div>
            <div className="flex justify-between">
              <span className="text-gray-300">Adaptive Security</span>
              <span className="text-yellow-400">● Monitoring</span>
            </div>
          </div>
        </motion.div>
      </motion.div>

      {/* Security Levels */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        className="bg-gray-800/50 rounded-xl border border-cyan-500/20 p-6"
      >
        <h3 className="text-cyan-400 font-semibold text-lg mb-4">Security Assessment</h3>
        <div className="space-y-4">
          {securityLevels.map((level, index) => (
            <div key={level.name} className="space-y-2">
              <div className="flex justify-between">
                <span className="text-gray-300">{level.name}</span>
                <span className={`text-${level.color}-400 font-semibold`}>{level.value}%</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-2">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${level.value}%` }}
                  transition={{ delay: index * 0.1, duration: 1 }}
                  className={`h-2 rounded-full bg-${level.color}-500`}
                ></motion.div>
              </div>
            </div>
          ))}
        </div>
      </motion.div>
    </div>
  )
}