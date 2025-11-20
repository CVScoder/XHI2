// components/tabs/StrengthTesting.tsx
'use client'

import React, { useState } from 'react'
import { motion } from 'framer-motion'
import { usePipeline } from '../../context/PipelineContext'

const attackTypes = [
  {
    id: 'bruteforce',
    name: 'Brute Force Attack',
    description: 'Attempt to guess encryption keys through exhaustive search',
    intensity: 'High',
    duration: '2-5 minutes'
  },
  {
    id: 'replay',
    name: 'Replay Attack', 
    description: 'Intercept and retransmit valid data packets',
    intensity: 'Medium',
    duration: '1-3 minutes'
  },
  {
    id: 'sidechannel',
    name: 'Side-Channel Analysis',
    description: 'Analyze timing, power consumption, or EM emissions',
    intensity: 'Very High',
    duration: '5-10 minutes'
  },
  {
    id: 'cryptanalysis',
    name: 'Cryptanalytic Attack',
    description: 'Mathematical analysis of cryptographic primitives',
    intensity: 'Extreme',
    duration: '10-15 minutes'
  }
]

export default function StrengthTesting() {
  const [selectedAttack, setSelectedAttack] = useState<string | null>(null)
  const [isTesting, setIsTesting] = useState(false)
  const [testResults, setTestResults] = useState<any>(null)

  const runAttackTest = async (attackId: string) => {
    setIsTesting(true)
    setSelectedAttack(attackId)
    
    // Simulate attack testing
    await new Promise(resolve => setTimeout(resolve, 3000))
    
    const results = {
      success: Math.random() > 0.3, // 70% success rate for demonstration
      attempts: Math.floor(Math.random() * 10000) + 1000,
      timeElapsed: Math.floor(Math.random() * 300) + 30,
      vulnerabilitiesFound: Math.random() > 0.7 ? ['Weak nonce generation'] : []
    }
    
    setTestResults(results)
    setIsTesting(false)
  }

  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        className="grid grid-cols-1 lg:grid-cols-2 gap-6"
      >
        {/* Attack Selection */}
        <div className="space-y-4">
          <h2 className="text-2xl font-bold text-cyan-400">Security Strength Testing</h2>
          <p className="text-gray-300">
            Test the resilience of XenoCipher against various cryptographic attacks. 
            Each test simulates real-world attack scenarios.
          </p>
          
          <div className="space-y-3">
            {attackTypes.map((attack) => (
              <motion.div
                key={attack.id}
                whileHover={{ scale: 1.02 }}
                className={`p-4 rounded-lg border cursor-pointer transition-all ${
                  selectedAttack === attack.id
                    ? 'border-red-500 bg-red-500/10'
                    : 'border-gray-600 hover:border-cyan-500 bg-gray-800/50'
                }`}
                onClick={() => !isTesting && setSelectedAttack(attack.id)}
              >
                <div className="flex justify-between items-start">
                  <div>
                    <h3 className="font-semibold text-white">{attack.name}</h3>
                    <p className="text-sm text-gray-300 mt-1">{attack.description}</p>
                  </div>
                  <span className={`px-2 py-1 rounded text-xs ${
                    attack.intensity === 'Extreme' ? 'bg-red-500' :
                    attack.intensity === 'Very High' ? 'bg-orange-500' :
                    attack.intensity === 'High' ? 'bg-yellow-500' : 'bg-blue-500'
                  }`}>
                    {attack.intensity}
                  </span>
                </div>
                <div className="flex justify-between items-center mt-3">
                  <span className="text-sm text-gray-400">Duration: {attack.duration}</span>
                  <button
                    onClick={(e) => {
                      e.stopPropagation()
                      runAttackTest(attack.id)
                    }}
                    disabled={isTesting}
                    className="px-3 py-1 bg-red-600 hover:bg-red-700 disabled:bg-gray-600 rounded text-sm font-medium"
                  >
                    {isTesting && selectedAttack === attack.id ? 'Testing...' : 'Test'}
                  </button>
                </div>
              </motion.div>
            ))}
          </div>
        </div>

        {/* Test Results */}
        <div className="space-y-4">
          <h2 className="text-2xl font-bold text-cyan-400">Test Results</h2>
          
          {isTesting ? (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="p-8 text-center border border-cyan-500/30 rounded-lg bg-gray-800/50"
            >
              <div className="w-16 h-16 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
              <h3 className="text-xl font-semibold text-cyan-400">Running Security Test</h3>
              <p className="text-gray-300 mt-2">
                Simulating {attackTypes.find(a => a.id === selectedAttack)?.name}...
              </p>
            </motion.div>
          ) : testResults ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.9 }}
              animate={{ opacity: 1, scale: 1 }}
              className={`p-6 rounded-lg border ${
                testResults.success 
                  ? 'border-green-500 bg-green-500/10' 
                  : 'border-red-500 bg-red-500/10'
              }`}
            >
              <h3 className={`text-xl font-semibold ${
                testResults.success ? 'text-green-400' : 'text-red-400'
              }`}>
                {testResults.success ? '🛡️ Test Passed' : '⚠️ Security Alert'}
              </h3>
              
              <div className="mt-4 space-y-3">
                <div className="flex justify-between">
                  <span className="text-gray-300">Attack Resistance:</span>
                  <span className={testResults.success ? 'text-green-400' : 'text-red-400'}>
                    {testResults.success ? 'High' : 'Compromised'}
                  </span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-300">Attempts Blocked:</span>
                  <span className="text-cyan-400">{testResults.attempts.toLocaleString()}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-300">Test Duration:</span>
                  <span className="text-cyan-400">{testResults.timeElapsed}s</span>
                </div>
                
                {testResults.vulnerabilitiesFound.length > 0 && (
                  <div className="mt-4 p-3 bg-red-500/20 rounded border border-red-500/50">
                    <h4 className="font-semibold text-red-400">Vulnerabilities Found:</h4>
                    <ul className="list-disc list-inside mt-2 text-sm text-red-300">
                      {testResults.vulnerabilitiesFound.map((vuln: string, index: number) => (
                        <li key={index}>{vuln}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </motion.div>
          ) : (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="p-8 text-center border border-gray-600 rounded-lg bg-gray-800/50"
            >
              <div className="text-4xl mb-4">🛡️</div>
              <h3 className="text-xl font-semibold text-gray-400">No Test Results</h3>
              <p className="text-gray-500 mt-2">
                Select and run a security test to see results here
              </p>
            </motion.div>
          )}

          {/* Security Recommendations */}
          {testResults && !testResults.success && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="p-4 bg-yellow-500/10 border border-yellow-500/50 rounded-lg"
            >
              <h4 className="font-semibold text-yellow-400">Security Recommendations</h4>
              <ul className="list-disc list-inside mt-2 text-sm text-yellow-300">
                <li>Increase key rotation frequency</li>
                <li>Implement additional nonce validation</li>
                <li>Enable adaptive encryption mode</li>
                <li>Monitor for unusual traffic patterns</li>
              </ul>
            </motion.div>
          )}
        </div>
      </motion.div>
    </div>
  )
}