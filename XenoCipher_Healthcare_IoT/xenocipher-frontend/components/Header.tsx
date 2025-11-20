// components/Header.tsx
'use client'

import { motion } from 'framer-motion'

export default function Header() {
  return (
    <motion.header 
      className="border-b border-cyan-500/30 bg-black/50 backdrop-blur-lg sticky top-0 z-50"
      initial={{ opacity: 0, y: -50 }}
      animate={{ opacity: 1, y: 0 }}
    >
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          {/* Logo */}
          <motion.div 
            className="flex items-center space-x-4"
            whileHover={{ scale: 1.05 }}
          >
            <div className="relative">
              <div className="w-12 h-12 bg-gradient-to-br from-cyan-400 to-green-400 rounded-lg flex items-center justify-center shadow-lg shadow-cyan-500/25">
                <span className="text-black font-bold text-lg">X</span>
              </div>
              <div className="absolute -inset-1 bg-cyan-500 rounded-lg blur opacity-30"></div>
            </div>
            <div>
              <h1 className="text-2xl font-bold text-gradient">XenoCipher</h1>
              <p className="text-cyan-300 text-sm">Quantum-Resistant IoT Security</p>
            </div>
          </motion.div>

          {/* Status Indicators */}
          <div className="flex items-center space-x-6">
            <motion.div 
              className="flex items-center space-x-2"
              whileHover={{ scale: 1.1 }}
            >
              <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
              <span className="text-green-400 text-sm font-mono">SYSTEM ONLINE</span>
            </motion.div>
            
            <motion.div 
              className="flex items-center space-x-2"
              whileHover={{ scale: 1.1 }}
            >
              <div className="w-3 h-3 bg-cyan-500 rounded-full"></div>
              <span className="text-cyan-400 text-sm font-mono">ENCRYPTION ACTIVE</span>
            </motion.div>
          </div>
        </div>
      </div>
    </motion.header>
  )
}