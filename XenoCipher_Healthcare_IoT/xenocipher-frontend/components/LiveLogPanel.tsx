// components/LiveLogPanel.tsx
'use client'

import { motion, AnimatePresence } from 'framer-motion'
import { LogEntry } from '../types/pipeline'

interface LiveLogPanelProps {
  logs: LogEntry[]
}

export default function LiveLogPanel({ logs }: LiveLogPanelProps) {
  const getLogColor = (type: LogEntry['type']) => {
    switch (type) {
      case 'error': return 'text-red-400'
      case 'warning': return 'text-yellow-400'
      case 'success': return 'text-green-400'
      case 'threat': return 'text-red-500 font-bold'
      default: return 'text-gray-300'
    }
  }

  const getLogIcon = (type: LogEntry['type']) => {
    switch (type) {
      case 'error': return '❌'
      case 'warning': return '⚠️'
      case 'success': return '✅'
      case 'threat': return '🚨'
      default: return 'ℹ️'
    }
  }

  const getSourceColor = (source: LogEntry['source']) => {
    switch (source) {
      case 'esp32': return 'text-blue-400'
      case 'server': return 'text-cyan-400'
      case 'security': return 'text-red-400'
      case 'pipeline': return 'text-purple-400'
      default: return 'text-gray-400'
    }
  }

  return (
    <motion.div 
      className="bg-gray-800/50 rounded-2xl border border-cyan-500/20 p-6 h-full"
      initial={{ opacity: 0, x: 50 }}
      animate={{ opacity: 1, x: 0 }}
    >
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xl font-bold text-cyan-400">Live Event Log</h3>
        <div className="flex items-center space-x-2">
          <motion.div 
            className="w-2 h-2 bg-green-500 rounded-full"
            animate={{ scale: [1, 1.5, 1] }}
            transition={{ duration: 2, repeat: Infinity }}
          />
          <span className="text-green-400 text-sm font-mono">LIVE</span>
        </div>
      </div>

      {/* SAFE SCROLL CONTAINER */}
      <div className="bg-black/40 rounded-lg border border-gray-600 h-96 overflow-hidden">
        <div 
          className="h-full overflow-y-auto p-4 space-y-3 scroll-container"
          style={{ pointerEvents: 'auto' }}
        >
          <AnimatePresence initial={false}>
            {logs.length === 0 ? (
              <div className="text-center text-gray-500 py-8">
                <div className="text-2xl mb-2">📝</div>
                <p>Waiting for events...</p>
              </div>
            ) : (
              <div className="flex flex-col-reverse gap-3">
                {logs.slice().reverse().map((log) => (
                  <motion.div
                    key={log.id}
                    initial={{ opacity: 0, y: 20 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, x: -100 }}
                    className="border-l-4 border-cyan-500/50 pl-3 py-2 bg-gray-900/50 rounded-r-lg"
                    style={{ pointerEvents: 'auto' }}
                  >
                    <div className="flex items-start justify-between mb-1">
                      <div className="flex items-center space-x-2">
                        <span>{getLogIcon(log.type)}</span>
                        <span className={`text-xs font-mono ${getSourceColor(log.source)}`}>
                          [{log.source.toUpperCase()}]
                        </span>
                      </div>
                      <span className="text-xs text-gray-500">
                        {new Date(log.timestamp).toLocaleTimeString([], { 
                          hour: '2-digit', 
                          minute: '2-digit', 
                          second: '2-digit' 
                        })}
                      </span>
                    </div>
                    <p className={`text-sm ${getLogColor(log.type)}`}>
                      {log.message}
                    </p>
                  </motion.div>
                ))}
              </div>
            )}
          </AnimatePresence>
        </div>
      </div>

      <div className="mt-4 text-xs text-gray-400">
        Showing {logs.length} events
      </div>
    </motion.div>
  )
}