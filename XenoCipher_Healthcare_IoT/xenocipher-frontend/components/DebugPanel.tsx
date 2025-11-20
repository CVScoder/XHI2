// components/DebugPanel.tsx
'use client'

import { useWebSocket } from '../context/WebSocketContext'

export default function DebugPanel() {
  const { isConnected, lastMessage, messageHistory, connectionStatus } = useWebSocket()

  return (
    <div className="fixed bottom-4 right-4 w-96 bg-black/90 border border-cyan-500 rounded-lg p-4 text-xs font-mono max-h-96 overflow-y-auto">
      <h3 className="text-cyan-400 font-bold mb-2">WebSocket Debug</h3>
      
      <div className="space-y-2">
        <div className="flex justify-between">
          <span>Status:</span>
          <span className={
            connectionStatus === 'connected' ? 'text-green-400' :
            connectionStatus === 'connecting' ? 'text-yellow-400' :
            'text-red-400'
          }>
            {connectionStatus.toUpperCase()}
          </span>
        </div>
        
        <div className="flex justify-between">
          <span>Connected:</span>
          <span className={isConnected ? 'text-green-400' : 'text-red-400'}>
            {isConnected ? 'YES' : 'NO'}
          </span>
        </div>

        <div className="flex justify-between">
          <span>Messages Received:</span>
          <span className="text-cyan-400">{messageHistory.length}</span>
        </div>

        {lastMessage && (
          <div className="mt-3 p-2 bg-gray-800 rounded border">
            <div className="text-cyan-300">Last Message:</div>
            <div className="text-green-400">{lastMessage.type}</div>
            <pre className="text-gray-300 mt-1 whitespace-pre-wrap">
              {JSON.stringify(lastMessage, null, 2)}
            </pre>
          </div>
        )}

        <div className="mt-3">
          <div className="text-cyan-300 mb-1">Recent Messages:</div>
          {messageHistory.slice(-5).map((msg, index) => (
            <div key={index} className="text-gray-400 truncate">
              {msg.type} - {new Date().toLocaleTimeString()}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}