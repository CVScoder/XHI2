// context/PipelineContext.tsx
'use client'

import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'
import { useWebSocket } from './WebSocketContext'
import { 
  PipelineStep, 
  StepInfo, 
  SequentialPipelineData, 
  ESP32Data, 
  ServerData,
  HealthData,
  EncryptionDetails,
  DecryptionDetails,
  LogEntry
} from '../types/pipeline'
import { 
  validateDecryptedData, 
  getValidationErrorMessage, 
  logValidationDetails,
  formatRawBytes 
} from '../lib/data-validation'

// Create a safe hook that doesn't throw if ZeroTrust is not available
const useSafeZeroTrust = () => {
  try {
    // Use require to avoid build-time errors
    const { useZeroTrust } = require('./ZeroTrustContext')
    // eslint-disable-next-line react-hooks/rules-of-hooks
    return useZeroTrust()
  } catch (error) {
    // Fallback when ZeroTrust is not available
    return {
      isZeroTrustMode: false,
      zeroTrustData: {
        threatLevel: 'green' as const,
        ephemeralIdentity: undefined
      }
    }
  }
}

export interface PipelineContextType {
  pipelineData: SequentialPipelineData & {
    zeroTrust?: {
      enabled: boolean
      threatLevel: 'green' | 'yellow' | 'red'
      ephemeralIdentity?: string
    }
  }
  startPipeline: () => void
  resetPipeline: () => void
  simulateStep: (step: PipelineStep) => void
  messageHistory: any[]
  logs: LogEntry[]
  addLog: (entry: Omit<LogEntry, 'id' | 'timestamp'>) => void
  clearLogs: () => void
}

const PipelineContext = createContext<PipelineContextType | undefined>(undefined)

export const initialData: SequentialPipelineData = {
  currentStep: 'idle',
  previousStep: 'idle',
  esp32Connected: false,
  serverConnected: false,
  lastUpdated: Date.now(),
}

// Step definitions with proper typing
export const steps: StepInfo[] = [
  { id: 'idle', title: 'Ready', description: 'System initialized and ready', icon: '⚡', color: 'gray' },
  { id: 'requesting_public_key', title: 'Requesting Public Key', description: 'ESP32 requesting NTRU public key', icon: '🔑', color: 'blue' },
  { id: 'encrypting_master_key', title: 'Encrypting Master Key', description: 'ESP32 encrypting 256-bit master key', icon: '🔒', color: 'purple' },
  { id: 'sending_master_key', title: 'Sending Master Key', description: 'Sending encrypted master key to server', icon: '📤', color: 'orange' },
  { id: 'master_key_established', title: 'Key Exchange Complete', description: 'Secure master key established', icon: '✅', color: 'green' },
  { id: 'encrypting_data', title: 'Encrypting Health Data', description: 'ESP32 encrypting health data with XenoCipher', icon: '🔄', color: 'cyan' },
  { id: 'sending_data', title: 'Sending Encrypted Data', description: 'Transmitting encrypted packet to server', icon: '🚀', color: 'pink' },
  { id: 'receiving_data', title: 'Receiving Data', description: 'Server receiving encrypted data', icon: '📥', color: 'yellow' },
  { id: 'decrypting_data', title: 'Decrypting Data', description: 'Server decrypting health data', icon: '🔓', color: 'teal' },
  { id: 'completed', title: 'Process Complete', description: 'Data successfully processed and stored', icon: '🎉', color: 'emerald' },
]

export function PipelineProvider({ children }: { children: React.ReactNode }) {
  const [pipelineData, setPipelineData] = useState<SequentialPipelineData>(initialData)
  const [messageHistory, setMessageHistory] = useState<any[]>([])
  const [logs, setLogs] = useState<LogEntry[]>([])
  const { lastMessage, sendMessage, isConnected } = useWebSocket()
  
  // Use the safe hook instead of direct import
  const { isZeroTrustMode, zeroTrustData } = useSafeZeroTrust()
  
  // Add log entry helper
  const addLog = useCallback((entry: Omit<LogEntry, 'id' | 'timestamp'>) => {
    const logEntry: LogEntry = {
      ...entry,
      id: `log-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: Date.now()
    }
    setLogs(prev => [...prev.slice(-99), logEntry]) // Keep last 100 logs
  }, [])
  
  // Clear logs helper
  const clearLogs = useCallback(() => {
    setLogs([])
  }, [])

  // Enhanced pipeline data with Zero Trust info
  const enhancedPipelineData = {
    ...pipelineData,
    zeroTrust: {
      enabled: isZeroTrustMode,
      threatLevel: zeroTrustData.threatLevel,
      ephemeralIdentity: zeroTrustData.ephemeralIdentity
    }
  }

  // Update server connection status
  useEffect(() => {
    setPipelineData(prev => ({
      ...prev,
      serverConnected: isConnected,
      lastUpdated: Date.now()
    }))
  }, [isConnected])

  // Parse health data from plaintext with validation
  const parseHealthData = (plaintext: string | null | undefined): HealthData => {
    // Validate the decrypted data first
    const validation = validateDecryptedData(plaintext)
    
    if (!validation.isValid) {
      // Log validation failure for debugging
      logValidationDetails(plaintext || '', validation)
      
      // Return invalid health data
      return {
        heartRate: 0,
        spo2: 0,
        steps: 0,
        timestamp: Date.now()
      }
    }
    
    // Use validated parsed data
    if (validation.parsedData) {
      return {
        heartRate: validation.parsedData.heartRate,
        spo2: validation.parsedData.spo2,
        steps: validation.parsedData.steps,
        timestamp: Date.now()
      }
    }
    
    // Fallback: try to parse manually if validation passed but no parsed data
    try {
      const hrMatch = validation.cleanedData?.match(/HR-(\d+)/i)
      const spo2Match = validation.cleanedData?.match(/SPO2-(\d+)/i)
      const stepsMatch = validation.cleanedData?.match(/STEPS-(\d+)/i)
      
      return {
        heartRate: hrMatch ? parseInt(hrMatch[1], 10) : 0,
        spo2: spo2Match ? parseInt(spo2Match[1], 10) : 0,
        steps: stepsMatch ? parseInt(stepsMatch[1], 10) : 0,
        timestamp: Date.now()
      }
    } catch (error) {
      console.error('[Pipeline] ❌ Failed to parse health data:', error)
      return {
        heartRate: 0,
        spo2: 0,
        steps: 0,
        timestamp: Date.now()
      }
    }
  }

  // Generate encryption details from real data
  const generateEncryptionDetails = (message: any): EncryptionDetails => {
    return {
      plaintext: message.plaintext || 'Unknown',
      lfsrOutput: `LFSR[${message.pipeline?.lfsrState || 'N/A'}]`,
      chaosMapOutput: `CHAOS[${message.pipeline?.chaosState || 'N/A'}]`,
      transpositionOutput: `TRANS[${message.pipeline?.transpositionKey || 'N/A'}]`,
      finalEncryptedPacket: message.encData || 'No data',
      metadata: {
        salt: message.pipeline?.salt || 'N/A',
        key: message.pipeline?.key || 'N/A',
        iv: message.pipeline?.iv || 'N/A',
        authTag: message.pipeline?.authTag || 'N/A',
        timestamp: message.timestamp || Date.now()
      }
    }
  }

  // Generate decryption details from real data
  const generateDecryptionDetails = (message: any): DecryptionDetails => {
    const healthData = parseHealthData(message.finalPlaintext)
    
    return {
      encryptedPacket: message.encryptedPacket || 'No data',
      reversedTransposition: `REV_TRANS[${message.pipeline?.reverseTransposition || 'N/A'}]`,
      reversedChaosMap: `REV_CHAOS[${message.pipeline?.reverseChaos || 'N/A'}]`,
      reversedLFSR: `REV_LFSR[${message.pipeline?.reverseLFSR || 'N/A'}]`,
      finalPlaintext: message.finalPlaintext || 'No data',
      verification: {
        hmacValid: message.pipeline?.hmacValid !== false,
        integrityCheck: message.pipeline?.integrityCheck !== false,
        timestampValid: message.pipeline?.timestampValid !== false
      },
      timing: {
        totalTime: message.decryptionTime || 0,
        decryptionTime: message.pipeline?.decryptionTime || 0,
        verificationTime: message.pipeline?.verificationTime || 0
      }
    }
  }

  // Handle WebSocket messages with real data
  useEffect(() => {
    if (!lastMessage) return

    console.log('[Pipeline] 📨 Processing WebSocket message:', lastMessage.type, lastMessage)

    // Add to message history for debugging
    setMessageHistory(prev => [...prev.slice(-49), lastMessage])

    const { type, ...data } = lastMessage

    // In Zero Trust Mode, validate all incoming messages
    if (isZeroTrustMode) {
      const validation = validateMessageInZeroTrust(lastMessage, zeroTrustData.threatLevel)
      if (!validation.isValid) {
        console.warn('[Pipeline] 🚨 Zero Trust validation failed:', validation.errors)
        return
      }
    }

    switch (type) {
      case 'security_update':
        console.log('[Pipeline] 🛡️ Security update received')
        setPipelineData(prev => ({
          ...prev,
          esp32Connected: data.esp32_connected !== false,
          lastUpdated: Date.now()
        }))
        break

      case 'encryption_update':
        console.log('[Pipeline] 🔐 Encryption update received')
        
        // Mark ESP32 as connected when we receive encryption updates
        setPipelineData(prev => ({
          ...prev,
          esp32Connected: true,
          lastUpdated: Date.now()
        }))
        
        const encryptionDetails = generateEncryptionDetails(data)
        
        // Log successful encryption
        addLog({
          type: 'success',
          message: `Data encrypted: ${data.plaintext || 'Unknown'}`,
          source: 'esp32'
        })
        
        setPipelineData(prev => ({
          ...prev,
          currentStep: 'sending_data',
          previousStep: prev.currentStep,
          esp32Data: {
            ...prev.esp32Data,
            plaintext: data.plaintext,
            encryptedPacket: data.encData,
            encryptionTime: data.timestamp,
            encryptionDetails
          },
          lastUpdated: Date.now()
        }))
        break

      case 'decryption_update':
        console.log('[Pipeline] 🔓 Decryption complete')
        
        // Validate decrypted data BEFORE processing
        const validation = validateDecryptedData(data.finalPlaintext)
        
        if (!validation.isValid) {
          // Log corruption/attack details
          const errorMsg = getValidationErrorMessage(validation)
          logValidationDetails(data.finalPlaintext || '', validation)
          
          addLog({
            type: validation.attackDetected ? 'threat' : 'error',
            message: errorMsg,
            source: 'server'
          })
          
          // Update pipeline with error state - NEVER display corrupted data
          setPipelineData(prev => ({
            ...prev,
            currentStep: 'completed',
            previousStep: prev.currentStep,
            serverData: {
              ...prev.serverData,
              decryptedData: '[CORRUPTED_DATA: Invalid UTF-8 or malformed payload]',
              decryptionTime: data.decryptionTime,
              healthData: {
                heartRate: 0,
                spo2: 0,
                steps: 0,
                timestamp: Date.now()
              },
              decryptionDetails: {
                encryptedPacket: data.encryptedPacket || 'No data',
                reversedTransposition: 'N/A',
                reversedChaosMap: 'N/A',
                reversedLFSR: 'N/A',
                finalPlaintext: validation.rawBytes ? `Raw bytes: ${formatRawBytes(data.finalPlaintext || '')}` : '[CORRUPTED_DATA]',
                verification: {
                  hmacValid: false,
                  integrityCheck: false,
                  timestampValid: false
                },
                timing: {
                  totalTime: data.decryptionTime || 0,
                  decryptionTime: 0,
                  verificationTime: 0
                }
              }
            },
            lastUpdated: Date.now()
          }))
          break
        }
        
        // Valid data - proceed normally
        const decryptionDetails = generateDecryptionDetails(data)
        const healthData = parseHealthData(validation.cleanedData)
        
        // Log successful decryption
        addLog({
          type: 'success',
          message: `Data decrypted: ${validation.cleanedData}`,
          source: 'server'
        })
        
        setPipelineData(prev => ({
          ...prev,
          currentStep: 'completed',
          previousStep: prev.currentStep,
          serverData: {
            ...prev.serverData,
            decryptedData: validation.cleanedData || '',
            decryptionTime: data.decryptionTime,
            healthData,
            decryptionDetails
          },
          lastUpdated: Date.now()
        }))
        break

      case 'public_key_response':
        console.log('[Pipeline] 🔑 Received public key')
        setPipelineData(prev => ({
          ...prev,
          currentStep: 'encrypting_master_key',
          previousStep: prev.currentStep,
          esp32Data: {
            ...prev.esp32Data,
            publicKey: data.publicKey
          },
          lastUpdated: Date.now()
        }))
        break

      case 'data_received':
        console.log('[Pipeline] 📥 Data received by server')
        setPipelineData(prev => ({
          ...prev,
          currentStep: 'decrypting_data',
          previousStep: prev.currentStep,
          serverData: {
            ...prev.serverData,
            receivedPacket: data.packet
          },
          lastUpdated: Date.now()
        }))
        break

      case 'connection_established':
        console.log('[Pipeline] ✅ WebSocket connection established')
        addLog({
          type: 'info',
          message: 'Message: connection_established',
          source: 'pipeline'
        })
        setPipelineData(prev => ({
          ...prev,
          serverConnected: true,
          lastUpdated: Date.now()
        }))
        break

      case 'master_key_received':
        console.log('[Pipeline] 🔒 Master key received')
        addLog({
          type: 'info',
          message: 'Message: master_key_received',
          source: 'pipeline'
        })
        setPipelineData(prev => ({
          ...prev,
          currentStep: 'master_key_established',
          previousStep: prev.currentStep,
          esp32Connected: true, // ESP32 is connected if master key exchange succeeds
          esp32Data: {
            ...prev.esp32Data,
            masterKey: data.masterKey
          },
          lastUpdated: Date.now()
        }))
        break

      case 'health_data_update':
        addLog({
          type: 'info',
          message: 'Message: health_data_update',
          source: 'pipeline'
        })
        break

      case 'session_summary_update':
        addLog({
          type: 'info',
          message: 'Message: session_summary_update',
          source: 'pipeline'
        })
        break

      // Zero Trust specific message types
      case 'threat_level_update':
        console.log('[Pipeline] 🛡️ Threat level update received')
        break

      case 'zero_trust_alert':
        console.log('[Pipeline] 🚨 Zero Trust alert received')
        break

      default:
        console.log('[Pipeline] ❓ Unknown message type:', type, data)
    }
  }, [lastMessage, isZeroTrustMode, zeroTrustData.threatLevel])

  // Zero Trust message validation
  const validateMessageInZeroTrust = (message: any, threatLevel: string) => {
    const errors: string[] = []

    // Check for suspicious timestamps (replay attacks)
    if (message.timestamp && Date.now() - message.timestamp > 30000) {
      errors.push('Message timestamp too old - potential replay attack')
    }

    // Check for unusual message sizes
    if (JSON.stringify(message).length > 10000) {
      errors.push('Message size exceeds security limits')
    }

    // Check for known attack patterns in data
    if (message.data && containsSuspiciousPatterns(message.data)) {
      errors.push('Message contains suspicious patterns')
    }

    // In high threat levels, be more restrictive
    if (threatLevel === 'red') {
      if (message.type && !['public_key_response', 'master_key_received'].includes(message.type)) {
        errors.push('Message type not allowed in high threat level')
      }
    }

    return {
      isValid: errors.length === 0,
      errors
    }
  }

  const containsSuspiciousPatterns = (data: any): boolean => {
    const str = JSON.stringify(data).toLowerCase()
    const suspiciousPatterns = [
      'script',
      'javascript:',
      'eval(',
      'base64',
      '%00',
      '\\x00'
    ]
    return suspiciousPatterns.some(pattern => str.includes(pattern))
  }

  const startPipeline = useCallback(() => {
    if (isZeroTrustMode && zeroTrustData.threatLevel === 'red') {
      console.error('[Pipeline] 🚨 Cannot start pipeline: Threat level RED in Zero Trust Mode')
      return
    }

    console.log('[Pipeline] 🚀 Starting pipeline' + (isZeroTrustMode ? ' in Zero Trust Mode' : ''))
    
    setPipelineData({
      ...initialData,
      currentStep: 'requesting_public_key',
      previousStep: 'idle',
      esp32Connected: true,
      serverConnected: isConnected,
      lastUpdated: Date.now()
    })

    // In Zero Trust Mode, add additional security headers
    const messagePayload: any = { 
      type: 'request_public_key',
      device: 'esp32_health_monitor',
      timestamp: Date.now()
    }

    if (isZeroTrustMode) {
      messagePayload.zeroTrust = {
        sessionId: zeroTrustData.ephemeralIdentity,
        threatLevel: zeroTrustData.threatLevel
      }
    }

    // Request public key from server
    setTimeout(() => {
      console.log('[Pipeline] 📡 ESP32 requesting public key')
      sendMessage(messagePayload)
    }, 1000)
  }, [sendMessage, isConnected, isZeroTrustMode, zeroTrustData])

  const resetPipeline = useCallback(() => {
    console.log('[Pipeline] 🔁 Resetting pipeline')
    setPipelineData(initialData)
    setMessageHistory([])
  }, [])

  const simulateStep = useCallback((step: PipelineStep) => {
    console.log('[Pipeline] 🎯 Simulating step:', step)
    setPipelineData(prev => ({
      ...prev,
      currentStep: step,
      previousStep: prev.currentStep,
      lastUpdated: Date.now()
    }))
  }, [])

  const value: PipelineContextType = {
    pipelineData: enhancedPipelineData,
    startPipeline,
    resetPipeline,
    simulateStep,
    messageHistory,
    logs,
    addLog,
    clearLogs,
  }

  return (
    <PipelineContext.Provider value={value}>
      {children}
    </PipelineContext.Provider>
  )
}

export function usePipeline() {
  const context = useContext(PipelineContext)
  if (context === undefined) {
    throw new Error('usePipeline must be used within a PipelineProvider')
  }
  return context
}