// context/ZeroTrustContext.tsx
'use client'

import React, { createContext, useContext, useState, useCallback, ReactNode } from 'react'

export type ThreatLevel = 'green' | 'yellow' | 'red'

interface ZeroTrustContextType {
  isZeroTrustMode: boolean
  enableZeroTrust: () => void
  disableZeroTrust: () => void
  zeroTrustData: {
    sessionKey?: string
    ephemeralIdentity?: string
    threatLevel: ThreatLevel
  }
}

const ZeroTrustContext = createContext<ZeroTrustContextType | undefined>(undefined)

interface ZeroTrustProviderProps {
  children: ReactNode
}

export function ZeroTrustProvider({ children }: ZeroTrustProviderProps) {
  const [isZeroTrustMode, setIsZeroTrustMode] = useState(false)
  const [zeroTrustData, setZeroTrustData] = useState<{
    sessionKey?: string
    ephemeralIdentity?: string
    threatLevel: ThreatLevel
  }>({
    threatLevel: 'green'
  })

  const enableZeroTrust = useCallback(() => {
    console.log('[Zero Trust] 🚀 Activating Zero Trust Mode...')
    
    // Generate ephemeral session data
    const sessionKey = Array.from({ length: 32 }, () => 
      Math.floor(Math.random() * 256).toString(16).padStart(2, '0')
    ).join('')
    
    const words = [
      'quantum', 'lattice', 'cipher', 'void', 'neon', 'trust', 'zero', 'burn',
      'crypto', 'secure', 'ghost', 'shadow', 'black', 'red', 'green', 'pulse'
    ]
    
    const ephemeralIdentity = Array.from({ length: 4 }, () => 
      words[Math.floor(Math.random() * words.length)]
    ).join('-')
    
    setZeroTrustData({
      sessionKey,
      ephemeralIdentity,
      threatLevel: 'yellow' // Starting threat level
    })
    setIsZeroTrustMode(true)
    
    console.log('[Zero Trust] ✅ Mode activated with ephemeral identity:', ephemeralIdentity)
    
    // Simulate threat level changes for demo
    setTimeout(() => {
      setZeroTrustData(prev => ({ ...prev, threatLevel: 'green' }))
      console.log('[Zero Trust] 🟢 Threat level: GREEN')
    }, 5000)
  }, [])

  const disableZeroTrust = useCallback(() => {
    console.log('[Zero Trust] 🗑️ Deactivating Zero Trust Mode...')
    
    // Clear all ephemeral data
    setZeroTrustData({
      threatLevel: 'green'
    })
    setIsZeroTrustMode(false)
    
    console.log('[Zero Trust] ✅ Mode deactivated, all data destroyed')
  }, [])

  // Function to update threat level (can be called from security monitoring)
  const updateThreatLevel = useCallback((level: ThreatLevel) => {
    setZeroTrustData(prev => ({ ...prev, threatLevel: level }))
    console.log(`[Zero Trust] 🚨 Threat level updated: ${level.toUpperCase()}`)
  }, [])

  const value: ZeroTrustContextType = {
    isZeroTrustMode,
    enableZeroTrust,
    disableZeroTrust,
    zeroTrustData
  }

  return (
    <ZeroTrustContext.Provider value={value}>
      {children}
    </ZeroTrustContext.Provider>
  )
}

// Hook to use Zero Trust context
export function useZeroTrust(): ZeroTrustContextType {
  const context = useContext(ZeroTrustContext)
  
  if (context === undefined) {
    throw new Error('useZeroTrust must be used within a ZeroTrustProvider')
  }
  
  return context
}

// Optional: Hook for security monitoring components
export function useZeroTrustSecurity() {
  const { isZeroTrustMode, zeroTrustData } = useZeroTrust()
  
  // Security monitoring logic can go here
  const getSecurityStatus = useCallback(() => {
    return {
      isActive: isZeroTrustMode,
      threatLevel: zeroTrustData.threatLevel,
      protections: {
        active: isZeroTrustMode,
        threatLevel: zeroTrustData.threatLevel
      }
    }
  }, [isZeroTrustMode, zeroTrustData.threatLevel])

  return {
    securityStatus: getSecurityStatus(),
    isZeroTrustMode,
    zeroTrustData
  }
}

export default ZeroTrustContext