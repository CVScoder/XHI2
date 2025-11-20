// hooks/useZeroTrustSecurity.ts
import { useEffect, useCallback } from 'react'
import {useZeroTrust } from '../context/ZeroTrustContext' // Change to default import

export function useZeroTrustSecurity() {
  const { isZeroTrustMode, zeroTrustData } = useZeroTrust()

  // Monitor clipboard access
  const handleCopy = useCallback((e: ClipboardEvent) => {
    if (!isZeroTrustMode) return
    
    console.warn('[Zero Trust] 📋 Clipboard access attempted in Zero Trust Mode')
  }, [isZeroTrustMode])

  // Monitor app visibility changes
  const handleVisibilityChange = useCallback(() => {
    if (!isZeroTrustMode) return
    console.log('[Zero Trust] 👁️ App visibility changed')
  }, [isZeroTrustMode])

  useEffect(() => {
    if (!isZeroTrustMode) return

    console.log('[Zero Trust Security] 🛡️ Activating security monitoring')

    // Add event listeners
    document.addEventListener('copy', handleCopy)
    document.addEventListener('visibilitychange', handleVisibilityChange)

    return () => {
      document.removeEventListener('copy', handleCopy)
      document.removeEventListener('visibilitychange', handleVisibilityChange)
      console.log('[Zero Trust Security] 🛡️ Security monitoring deactivated')
    }
  }, [isZeroTrustMode, handleCopy, handleVisibilityChange])

  return {
    isZeroTrustMode,
    zeroTrustData
  }
}

export default useZeroTrustSecurity