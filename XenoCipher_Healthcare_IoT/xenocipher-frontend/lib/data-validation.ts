// lib/data-validation.ts
// Robust data validation utilities for health telemetry

export interface ValidationResult {
  isValid: boolean
  cleanedData?: string
  errorType?: 'utf8_corruption' | 'pattern_mismatch' | 'length_invalid' | 'empty'
  rawBytes?: string
  shouldDisplay?: boolean
  attackDetected?: boolean
  parsedData?: {
    heartRate: number
    spo2: number
    steps: number
  }
}

// Health data pattern: HR-XX SPO2-XX STEPS-XXXXX
export const HEALTH_DATA_PATTERN = /^HR-(\d{1,3})\s+SPO2-(\d{1,3})\s+STEPS-(\d{1,5})$/i

// Valid ranges for health data
const VALID_HR_RANGE = { min: 30, max: 200 }
const VALID_SPO2_RANGE = { min: 70, max: 100 }
const VALID_STEPS_RANGE = { min: 0, max: 50000 }

/**
 * Checks if a string is valid UTF-8
 */
export function isValidUTF8(str: string): boolean {
  if (!str) return false
  
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i)
    
    // Check for null bytes or control characters (except common whitespace)
    if (code === 0 || (code >= 1 && code <= 8) || (code >= 14 && code <= 31 && code !== 27)) {
      return false
    }
    
    // Check for replacement character (indicates UTF-8 decoding error)
    if (code === 0xFFFD) {
      return false
    }
  }
  
  // Check for common corruption patterns
  const corruptionPatterns = [
    /[\u0000-\u0008\u000E-\u001F\u007F-\u009F]/, // Control characters
    /\uFFFD/, // Replacement character
    /[\uD800-\uDFFF]/, // Surrogate pairs (malformed)
  ]
  
  for (const pattern of corruptionPatterns) {
    if (pattern.test(str)) {
      return false
    }
  }
  
  return true
}

/**
 * Cleans UTF-8 string by removing invalid sequences
 */
export function cleanUTF8(str: string): string {
  if (!str) return ''
  
  let result = ''
  for (let i = 0; i < str.length; i++) {
    const code = str.charCodeAt(i)
    
    // Keep printable ASCII and common whitespace
    if (code >= 32 && code <= 126 || code === 9 || code === 10 || code === 13) {
      result += str[i]
    } else if (code === 0xFFFD) {
      // Skip replacement characters
      continue
    } else if (code > 127 && code < 0xD800) {
      // Keep valid UTF-8 characters (simplified check)
      result += str[i]
    }
    // Skip invalid bytes
  }
  
  return result
}

/**
 * Validates decrypted health data
 */
export function validateDecryptedData(decryptedText: string | null | undefined): ValidationResult {
  // Check for null/undefined/empty
  if (!decryptedText || decryptedText.trim().length === 0) {
    return {
      isValid: false,
      errorType: 'empty',
      shouldDisplay: false,
      attackDetected: false
    }
  }
  
  // Check UTF-8 validity
  if (!isValidUTF8(decryptedText)) {
    const rawBytes = Array.from(decryptedText)
      .map(c => c.charCodeAt(0).toString(16).padStart(2, '0'))
      .join(' ')
    
    return {
      isValid: false,
      errorType: 'utf8_corruption',
      rawBytes,
      shouldDisplay: false,
      attackDetected: true
    }
  }
  
  // Clean and trim the text
  const cleaned = cleanUTF8(decryptedText).trim()
  
  if (cleaned.length === 0) {
    return {
      isValid: false,
      errorType: 'empty',
      shouldDisplay: false,
      attackDetected: true
    }
  }
  
  // Check length (should be reasonable for health data)
  if (cleaned.length > 100 || cleaned.length < 10) {
    return {
      isValid: false,
      errorType: 'length_invalid',
      cleanedData: cleaned,
      shouldDisplay: false,
      attackDetected: true
    }
  }
  
  // Validate exact health data pattern
  const match = cleaned.match(HEALTH_DATA_PATTERN)
  if (!match) {
    return {
      isValid: false,
      errorType: 'pattern_mismatch',
      cleanedData: cleaned,
      shouldDisplay: false,
      attackDetected: true
    }
  }
  
  // Extract and validate ranges
  const heartRate = parseInt(match[1], 10)
  const spo2 = parseInt(match[2], 10)
  const steps = parseInt(match[3], 10)
  
  // Validate physiological ranges
  if (
    heartRate < VALID_HR_RANGE.min || heartRate > VALID_HR_RANGE.max ||
    spo2 < VALID_SPO2_RANGE.min || spo2 > VALID_SPO2_RANGE.max ||
    steps < VALID_STEPS_RANGE.min || steps > VALID_STEPS_RANGE.max
  ) {
    return {
      isValid: false,
      errorType: 'pattern_mismatch',
      cleanedData: cleaned,
      parsedData: { heartRate, spo2, steps },
      shouldDisplay: false,
      attackDetected: true
    }
  }
  
  // Valid data
  return {
    isValid: true,
    cleanedData: cleaned,
    shouldDisplay: true,
    attackDetected: false,
    parsedData: { heartRate, spo2, steps }
  }
}

/**
 * Gets user-friendly error message for validation result
 */
export function getValidationErrorMessage(validation: ValidationResult): string {
  switch (validation.errorType) {
    case 'utf8_corruption':
      if (validation.attackDetected) {
        return '⚠️ SECURITY: Invalid character sequences detected - potential corruption or attack'
      }
      return '❌ Decryption failed - Corrupted character sequences detected'
    
    case 'pattern_mismatch':
      if (validation.parsedData) {
        return `❌ Invalid health data ranges - HR:${validation.parsedData.heartRate} SpO2:${validation.parsedData.spo2} Steps:${validation.parsedData.steps}`
      }
      return '❌ Invalid health data format - Expected: HR-XX SPO2-XX STEPS-XXXX'
    
    case 'length_invalid':
      return '❌ Invalid data length - Packet may be corrupted or truncated'
    
    case 'empty':
      return '❌ Empty decrypted data - Decryption may have failed'
    
    default:
      return '❌ Unknown validation error'
  }
}

/**
 * Formats raw bytes for debugging
 */
export function formatRawBytes(data: string, maxBytes: number = 32): string {
  const bytes = Array.from(data)
    .slice(0, maxBytes)
    .map(c => c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase())
    .join(' ')
  
  return `${bytes}${data.length > maxBytes ? '...' : ''} (${data.length} bytes)`
}

/**
 * Logs validation details for debugging
 */
export function logValidationDetails(decryptedText: string, validation: ValidationResult): void {
  console.group('🔍 Data Validation Details')
  console.log('Input:', decryptedText)
  console.log('Length:', decryptedText.length)
  console.log('Validation:', validation)
  
  if (validation.errorType === 'utf8_corruption' && validation.rawBytes) {
    console.warn('🚨 UTF-8 Corruption Detected')
    console.warn('Raw bytes:', validation.rawBytes)
  }
  
  if (!validation.isValid) {
    console.error('❌ Validation failed:', getValidationErrorMessage(validation))
  }
  
  console.groupEnd()
}

