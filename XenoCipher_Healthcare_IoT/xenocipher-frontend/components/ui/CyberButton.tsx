// components/ui/CyberButton.tsx
'use client'

import React from 'react'
import { motion } from 'framer-motion'

interface CyberButtonProps {
  children: React.ReactNode
  onClick?: () => void
  variant?: 'primary' | 'secondary' | 'danger'
  disabled?: boolean
  className?: string
}

export default function CyberButton({ 
  children, 
  onClick, 
  variant = 'primary', 
  disabled = false,
  className = '' 
}: CyberButtonProps) {
  const variants = {
    primary: 'bg-cyan-500 hover:bg-cyan-600 border-cyan-400',
    secondary: 'bg-gray-700 hover:bg-gray-600 border-gray-500',
    danger: 'bg-red-500 hover:bg-red-600 border-red-400'
  }

  return (
    <motion.button
      whileHover={{ scale: disabled ? 1 : 1.05 }}
      whileTap={{ scale: disabled ? 1 : 0.95 }}
      onClick={onClick}
      disabled={disabled}
      className={`
        px-4 py-2 rounded-lg border-2 font-mono font-bold
        transition-all duration-200 disabled:opacity-50
        disabled:cursor-not-allowed ${variants[variant]} ${className}
      `}
    >
      {children}
    </motion.button>
  )
}