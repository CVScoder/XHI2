// app/page.tsx (Simplified - No Loading Screen)
'use client'

import XenoCipherDashboard from '../components/XenoCipherDashboard'

export default function Home() {
  return (
    <main className="min-h-screen">
      <XenoCipherDashboard />
    </main>
  )
}