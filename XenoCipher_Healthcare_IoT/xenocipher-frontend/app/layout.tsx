// app/layout.tsx
import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import './globals.css'
import { WebSocketProvider } from '../context/WebSocketContext'
import { PipelineProvider } from '../context/PipelineContext'
import { ZeroTrustProvider } from '../context/ZeroTrustContext'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'XenoCipher - Secure Health Data Pipeline',
  description: 'Real-time monitoring dashboard for secure health data transmission with Zero Trust security',
  keywords: 'encryption, health data, zero trust, cybersecurity, real-time monitoring',
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" className="dark">
      <head>
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" />
      </head>
      <body className={`${inter.className} bg-gray-900 text-white antialiased`}>
        <ZeroTrustProvider>
          <WebSocketProvider>
            <PipelineProvider>
              {children}
            </PipelineProvider>
          </WebSocketProvider>
        </ZeroTrustProvider>
      </body>
    </html>
  )
}