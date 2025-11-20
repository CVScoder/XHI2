// app/loading.tsx
export default function Loading() {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 via-black to-gray-900 flex items-center justify-center">
        <div className="text-center">
          <div className="w-16 h-16 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin mx-auto mb-4"></div>
          <h2 className="text-xl font-bold text-cyan-400 mb-2">XenoCipher</h2>
          <p className="text-gray-400">Initializing Cryptographic Systems...</p>
        </div>
      </div>
    )
  }