// lib/animations.ts
export const fadeInUp = {
    initial: { opacity: 0, y: 20 },
    animate: { opacity: 1, y: 0 },
    exit: { opacity: 0, y: -20 }
  }
  
  export const staggerChildren = {
    animate: {
      transition: {
        staggerChildren: 0.1
      }
    }
  }
  
  export const cyberGlow = {
    initial: { boxShadow: '0 0 0px #00ff88' },
    animate: { boxShadow: '0 0 10px #00ff88, 0 0 20px #00ff88' },
    hover: { boxShadow: '0 0 15px #00ff88, 0 0 30px #00ff88' }
  }