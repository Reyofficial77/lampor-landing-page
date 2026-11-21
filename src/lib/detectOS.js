const ua = () => navigator.userAgent || ''

// Mengembalikan 'android' | 'windows' | 'ios' | 'mac' | 'linux' | 'unknown'
export function detectOS() {
  const u = ua()
  if (/android/i.test(u)) return 'android'
  if (/iphone|ipad|ipod/i.test(u) || (/Macintosh/.test(u) && navigator.maxTouchPoints > 1)) return 'ios'
  const p = navigator.userAgentData?.platform || navigator.platform || ''
  if (/win/i.test(p) || /windows/i.test(u)) return 'windows'
  if (/mac/i.test(p) || /Macintosh/.test(u)) return 'mac'
  if (/linux|x11/i.test(u)) return 'linux'
  return 'unknown'
}
