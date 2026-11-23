export const GAME = {
  name: 'LAMPOR: Malam Jahanam',
  version: '1.3.0',
  developer: 'AstraDev',
  repo: 'Reyofficial77/lampor',
}

// ============================================================
// PASANG LINK DOWNLOAD DI SINI (cukup ganti 2 baris ini).
// Isi dengan link langsung ke file; kosongkan ('') untuk memakai
// deteksi otomatis rilis terbaru dari GitHub.
// ============================================================
export const DOWNLOAD_LINKS = {
  windows: '', // contoh: 'https://github.com/Reyofficial77/lampor/releases/download/v1.3.0/LAMPOR-Windows.zip'
  android: '', // contoh: 'https://github.com/Reyofficial77/lampor/releases/download/v1.3.0/LAMPOR.apk'
}

// Ganti pola nama file jika aset rilis GitHub Anda berbeda.
export const PLATFORMS = {
  windows: {
    id: 'windows',
    label: 'Windows',
    req: 'Windows 10/11 (64-bit)',
    ext: /\.(exe|zip|msi)$/i,
    hint: /win/i,
    icon: 'monitor',
  },
  android: {
    id: 'android',
    label: 'Android',
    req: 'Android 7.0 (Nougat) ke atas',
    ext: /\.apk$/i,
    hint: /./,
    icon: 'smartphone',
  },
}

export const RELEASES_URL = `https://github.com/${GAME.repo}/releases/latest`
export const DONATION_URL = 'https://saweria.co/lordreyid'
export const WEB_PLAY_URL = 'https://lampor.vercel.app'
