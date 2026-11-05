// Sources each third-party service needs in a Content Security Policy.
// Keep entries minimal and documented; check the vendor's docs when they change.
export const SERVICES = {
  'google-analytics': {
    label: 'Google Analytics 4 / gtag.js',
    'script-src': ['https://www.googletagmanager.com'],
    'connect-src': ['https://*.google-analytics.com', 'https://*.analytics.google.com', 'https://*.googletagmanager.com'],
    'img-src': ['https://*.google-analytics.com', 'https://*.googletagmanager.com'],
  },
  'google-tag-manager': {
    label: 'Google Tag Manager',
    'script-src': ['https://www.googletagmanager.com'],
    'img-src': ['https://www.googletagmanager.com'],
    'frame-src': ['https://www.googletagmanager.com'],
  },
  'google-adsense': {
    label: 'Google AdSense (ads load many Google domains; keep this broad)',
    'script-src': ['https://pagead2.googlesyndication.com', 'https://*.googlesyndication.com', 'https://*.google.com', 'https://*.gstatic.com', 'https://*.doubleclick.net', 'https://*.adtrafficquality.google', 'https://*.googleadservices.com'],
    'frame-src': ['https://*.doubleclick.net', 'https://*.googlesyndication.com', 'https://*.google.com', 'https://*.adtrafficquality.google'],
    'connect-src': ['https://*.google.com', 'https://*.doubleclick.net', 'https://*.googlesyndication.com', 'https://*.adtrafficquality.google'],
    'img-src': ['https:'],
  },
  'google-fonts': {
    label: 'Google Fonts',
    'style-src': ['https://fonts.googleapis.com'],
    'font-src': ['https://fonts.gstatic.com'],
  },
  'cloudflare-web-analytics': {
    label: 'Cloudflare Web Analytics',
    'script-src': ['https://static.cloudflareinsights.com'],
    'connect-src': ['https://cloudflareinsights.com'],
  },
  youtube: {
    label: 'YouTube embeds',
    'frame-src': ['https://www.youtube-nocookie.com', 'https://www.youtube.com'],
    'img-src': ['https://i.ytimg.com'],
  },
  vimeo: {
    label: 'Vimeo embeds',
    'frame-src': ['https://player.vimeo.com'],
  },
  stripe: {
    label: 'Stripe.js / Checkout',
    'script-src': ['https://js.stripe.com'],
    'frame-src': ['https://js.stripe.com', 'https://hooks.stripe.com'],
    'connect-src': ['https://api.stripe.com'],
  },
  recaptcha: {
    label: 'Google reCAPTCHA',
    'script-src': ['https://www.google.com/recaptcha/', 'https://www.gstatic.com/recaptcha/'],
    'frame-src': ['https://www.google.com/recaptcha/', 'https://recaptcha.google.com/recaptcha/'],
  },
  'cloudflare-turnstile': {
    label: 'Cloudflare Turnstile',
    'script-src': ['https://challenges.cloudflare.com'],
    'frame-src': ['https://challenges.cloudflare.com'],
  },
  jsdelivr: { label: 'jsDelivr CDN', 'script-src': ['https://cdn.jsdelivr.net'], 'style-src': ['https://cdn.jsdelivr.net'] },
  cdnjs: { label: 'cdnjs', 'script-src': ['https://cdnjs.cloudflare.com'], 'style-src': ['https://cdnjs.cloudflare.com'] },
  unpkg: { label: 'unpkg', 'script-src': ['https://unpkg.com'], 'style-src': ['https://unpkg.com'] },
};
