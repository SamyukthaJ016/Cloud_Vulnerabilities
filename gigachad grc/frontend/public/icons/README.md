# PWA Icons

This directory should contain the following icon files for PWA support:

## Required Icons

| File | Size | Purpose |
|------|------|---------|
| `icon-72x72.png` | 72x72 | Android low-res |
| `icon-96x96.png` | 96x96 | Android low-res |
| `icon-128x128.png` | 128x128 | Android medium-res |
| `icon-144x144.png` | 144x144 | Android medium-res |
| `icon-152x152.png` | 152x152 | iOS |
| `icon-192x192.png` | 192x192 | Android high-res, Apple Touch Icon |
| `icon-384x384.png` | 384x384 | Android high-res |
| `icon-512x512.png` | 512x512 | Android splash screen |

## Shortcut Icons

| File | Size | Purpose |
|------|------|---------|
| `shortcut-dashboard.png` | 96x96 | Dashboard shortcut |
| `shortcut-controls.png` | 96x96 | Controls shortcut |
| `shortcut-risks.png` | 96x96 | Risks shortcut |
| `shortcut-vendors.png` | 96x96 | Vendors shortcut |

## Generating Icons

You can use the following tools to generate icons from a source image:

1. **PWA Asset Generator**: `npx pwa-asset-generator logo.svg ./public/icons`
2. **Real Favicon Generator**: https://realfavicongenerator.net/
3. **Maskable.app**: https://maskable.app/editor

## Icon Guidelines

- Use PNG format for all icons
- Icons should be square
- For maskable icons, ensure the safe zone (center 80%) contains the essential design
- Use a solid background color (#0f172a recommended for dark theme)
- Primary icon color should be #3b82f6 (brand blue)

## Placeholder SVG

Until proper icons are generated, you can use the existing favicon.svg as a reference.
The favicon uses the GigaChad GRC shield design.




