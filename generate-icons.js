// Node.js-Script zum Erzeugen einfacher Icons
// Ausführen: node generate-icons.js
const { createCanvas } = require('canvas');
const fs = require('fs');

function createIcon(size) {
  const canvas = createCanvas(size, size);
  const ctx = canvas.getContext('2d');

  // Hintergrund
  const grad = ctx.createRadialGradient(size/2, size/2, 0, size/2, size/2, size/2);
  grad.addColorStop(0, '#cba6f7');
  grad.addColorStop(1, '#7c3aed');
  ctx.fillStyle = grad;
  ctx.beginPath();
  ctx.arc(size/2, size/2, size/2, 0, Math.PI * 2);
  ctx.fill();

  // Schlüssel-Emoji
  ctx.font = `${size * 0.55}px serif`;
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillText('🔑', size/2, size/2 + size * 0.03);

  return canvas.toBuffer('image/png');
}

try {
  fs.writeFileSync('icons/icon-48.png', createIcon(48));
  fs.writeFileSync('icons/icon-96.png', createIcon(96));
  console.log('Icons erstellt.');
} catch(e) {
  console.log('canvas-Modul nicht verfügbar, Icons werden als Platzhalter erstellt.');
  // Minimale 1x1 PNG als Fallback
  const tiny = Buffer.from(
    'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==',
    'base64'
  );
  fs.writeFileSync('icons/icon-48.png', tiny);
  fs.writeFileSync('icons/icon-96.png', tiny);
}
