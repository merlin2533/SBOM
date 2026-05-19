// Copies the prebuilt tus-js-client UMD bundle into public/vendor/ so the
// browser can load it under our strict CSP without reaching out to a CDN.
const fs = require('fs');
const path = require('path');

const candidates = [
  'node_modules/tus-js-client/dist/tus.min.js',
  'node_modules/tus-js-client/dist/tus.js',
];

const src = candidates.find((p) => fs.existsSync(path.resolve(p)));
if (!src) {
  console.error('vendor-tus: could not find tus-js-client UMD bundle. Did you run npm install?');
  process.exit(1);
}

const destDir = path.resolve('public/vendor');
fs.mkdirSync(destDir, { recursive: true });
const dest = path.join(destDir, 'tus.min.js');
fs.copyFileSync(path.resolve(src), dest);
console.log(`vendor-tus: ${src} → ${path.relative(process.cwd(), dest)}`);
