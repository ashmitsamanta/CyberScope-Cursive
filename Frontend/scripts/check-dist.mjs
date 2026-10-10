import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const distDir = path.resolve(__dirname, '../dist');

if (!fs.existsSync(distDir)) {
  console.error('[check-dist] Error: dist/ directory does not exist.');
  process.exit(1);
}

const htmlFiles = fs.readdirSync(distDir).filter(f => f.endsWith('.html'));
const missingFiles = [];

function isLocalRef(ref) {
  if (!ref || typeof ref !== 'string') return false;
  const trimmed = ref.trim();
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://') || trimmed.startsWith('//')) return false;
  if (trimmed.startsWith('data:') || trimmed.startsWith('javascript:') || trimmed.startsWith('mailto:') || trimmed.startsWith('tel:')) return false;
  if (trimmed.startsWith('#')) return false;
  return true;
}

function cleanRef(ref) {
  return ref.trim().split('?')[0].split('#')[0];
}

for (const htmlFile of htmlFiles) {
  const filePath = path.join(distDir, htmlFile);
  const content = fs.readFileSync(filePath, 'utf8');

  const scriptRegex = /<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi;
  const linkRegex = /<link\b[^>]*\bhref=["']([^"']+)["'][^>]*>/gi;
  const imgRegex = /<img\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi;

  const matches = [];
  let match;

  while ((match = scriptRegex.exec(content)) !== null) {
    matches.push(match[1]);
  }
  while ((match = linkRegex.exec(content)) !== null) {
    matches.push(match[1]);
  }
  while ((match = imgRegex.exec(content)) !== null) {
    matches.push(match[1]);
  }

  for (const rawRef of matches) {
    if (!isLocalRef(rawRef)) continue;
    const ref = cleanRef(rawRef);
    if (!ref) continue;

    const relativeRef = ref.startsWith('/') ? ref.slice(1) : ref;
    const targetPath = path.join(distDir, relativeRef);

    if (!fs.existsSync(targetPath)) {
      missingFiles.push(`${htmlFile} -> ${rawRef}`);
    }
  }
}

if (missingFiles.length > 0) {
  console.error('[check-dist] FAILED! The following referenced asset files are missing in dist/:');
  missingFiles.forEach(m => console.error(`  - ${m}`));
  process.exit(1);
} else {
  console.log('[check-dist] PASSED! All referenced asset files exist in dist/.');
  process.exit(0);
}
