import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const frontendDir = path.resolve(__dirname, '..');
const distDir = path.resolve(frontendDir, 'dist');

if (!fs.existsSync(distDir)) {
  console.error('[check-css-order] Error: dist/ directory does not exist.');
  process.exit(1);
}

function findFirstLocalStylesheetIndex(html) {
  const linkRegex = /<link\b([^>]*)>/gi;
  let match;
  while ((match = linkRegex.exec(html)) !== null) {
    const attrs = match[1];
    const relMatch = /rel=["']?([^"'\s>]+)["']?/i.exec(attrs);
    const hrefMatch = /href=["']?([^"'\s>]+)["']?/i.exec(attrs);
    if (relMatch && relMatch[1].toLowerCase().includes('stylesheet')) {
      const href = hrefMatch ? hrefMatch[1] : '';
      if (href && !href.startsWith('http://') && !href.startsWith('https://') && !href.startsWith('//')) {
        return match.index;
      }
    }
  }
  return -1;
}

function findFirstInlineStyleIndex(html) {
  const styleRegex = /<style\b[^>]*>/gi;
  const match = styleRegex.exec(html);
  return match ? match.index : -1;
}

const htmlFiles = fs.readdirSync(frontendDir).filter(f => f.endsWith('.html'));
const mismatches = [];

for (const htmlFile of htmlFiles) {
  const sourcePath = path.join(frontendDir, htmlFile);
  const distPath = path.join(distDir, htmlFile);

  if (!fs.existsSync(distPath)) continue;

  const sourceHtml = fs.readFileSync(sourcePath, 'utf8');
  const sourceLinkIdx = findFirstLocalStylesheetIndex(sourceHtml);
  const sourceStyleIdx = findFirstInlineStyleIndex(sourceHtml);

  // Only check pages that link a local stylesheet AND have an inline <style>
  if (sourceLinkIdx !== -1 && sourceStyleIdx !== -1) {
    const sourceOrder = sourceLinkIdx < sourceStyleIdx ? 'before' : 'after';

    const distHtml = fs.readFileSync(distPath, 'utf8');
    const distLinkIdx = findFirstLocalStylesheetIndex(distHtml);
    const distStyleIdx = findFirstInlineStyleIndex(distHtml);

    let distOrder = 'missing';
    if (distLinkIdx !== -1 && distStyleIdx !== -1) {
      distOrder = distLinkIdx < distStyleIdx ? 'before' : 'after';
    }

    if (sourceOrder !== distOrder) {
      mismatches.push(`${htmlFile}: source=${sourceOrder}, dist=${distOrder}`);
    }
  }
}

if (mismatches.length > 0) {
  console.error('[check-css-order] FAILED! CSS ordering mismatch detected:');
  mismatches.forEach(m => console.error(`  ${m}`));
  process.exit(1);
} else {
  console.log('[check-css-order] PASSED! CSS loading order is preserved in dist/.');
  process.exit(0);
}
