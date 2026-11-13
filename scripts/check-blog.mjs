import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const blogRoot = join(repoRoot, 'my-blog');
const publicRoot = join(blogRoot, 'public');

function walk(directory, extension) {
  if (!existsSync(directory)) return [];

  return readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) return walk(path, extension);
    return path.endsWith(extension) ? [path] : [];
  });
}

function assertGeneratedMetadata() {
  const indexPath = join(publicRoot, 'index.html');
  assert.ok(existsSync(indexPath), 'public/index.html is missing; run npm run build first');

  const html = readFileSync(indexPath, 'utf8');
  assert.match(html, /<html lang="zh-CN"/, 'homepage language must be zh-CN');
  assert.doesNotMatch(html, /example\.com|github\.com\/xxxxxx|This is my Blog/, 'homepage still contains placeholder content');
  assert.match(html, /https:\/\/github\.com\/wing-147/, 'homepage must link to the real GitHub profile');
  assert.doesNotMatch(html, /localSearch:\s*undefined/, 'local search is configured with an obsolete Butterfly key');
  assert.match(html, /id="search-button"/, 'local search button is missing');
}

function assertCustomStyles() {
  const indexPath = join(publicRoot, 'index.html');
  const stylesheetPath = join(publicRoot, 'css', 'custom.css');

  assert.ok(existsSync(stylesheetPath), 'custom stylesheet is missing');
  const stylesheet = readFileSync(stylesheetPath, 'utf8');
  assert.match(
    readFileSync(indexPath, 'utf8'),
    /<link rel="stylesheet" href="\/css\/custom\.css">/,
    'custom stylesheet is not linked from generated pages'
  );
  assert.match(
    stylesheet,
    /\.search-dialog hr(?:,\s*\.search-dialog hr::before)?\s*\{[^}]*display:\s*none;/s,
    'search dialog zipper decoration is still visible'
  );
  assert.match(
    stylesheet,
    /#rightside-config[^}]*animation:\s*none;/s,
    'right-side settings gear is still animated'
  );
}

function assertVisitorCounterUsesAvailableService() {
  const html = readFileSync(join(publicRoot, 'index.html'), 'utf8');

  assert.doesNotMatch(
    html,
    /busuanzi\.ibruce\.info/,
    'homepage still loads the unreliable default Busuanzi service'
  );
  assert.match(
    html,
    /<script[^>]+src="https:\/\/busuanzi\.icodeq\.com\/busuanzi\.pure\.mini\.js"/,
    'homepage does not load the configured Busuanzi-compatible counter'
  );
}

function assertFooterImageIsConfigured() {
  const html = readFileSync(join(publicRoot, 'index.html'), 'utf8');
  const match = html.match(/<footer id="footer" style="background-image: url\((\/[^)]+)\);">/);

  assert.ok(match, 'homepage footer image is not configured');
  const imagePath = join(publicRoot, match[1].replace(/^\/+/, ''));
  assert.ok(existsSync(imagePath), `homepage footer image is missing: ${match[1]}`);
}

function assertGeneratedAssetsExist() {
  const mainStylesheet = join(publicRoot, 'css', 'index.css');
  assert.ok(existsSync(mainStylesheet), 'generated main stylesheet is missing');
  assert.ok(statSync(mainStylesheet).size > 1_000, 'generated main stylesheet is empty or incomplete');

  const missing = [];
  const encodedBackslashes = [];
  const assetPattern = /(?:src|href)="(\/[^"?#]+\.(?:css|gif|ico|jpe?g|js|png|svg|webp|xml))[^"#]*"/gi;

  for (const htmlPath of walk(publicRoot, '.html')) {
    const html = readFileSync(htmlPath, 'utf8');
    for (const match of html.matchAll(assetPattern)) {
      const urlPath = match[1];
      if (urlPath.startsWith('//')) continue;
      if (/%5c/i.test(urlPath)) encodedBackslashes.push(`${htmlPath}: ${urlPath}`);

      const filePath = join(publicRoot, decodeURIComponent(urlPath).replace(/^\/+/, ''));
      if (!existsSync(filePath) || !statSync(filePath).isFile()) {
        missing.push(`${htmlPath}: ${urlPath}`);
      }
    }
  }

  assert.deepEqual(encodedBackslashes, [], `generated asset URLs contain encoded backslashes:\n${encodedBackslashes.join('\n')}`);
  assert.deepEqual(missing, [], `generated pages reference missing local assets:\n${missing.join('\n')}`);
}

function assertMarkdownImagePaths() {
  const markdownRoots = [
    join(blogRoot, 'source'),
    join(repoRoot, 'manuscripts')
  ];
  const invalid = [];
  const missing = [];
  const imagePattern = /!\[[^\]]*\]\(([^)\s]+)(?:\s+['"][^'"]*['"])?\)/g;

  for (const markdownRoot of markdownRoots) {
    for (const markdownPath of walk(markdownRoot, '.md')) {
      const markdown = readFileSync(markdownPath, 'utf8');
      assert.doesNotMatch(markdown, /^commets:/m, `${markdownPath} misspells the comments front-matter key`);
      for (const match of markdown.matchAll(imagePattern)) {
        const imagePath = match[1];
        if (/^(?:https?:)?\/\//.test(imagePath) || imagePath.startsWith('data:')) continue;
        if (imagePath.includes('\\')) invalid.push(`${markdownPath}: ${imagePath}`);

        const filePath = imagePath.startsWith('/')
          ? join(blogRoot, 'source', imagePath.replace(/^\/+/, ''))
          : resolve(dirname(markdownPath), imagePath);
        if (!existsSync(filePath) || !statSync(filePath).isFile()) {
          missing.push(`${markdownPath}: ${imagePath}`);
        }
      }
    }
  }

  assert.deepEqual(invalid, [], `Markdown image paths contain Windows backslashes:\n${invalid.join('\n')}`);
  assert.deepEqual(missing, [], `Markdown image paths point to missing files:\n${missing.join('\n')}`);
}

function assertThemeCheckoutIsReproducible() {
  const status = execFileSync('git', ['submodule', 'status', '--', 'my-blog/themes/butterfly'], {
    cwd: repoRoot,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe']
  }).trim();
  assert.ok(status && !status.startsWith('-'), 'Butterfly submodule is not initialized');
}

function assertPagesWorkflow() {
  const workflowPath = join(repoRoot, '.github', 'workflows', 'pages.yml');
  assert.ok(existsSync(workflowPath), 'GitHub Pages workflow is missing');

  const requireFromBlog = createRequire(join(blogRoot, 'package.json'));
  const yaml = requireFromBlog('js-yaml');
  const workflow = yaml.load(readFileSync(workflowPath, 'utf8'));

  assert.ok(workflow.on?.push?.branches?.includes('main'), 'Pages workflow must deploy pushes to main');
  assert.ok(workflow.on?.workflow_dispatch !== undefined, 'Pages workflow must support manual runs');

  const buildSteps = workflow.jobs?.build?.steps ?? [];
  const checkout = buildSteps.find(step => String(step.uses).startsWith('actions/checkout@'));
  const setupNode = buildSteps.find(step => String(step.uses).startsWith('actions/setup-node@'));
  const upload = buildSteps.find(step => String(step.uses).startsWith('actions/upload-pages-artifact@'));
  const runCommands = buildSteps.filter(step => step.run).map(step => step.run).join('\n');

  assert.equal(checkout?.with?.submodules, 'recursive', 'Pages checkout must include the Butterfly submodule');
  assert.equal(setupNode?.with?.['node-version-file'], 'my-blog/.nvmrc', 'Pages workflow must use the project Node version');
  assert.match(runCommands, /npm ci/, 'Pages workflow must install the locked dependencies');
  assert.match(runCommands, /npm run build/, 'Pages workflow must build the site');
  assert.match(runCommands, /npm test/, 'Pages workflow must run the blog checks');
  assert.equal(upload?.with?.path, 'my-blog/public', 'Pages workflow must upload the generated site');
  assert.ok(workflow.jobs?.deploy?.needs === 'build', 'Pages deployment must wait for the build');
}

assertGeneratedMetadata();
assertCustomStyles();
assertVisitorCounterUsesAvailableService();
assertFooterImageIsConfigured();
assertGeneratedAssetsExist();
assertMarkdownImagePaths();
assertThemeCheckoutIsReproducible();
assertPagesWorkflow();

console.log('Blog checks passed.');
