import {
  cpSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const scriptPath = fileURLToPath(import.meta.url);
const defaultRepoRoot = process.env.BLOG_IMPORT_ROOT || resolve(scriptDirectory, '..');

function fail(message) {
  throw new Error(message);
}

function rewriteImagePaths(markdown, slug) {
  const relativeImage = /(!\[[^\]]*\]\()(?:\.\/)?images\/([^\s)]+)((?:\s+['"][^'"]*['"])?\))/g;
  return markdown.replace(
    relativeImage,
    (_match, opening, imagePath, closing) => `${opening}/images/${slug}/${imagePath}${closing}`
  );
}

export function parseArguments(args) {
  const unknownOption = args.find(argument => argument.startsWith('--') && argument !== '--force');
  if (unknownOption) fail(`unknown option: ${unknownOption}`);

  const slugs = args.filter(argument => argument !== '--force');
  if (slugs.length !== 1) {
    fail('usage: npm run import:manuscript -- <article-slug> [--force]');
  }

  return { slug: slugs[0], force: args.includes('--force') };
}

export function importManuscript(slug, { repoRoot = defaultRepoRoot, force = false } = {}) {
  if (!slug || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(slug)) {
    fail('article-slug must contain only letters, numbers, dots, underscores, and hyphens');
  }

  const manuscriptRoot = join(repoRoot, 'manuscripts', slug);
  const sourceMarkdown = join(manuscriptRoot, `${slug}.md`);
  const sourceImages = join(manuscriptRoot, 'images');
  const targetMarkdown = join(repoRoot, 'my-blog', 'source', '_posts', `${slug}.md`);
  const targetImages = join(repoRoot, 'my-blog', 'source', 'images', slug);

  if (!existsSync(sourceMarkdown)) fail(`manuscript does not exist: ${sourceMarkdown}`);
  if (!existsSync(sourceImages)) fail(`image directory does not exist: ${sourceImages}`);
  if (!force && existsSync(targetMarkdown)) fail(`published article already exists: ${targetMarkdown}`);
  if (!force && existsSync(targetImages)) fail(`published image directory already exists: ${targetImages}`);

  const markdown = rewriteImagePaths(readFileSync(sourceMarkdown, 'utf8'), slug);
  mkdirSync(dirname(targetMarkdown), { recursive: true });
  mkdirSync(dirname(targetImages), { recursive: true });

  const stagingRoot = mkdtempSync(join(repoRoot, '.manuscript-import-'));
  const stagedMarkdown = join(stagingRoot, `${slug}.md`);
  const stagedImages = join(stagingRoot, 'images');
  const backupMarkdown = join(stagingRoot, 'previous.md');
  const backupImages = join(stagingRoot, 'previous-images');
  let markdownBackedUp = false;
  let imagesBackedUp = false;
  let markdownInstalled = false;
  let imagesInstalled = false;

  try {
    writeFileSync(stagedMarkdown, markdown, { flag: 'wx' });
    cpSync(sourceImages, stagedImages, { recursive: true, errorOnExist: true, force: false });

    if (force && existsSync(targetMarkdown)) {
      renameSync(targetMarkdown, backupMarkdown);
      markdownBackedUp = true;
    }
    if (force && existsSync(targetImages)) {
      renameSync(targetImages, backupImages);
      imagesBackedUp = true;
    }

    renameSync(stagedMarkdown, targetMarkdown);
    markdownInstalled = true;
    renameSync(stagedImages, targetImages);
    imagesInstalled = true;
  } catch (error) {
    if (markdownInstalled) rmSync(targetMarkdown, { force: true });
    if (imagesInstalled) rmSync(targetImages, { recursive: true, force: true });
    if (markdownBackedUp) renameSync(backupMarkdown, targetMarkdown);
    if (imagesBackedUp) renameSync(backupImages, targetImages);
    throw error;
  } finally {
    rmSync(stagingRoot, { recursive: true, force: true });
  }

  return { manuscriptRoot, targetMarkdown, targetImages };
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    const { slug, force } = parseArguments(process.argv.slice(2));
    const { manuscriptRoot, targetMarkdown, targetImages } = importManuscript(slug, { force });
    console.log(`${force ? 'Force-imported' : 'Imported'} manuscript "${slug}".`);
    console.log(`Post: ${targetMarkdown}`);
    console.log(`Images: ${targetImages}`);
    console.log(`Original preserved: ${manuscriptRoot}`);
  } catch (error) {
    console.error(`Import failed: ${error.message}`);
    process.exitCode = 1;
  }
}
