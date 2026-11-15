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

function rewriteAssetPaths(markdown, slug) {
  const relativeImage = /(!\[[^\]]*\]\()(?:\.\/)?images\/([^\s)]+)((?:\s+['"][^'"]*['"])?\))/g;
  const relativeAttachment = /(\[[^\]]*\]\()(?:\.\/)?attachments\/([^\s)]+)((?:\s+['"][^'"]*['"])?\))/g;
  const withImagePaths = markdown.replace(
    relativeImage,
    (_match, opening, imagePath, closing) => `${opening}/images/${slug}/${imagePath}${closing}`
  );
  return withImagePaths.replace(
    relativeAttachment,
    (_match, opening, attachmentPath, closing) => `${opening}/downloads/${slug}/${attachmentPath}${closing}`
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
  const sourceAttachments = join(manuscriptRoot, 'attachments');
  const targetMarkdown = join(repoRoot, 'my-blog', 'source', '_posts', `${slug}.md`);
  const targetImages = join(repoRoot, 'my-blog', 'source', 'images', slug);
  const targetAttachments = join(repoRoot, 'my-blog', 'source', 'downloads', slug);
  const hasSourceAttachments = existsSync(sourceAttachments);

  if (!existsSync(sourceMarkdown)) fail(`manuscript does not exist: ${sourceMarkdown}`);
  if (!existsSync(sourceImages)) fail(`image directory does not exist: ${sourceImages}`);
  if (!force && existsSync(targetMarkdown)) fail(`published article already exists: ${targetMarkdown}`);
  if (!force && existsSync(targetImages)) fail(`published image directory already exists: ${targetImages}`);
  if (!force && existsSync(targetAttachments)) {
    fail(`published attachment directory already exists: ${targetAttachments}`);
  }

  const markdown = rewriteAssetPaths(readFileSync(sourceMarkdown, 'utf8'), slug);
  mkdirSync(dirname(targetMarkdown), { recursive: true });
  mkdirSync(dirname(targetImages), { recursive: true });
  mkdirSync(dirname(targetAttachments), { recursive: true });

  const stagingRoot = mkdtempSync(join(repoRoot, '.manuscript-import-'));
  const stagedMarkdown = join(stagingRoot, `${slug}.md`);
  const stagedImages = join(stagingRoot, 'images');
  const stagedAttachments = join(stagingRoot, 'attachments');
  const backupMarkdown = join(stagingRoot, 'previous.md');
  const backupImages = join(stagingRoot, 'previous-images');
  const backupAttachments = join(stagingRoot, 'previous-attachments');
  let markdownBackedUp = false;
  let imagesBackedUp = false;
  let attachmentsBackedUp = false;
  let markdownInstalled = false;
  let imagesInstalled = false;
  let attachmentsInstalled = false;

  try {
    writeFileSync(stagedMarkdown, markdown, { flag: 'wx' });
    cpSync(sourceImages, stagedImages, { recursive: true, errorOnExist: true, force: false });
    if (hasSourceAttachments) {
      cpSync(sourceAttachments, stagedAttachments, { recursive: true, errorOnExist: true, force: false });
    }

    if (force && existsSync(targetMarkdown)) {
      renameSync(targetMarkdown, backupMarkdown);
      markdownBackedUp = true;
    }
    if (force && existsSync(targetImages)) {
      renameSync(targetImages, backupImages);
      imagesBackedUp = true;
    }
    if (force && existsSync(targetAttachments)) {
      renameSync(targetAttachments, backupAttachments);
      attachmentsBackedUp = true;
    }

    renameSync(stagedMarkdown, targetMarkdown);
    markdownInstalled = true;
    renameSync(stagedImages, targetImages);
    imagesInstalled = true;
    if (hasSourceAttachments) {
      renameSync(stagedAttachments, targetAttachments);
      attachmentsInstalled = true;
    }
  } catch (error) {
    if (markdownInstalled) rmSync(targetMarkdown, { force: true });
    if (imagesInstalled) rmSync(targetImages, { recursive: true, force: true });
    if (attachmentsInstalled) rmSync(targetAttachments, { recursive: true, force: true });
    if (markdownBackedUp) renameSync(backupMarkdown, targetMarkdown);
    if (imagesBackedUp) renameSync(backupImages, targetImages);
    if (attachmentsBackedUp) renameSync(backupAttachments, targetAttachments);
    throw error;
  } finally {
    rmSync(stagingRoot, { recursive: true, force: true });
  }

  return {
    manuscriptRoot,
    targetMarkdown,
    targetImages,
    targetAttachments: hasSourceAttachments ? targetAttachments : undefined
  };
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  try {
    const { slug, force } = parseArguments(process.argv.slice(2));
    const { manuscriptRoot, targetMarkdown, targetImages, targetAttachments } = importManuscript(slug, { force });
    console.log(`${force ? 'Force-imported' : 'Imported'} manuscript "${slug}".`);
    console.log(`Post: ${targetMarkdown}`);
    console.log(`Images: ${targetImages}`);
    console.log(`Attachments: ${targetAttachments || 'none'}`);
    console.log(`Original preserved: ${manuscriptRoot}`);
  } catch (error) {
    console.error(`Import failed: ${error.message}`);
    process.exitCode = 1;
  }
}
