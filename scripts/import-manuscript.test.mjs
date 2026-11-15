import assert from 'node:assert/strict';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { importManuscript, parseArguments } from './import-manuscript.mjs';

function createFixture(slug) {
  const repoRoot = mkdtempSync(join(tmpdir(), 'blog-import-'));
  const manuscriptRoot = join(repoRoot, 'manuscripts', slug);

  mkdirSync(join(manuscriptRoot, 'images', 'nested'), { recursive: true });
  mkdirSync(join(manuscriptRoot, 'attachments', 'nested'), { recursive: true });
  mkdirSync(join(repoRoot, 'my-blog', 'source', '_posts'), { recursive: true });
  mkdirSync(join(repoRoot, 'my-blog', 'source', 'images'), { recursive: true });

  writeFileSync(
    join(manuscriptRoot, `${slug}.md`),
    [
      '---',
      'title: 测试文章',
      '---',
      '',
      '![diagram](images/diagram.png)',
      '![nested](./images/nested/detail.png "详情")',
      '![absolute](/images/shared.png)',
      '![external](https://example.com/external.png)',
      '[bundle](attachments/challenge-files.zip "题目附件")',
      '[nested bundle](./attachments/nested/source-and-exp.zip)',
      '[absolute bundle](/downloads/shared.zip)',
      '[external bundle](https://example.com/shared.zip)',
      ''
    ].join('\n')
  );
  writeFileSync(join(manuscriptRoot, 'images', 'diagram.png'), 'diagram');
  writeFileSync(join(manuscriptRoot, 'images', 'nested', 'detail.png'), 'detail');
  writeFileSync(join(manuscriptRoot, 'attachments', 'challenge-files.zip'), 'challenge');
  writeFileSync(join(manuscriptRoot, 'attachments', 'nested', 'source-and-exp.zip'), 'source and exp');

  return repoRoot;
}

test('imports a manuscript and rewrites only its relative image paths', t => {
  const slug = 'demo-post';
  const repoRoot = createFixture(slug);
  t.after(() => rmSync(repoRoot, { recursive: true, force: true }));

  importManuscript(slug, { repoRoot });

  const published = readFileSync(
    join(repoRoot, 'my-blog', 'source', '_posts', `${slug}.md`),
    'utf8'
  );
  assert.match(published, /!\[diagram\]\(\/images\/demo-post\/diagram\.png\)/);
  assert.match(published, /!\[nested\]\(\/images\/demo-post\/nested\/detail\.png "详情"\)/);
  assert.match(published, /!\[absolute\]\(\/images\/shared\.png\)/);
  assert.match(published, /!\[external\]\(https:\/\/example\.com\/external\.png\)/);

  assert.equal(
    readFileSync(join(repoRoot, 'my-blog', 'source', 'images', slug, 'diagram.png'), 'utf8'),
    'diagram'
  );
  assert.equal(
    readFileSync(join(repoRoot, 'my-blog', 'source', 'images', slug, 'nested', 'detail.png'), 'utf8'),
    'detail'
  );
  assert.ok(existsSync(join(repoRoot, 'manuscripts', slug, `${slug}.md`)), 'original must remain');
});

test('imports attachments and rewrites only their relative Markdown links', t => {
  const slug = 'attachment-post';
  const repoRoot = createFixture(slug);
  t.after(() => rmSync(repoRoot, { recursive: true, force: true }));

  importManuscript(slug, { repoRoot });

  const published = readFileSync(
    join(repoRoot, 'my-blog', 'source', '_posts', `${slug}.md`),
    'utf8'
  );
  assert.match(published, /\[bundle\]\(\/downloads\/attachment-post\/challenge-files\.zip "题目附件"\)/);
  assert.match(published, /\[nested bundle\]\(\/downloads\/attachment-post\/nested\/source-and-exp\.zip\)/);
  assert.match(published, /\[absolute bundle\]\(\/downloads\/shared\.zip\)/);
  assert.match(published, /\[external bundle\]\(https:\/\/example\.com\/shared\.zip\)/);
  assert.equal(
    readFileSync(join(repoRoot, 'my-blog', 'source', 'downloads', slug, 'challenge-files.zip'), 'utf8'),
    'challenge'
  );
  assert.equal(
    readFileSync(join(repoRoot, 'my-blog', 'source', 'downloads', slug, 'nested', 'source-and-exp.zip'), 'utf8'),
    'source and exp'
  );
});

test('keeps attachments optional for manuscripts that only contain images', t => {
  const slug = 'images-only-post';
  const repoRoot = createFixture(slug);
  const manuscriptRoot = join(repoRoot, 'manuscripts', slug);
  const manuscriptPath = join(manuscriptRoot, `${slug}.md`);
  t.after(() => rmSync(repoRoot, { recursive: true, force: true }));

  rmSync(join(manuscriptRoot, 'attachments'), { recursive: true });
  const markdown = readFileSync(manuscriptPath, 'utf8')
    .split('\n')
    .filter(line => !line.includes('bundle]'))
    .join('\n');
  writeFileSync(manuscriptPath, markdown);

  const result = importManuscript(slug, { repoRoot });

  assert.equal(result.targetAttachments, undefined);
  assert.ok(!existsSync(join(repoRoot, 'my-blog', 'source', 'downloads', slug)));
  assert.ok(existsSync(join(repoRoot, 'my-blog', 'source', 'images', slug, 'diagram.png')));
});

test('refuses to overwrite an existing published article', t => {
  const slug = 'existing-post';
  const repoRoot = createFixture(slug);
  const publishedPath = join(repoRoot, 'my-blog', 'source', '_posts', `${slug}.md`);
  t.after(() => rmSync(repoRoot, { recursive: true, force: true }));

  writeFileSync(publishedPath, 'keep me');
  assert.throws(() => importManuscript(slug, { repoRoot }), /already exists/);
  assert.equal(readFileSync(publishedPath, 'utf8'), 'keep me');
  assert.ok(!existsSync(join(repoRoot, 'my-blog', 'source', 'images', slug)));
});

test('refuses to overwrite an existing published attachment directory without force', t => {
  const slug = 'attachment-collision';
  const repoRoot = createFixture(slug);
  const publishedPath = join(repoRoot, 'my-blog', 'source', '_posts', `${slug}.md`);
  const publishedImages = join(repoRoot, 'my-blog', 'source', 'images', slug);
  const publishedAttachments = join(repoRoot, 'my-blog', 'source', 'downloads', slug);
  t.after(() => rmSync(repoRoot, { recursive: true, force: true }));

  mkdirSync(publishedAttachments, { recursive: true });
  writeFileSync(join(publishedAttachments, 'keep.zip'), 'keep me');

  assert.throws(() => importManuscript(slug, { repoRoot }), /attachment directory already exists/);
  assert.ok(!existsSync(publishedPath), 'article must not be installed after an attachment collision');
  assert.ok(!existsSync(publishedImages), 'images must not be installed after an attachment collision');
  assert.equal(readFileSync(join(publishedAttachments, 'keep.zip'), 'utf8'), 'keep me');
});

test('force replaces the published article and its complete asset directories', t => {
  const slug = 'revised-post';
  const repoRoot = createFixture(slug);
  const publishedPath = join(repoRoot, 'my-blog', 'source', '_posts', `${slug}.md`);
  const publishedImages = join(repoRoot, 'my-blog', 'source', 'images', slug);
  const publishedAttachments = join(repoRoot, 'my-blog', 'source', 'downloads', slug);
  t.after(() => rmSync(repoRoot, { recursive: true, force: true }));

  mkdirSync(publishedImages, { recursive: true });
  mkdirSync(publishedAttachments, { recursive: true });
  writeFileSync(publishedPath, 'old article');
  writeFileSync(join(publishedImages, 'diagram.png'), 'old diagram');
  writeFileSync(join(publishedImages, 'stale.png'), 'remove me');
  writeFileSync(join(publishedAttachments, 'challenge-files.zip'), 'old challenge');
  writeFileSync(join(publishedAttachments, 'stale.zip'), 'remove me');

  importManuscript(slug, { repoRoot, force: true });

  assert.match(readFileSync(publishedPath, 'utf8'), /\/images\/revised-post\/diagram\.png/);
  assert.equal(readFileSync(join(publishedImages, 'diagram.png'), 'utf8'), 'diagram');
  assert.equal(readFileSync(join(publishedImages, 'nested', 'detail.png'), 'utf8'), 'detail');
  assert.ok(!existsSync(join(publishedImages, 'stale.png')), 'stale image must be removed');
  assert.equal(readFileSync(join(publishedAttachments, 'challenge-files.zip'), 'utf8'), 'challenge');
  assert.equal(
    readFileSync(join(publishedAttachments, 'nested', 'source-and-exp.zip'), 'utf8'),
    'source and exp'
  );
  assert.ok(!existsSync(join(publishedAttachments, 'stale.zip')), 'stale attachment must be removed');
  assert.ok(existsSync(join(repoRoot, 'manuscripts', slug, `${slug}.md`)), 'original must remain');
});

test('parses the force flag after the article slug', () => {
  assert.deepEqual(parseArguments(['revised-post', '--force']), {
    slug: 'revised-post',
    force: true
  });
});
