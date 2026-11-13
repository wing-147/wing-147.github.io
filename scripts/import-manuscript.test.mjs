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
      ''
    ].join('\n')
  );
  writeFileSync(join(manuscriptRoot, 'images', 'diagram.png'), 'diagram');
  writeFileSync(join(manuscriptRoot, 'images', 'nested', 'detail.png'), 'detail');

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

test('force replaces the published article and its complete image directory', t => {
  const slug = 'revised-post';
  const repoRoot = createFixture(slug);
  const publishedPath = join(repoRoot, 'my-blog', 'source', '_posts', `${slug}.md`);
  const publishedImages = join(repoRoot, 'my-blog', 'source', 'images', slug);
  t.after(() => rmSync(repoRoot, { recursive: true, force: true }));

  mkdirSync(publishedImages, { recursive: true });
  writeFileSync(publishedPath, 'old article');
  writeFileSync(join(publishedImages, 'diagram.png'), 'old diagram');
  writeFileSync(join(publishedImages, 'stale.png'), 'remove me');

  importManuscript(slug, { repoRoot, force: true });

  assert.match(readFileSync(publishedPath, 'utf8'), /\/images\/revised-post\/diagram\.png/);
  assert.equal(readFileSync(join(publishedImages, 'diagram.png'), 'utf8'), 'diagram');
  assert.equal(readFileSync(join(publishedImages, 'nested', 'detail.png'), 'utf8'), 'detail');
  assert.ok(!existsSync(join(publishedImages, 'stale.png')), 'stale image must be removed');
  assert.ok(existsSync(join(repoRoot, 'manuscripts', slug, `${slug}.md`)), 'original must remain');
});

test('parses the force flag after the article slug', () => {
  assert.deepEqual(parseArguments(['revised-post', '--force']), {
    slug: 'revised-post',
    force: true
  });
});
