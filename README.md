# wing's blog

基于 Hexo 7 和 Butterfly 5.3.5 的个人安全技术博客，计划发布到
`https://wing-147.github.io/`。

## 本地运行

```bash
git clone --recurse-submodules <repository-url>
cd blog/my-blog
nvm use
npm ci
npm run clean
npm run build
npm test
npm run server
```

浏览器访问 `http://localhost:4000/`。`npm run build` 和 `npm run server`
默认启用 Node.js 的 `--disable-proto=throw`，作为当前 `deepmerge` 低危公告的运行时缓解。

## 写新文章

仓库根目录的 `manuscripts/` 用于保存原稿和原始图片；Hexo 实际发布的文章位于
`my-blog/source/_posts/`，尚未发布的 Hexo 草稿位于 `my-blog/source/_drafts/`。

建议先创建草稿并在本地预览：

```bash
cd my-blog
npx hexo new draft "article-slug"
npm run server -- --draft
```

编辑 `source/_drafts/article-slug.md`。确认后发布、构建并检查：

```bash
npx hexo publish "article-slug"
npm run clean
npm run build
npm test
```

如果不需要草稿阶段，可以直接运行：

```bash
npx hexo new post "article-slug"
```

当前项目统一把文章图片放在 `my-blog/source/images/<article-slug>/`，Markdown 中使用
`/images/<article-slug>/image.png` 引用。

### 从原稿一键导入

每篇原稿统一使用以下结构：

```text
manuscripts/<article-slug>/
├── <article-slug>.md
└── images/
    ├── image.png
    └── ...
```

原稿 Markdown 中使用相对图片路径，例如：

```markdown
![说明](images/image.png)
```

执行导入：

```bash
cd my-blog
npm run import:manuscript -- <article-slug>
```

该命令会：

1. 将原稿复制到 `my-blog/source/_posts/<article-slug>.md`；
2. 将图片递归复制到 `my-blog/source/images/<article-slug>/`；
3. 将相对图片路径改写为 `/images/<article-slug>/image.png`；
4. 保留 `manuscripts/` 中的原稿；
5. 目标文章或图片目录已存在时停止，不覆盖已有内容。

修改原稿后，可以强制同步到已发布文章：

```bash
npm run import:manuscript -- <article-slug> --force
```

强制模式会完整替换对应的 Markdown 和图片目录，因此原稿中已经删除的旧图片也会从
`my-blog/source/images/<article-slug>/` 移除。替换过程会临时备份旧版本；如果新版本
安装失败，脚本会自动恢复旧文章和旧图片。

## 发布

推送到 `main` 后，[Pages workflow](.github/workflows/pages.yml) 会执行以下步骤：

1. 检出源码和 Butterfly 子模块；
2. 使用 `.nvmrc` 指定的 Node.js 版本安装锁定依赖；
3. 审计中危及以上的生产依赖漏洞；
4. 构建并检查生成站点；
5. 将 `my-blog/public` 部署到 GitHub Pages。

GitHub 仓库需要在 **Settings → Pages → Build and deployment → Source** 中选择
**GitHub Actions**。
