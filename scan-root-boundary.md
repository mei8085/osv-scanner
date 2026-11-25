# 扫描根边界与结果来源归属分析

> 分析对象：`osv-scanner`（分支 `task/379`，基线提交 `66586f4`）及其核心引擎依赖 `github.com/google/osv-scalibr v0.5.4-0.20261116103409-40cdfcf8b822`。
> 范围限定：源码目录扫描路径（`osv-scanner scan source`、MCP `scan_deps` 与库入口 `pkg/osvscanner.DoScan`），容器镜像扫描（`DoContainerScan`）仅在边界对比处提及。

## 0. 结论摘要

1. **源码扫描的实际范围不是由文件系统（FS）句柄限定的，而是由 osv-scanner 自己构造的 `PathsToExtract` 词法路径清单限定的。** 在 Linux 上 scalibr 的 `ScanRoots` 恒为 `/`（`pkg/osvscanner/scan.go:334` 经 `fs.RealFSScanRoots(root)`，其中 `root` 来自 `getRootDir`，`scan.go:491-501`），FS 层的 `os.Root` confinement 对 `/` 不产生任何实际收窄。范围收敛发生在两处：osv-scanner 的 `pathToRootMap` 输入去重（`scan.go:426-453`）与 scalibr 的 `walkIndividualPaths`/`shouldSkipDir` 遍历剪枝。
2. **越界读取与重复计数由不同层约束，且都不是单一防线。**
   - 越界读取（符号链接逃逸、`..` 逃逸）：底层由 scalibr 的 `rootFS`（`os.OpenRoot` + 逐组件符号链接重解析，`fs/fs.go:97-286`）在 FS 访问层拦截；但在源码扫描配置下根为 `/`，该拦截对宿主文件系统不构成边界，真正的"项目边界"只存在于遍历入口清单。
   - 重复计数：输入层由 `pathToRootMap` 的后代抑制防止同一路径被登记两次；结果层由 osv-scanner 在每个 scalibr 扫描返回后做相邻包折叠（`scan.go:367-389`）与漏洞去重（`dedupPackageVulns`，`scan.go:523-558`）。scalibr 自身的 `inventory.Inventory.Append`（`inventory/inventory.go:64-74`）只做拼接、**不做任何去重**。
3. **显式文件输入（`--lockfile`/`--sbom`）按设计绕过全部目录排除规则**（`--x-exclude`、`.gitignore`、非递归剪枝），这是可判定的既有行为而非缺陷；但显式符号链接的解析结果取决于 FS 条件，归属路径使用的是用户给定的词法路径而非解析后的真实路径。
4. 收敛方案的核心应是：**以"规范化后的输入入口集合"作为唯一范围事实来源，把符号链接解析策略与归属键（attribution key）显式化，并在 osv-scanner 层补齐跨 root、跨重复入口的统一去重**，而不是依赖 scalibr 的 FS 句柄边界。

---

## 1. 责任边界：扫描根、排除规则与结果来源各自由谁约束

### 1.1 调用链与分层总览

```
CLI / MCP
  cmd/osv-scanner/scan/source/command.go        DirectoryPaths / LockfilePaths / Recursive / NoIgnore
  cmd/osv-scanner/mcp/command.go                 DirectoryPaths + IgnoreGlobPatterns(→ g: 前缀)
        │
        ▼
pkg/osvscanner.DoScan (osvscanner.go:112)
        │
        ▼
pkg/osvscanner.scan (scan.go:207)
  ① parseExcludePatterns         exclude.go:33   词法模式解析（精确名 / g: glob / r: regex）
  ② pathToRootMap                scan.go:426     绝对化 + 后代抑制 → rootMap（输入去重）
  ③ scalibr.Scan(ScanConfig{…})  scan.go:331     每个 root 一次扫描
        │
        ▼
scalibr Scanner.Scan (scalibr.go:199)
  ④ filesystem.Run → InitWalkContext             绝对路径剥离为 root 相对路径
  ⑤ RunFS: walkIndividualPaths 或 WalkDirUnsorted 遍历
  ⑥ walkContext.handleFile / shouldSkipDir       目录剪枝、gitignore、符号链接开关
  ⑦ rootFS (os.OpenRoot)                         每次 Open/Stat/ReadDir 的 FS 层边界
        │
        ▼
pkg/osvscanner.scan 收尾
  ⑧ 包相邻折叠 + PackageVuln 去重   scan.go:367-390
  ⑨ buildVulnerabilityResults       vulnerability_result.go:26  按 SourceInfo{Path,Type} 分组
```

### 1.2 "扫描根"在两个层次上的不同含义

| 层次 | 实体 | 取值（源码扫描，Linux） | 作用 |
|---|---|---|---|
| osv-scanner 逻辑根 | `rootMap` 的 key（`scan.go:234`） | 恒为 `/`（`getRootDir`，`scan.go:491-501`） | 把多个输入路径聚合到一次 scalibr 调用；Windows 上为盘符（如 `C:\`），可能产生多个 key |
| scalibr FS 根 | `ScanRoot{FS: DirFS("/"), Path: "/"}`（`fs/fs.go:319-327`） | 同上 | 提供 `os.Root` 句柄与 root 相对路径命名空间；包的 `ScanRoot` 字段被无条件写成该值（`extractor/filesystem/filesystem.go:151-156`） |
| 实际遍历入口 | `ScanConfig.PathsToExtract`（`scan.go:335`） | 用户输入经 `filepath.Abs` 后的绝对路径 | **真正决定哪些文件被读取** |

关键推论：**FS 根 `/` 等于宿主真实根，`os.Root` 的 confinement 在源码扫描场景下退化为"禁止解析到 `/` 之外"——而宿主上不存在 `/` 之外的路径。** `rootFS` 中那套精心实现的逃逸拦截（`resolveInRoot` 处理绝对符号链接重写、`maxSymlinkDepth=40` 循环检测，`fs/fs.go:75-92, 219-286`，并有 `TestDirFS_Symlinks` 固化逃逸/循环必须报错的契约，`fs/fs_test.go:150-277`）主要保护的是容器/镜像 rootfs 与非 `/` 根的场景；源码扫描享受不到同级别的项目边界保护。

### 1.3 越界读取由哪一层约束

#### 1.3.1 FS 访问层（scalibr，条件性生效）

- `DirFS(root)` 内部懒加载 `os.OpenRoot(root)`（`fs/fs.go:107-119`），所有 `Open/ReadDir/Stat/Lstat/ReadLink` 都经该句柄（`fs/fs.go:166-188`）。Go 标准库保证经 `os.Root` 的访问不能被符号链接或 `..` 带到句柄根之外，逃逸返回 `"path escapes from parent"`（`fs/fs.go:78-92, 207-213`）。
- 对**根内绝对符号链接**（容器 rootfs 中 `/etc/os-release -> /usr/lib/os-release` 这类），scalibr 自行逐组件重解析并改写为 root 相对路径后重试（`fs/fs.go:219-286`）；对逃逸链接与符号链接循环则放行标准库错误。
- **源码扫描下 root=`/`**：项目目录内一个指向项目外部（仍在 `/` 下）的符号链接不会触发任何逃逸错误。因此 FS 层约束的真实语义是"不脱离操作系统根"，而非"不脱离用户指定的项目目录"。

#### 1.3.2 遍历入口层（osv-scanner + scalibr，实际生效的项目边界）

- 入口只来自用户显式给出的路径：`DirectoryPaths`、`LockfilePaths`、`SBOMPaths` 全部经 `pathToRootMap` 绝对化并登记（`scan.go:245-298`）。不存在"从 CWD 自动发现根"的逻辑；无输入且无 git commit 时直接没有扫描目标。
- scalibr 侧 `stripFromAtLeastOnePrefix` 要求每个 `PathsToExtract`/`DirsToSkip` 必须位于某个 ScanRoot 之下，否则报 `ErrNotRelativeToScanRoots`（`extractor/filesystem/filesystem.go:666-718`）。在 root=`/` 时该校验等价于"绝对路径必须以 `/` 开头"，几乎总是通过。
- 遍历本身不跟随目录树中遇到的符号链接：`WalkDirUnsorted` 明确 "does not follow symbolic links found in directories, but if root itself is a symbolic link, its target will be walked"（`fs/diriterate/../internal/walkdir_iterate.go:111-113`）；且 `handleFile` 对非常规文件在 `ReadSymlinks=false` 时直接返回（`extractor/filesystem/filesystem.go:494-504`）。osv-scanner 硬编码 `ReadSymlinks: false`（`scan.go:342`），**仓库内没有任何开关可以打开它**（全仓 grep 仅 `scan.go` 一处引用）。

综合：树内符号链接（无论指向树内还是树外）在默认遍历中不会被读取，这是当前防止"项目树内一个链接把扫描带出项目"的实际机制；但它是**遍历策略**而非访问控制——一旦符号链接本身成为显式入口（见 §2.3），同一文件就会被读取。

### 1.4 排除规则由哪一层约束

| 规则 | 解析层 | 执行层与执行点 | 作用对象 |
|---|---|---|---|
| `--x-exclude` 精确目录名 | osv-scanner `parseExcludePatterns` → `dirsToSkip`（`exclude.go:33-89`） | scalibr `shouldSkipDir` 的 map 查找（`filesystem.go:572-575`） | 仅目录；匹配的是 **root 相对的完整词法路径**（经 `stripAllPathPrefixes` 剥离，`filesystem.go:274-278`） |
| `g:` glob / `r:` regex | 同上，合并为 `{p1,p2}` / `(p1|p2)` 单模式 | `shouldSkipDir` 中 `glob.Match(path)` / `regexp.MatchString(path)`（`filesystem.go:583-588`） | 仅目录，路径基准同上；MCP 的 `ignore_glob_patterns` 自动加 `g:` 前缀（`mcp/command.go:120-123`），其 JSON schema 已注明匹配基准是"相对文件系统根、无前导斜杠"的路径 |
| `.gitignore` | scalibr 遍历目录时实时解析（`internal/gitignore.go`，`ParseDirForGitignore`/`ParseParentGitignores`） | 目录级 `shouldSkipDir` 与文件级 `handleFile` 两处（`filesystem.go:459-469, 506-510, 580-582`） | 目录与文件；`--no-ignore` 经 `UseGitignore: !actions.NoIgnore` 关闭（`scan.go:340`） |
| 非递归 `IgnoreSubDirs` | CLI `--recursive` 取反（`source/command.go:129`） | `shouldSkipDir`：非 `pathsToExtract` 成员的目录一律剪枝（`filesystem.go:576-579`） | 子目录 |

两个重要边界事实：

1. **排除规则只在 `handleFile` 的目录分支里生效，且 `walkIndividualPaths` 对显式文件直接调用 `handleFile(p, entry, nil)`（`filesystem.go:394-425, 418`），不经过任何 `shouldSkipDir` 判定。** 因此 `--lockfile`/`--sbom` 显式指定的文件，即使位于被 exclude 命中的目录内也照常提取。gitignore 的豁免更隐蔽一层：显式文件入口走的是 `walkIndividualPaths` 的文件分支，该分支不加载任何 `.gitignore`（只有显式**目录**入口才调 `ParseParentGitignores`，`filesystem.go:403-409`），到达 `handleFile` 的文件级 gitignore 检查时 `wc.gitignores` 为 nil，匹配必然为空（`filesystem.go:506-510`）。文档只声明了"`--x-exclude` 目前只排除目录、不排除单个文件"（`docs/scan-source.md:47`），并未写明显式输入对 exclude 与 gitignore 的整体豁免，后者属于实现层面的隐含契约。
2. `ErrorOnFSErrors: false`（`scan.go:346`）：权限错误等 FS 错误只记日志、不中断（`filesystem.go:441-452`），即"读不到的子树静默缺失"，范围失败不会上抛为扫描失败；但显式入口提取失败会经 `statsCollector.filesExtracted` 对账后上抛 `ErrExtractorNotFound`（`scan.go:401-405`），插件状态中的显式路径错误还会转成 critical error（`logPluginStatus`，`scan.go:560-594`）。**显式输入与遍历发现的输入，错误等级不同。**

### 1.5 结果来源（归属）由哪一层约束

漏洞报告中的来源是 `models.SourceInfo{Path, Type}`（`pkg/models/results.go:180-183`），在 `buildVulnerabilityResults` 中按该键分组（`vulnerability_result.go:116-135`）：

- `Path = filepath.ToSlash(imodels.Location(p))`，而 `Location = filepath.Join(pkg.ScanRoot, pkg.Location.PathOrEmpty())`（`imodels.go:44-52`）。源码扫描下 `ScanRoot="/"`，所以报告路径就是**以 `/` 为前缀的用户输入词法绝对路径**（容器等虚拟 FS 下 ScanRoot 为空时回退 `/`）。
- `Type` 由产出该包的插件名映射：`os/*` → OS 包、sbom 预设 → SBOM、git 插件 → git、lockfile 预设 → 项目包（`imodels.go:54-70`）。
- 归属路径在整条流水线中保持词法形式：`StoreAbsolutePath: false`（`scan.go:344`），scalibr 存 root 相对路径，osv-scanner 在报告拼接时才加回根；任何一层都不调用 `filepath.EvalSymlinks`。
- 配置忽略（`osv-scanner.toml`）的匹配同样以该词法 `Location` 为键（filter annotator `filter.go:144-159` 与 `configManager.Get(imodels.Location(psr))`），所以**归属路径一旦不稳定，忽略规则与漏洞归属会同时失真**。

### 1.6 重复计数由哪一层约束

| 机制 | 位置 | 保证什么 | 不保证什么 |
|---|---|---|---|
| 输入后代抑制 | `pathToRootMap` + `isDescendent`（`scan.go:426-486`） | 递归模式下，已登记目录的后代路径不再加入 `PathsToExtract`；同路径重复登记被 `rel == "."` 拦截 | 非递归模式下目录入口**不做**后代抑制（`scan.go:439-442` 提前 append 返回），两个重叠目录会产生两次遍历；注释要求"目录先于文件添加"，调用方当前按 Directory→Lockfile→SBOM 顺序满足（`scan.go:245-298`），逆序输入则抑制失效 |
| FS 遍历 | scalibr 每次 `Scan` 独立 walk | 单次 walk 内每个 inode 路径只访问一次 | 跨多次 `Scan`（多个 rootMap key，Windows 盘符场景）无共享状态 |
| 清单拼接 | `inventory.Inventory.Append`（`inventory/inventory.go:64-74`） | — | 纯 append，**无去重**；scalibr 全库不做包级身份合并 |
| 包折叠 | osv-scanner 对单次 `Scan` 返回先 `inventorySort` 排序再折叠相邻全等项（`scan.go:367-383`） | 同一次 scalibr 调用内、排序键（location/name/version/sourceCode/purl，`invsort.go:13-42`）完全相同的包合并为一个指针 | 仅相邻折叠，非全局 map 去重；**跨 root 的多次 `Scan` 结果在 `inv.Packages = append(...)`（`scan.go:392-394`）处不再去重**；location 不同（硬链接、同一文件的两个路径别名、树内+树外两份副本）即视为不同包 |
| 漏洞去重 | `dedupPackageVulns` 以 `{*Package 指针, vulnID}` 为键（`scan.go:518-558`），合并 `Plugins` | 同一包指针上的重复匹配项收敛 | 包折叠后通过 `pkgMap` 回写指针（`scan.go:385-389`）才能生效；若两个包未被折叠，同一漏洞 ID 仍会在两个来源下各出现一次 |
| 报告分组 | `groupedBySource map[SourceInfo]…`（`vulnerability_result.go:41, 128-135`） | 同 `{Path,Type}` 的包归入同一 PackageSource | 路径字符串差异（`./a` 与 `a`、符号链接路径与目标路径、尾部分隔符）会形成不同分组；前置的 `filepath.Abs`（`scan.go:427`）只消除 CWD 相对形式，不做符号链接规范化 |

即：**重复计数的防线在 osv-scanner 而非 scalibr，且是"输入抑制 + 单轮相邻折叠"两道局部防线，不存在基于包身份（purl/name/version+内容哈希）的全局归一。**

---

## 2. 已保证行为 vs 底层/文件系统条件行为

### 2.1 源码层面已保证（有代码与测试契约）

1. **树内符号链接默认不跟随。** `ReadSymlinks:false` 硬编码（`scan.go:342`）+ walk 不跟随目录链接（`walkdir_iterate.go:111-113`）+ 非常规文件跳过（`filesystem.go:494-504`）。
2. **FS 句柄根之外不可达。** `os.Root` 逃逸报错、绝对链接 root 内重写、40 跳循环上限，由 scalibr `TestDirFS_Symlinks` 等测试固化（`fs/fs_test.go:150-277`）。
3. **显式入口必须被处理，否则整体失败。** `filesExtracted` 对账 → `ErrExtractorNotFound`（`scan.go:401-405`）；显式路径上的插件错误升级为 critical（`scan.go:575-590`）。
4. **同一 scalibr 调用内的全等包与重复漏洞收敛**（`scan.go:367-390`），输出确定性排序（scalibr `sortResults`，`scalibr.go:554-560`；报告侧 `vulnerability_result.go:148-153`）。
5. **输入同路径重复在递归模式下不产生重复遍历**（`isDescendent` 的 `.` 判定，`scan.go:465-468`，并有 `Test_isDescendent` 覆盖，`scan_test.go:127-219`）。
6. **排除模式的语法解析与非法模式报错**在 osv-scanner 层有单测（`exclude_test.go`）；模式执行语义由 scalibr `filesystem_test.go` 的 `dirsToSkip/skipDirGlob/skipDirRegex/ignoreSubDirs` 用例覆盖。
7. **归属路径可重现**：全部基于词法路径，不做真实路径解析，同一输入在同一机器上反复扫描得到相同 `SourceInfo`。

### 2.2 取决于底层扫描器或文件系统条件、源码未保证的部分

1. **项目边界外的可读性。** root=`/` 时，指向项目外的**显式**符号链接入口能否读取，完全取决于宿主权限与目标是否存在；`os.Stat`（注意是 `pathToRootMap` 用的 `os.Stat` 而非 `Lstat`，`scan.go:432`）会跟随链接，断链直接报 `failed to resolve path`。扫描器不区分"项目内文件"与"经链接到达的项目外文件"。
2. **硬链接与 bind mount。** 两者在词法路径上是两个独立位置，遍历与归属都按两个来源处理；是否真有同一 inode 的两个路径，只有文件系统知道，扫描器不查询 inode，因此可能对同一物理文件计数两次（当前去重键含 location，必然不去重）。
3. **遍历期间的并发变更。** `walkDirUnsorted` 基于 `getdents` 流式读取，文档自述存在 TOCTOU：文件可能在 walk 中被删除/替换（`walkdir_iterate.go:39-42`）。权限/IO 错误默认吞掉（`ErrorOnFSErrors:false`），报告可能静默缺项。
4. **Windows 多 root。** `getRootDir` 按盘符返回（`scan.go:492-494`），跨盘符输入形成多个 rootMap key → 多次 `Scan` → 命中 §1.6 的跨 root 不去重区间；scalibr 还禁止"`PathsToExtract` 非空且多 ScanRoot"的组合（`scalibr.go:235-237`，`errFilesWithSeveralRoots`），osv-scanner 以"每盘符一次独立 Scan、各自 PathsToExtract"的方式绕开，跨盘重叠路径无收敛。
5. **Go 运行时能力。** `os.OpenRoot`/`os.Root` 的语义依赖 Go 1.24+ 的标准库实现与平台支持；旧工具链或非支持平台上 confinement 行为不同。仓库 `go.mod` 要求新工具链（AGENTS.md 也提示用 `GOTOOLCHAIN` 对齐），这一前提属于环境条件而非业务代码保证。
6. **`..` 与词法包含判断的文本性质。** `isDescendent` 与 `stripFromAtLeastOnePrefix` 都是 `filepath.Rel`/前缀字符串判断，不解析符号链接；若输入路径本身含 `..`，`filepath.Abs` 只做词法清理（Clean），不验证清理后的路径与链接解析后的路径是否同一实体。
7. **gitignore 的解析结果依赖目录中实际存在的 `.gitignore` 文件内容与遍历上下文。** 父目录 gitignore 仅在入口是目录时由 `walkIndividualPaths` 调 `ParseParentGitignores` 补采（`filesystem.go:403-409`）；显式文件入口既不补采也不应用任何 gitignore（匹配器状态为 nil）。

### 2.3 显式文件输入的现状判定

| 情形 | 当前行为 | 可判定性 |
|---|---|---|
| `--lockfile /proj/a/package-lock.json`，普通文件 | 经 `os.Stat` 绝对化 → 进 `PathsToExtract` + `overrideMap`；绕过 exclude/gitignore/非递归；必达，失败即错 | 归属固定为该词法路径，可判定 |
| 显式文件是指向项目内目标的符号链接 | `os.Stat` 跟随成功；walk 以链接的词法路径 `Stat`（经 `os.Root`，root=`/` 可解析）→ 读取目标内容；**Location 记链接路径** | 内容来自目标、归属记链接路径，规则上可判定但需要文档化 |
| 显式文件是指向项目外目标的符号链接 | 同上且成功（目标在 `/` 内即无 FS 拦截）；项目边界被显式输入合法突破 | 归属仍在项目路径名下，消费者无法从报告区分内容是否来自边界外 |
| 显式文件是断链 | `pathToRootMap` 的 `os.Stat` 直接错误，扫描中止 | 显式失败，可判定 |
| 显式文件位于被 `--x-exclude` 命中的目录 | 照常提取（豁免，§1.4） | 与目录遍历语义不一致，易被误判为 bug，需明确契约 |
| 同一文件同时被目录遍历与 `--lockfile` 覆盖 | 递归模式输入层抑制（不新增入口），但 `overrideMap` 仍登记；提取由 walk 触发、override 生效；`specificPaths` 对账仍通过 | 可判定 |
| 非递归模式两个重叠目录 | 两次独立 walk，包折叠兜底全等项；location 相同则收敛，location 不同则双计 | 部分可判定，存在双计窗口 |

---

## 3. 收敛方案：让漏洞报告中的依赖归属可判定

目标不变量：**对任意一次扫描，能机械判定报告中每个依赖"从哪个授权入口到达、落在哪个根相对位置、是否与另一条目是同一物理/逻辑实体"。** 以下方案保持对显式文件输入的兼容，按改动所在层组织，优先级从高到低。

### 3.1 设计原则

1. **入口清单是唯一范围事实（single source of scope）。** 不再依赖 FS 根隐含表达项目边界——源码扫描根为 `/` 是既定事实，应承认 `PathsToExtract` 才是边界，并让所有规则（排除、gitignore、对账、归属）都引用同一份规范化入口集合。
2. **词法归属与物理身份分离。** 报告路径继续沿用用户给定的词法路径（保证忽略规则、快照、差分稳定），另引入内部物理身份用于去重，不把 `EvalSymlinks` 的结果直接写进 `SourceInfo.Path`。
3. **显式输入优先且豁免遍历类规则，但豁免要显式化、可观测。** 把当前的隐含契约变成代码中的命名策略与日志，而不是改变它（改变会破坏现有用户行为与测试快照）。

### 3.2 具体改动建议

#### A. 输入规范化与入口登记（osv-scanner 层，`pkg/osvscanner/scan.go`）

1. 引入 `scanEntry` 结构统一三类输入：
   ```go
   type scanEntry struct {
       absPath     string // filepath.Abs 后的词法绝对路径（现有行为）
       kind        entryKind // dirRecursive / dirShallow / explicitFile
       extractor   filesystem.Extractor // 仅 explicitFile，来自现有 overrideMap
       origin      string // "directory" | "lockfile" | "sbom"
   }
   ```
   用一个 slice 替代当前 `rootMap[root][]string` + `overrideMap` + `specificPaths` 三个并行结构，消除"目录必须先于文件"的顺序依赖（当前仅靠调用顺序与注释维持，`scan.go:425`）。
2. 规范化时对**每个入口**做一次 `os.Lstat` + 可选 `filepath.EvalSymlinks`，仅用于记录 `resolvedPath`/`isSymlink` 元数据与判定，不替换 `absPath`。现状只 `os.Stat`（`scan.go:432`），无法区分链接与普通文件。
3. 修复非递归目录的抑制缺口：`fi.IsDir() && !recursive` 分支（`scan.go:439-442`）同样经过重叠判定——浅层目录互相重叠时按最长路径/先到先得合并，并在日志中声明被合并的入口。
4. 对跨 root（Windows 盘符）入口做统一登记并保留入口顺序，为 D 步的全局去重提供输入。

#### B. 符号链接策略显式化（osv-scanner 策略层 + scalibr 能力层）

1. 在 `ScannerActions` 增加内聚的链接策略字段（而非裸露 scalibr 的 `ReadSymlinks`），建议三态：
   - `legacy`（默认，等同当前：树内不跟随、显式入口经 `os.Stat` 跟随）；
   - `disallow-external`（推荐的新严格模式：显式链接解析后的真实路径若不在任一**目录入口的规范化根**之下，拒绝该入口并返回明确错误，而不是静默读取边界外内容）；
   - `follow`（映射到 scalibr `ReadSymlinks:true`，供确实需要跟随树内链接的场景）。
2. 判定"外部"的基准应为 A 步登记的目录入口解析路径集合，而不是 scalibr 的 FS 根 `/`。这样在不修改 scalibr FS 语义的前提下补上项目级边界。
3. 无论哪种策略，对**实际跟随过的链接**在 stats/日志中产出一条 `link followed: lexical -> resolved` 记录（复用 `fileOpenedPrinter`，`stats.go`），让越界读取在运行时可审计；MCP 场景可把该记录回传给工具调用方。

#### C. 排除规则与显式输入的契约化

1. 保持"显式文件豁免 exclude/gitignore"的现行行为，但：
   - 在 `docs/scan-source.md` 明确写出该豁免（当前文档只说 exclude 不作用于文件，未覆盖显式入口整体豁免与 gitignore 豁免）；
   - 当显式入口命中某条排除模式或 gitignore 时，输出一条 info 级日志（"explicit input overrides exclude pattern …"），把静默豁免变成可观测事件。
2. MCP 的 `ignore_glob_patterns` schema 已说明匹配基准是相对 FS 根的路径；在 A 步统一入口后，建议让 glob/regex 的匹配基准在文档与帮助文本中统一表述为"root 相对词法路径"，并补一个跨平台（盘符、分隔符）用例，避免 Windows 下基准漂移。

#### D. 统一去重与归属键（osv-scanner 结果层）

1. 把当前"每轮 Scan 内相邻折叠"（`scan.go:367-383`）升级为**跨所有 root 的全局归并**：在全部 `Scan` 完成后，对聚合 `inv.Packages` 按现有 `inventorySort` 键排序并做一次全等折叠，复用已有的 `pkgMap` 指针回写机制，让跨 root 的 `PackageVuln` 也能经 `dedupPackageVulns` 收敛。改动局限于 `scan()` 收尾段，不触碰 scalibr。
2. 引入内部物理身份键辅助判定（不改变输出 schema）：
   ```
   identityKey = purl （或 ecosystem/name/version）
   physicalKey = resolvedPath(descriptor) + 文件大小 + modtime（可选 inode，平台不可用时降级）
   ```
   - `identityKey` 相同且 `physicalKey` 相同（硬链接/重复入口）→ 合并为一个包，Locations 列表保留全部词法路径（scalibr 的 `PackageLocation.Related` 已是多位置结构，`extractor.go:83-89`），报告 `SourceInfo` 取确定性的最小词法路径，其余路径进可扩展字段或日志。
   - `identityKey` 相同但 `physicalKey` 不同（两份独立副本，如 monorepo 多份 vendored 拷贝）→ **保持双计**，这是真实的两个来源，但在报告中可标记同身份分组，避免消费者误报为工具重复。
   - 现状二者无法区分，这是"重复计数"争议的根因。
3. `buildVulnerabilityResults` 的分组键继续使用词法 `SourceInfo`（保证 `osv-scanner.toml` 忽略规则与快照稳定），但分组前断言每个包的词法路径唯一；归并产生的多位置包只进入一个分组，从结构上杜绝同一漏洞 ID 在两个 PackageSource 下重复出现。

#### E. 测试与验证（对应 AGENTS.md §4.2 的测试要求）

1. 在 `pkg/osvscanner` 新增表驱动测试覆盖当前缺口：树内链接/树外链接/断链显式入口、非递归重叠目录、同路径重复、硬链接双路径、exclude 命中目录内的显式文件、Windows 风格多 root（用 `filepath.FromSlash` 构造，参考 `scan_test.go:212-216` 的既有写法）。
2. 为 B 的严格模式增加"外部链接被拒绝"的用例，以及 legacy 模式行为不变的快照用例（`make test SNAPS=true` 重建快照）。
3. 为 D 的全局归并增加跨两轮 `Scan` 的合成 inventory 用例，验证漏洞计数不随入口顺序/重复度变化。
4. 全部验证通过 `./scripts/run_lints.sh` 与 `make test`；本环境工具链下载受限，落地实现时需按 AGENTS.md 用 `GOTOOLCHAIN` 对齐 `go.mod` 版本后执行。

### 3.3 方案与现状的兼容性矩阵

| 维度 | 现状 | 方案后 | 兼容性 |
|---|---|---|---|
| 普通目录/文件扫描 | 词法路径归属 | 不变，增加内部元数据 | 输出快照不变 |
| 显式 `--lockfile/--sbom` | 豁免排除规则、必达 | 语义保留，增加日志与策略字段；默认策略即现状 | 完全兼容 |
| 树内符号链接 | 不跟随 | 默认不跟随；新增严格/跟随可选策略 | 默认兼容 |
| 显式外部链接 | 静默可读、归属记词法路径 | 默认同现状；严格模式显式拒绝并给错误 |  opt-in 增强 |
| 同路径重复输入 | 递归模式已抑制 | 全模式抑制 + 跨 root 全局归并 | 仅减少重复，不新增结果 |
| 硬链接/同物理文件多路径 | 双计 | 合并为多位置单包 | 报告条目数可能变化，需快照更新与发行说明 |
| 两份独立副本 | 双计 | 保持双计 + 同身份标记 | 计数不变，增加可判定标注 |
| 容器扫描 `DoContainerScan` | 虚拟 FS、ScanRoot 为空 | 不改动（其边界由镜像 FS 与 layer trace 另行保证） | 不受影响 |

### 3.4 不建议的方向

- **不要把源码扫描的 scalibr `ScanRoots` 收窄为项目目录来"获得边界"。** 当前多入口（多目录、目录+散文件混合）依赖 root=`/` 共享一次 walk 与统一 root 相对命名；收窄根会触发 scalibr 的多 root 限制（`errFilesWithSeveralRoots`），改变 Location 命名空间并使全部既有快照、忽略规则路径基准失效。边界应在入口策略层（B）实现。
- **不要在归属路径中直接写入 `EvalSymlinks` 结果。** 这会让报告路径随机器布局变化、破坏配置匹配与可重现性；真实路径只应作为内部物理键与审计信息。
- **不要在 scalibr 的 `Inventory.Append` 中加入隐式去重。** 该库被容器/二进制等多场景复用，osv-scanner 需要的归并语义（含报告分组、toml 匹配）是产品策略，按 AGENTS.md §5 的分工，CLI 侧输出/配置策略归属本仓库，归并应留在 `pkg/osvscanner`。

---

## 4. 关键代码索引

| 主题 | 位置 |
|---|---|
| 扫描配置组装（ReadSymlinks=false、StoreAbsolutePath=false、exclude 透传） | `pkg/osvscanner/scan.go:330-356` |
| 输入绝对化、root 选择、后代抑制 | `pkg/osvscanner/scan.go:426-501` |
| 单轮包折叠与漏洞去重 | `pkg/osvscanner/scan.go:367-390, 518-558` |
| 显式入口提取对账 | `pkg/osvscanner/scan.go:399-405, 560-594`；`pkg/osvscanner/stats.go` |
| 排除模式解析 | `pkg/osvscanner/exclude.go:33-118` |
| 报告来源分组 | `pkg/osvscanner/vulnerability_result.go:43-153`；`internal/imodels/imodels.go:44-70` |
| 预匹配过滤（toml 忽略） | `internal/scalibrannotator/filter/filter.go:70-209` |
| FS 根 confinement 与符号链接重解析 | scalibr `fs/fs.go:75-286` |
| 遍历剪枝（exclude/gitignore/非递归/链接开关） | scalibr `extractor/filesystem/filesystem.go:394-590` |
| walk 不跟随树内链接的契约 | scalibr `extractor/filesystem/internal/walkdir_iterate.go:104-124` |
| root 相对路径剥离与前缀校验 | scalibr `extractor/filesystem/filesystem.go:267-305, 666-718` |
| 清单拼接不去重 | scalibr `inventory/inventory.go:64-74` |
| 多 root + PathsToExtract 限制 | scalibr `scalibr.go:233-237` |
| MCP glob 入参 | `cmd/osv-scanner/mcp/command.go:56, 119-135` |
