# Changelog

## 1.0.3 — 2026-08-30

### 新增：响应体旁观

接口返回的 JSON 里往往直接躺着手机号 / 身份证 / 邮箱 / token，但响应体此前从未进过扫描管线 ——
静态扫描只看 HTML 与 JS 源码。现在在 MAIN world 包装 `Response.text/json` 与 XHR
`responseText/response` 的**读取时刻**旁观数据（页面不读就不记，数据本来就下载完了，
不发起任何请求），命中项标注 `[response-body]` 来源。
限制：单页 30 条 / 单条 128KB 截断 / 轮询同接口同内容去重 / 二进制类型跳过

### 降噪：secret 提取

`filterSecretNoise`（纯函数）移到 `extractInfo` 唯一出口，源码 / 响应体 / 存储值一个语义，
丢弃两类高频误报：

- **裸业务字段键**：`"username":"renqiang"` 这类，响应体与源码里都无情报价值
- **JS 代码值**：`username = document`、`PrivateKey=function`、`passwordErrEl = document` ——
  值是 JS 关键字或全局对象，明显是 DOM/逻辑赋值而非凭据

保留：真凭据形态（LTAI / jdbc:// / `password:"admin@123"`）、PEM 私钥头、
能被规则完整捕获的前缀键（`SMTP_USER` 等）。

### 修复

- **手机号规则升级**（`RE_MOBILE`）：旧版 `['"]11位['"]` 写法，只有引号包住的
  字符串字面量能命中，页面正文纯文本（联系方式页的 `<td>13800138000</td>`、`tel:` 链接）全部漏检；
  号段表也停留在 2020 年，漏 170/171（虚拟运营商）与 190-193（含广电 192）。现改为：
  引号可选、号段对齐当前分配、容忍 3-4-4 分隔与 `+86` 前缀，前后数字边界挡住 12 位订单号 /
  13 位毫秒时间戳的子串误报


### 界面

- **视觉全面现代化**（popup / 设置页 / 悬浮面板）：主色从黑白灰换成大众熟悉的蓝色系，
  分段式圆角页签、8-10px 圆角输入框与按钮、聚焦光环（focus ring）、iOS 式开关（替代
  「开启/关闭」文字按钮，带 role/aria 语义）、结果值改等宽字体、细圆角滚动条、
  hover/过渡微交互；「清理本地缓存」改为醒目的危险操作按钮
- **popup 空状态说清楚「为什么是空的」**：此前一片空白只有角落一行小字。现在会区分三种情况并给出指引 ——
  目标站命中站点级白名单（直接读共享匹配器 `IHHostMatch` 给出结论，附「打开配置页」按钮）、
  chrome:// 等不支持的页面类型、以及普通的还在扫描中
- **零命中的分类整组不再渲染**：20 个分类里通常大半是 0，此前全铺开满屏 🈚️；总量仍看顶部 chip
- **暗色模式**：三处界面全部跟随系统 `prefers-color-scheme`，配色收敛为 CSS 变量，
  暗色覆盖置于样式表末尾保证层叠正确
- **「展开全部 / 折叠全部」按钮文案随状态切换**（此前永远显示「展开全部」）
- **左右两列按命中量动态均衡**：原先固定「主信息=左、网络资源=右」，大站（上千命中几乎全在
  url/static 组）会出现一侧几千像素、另一侧大片留白的断层；现按命中量贪心分配，
  每列都有内容，并保持分类先后顺序
- 搜索框改用 `type=search`（原生清除按钮）；筛选把结果全部滤没时 summary 给出明确提示
- popup 新增 `?url=` 调试参数，可直接查看任意页面的落盘结果，不必切到那个标签页
- 设置页「运行时钩子」提示补充响应体旁观能力说明

### 修复（界面相关）

- **设置页横向溢出裁切开关**：重写样式时丢了 `*{box-sizing:border-box}`，body 退回 content-box
  （708px 内容 + 28px padding = 736px 实际占宽），右缘的开关被挤出视口；提示文案里的长代码
  token（`XMLHttpRequest.prototype.open/send`）不可断行会进一步撑宽。两处已修复，
  无头 Chrome 实测 `scrollWidth === clientWidth`
- **徽标数与 popup 命中数不同步**：`refreshBadge` 此前只被部分数据路径调用，SPA 增量补扫场景下
  徽标（如 865）明显落后于 popup 实时命中（如 1490）。现在 `markDirty` 统一刷新，
  每个数据批次同步一次
- **popup 动态刷新体验**：① 存储落盘与 SW 实时态交错到达时旧快照可能覆盖新快照，现按
  `updatedAt` 防乱序丢弃；② 全量重渲染会重置滚动位置，SPA 补扫高频触发时页面跳来跳去，
  现在刷新前后保持滚动位置
- **hash 路由 SPA 的数据分桶**：条目键统一去掉 `#hash`（content.js `pageKey()` / engine 'get' /
  popup 三处同一语义）。此前 hash 路由每次导航 `location.href` 都在变，运行时与框架消息按
  hash URL 各建条目 —— 徽标统计最新 hash 条目（1375）、popup 按 tab.url 查到另一个条目（411），
  两边永远对不上；数据也被打散。现在同一文档的所有数据合并进一个条目
- **SPA 批量抓取的落盘缺口**：`persist()` 此前不触发落盘，SPA 一次批量（≤20 个 JS）抓取期间
  增量全部驻留内存，只在整批结束时写一次 —— SW 中途回收会丢掉整批。现在每批合并都排一次
  落盘（flushTimer 去重，400ms 合并为一次写入）
- **「处理中 0/0」误导**：运行时 / SPA 消息单独创建的条目没有任务列表，popup 状态栏永远显示
  「处理中 0/0」。现在无任务列表时显示「运行时观测中」

### 降噪：基于真实站点导出的全分类调优

以一次真实扫描导出（828 条命中）为样本逐类校准，整体降噪 **69%**（828 → 253），
真凭据 / 真接口 / 真内网 IP 零丢失：

- **secret 156 → 16**：核心判据升级为「值有没有加引号」—— 带引号是字符串字面量，只滤可确证的
  伪凭据（截断 JWT 前缀、SCREAMING 键 + 错误码、值与键同词的常量自定义、算法名、环境名、
  值的词集 ⊆ 键的词集的 SDK 事件常量）；未加引号是代码上下文，混淆变量引用占九成
  （password:t、cancelToken=void、password = RSA、token_res = await、city_config），
  只保留像真凭据的（含数字、≥5 位截断前导）
- **sfz 61 → 0**：新增三重校验 —— 省份区域码（GB/T 2260）+ 出生日期合理 + 18 位证
  ISO 7064 MOD 11-2 校验码；15 位老证无校验位且早已停发，整体不再收录
  （此前 61 条「身份证」全是随机浮点数去掉 0. 前缀的碎片，0 条为真）
- **incomplete_path 40 → 27**：过滤全大写无小写字母（N/A、OS/2、DTLS/SCTP、YYYY/MM/DD）
  与单字符段（o/i14u9pJrxRKAsu）
- **path 424 → 138**：过滤打包器模块导入（./af、../utils —— moment 语言包一个库就带出 130 条）、
  webpack runtime 内部模块、/1 这类单字符碎片
- **ip 4 → 1**：八位组越界（4.0.0.999 是版本号）与 0.0.0.0 / 127.0.0.1 不再收录
- **domain / url 143 → 71**：过滤 XML 命名空间与协议标识（opengis.net、w3.org、webrtc.org、
  earth.google.com/kml）与声网 SDK 云（sd-rtn.com，一个 SDK 带出 30+ 条）
- **真实请求记录**：图片 / 字体 / 地形瓦片等静态资源请求不再记录（terrain 瓦片一次就 20 条），
  只留 API 调用
- **资源黑名单补漏**：SPA 增量补扫路径此前不过滤资源黑名单（运行时注入的 hm.baidu.com 经
  url/static 分类入库），现统一过滤；alicdn.com / at.alicdn.com（iconfont 公共 CDN）加入内置黑名单

## 1.0.2 — 2026-08-29

### 新增：运行时观测面

静态扫描只能看到「HTML 里写了什么」，1.0.2 补上「浏览器实际做了什么」。
全部**被动记录**，不发起任何请求，不占用请求边界里的风险额度。

- **网络请求记录**（`enable_request_log`，默认开）：`chrome.webRequest.onCompleted` 记录页面实际发出的
  XHR / fetch 地址、请求方法与查询参数名。白名单站点一个请求都不记，4xx/5xx 不记（噪声太大）
- **运行时钩子**（`enable_runtime`，默认开，MAIN world）：包装 `fetch` 与 `XMLHttpRequest.prototype.open/send`
  记录真实调用；记录 WebSocket / SSE / Worker 端点；读取本地存储（Web Storage、cookie）的键名与值，
  值会再过一遍规则库，命中的凭据进「敏感信息」并标注来源 `[storage-value]`
- **SPA 增量补扫**（`enable_spa_rescan`，默认开）：监听 DOM 插入，路由切换后懒加载进来的 script
  会补抓（每批 20 个、3 分钟后停止），不再只扫首屏那一瞬
- 新增 4 个结果分类：**真实请求** / **端点** / **存储键名** / **参数名**，在 popup 里单列「运行时观测」一组

### 修复

- **协议白名单误杀 `ws` / `wss`**：`hasBadScheme` 此前只放行 http/https，WebSocket 端点连同运行时钩子
  记到的 `wss://` 一起被丢掉。现加入 ws / wss 白名单
- **相对地址没补齐 base**：axios 之类常配 `baseURL + "/api/x"`，记录时直接用 `new URL(url)` 会失败，
  留下的是一串没用的相对路径。现统一按页面 URL 解析

### 重构

- 名单匹配器从 `content.js` 抽到 **`src/utils/hostmatch.js`**：background 侧的 webRequest 记录也需要判断
  站点白名单，与其复制一份实现（必然 diverge），不如抽成共享模块 —— content 侧走 `content_scripts`，
  background 侧走 `importScripts`，两边加载同一份代码

## 1.0.1 — 2026-08-29

### 修复：域名白名单不生效

- **匹配器重写**：原实现是 `host.endsWith(rule)` 裸串后缀匹配，两头都不对
  - 漏拦：`.example.com` 匹配不到 `example.com` 本身；完整网址、`*.example.com`、大小写不一致全部失效
  - 误拦：`example.com` 会把 `notexample.com` 一起拦掉
  - 现改为「归一化成 `host[:port]` → 精确匹配 or 子域匹配（要求 `.` 分隔）」，并兼容 IPv6 与显式端口
- **覆盖面补齐**：白名单原先只拦 `find`，MAIN world 回传的 Vue/Next/Nuxt 路由表与全局配置仍然照抓 → 现在 `boot()` 前置拦截，并覆盖 framework 消息与悬浮面板
- **即时生效**：`settingsPromise` 原先永久缓存，改完白名单必须刷新页面 → 监听 `chrome.storage.onChanged` 失效缓存，并把已注入的悬浮面板摘掉
- **iframe base 修正**：iframe 文档原来用顶层 `location.href` 作为相对地址基准，现改用 iframe 自身 URL，并按被扫描文档的 host 判白名单
- **设置页**：白名单保存原先复用 Webhook 区的提示（在页面底部，容易误以为没保存）→ 独立提示 + 保存条数；保存时归一化回写，展示实际生效的规则

### 新增

- **内置默认名单大幅扩充**，并拆成作用点不同的两层：
  - `DEFAULT_WHITELIST`（站点级，136 条）：搜索引擎、社交、电商、代码托管、协作 SaaS、邮箱、流媒体、大厂官网、安全社区；命中的页面完全不扫描
  - `DEFAULT_RESOURCE_BLOCK`（资源级，100 条）：统计埋点、广告、验证码风控、客服、地图、错误监控、A/B 配置、公共 CDN 等第三方 SDK；页面照扫但这些脚本跳过不抓
- **内置名单与用户配置改为叠加**：旧行为是「用户一填，内置整体失效」，填了自己的一条就把 google 放出来了
- 新增「使用内置默认名单」开关，可整体关闭内置的两层名单
- 资源级黑名单在设置页可编辑；当前页面所在域名永远不会被这条名单拦下，避免误伤目标自有 CDN

### 修复：设置页样式

- **popup 里横向溢出**：settings.html 的 body 为死宽 `width:820px`，而从 popup 的「配置」tab 进来时
  Chrome 弹窗上限 800px → 溢出 20px。加 `max-width:100%` 后 tab 里仍 820px、弹窗里自动收敛
- 说明块原先误用 `.row`，带出多余的 `border-bottom` 分隔线 → 新增 `.note` 类
- `.row` 的 `align-items:center` 让长文案行的开关飘在段落正中 → 新增 `.row.align-top`
- `<code>` 在扩展页无样式（裸等宽无背景），示例值辨识度差 → 补 chip 底 + 边框
- `.grid .k` 仅 90px 装不下「自定义 headers」会折行 → 改 112px

## 1.0.0 — 2026-08-29

品牌发布：正式命名为 **InfoHunter**，全新图标与文案。

### 修复

- `Promise.race` + 全局 `abort()`：开启超时后只剩最先返回的 1 个请求，结果几乎为空 → 改为逐请求 `AbortController`（2s / 8s）
- 无并发上限：数百个 JS 一次性并发导致浏览器排队卡死 → 定长并发队列（设置页可调 1–16）
- MV3 service worker 30s 空闲回收后结果全丢 → 增量落盘 + 启动 rehydrate + 3 天 TTL 清理
- `tmp_target_list.pop(href)`（`pop()` 不接受参数）→ 改为显式过滤当前页 URL
- 悬浮面板 `sleep()` 未 `await` 导致的递归死循环 → setTimeout 轮询 + 次数上限
- `settingSafeMode` 异步读取/同步使用竞态 → 一次性加载缓存
- popup 把页面可控数据写入 `href`（`javascript:` 注入面）→ 纯文本渲染
- `JSON.parse(headers)` 无异常捕获、`forEach`+`splice` 过滤漏项 → 修复
- 归一化缺失：`\/`、`%2F`、尾逗号等让同一路径被算成多条 → 先归一化再过滤

### 新增

- **接口语义还原**：识别 `axios.*`、`$http.*`、`request({url,method,data})`、`fetch()`，产出 `method + path + 参数名`
- **凭据结构化**：按厂商前缀分类（阿里云/腾讯云/AWS/GitHub/GitLab/Slack/Stripe/私钥/数据库连接串/机器人 Webhook 等）+ 可信度分级
- **JWT 解码与风险标记**：`alg=none`、对称签名、无 `exp`、payload 含权限字段
- **Sourcemap 全链路**：发现 → 拉取 → 还原原始源码路径与内容 → 二次提取
- **框架运行时分析**（MAIN world）：Vue2/3、Next.js（Pages + App Router RSC）、Nuxt 2/3、React Router v6、webpack chunk 枚举
- **Popup 交互**：分类计数与筛选、实时搜索、作用域过滤、来源溯源、4 种导出（JSON/CSV/URL/路径）

### 安全设计

- 请求边界分级：只发「浏览器本来就会发」的请求；`.js.map`（低风险，默认开）、JS 递归 depth 2（中风险，默认关）
- 不实现任何「探测不存在路径」的能力，避免在目标侧被判定为扫描
