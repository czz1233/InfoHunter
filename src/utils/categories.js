/**
 * InfoHunter - 共享分类定义
 *
 * 该脚本作为 content_scripts 的第一项加载，运行在隔离世界（isolated world），
 * 与 content.js / float 面板共享同一全局作用域，用于消除分类列表在多处重复定义的问题。
 * popup.js 通过 chrome.runtime.getURL 无法直接引用本文件（不同文档），
 * 因此 popup 侧保持一份同构拷贝，改动时两处需同步。
 */

var FS_CATEGORIES = [
  { key: 'secret',          label: '敏感信息',     i18n: 'popupSecret',          group: 'main',    order: 1 },
  { key: 'jwt',             label: 'JWT',        i18n: 'popupJwt',             group: 'main',    order: 2 },
  { key: 'sfz',             label: '身份证',       i18n: 'popupSfz',             group: 'main',    order: 3 },
  { key: 'mobile',          label: '手机号',       i18n: 'popupMobile',          group: 'main',    order: 4 },
  { key: 'mail',            label: '邮箱',        i18n: 'popupMail',            group: 'main',    order: 5 },
  { key: 'algorithm',       label: '算法',        i18n: 'popupAlgorithm',       group: 'main',    order: 6 },
  { key: 'api',             label: '接口',        i18n: 'popupApi',             group: 'main',    order: 7 },
  { key: 'route',           label: '路由',        i18n: 'popupRoute',           group: 'route',   order: 8 },
  { key: 'domain',          label: '域名',        i18n: 'popupDomain',          group: 'net',     order: 9 },
  { key: 'ip_port',         label: 'IP加端口',     i18n: 'popupIpPort',          group: 'net',     order: 10 },
  { key: 'ip',              label: 'IP',         i18n: 'popupIp',              group: 'net',     order: 11 },
  { key: 'url',             label: 'URL',        i18n: 'popupUrl',             group: 'net',     order: 12 },
  { key: 'path',            label: 'PATH',       i18n: 'popupPath',            group: 'net',     order: 13 },
  { key: 'incomplete_path', label: 'IncompletePath', i18n: 'popupIncompletePath', group: 'net',   order: 14 },
  { key: 'static',          label: 'StaticPath', i18n: 'popupStaticPath',      group: 'net',     order: 15 },
  { key: 'sourcemap',       label: 'Sourcemap',  i18n: 'popupSourcemap',       group: 'net',     order: 16 },
  { key: 'request',         label: '真实请求',    i18n: 'popupRequest',          group: 'runtime', order: 17 },
  { key: 'endpoint',        label: '端点',        i18n: 'popupEndpoint',         group: 'runtime', order: 18 },
  { key: 'storage',         label: '存储键名',    i18n: 'popupStorage',          group: 'runtime', order: 19 },
  { key: 'param',           label: '参数名',      i18n: 'popupParam',            group: 'runtime', order: 20 }
];

/** 供 background 侧遍历的分类 key 顺序（不含展示层字段） */
var FS_KEYS = FS_CATEGORIES.map(function (c) { return c.key; });

if (typeof window !== 'undefined') {
  window.FS_CATEGORIES = FS_CATEGORIES;
  window.FS_KEYS = FS_KEYS;
}
