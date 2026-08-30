/**
 * InfoHunter - MV3 service worker 入口
 *
 * 按职责拆成几块，通过 importScripts 载入 classic service worker 的同一全局作用域：
 *   src/utils/hostmatch.js —— 站点白名单 / 资源黑名单匹配器（与 content 侧共用同一份）
 *   rules.js     —— 730 条 nuclei 正则，纯数据
 *   analyzers.js —— 语义分析纯函数（凭据分类 / JWT 解码 / 接口语义还原），零网络请求
 *   engine.js    —— 抓取与调度引擎，负责所有 fetch
 *
 * 这样改规则不会碰引擎，改分析逻辑不会误伤 700+ 条正则，
 * 而且 analyzers.js 是纯函数，可以脱离浏览器单独跑测试。
 */

try {
  importScripts('src/utils/hostmatch.js', 'rules.js', 'analyzers.js', 'engine.js');
} catch (e) {
  // importScripts 失败时扩展无法工作，写一条日志便于排查
  // eslint-disable-next-line no-console
  console.warn('[InfoHunter] 模块载入失败:', e && e.message);
}

chrome.runtime.onInstalled.addListener(function (details) {
  if (['install', 'update'].indexOf(details.reason) > -1) {
    chrome.tabs.create({ url: chrome.runtime.getURL('getstarted.html') });
  }
});
