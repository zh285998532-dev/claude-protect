'use strict';

function presentation(result, { platform = process.platform, remote = false } = {}) {
  if (platform !== 'linux' || remote) {
    return { text: '$(circle-slash) Protect: 不支持此环境', color: 'statusBarItem.warningBackground',
      detail: '面向 Ubuntu 桌面本地 VS Code。远程窗口不计为受保护。' };
  }
  if (!result || !result.kernel_ok) {
    return { text: '$(shield) Protect: 未就绪', color: 'statusBarItem.errorBackground',
      detail: '未验证内核隔离。请查看状态；不会自动修改网络或放行直连。' };
  }
  if (!result.session_isolated) {
    return { text: '$(warning) Protect: 此窗口未隔离', color: 'statusBarItem.warningBackground',
      detail: '隔离服务已就绪，但此窗口运行在外部。请使用“打开受保护窗口”。' };
  }
  if (!result.upstream_managed) {
    return { text: '$(warning) Protect: 上游未受控', color: 'statusBarItem.warningBackground',
      detail: '应用隔离已核对，但外部代理的 DNS 和实际出口没有被本项目限制。' };
  }
  if (result.upstream_test_only) {
    return { text: '$(warning) Protect: 测试上游', color: 'statusBarItem.warningBackground',
      detail: '当前是测试用私网或明文上游配置，不能作为生产保护配置。' };
  }
  return { text: '$(shield) Protect: 双层出站已核对', color: undefined,
    detail: '命名空间、出站规则、路由已核对。代理可达性需单独测试；不代表账号安全。' };
}

module.exports = { presentation };
