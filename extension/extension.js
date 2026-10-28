'use strict';
const vscode = require('vscode');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const { presentation } = require('./status');
const execute = promisify(execFile);
const CLI = '/usr/local/bin/claude-protect';

function activate(context) {
  const output = vscode.window.createOutputChannel('Claude Protect');
  const badge = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 80);
  badge.command = 'claudeProtect.status';
  let latest;
  let updating = false;
  let disposed = false;

  async function refresh() {
    if (updating || disposed) return;
    updating = true;
    try {
      if (process.platform !== 'linux' || vscode.env.remoteName) {
        latest = undefined;
      } else {
        const { stdout } = await execute(CLI, ['status', '--json'], { timeout: 12000, maxBuffer: 65536 });
        latest = JSON.parse(stdout);
      }
    } catch (error) {
      latest = { kernel_ok: false, error: error.code === 'ENOENT' ? 'Ubuntu 配套组件尚未安装。' : '状态服务不可达或隔离核对失败。' };
      if (error.stdout) {
        try { latest = JSON.parse(error.stdout); } catch { /* No trusted status response. */ }
      }
    } finally {
      if (!disposed) {
        const view = presentation(latest, { remote: Boolean(vscode.env.remoteName) });
        badge.text = view.text;
        badge.backgroundColor = view.color ? new vscode.ThemeColor(view.color) : undefined;
        badge.tooltip = view.detail;
        badge.show();
      }
      updating = false;
    }
  }

  const register = (id, handler) => context.subscriptions.push(vscode.commands.registerCommand(id, handler));
  register('claudeProtect.status', async () => {
    await refresh();
    output.clear();
    output.appendLine(presentation(latest, { remote: Boolean(vscode.env.remoteName) }).detail);
    output.appendLine(JSON.stringify(latest || {}, null, 2));
    output.show();
  });
  register('claudeProtect.launch', async () => {
    if (process.platform !== 'linux' || vscode.env.remoteName) {
      vscode.window.showErrorMessage('请在 Ubuntu 桌面的本地 VS Code 中使用。');
      return;
    }
    if (!vscode.workspace.isTrusted) {
      vscode.window.showWarningMessage('请先确认并信任当前工作区，再启动受保护窗口。');
      return;
    }
    let folder = vscode.workspace.workspaceFolders?.[0]?.uri;
    if (!folder) {
      const selected = await vscode.window.showOpenDialog({ canSelectFolders: true, canSelectFiles: false, canSelectMany: false });
      folder = selected?.[0];
    }
    if (!folder || folder.scheme !== 'file') return;
    const terminal = vscode.window.createTerminal({ name: 'Claude Protect 启动', shellPath: CLI,
      shellArgs: ['launch', folder.fsPath] });
    terminal.show();
  });
  register('claudeProtect.browser', () => {
    if (process.platform !== 'linux' || vscode.env.remoteName) {
      vscode.window.showErrorMessage('请在 Ubuntu 桌面的本地 VS Code 中使用。');
      return;
    }
    const terminal = vscode.window.createTerminal({ name: 'Claude Protect 浏览器', shellPath: CLI,
      shellArgs: ['browser', 'https://claude.ai/'] });
    terminal.show();
  });
  register('claudeProtect.probe', async () => {
    if (!vscode.workspace.isTrusted || !latest?.session_isolated) {
      vscode.window.showWarningMessage('请在已核对隔离的受保护窗口中运行联网验证。');
      return;
    }
    output.show();
    output.appendLine('检查 IPv4/IPv6、DNS、主机端口阻断，并经代理连接 example.com 验证 TLS。');
    try {
      const { stdout } = await execute(CLI, ['probe'], { timeout: 35000, maxBuffer: 65536 });
      output.appendLine(stdout);
    } catch (error) {
      output.appendLine(error.stdout || error.stderr || '测试未完成。请在终端运行 claude-protect probe。');
    }
  });
  register('claudeProtect.keyring', async () => {
    if (process.platform !== 'linux' || vscode.env.remoteName) {
      vscode.window.showErrorMessage('请在 Ubuntu 桌面的本地 VS Code 中使用。');
      return;
    }
    output.show();
    try {
      const { stdout } = await execute(CLI, ['keyring-status', '--json'], { timeout: 18000, maxBuffer: 65536 });
      output.appendLine(stdout);
      output.appendLine('这是服务可用性预检；Chrome 实际存储后端和磁盘加密仍需单独验收。');
    } catch {
      output.appendLine('密钥链预检未通过；请在正常桌面解锁密钥链，再运行 claude-protect keyring-status。');
    }
  });
  register('claudeProtect.guide', async () => {
    await vscode.commands.executeCommand('markdown.showPreview', vscode.Uri.joinPath(context.extensionUri, 'readme.md'));
  });
  const timer = setInterval(refresh, 15000);
  context.subscriptions.push(output, badge, { dispose() { disposed = true; clearInterval(timer); } });
  refresh();
}

module.exports = { activate };
