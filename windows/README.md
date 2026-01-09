# Windows 用户快速入门

欢迎使用 AWS WAF 多账户配置工具！本文档将帮助 Windows 用户快速上手。

## 环境准备

### 1. 安装 Python 3.7+

1. 访问 https://www.python.org/downloads/
2. 下载最新版 Python 3（建议 3.9 或更高）
3. 运行安装程序
4. **重要**: 勾选 "Add Python to PATH"
5. 点击 "Install Now"

验证安装：
```powershell
python --version
# 应该显示: Python 3.x.x
```

### 2. 安装 AWS CLI

1. 下载 AWS CLI 安装包: https://awscli.amazonaws.com/AWSCLIV2.msi
2. 双击运行安装程序
3. 使用默认设置完成安装
4. 重启 PowerShell

验证安装：
```powershell
aws --version
# 应该显示: aws-cli/2.x.x ...
```

### 3. 安装项目依赖

在项目根目录运行：
```powershell
pip install -r requirements.txt
```

## 使用方法

### 交互式扫描（推荐新用户）

```powershell
python waf_cli.py scan --interactive
```

这会启动一个交互式菜单，类似于 Unix 系统的 `waf_scan.sh`，提供以下选项：
- 快速扫描（使用配置文件）
- 快速测试（单账户单区域）
- 自定义扫描（指定参数）
- 调试模式
- 查看帮助

### 命令行模式

#### 扫描 WAF 配置

```powershell
# 使用配置文件扫描
python waf_cli.py scan

# 指定单个 profile
python waf_cli.py scan -p AdministratorAccess-813923830882

# 指定多个 profile 和区域
python waf_cli.py scan -p profile1 profile2 -r us-east-1 us-west-2

# 指定输出文件
python waf_cli.py scan -p my-profile -o my_waf_config.json

# 调试模式
python waf_cli.py scan --debug

# 禁用并行扫描
python waf_cli.py scan --no-parallel
```

#### 分析扫描结果

```powershell
# 列出所有 Web ACL
python waf_cli.py analyze waf_config_20260107.json --list

# 规则统计分析
python waf_cli.py analyze waf_config_20260107.json --analyze

# 关联资源分析
python waf_cli.py analyze waf_config_20260107.json --resources

# 搜索特定 ACL
python waf_cli.py analyze waf_config_20260107.json --search "api"

# 导出为 CSV
python waf_cli.py analyze waf_config_20260107.json --csv report.csv
```

#### 检查资源关联

```powershell
python waf_cli.py check your-profile your-web-acl-name
```

#### 环境检查

```powershell
python waf_cli.py check-env
```

这会检查：
- Python 版本
- boto3 是否安装
- AWS CLI 是否安装

## 配置 AWS SSO

### 首次配置

```powershell
aws configure sso
```

按照提示输入：
- SSO start URL
- SSO Region
- 选择 AWS 账户
- 选择 IAM 角色
- CLI default client Region
- CLI default output format (建议: json)
- CLI profile name

### 登录

```powershell
aws sso login --profile your-profile-name
```

这会打开浏览器，完成 SSO 认证。

### 验证登录状态

```powershell
aws sts get-caller-identity --profile your-profile-name
```

应该返回账户信息：
```json
{
    "UserId": "AROA...:...",
    "Account": "123456789012",
    "Arn": "arn:aws:sts::123456789012:assumed-role/..."
}
```

## 常见问题

### 提示 "python 不是内部或外部命令"

**原因**: Python 未添加到 PATH 环境变量

**解决方法**:
1. 搜索 "环境变量" 或 "Environment Variables"
2. 点击 "编辑系统环境变量"
3. 点击 "环境变量" 按钮
4. 在 "系统变量" 或 "用户变量" 中找到 "Path"
5. 点击 "编辑"，添加 Python 安装路径（例如：`C:\Python310\` 和 `C:\Python310\Scripts\`）
6. 点击 "确定" 保存
7. 重启 PowerShell 或 CMD

或者使用完整路径：
```powershell
C:\Python310\python.exe waf_cli.py scan --interactive
```

### 提示 "无法加载文件，因为在此系统上禁止运行脚本"

**原因**: PowerShell 执行策略限制

**解决方法**:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

输入 `Y` 确认。

### 提示 "aws 不是内部或外部命令"

**原因**: AWS CLI 未安装或未添加到 PATH

**解决方法**:
1. 确认 AWS CLI 已安装：检查 `C:\Program Files\Amazon\AWSCLIV2\` 是否存在
2. 重启 PowerShell（安装后需要重启）
3. 如果仍然不工作，手动添加到 PATH：`C:\Program Files\Amazon\AWSCLIV2\`

### 提示 "boto3 未安装" 或 "colorama 未安装"

**原因**: Python 依赖包未安装

**解决方法**:
```powershell
pip install -r requirements.txt
```

或单独安装：
```powershell
pip install boto3 colorama
```

### 颜色显示异常

**原因**: 终端不支持 ANSI 颜色（较旧的 CMD）

**解决方法**:
- 使用 PowerShell（推荐）而不是 CMD
- 或使用 Windows Terminal（微软商店免费下载）
- colorama 库会自动处理大多数情况

### SSO 登录失败

**原因**: 可能是网络问题、凭证过期或配置错误

**解决方法**:
1. 检查网络连接
2. 确认 SSO start URL 正确
3. 重新配置 SSO：
   ```powershell
   aws configure sso --profile your-profile
   ```
4. 尝试删除旧的 SSO 缓存：
   ```powershell
   Remove-Item -Recurse -Force $env:USERPROFILE\.aws\sso\cache\
   ```

### 扫描时提示权限不足

**原因**: AWS IAM 权限不足

**需要的 IAM 权限**:
- `wafv2:ListWebACLs`
- `wafv2:GetWebACL`
- `wafv2:ListResourcesForWebACL`
- `cloudfront:ListDistributionsByWebACLId`
- `sts:GetCallerIdentity`

联系您的 AWS 管理员添加这些权限。

## 直接使用 Python 脚本（高级）

如果您熟悉命令行，也可以直接使用原始 Python 脚本：

```powershell
# 扫描
python get_waf_config.py -p your-profile

# 分析
python analyze_waf_config.py waf_config.json --list
```

这些脚本与 `waf_cli.py` 底层相同，只是接口不同。

## 更多帮助

- 查看主 README: 返回上一级目录，查看 `README.md`
- 查看开发文档: `CLAUDE.md`
- 查看帮助信息:
  ```powershell
  python waf_cli.py --help
  python waf_cli.py scan --help
  python waf_cli.py analyze --help
  ```

## 反馈和支持

如遇到问题，请提供以下信息：
- Python 版本（`python --version`）
- AWS CLI 版本（`aws --version`）
- 运行环境（Windows 10/11, PowerShell/CMD 版本）
- 错误信息截图或完整输出
