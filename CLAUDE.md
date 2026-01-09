# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

AWS 多账户 WAF 配置提取和分析工具集。从多个 AWS member accounts 中自动提取 WAF v2 Web ACL 配置，支持 AWS SSO 认证，并提供分析和可视化功能。

**🌍 跨平台支持**: 现已支持 Windows、macOS 和 Linux！

## 核心架构

### 新架构（跨平台）

项目现在提供两套等价的工具：

**跨平台 Python 工具（推荐）**:
```
waf_cli.py (统一CLI入口)
    ├── scan 子命令 → 调用 InteractiveMenu → get_waf_config.py
    ├── analyze 子命令 → 调用 analyze_waf_config.py
    ├── check 子命令 → 调用 ResourceChecker
    └── check-env 子命令 → 调用 EnvironmentChecker
```

**Unix 传统工具**:
```
unix/waf_scan.sh (交互式入口，bash)
    ↓ 调用
get_waf_config.py (核心提取器)
    ↓ 生成 JSON
analyze_waf_config.py (分析器)
```

### 目录结构

```
waf-config-tool/
├── unix/                           # Unix 专用 bash 脚本
│   ├── waf_scan.sh
│   └── check_waf_resources.sh
├── windows/                        # Windows 文档
│   └── README.md                   # Windows 快速入门
├── core/                           # 核心模块（跨平台）
│   ├── __init__.py
│   ├── waf_environment.py          # 环境检查
│   ├── waf_interactive.py          # 交互式菜单
│   └── waf_resource_checker.py     # 资源检查
├── waf_cli.py                      # 统一CLI入口（跨平台）
├── get_waf_config.py               # 核心扫描（保持不变）
├── analyze_waf_config.py           # 分析工具（保持不变）
├── waf_scan_config.json            # 配置文件
└── requirements.txt                # Python依赖
```

### 关键组件

#### 核心扫描和分析

1. **WAFConfigExtractor** (`get_waf_config.py`):
   - 使用 boto3 与 AWS WAFv2 API 交互
   - 支持并行扫描多账户/多区域（`ThreadPoolExecutor`）
   - CloudFront scope 只在 `us-east-1` 扫描（全局资源）
   - Regional scope 在所有指定区域扫描
   - 自动解析资源 ARN，提取 friendly_type 和 resource_id

2. **WAFConfigAnalyzer** (`analyze_waf_config.py`):
   - 解析 JSON 输出
   - 生成规则统计、资源类型分布、CSV 导出
   - 支持搜索和过滤功能

#### 跨平台模块（新增）

3. **EnvironmentChecker** (`core/waf_environment.py`):
   - 检查 Python 版本（>= 3.7）
   - 检查 boto3 和 AWS CLI
   - 检查 SSO 登录状态
   - 自动检测运行环境（Windows/macOS/Linux/WSL）
   - 提供平台特定的安装指令

4. **InteractiveMenu** (`core/waf_interactive.py`):
   - 跨平台交互式菜单（替代 bash 菜单）
   - 使用 colorama 实现 Windows 颜色支持
   - 5 种扫描模式：快速扫描、快速测试、自定义、调试、帮助

5. **ResourceChecker** (`core/waf_resource_checker.py`):
   - 纯 Python 实现（替代 `check_waf_resources.sh`）
   - 无需 jq 工具
   - 检查 WAF ACL 的资源关联
   - 支持 CloudFront 和 Regional 资源

6. **统一 CLI 入口** (`waf_cli.py`):
   - 子命令架构：scan, analyze, check, check-env
   - 跨平台 subprocess 调用（Windows 使用 shell=True）
   - 调用现有 Python 脚本，保持向后兼容

### 配置文件结构

- `waf_scan_config.json`: 扫描配置（profiles、regions、scan_options）
- `waf_scan_config.json.example`: 示例模板
- **注意**: `waf_config_*.json` 包含敏感信息，已在 `.gitignore` 中

## 常用命令

### 跨平台方式（推荐）

```bash
# 交互式扫描
python waf_cli.py scan --interactive

# 使用配置文件扫描
python waf_cli.py scan

# 指定单个或多个账户
python waf_cli.py scan -p profile1 profile2

# 指定区域
python waf_cli.py scan -p my-profile -r us-east-1 us-west-2

# 调试模式
python waf_cli.py scan --debug

# 禁用并行
python waf_cli.py scan --no-parallel

# 分析结果
python waf_cli.py analyze waf_config_*.json --list
python waf_cli.py analyze waf_config_*.json --resources

# 检查资源关联
python waf_cli.py check profile-name web-acl-name

# 环境检查
python waf_cli.py check-env
```

### Unix 传统方式

```bash
# 使用交互式脚本
cd unix/
./waf_scan.sh

# 检查资源关联
./check_waf_resources.sh <profile-name> <web-acl-name>
```

### 直接使用 Python 脚本（向后兼容）

```bash
# 基础扫描
python3 get_waf_config.py
python3 get_waf_config.py -p profile1 -r us-east-1
python3 get_waf_config.py --debug

# 分析结果
python3 analyze_waf_config.py waf_config_*.json --list
python3 analyze_waf_config.py waf_config_*.json --analyze
python3 analyze_waf_config.py waf_config_*.json --csv report.csv
```

### AWS SSO 认证

```bash
# 配置 SSO
aws configure sso

# 登录（扫描前必须）
aws sso login --profile AdministratorAccess-275261018177

# 检查登录状态
aws sts get-caller-identity --profile AdministratorAccess-275261018177
```

## 重要的代码模式

### CloudFront vs Regional Scope

- **CloudFront**: 全局资源，只需在 `us-east-1` 扫描
- **Regional**: 区域资源，每个指定区域都要扫描
- `get_waf_config.py:289-312` 中实现了 scope 特定的扫描逻辑

### 获取关联资源的实现

**CloudFront scope**（`get_waf_config.py:177-228`）:
- 使用 **CloudFront API** 而不是 WAFv2 API
- 调用 `cloudfront.list_distributions_by_web_acl_id(WebACLId=arn)`
- 从 CloudFront 服务直接查询，更可靠
- 额外提取 `distribution_domain` 和 `distribution_status` 字段

**Regional scope**（`get_waf_config.py:231-263`）:
- 使用 **WAFv2 API** `list_resources_for_web_acl`
- 遍历所有支持的资源类型（ALB、API Gateway、AppSync 等）
- 每种资源类型单独查询

### 资源 ARN 解析

ARN 格式: `arn:partition:service:region:account-id:resource-type/resource-id`

关键映射关系（`get_waf_config.py:124-148`）:
- `elasticloadbalancing` + `loadbalancer/app` → Application Load Balancer
- `cloudfront` + `distribution` → CloudFront Distribution
- `apigateway` + `restapis` → REST API
- `cognito-idp` + `userpool` → Cognito User Pool

### 已知问题修复

- **CloudFront distribution 关联**: 使用 CloudFront API `list_distributions_by_web_acl_id` 替代 WAFv2 API，解决无法获取关联的问题
- **Managed Rule Groups 动作显示**: commit `5247b73` 修复了动作显示为 "Unknown" 的问题
- **CloudFront 区域发现**: commit `9fca584` 修复了 CloudFront WebACL 必须在 us-east-1 扫描的问题

## 必需的 IAM 权限

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "wafv2:ListWebACLs",
        "wafv2:GetWebACL",
        "wafv2:ListResourcesForWebACL",
        "cloudfront:ListDistributionsByWebACLId",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

**新增权限说明**:
- `cloudfront:ListDistributionsByWebACLId` - 获取与 WAF ACL 关联的 CloudFront distributions（2026-01-08 新增）

## 安全注意事项

输出的 JSON 文件包含敏感信息：
- AWS 账户 ID
- 资源 ARN（包含账户、区域、资源 ID）
- Web ACL 配置详情

**不要提交到 Git！** `.gitignore` 已配置忽略 `waf_config_*.json` 和 `*.csv`。

## 跨平台支持（2026-01-09 新增）

### Windows 特定处理

**subprocess 调用**:
- Windows 上所有 `subprocess.run()` 调用都使用 `shell=True`
- 原因: Windows CMD/PowerShell 对命令解析的差异

**颜色输出**:
- 使用 `colorama` 库实现跨平台 ANSI 颜色
- Windows CMD/PowerShell 原生不支持 ANSI 转义码，colorama 会自动转换

**路径处理**:
- 所有路径操作使用 `os.path` 或 `pathlib`
- 避免硬编码 `/` 或 `\` 分隔符

### 依赖管理

**requirements.txt**:
```
boto3>=1.26.0     # AWS SDK
colorama>=0.4.6   # 跨平台颜色输出
```

安装:
```bash
pip install -r requirements.txt
```

### 向后兼容性

✅ 保留所有现有脚本和功能
✅ Unix 用户可以继续使用 `unix/waf_scan.sh`
✅ 直接调用 `get_waf_config.py` 的脚本不受影响
✅ 配置文件格式完全不变
✅ 现有的 Git 历史和文档保持完整

### 测试清单

**Windows 测试**:
```powershell
python waf_cli.py check-env
python waf_cli.py scan --interactive
python waf_cli.py scan -p test-profile -r us-east-1
python waf_cli.py check test-profile test-acl
python waf_cli.py analyze test.json --list
```

**Unix 测试（向后兼容）**:
```bash
cd unix/
./waf_scan.sh                           # 旧工具仍然可用
cd ..
python3 waf_cli.py scan --interactive   # 新工具功能相同
```

## 最近改动

- 2026-01-09: **跨平台支持** - 添加 Windows/macOS/Linux 统一支持，创建 waf_cli.py 和 core 模块
- 2026-01-08: 修复 CloudFront distribution 关联获取问题，使用 CloudFront API 替代 WAFv2 API
- 2026-01-08: 修复 datetime.utcnow() deprecation warning
- 2026-01-08 (commit 3c318a1): 添加项目级 CLAUDE.md 文档
- 2026-01-07 (commit 612b769): 删除安全检查相关文件，简化项目结构
- 2026-01-07 (commit 5247b73): 修复 Managed Rule Groups 动作显示为 Unknown 的问题
- 2026-01-06 (commit b233d72): 改进规则显示功能
- 2026-01-06 (commit bc5fc8e): 整合和优化脚本结构，更新文档
- 2026-01-05 (commit 9fca584): 修复 CloudFront WebACL 发现问题（现在区域独立）
