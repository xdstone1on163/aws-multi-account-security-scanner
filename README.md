# AWS 多账户 WAF/ALB/Route53 配置提取工具集

从多个 AWS member account 中自动提取 WAF v2 Web ACL、ALB 和 Route53 DNS 配置的 Python 工具集。

**包含三个独立工具**:
- 🛡️ **WAF 工具**: 提取 WAF v2 Web ACL 配置和关联资源
- 🔀 **ALB 工具**: 提取 ALB/NLB 配置和 WAF 绑定状态
- 🌐 **Route53 工具**: 提取 Hosted Zone 和 DNS Records 配置（新增）

## 🌍 跨平台支持

本工具现在支持 **Windows**、**macOS** 和 **Linux**！

### 目录结构

```
waf-alb-route53-config-tool/
├── unix/                      # Unix 用户：bash 脚本入口
├── windows/                   # Windows 用户：快速入门文档
├── core/                      # 共享的核心模块
├── waf_cli.py                 # WAF 工具统一入口
├── alb_cli.py                 # ALB 工具统一入口
├── route53_cli.py             # Route53 工具统一入口（新增）
├── get_waf_config.py          # WAF 核心扫描器
├── get_alb_config.py          # ALB 核心扫描器
├── get_route53_config.py      # Route53 核心扫描器（新增）
├── analyze_waf_config.py      # WAF 分析工具
├── analyze_alb_config.py      # ALB 分析工具
├── analyze_route53_config.py  # Route53 分析工具（新增）
└── ...
```

### Windows 用户

👉 **查看详细文档**: [windows/README.md](windows/README.md)

**一行命令开始**:
```powershell
# 安装依赖
pip install -r requirements.txt

# 交互式扫描
python waf_cli.py scan --interactive
```

### Unix 用户（macOS/Linux）

**方式 1: 使用 bash 脚本（传统方式）**
```bash
cd unix/
./waf_scan.sh
```

**方式 2: 使用跨平台 Python 工具（推荐）**
```bash
python3 waf_cli.py scan --interactive
```

---

## 🚀 快速开始

### 新用户推荐：交互式扫描

**跨平台方式（Windows/macOS/Linux）：**

```bash
python waf_cli.py scan --interactive
```

**Unix 传统方式：**

```bash
cd unix/
./waf_scan.sh
```

### 高级用户：命令行模式

**WAF 工具:**
```bash
# 使用配置文件快速扫描
python waf_cli.py scan

# 指定 profile 扫描
python waf_cli.py scan -p profile1 profile2

# 分析结果
python waf_cli.py analyze waf_config_*.json --list
```

**ALB 工具（新增）:**
```bash
# 交互式扫描
python alb_cli.py scan --interactive

# Quick 模式：只获取基本信息和 WAF 状态
python alb_cli.py scan --mode quick

# Standard 模式：包含监听器、目标组、安全组
python alb_cli.py scan --mode standard

# Full 模式：包含监听器规则和目标健康状态
python alb_cli.py scan --mode full

# 分析结果并查看扫描模式信息
python alb_cli.py analyze alb_config_*.json --stats
python alb_cli.py analyze alb_config_*.json --waf-coverage
python alb_cli.py analyze alb_config_*.json --no-waf
```

**Route53 工具（新增）:**
```bash
# 扫描（使用配置文件，只扫描 Public Zones）
python route53_cli.py scan

# 扫描指定账户
python route53_cli.py scan -p profile1 profile2

# 分析 - 列出所有 Zones
python route53_cli.py analyze route53_config_*.json --list

# 分析 - 按记录类型统计
python route53_cli.py analyze route53_config_*.json --by-record-type

# 分析 - 按 Zone 类型统计
python route53_cli.py analyze route53_config_*.json --by-zone-type

# 搜索域名
python route53_cli.py analyze route53_config_*.json --search example.com

# 导出 CSV
python route53_cli.py analyze route53_config_*.json --csv route53_report.csv
```

### 或直接使用原始 Python 脚本

```bash
# 快速扫描（使用配置文件）
python3 get_waf_config.py

# 自定义扫描
python3 get_waf_config.py -p profile1 profile2 -r us-east-1 us-west-2

# 分析结果
python3 analyze_waf_config.py waf_config_*.json --list
```

## 📁 工具脚本说明

### 跨平台工具

| 脚本 | 类型 | 用途 | 使用场景 |
|------|------|------|----------|
| **waf_cli.py** | Python | **WAF 统一 CLI 入口** | ⭐ WAF 工具推荐入口，跨平台支持 |
| **alb_cli.py** | Python | **ALB 统一 CLI 入口** | ⭐ ALB 工具推荐入口，跨平台支持 |
| **route53_cli.py** | Python | **Route53 统一 CLI 入口** | ⭐ Route53 工具推荐入口，跨平台支持（新增） |
| **get_waf_config.py** | Python | WAF 核心提取工具 | 从 AWS 提取 WAF 配置 |
| **get_alb_config.py** | Python | ALB 核心提取工具 | 从 AWS 提取 ALB 配置 |
| **get_route53_config.py** | Python | Route53 核心提取工具 | 从 AWS 提取 Route53 配置（新增） |
| **analyze_waf_config.py** | Python | WAF 配置分析工具 | 分析 WAF 扫描结果，生成报告和统计 |
| **analyze_alb_config.py** | Python | ALB 配置分析工具 | 分析 ALB 扫描结果，WAF 覆盖率审计 |
| **analyze_route53_config.py** | Python | Route53 配置分析工具 | 分析 Route53 扫描结果，DNS 记录统计（新增） |

### Unix 专用工具（在 `unix/` 目录）

| 脚本 | 类型 | 用途 | 使用场景 |
|------|------|------|----------|
| **unix/waf_scan.sh** | Shell | 交互式扫描工具（Bash） | Unix 用户的传统入口，功能与 waf_cli.py 相同 |
| **unix/check_waf_resources.sh** | Shell | 调试验证工具（Bash） | 调试特定 Web ACL 的资源关联问题 |

### 核心模块（在 `core/` 目录）

| 模块 | 用途 |
|------|------|
| **core/waf_environment.py** | 环境检查（Python、boto3、AWS CLI、SSO 登录状态） |
| **core/waf_interactive.py** | 交互式菜单实现 |
| **core/waf_resource_checker.py** | 资源关联检查（替代 check_waf_resources.sh） |

### 调用流程

```
┌─────────────────────┐
│   新用户开始使用      │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  ./waf_scan.sh      │  ← 主入口（推荐）
│  - 检查环境          │
│  - SSO 登录         │
│  - 交互式菜单        │
└──────────┬──────────┘
           │
           │ 自动调用
           ▼
┌─────────────────────┐
│ get_waf_config.py   │  ← 核心扫描
│ 提取 WAF 配置        │
└──────────┬──────────┘
           │
           │ 生成 JSON
           ▼
┌─────────────────────┐
│ analyze_waf_config.py│ ← 分析结果
│ 生成报告和统计       │
└─────────────────────┘

            可选工具
┌──────────────────────┐
│ check_waf_resources.sh│
│ (调试资源关联)        │
└──────────────────────┘
```

## 功能特性

### WAF 工具
✅ 支持 AWS Identity Center (SSO) 多账户认证
✅ 并行扫描多个账户和区域
✅ 同时支持 CLOUDFRONT 和 REGIONAL scope
✅ 完整的错误处理和权限检查
✅ JSON 格式导出配置详情
✅ **自动获取 WAF ACL 关联的 AWS 资源**
✅ **智能解析资源 ARN，显示友好的资源类型**
✅ 数据分析和可视化工具
✅ CSV 导出功能
✅ 关联资源统计分析
✅ 交互式扫描脚本，易于使用

### ALB 工具
✅ 跨账号扫描 ALB/NLB 配置
✅ **三种扫描模式**：Quick（基本+WAF）/ Standard（+监听器+目标组）/ Full（+规则+健康状态）
✅ **反向 WAF 查询**：从 ALB 查询绑定的 WAF ACL
✅ WAF 覆盖率分析和安全审计
✅ 监听器和目标组统计
✅ 实时目标健康状态检查（Full 模式）
✅ 安全组详情提取
✅ 按类型/区域统计分析
✅ CSV 导出功能
✅ 智能提示不同扫描模式的差异

### Route53 工具（新增）
✅ 跨账号扫描 Public Hosted Zone 和 DNS Records
✅ **全局服务支持**：Route53 是全局服务，自动处理区域参数
✅ **只扫描 Public Zones**：专注于 Global level 的公有域名，不扫描 VPC level 的私有 Zone
✅ **完整的 DNS 记录提取**：A/AAAA/CNAME/MX/TXT/NS/SOA 等所有类型
✅ **7 种路由策略解析**：Simple/Weighted/Latency/Failover/Geolocation/Geoproximity/Multivalue
✅ **Alias 记录智能推断**：自动识别 ALB/CloudFront/S3/API Gateway 等目标类型
✅ **API 分页和限流保护**：自动处理大量记录和 API 限流重试
✅ 按记录类型/Zone 类型统计分析
✅ 路由策略使用情况统计
✅ 健康检查配置审计（查找缺少健康检查的高级路由策略）
✅ 按名称/值搜索 DNS 记录
✅ CSV 导出功能

## 前置要求

### 1. Python 环境

```bash
python3 --version  # 需要 Python 3.7+
```

**Windows 用户**: 从 https://www.python.org/downloads/ 下载安装

### 2. 安装依赖

```bash
# 推荐：使用 requirements.txt 安装所有依赖
pip install -r requirements.txt

# 或手动安装
pip install boto3 colorama
```

**依赖说明**:
- `boto3`: AWS SDK，用于调用 AWS API
- `colorama`: 跨平台颜色输出支持（Windows 兼容）

### 3. AWS 认证配置

#### 方式 A：AWS Identity Center (SSO) - 推荐
```bash
# 配置 SSO profile
aws configure sso

# 登录（在运行脚本前）
aws sso login --profile AdministratorAccess-275261018177
```

#### 方式 B：IAM 用户凭证
在 `~/.aws/credentials` 中配置：
```ini
[default]
aws_access_key_id = YOUR_ACCESS_KEY
aws_secret_access_key = YOUR_SECRET_KEY
```

### 4. 所需权限

#### WAF 工具权限

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

**权限说明**：
- `wafv2:ListResourcesForWebACL` - 获取 WAF ACL 关联的 AWS 资源（ALB、API Gateway 等）
- `cloudfront:ListDistributionsByWebACLId` - 获取 CloudFront distributions 与 WAF ACL 的关联关系

#### ALB 工具权限（新增）

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "elasticloadbalancing:DescribeLoadBalancers",
        "elasticloadbalancing:DescribeListeners",
        "elasticloadbalancing:DescribeRules",
        "elasticloadbalancing:DescribeTargetGroups",
        "elasticloadbalancing:DescribeTargetHealth",
        "wafv2:GetWebACLForResource",
        "ec2:DescribeSecurityGroups",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

**权限说明**：
- `elasticloadbalancing:*` - 获取 ALB/NLB 配置、监听器、目标组和健康状态
- `wafv2:GetWebACLForResource` - **反向查询**：从 ALB ARN 查询绑定的 WAF ACL
- `ec2:DescribeSecurityGroups` - 获取安全组详情

#### Route53 工具权限（新增）

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "route53:ListHostedZones",
        "route53:GetHostedZone",
        "route53:ListResourceRecordSets",
        "route53:ListTagsForResource",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

**权限说明**：
- `route53:ListHostedZones` - 列出所有 Hosted Zones
- `route53:GetHostedZone` - 获取 Zone 详情
- `route53:ListResourceRecordSets` - 获取 DNS 记录
- `route53:ListTagsForResource` - 获取 Zone 标签

可选（如需列出所有账户）：
```json
{
  "Effect": "Allow",
  "Action": [
    "organizations:ListAccounts",
    "organizations:DescribeAccount"
  ],
  "Resource": "*"
}
```

### 5. 配置文件

本工具支持两种配置文件方式：

#### 方式 A：统一配置文件（推荐）

使用单个配置文件 `aws_multi_account_scan_config.json` 管理所有工具（WAF、ALB、Route53）：

```bash
# 1. 复制示例文件
cp aws_multi_account_scan_config.json.example aws_multi_account_scan_config.json

# 2. 编辑配置文件，填入你的 AWS profiles
vi aws_multi_account_scan_config.json
```

**统一配置文件结构**：
```json
{
  "profiles": [
    "your-sso-profile-1",
    "your-sso-profile-2"
  ],
  "regions": {
    "common": ["us-east-1", "us-west-2", "ap-northeast-1"]
  },
  "waf": {
    "scan_options": { "parallel": true, "max_workers": 3 }
  },
  "alb": {
    "scan_options": { "mode": "standard", "parallel": true }
  },
  "route53": {
    "scan_options": { "parallel": true, "max_workers": 3 }
  }
}
```

**优点**：
- ✅ 一个文件管理所有工具配置
- ✅ profiles 和 regions 共享，避免重复
- ✅ 更容易维护和版本控制

#### 方式 B：独立配置文件（向后兼容）

每个工具使用独立的配置文件：

```bash
# WAF 工具
cp waf_scan_config.json.example waf_scan_config.json
vi waf_scan_config.json

# ALB 工具
cp alb_scan_config.json.example alb_scan_config.json
vi alb_scan_config.json

# Route53 工具
cp route53_scan_config.json.example route53_scan_config.json
vi route53_scan_config.json
```

**配置文件优先级**：
1. 独立配置文件（如 `waf_scan_config.json`）- 优先级最高
2. 统一配置文件（`aws_multi_account_scan_config.json`）- 备选
3. 命令行参数 - 可以覆盖配置文件

**示例**：
```bash
# 使用统一配置文件
python waf_cli.py scan  # 自动读取 aws_multi_account_scan_config.json

# 命令行参数覆盖配置文件
python waf_cli.py scan -p custom-profile -r us-east-1
```

## 使用指南

### 方式一：使用交互式脚本（推荐新用户）

**主扫描工具：`waf_scan.sh`**

```bash
./waf_scan.sh
```

这个脚本会自动：
1. ✅ 检查环境依赖（Python、boto3、AWS CLI）
2. ✅ 检查配置文件 `waf_scan_config.json`
3. ✅ 验证 AWS SSO 登录状态
4. ✅ 提供交互式菜单选择扫描模式

**菜单选项：**
- **选项 1** - 快速扫描：使用配置文件自动扫描所有账户
- **选项 2** - 快速测试：单账户单区域快速验证
- **选项 3** - 自定义扫描：手动指定参数
- **选项 4** - 调试模式：查看详细日志
- **选项 5** - 查看帮助

### 方式二：直接使用 Python 脚本（高级用户）

#### 基本用法
```bash
# 使用配置文件（waf_scan_config.json）
python3 get_waf_config.py

# 指定单个账户
python3 get_waf_config.py -p AdministratorAccess-275261018177

# 指定多个账户
python3 get_waf_config.py -p profile1 profile2 profile3
```

#### 指定区域
```bash
# 只扫描特定区域
python3 get_waf_config.py -r us-east-1 us-west-2 ap-northeast-1

# 扫描全球所有区域
python3 get_waf_config.py -r us-east-1 us-east-2 us-west-1 us-west-2 \
  ap-south-1 ap-northeast-1 ap-northeast-2 ap-southeast-1 ap-southeast-2 \
  ca-central-1 eu-central-1 eu-west-1 eu-west-2 eu-west-3 \
  sa-east-1
```

#### 其他选项
```bash
# 指定输出文件
python3 get_waf_config.py -o my_waf_report.json

# 启用调试模式
python3 get_waf_config.py --debug

# 串行扫描（禁用并行）
python3 get_waf_config.py --no-parallel

# 查看帮助
python3 get_waf_config.py --help
```

#### 输出示例
```
================================================================================
正在扫描账户: AdministratorAccess-275261018177
================================================================================
✓ 账户 ID: 275261018177

  扫描区域: us-east-1
    检查 CLOUDFRONT scope...
    ✓ 获取到 Web ACL: CloudFront-Protection (2 个关联资源)
    检查 REGIONAL scope...
    ✓ 获取到 Web ACL: API-Gateway-WAF (1 个关联资源)

  扫描区域: us-west-2
    检查 REGIONAL scope...
    ✓ 获取到 Web ACL: ALB-Protection (3 个关联资源)

================================================================================
扫描摘要
================================================================================

账户 275261018177 (AdministratorAccess-275261018177):
  - us-east-1 (CLOUDFRONT): 1 个 Web ACL, 2 个关联资源
  - us-east-1 (REGIONAL): 1 个 Web ACL, 1 个关联资源
  - us-west-2 (REGIONAL): 1 个 Web ACL, 3 个关联资源

总计: 3 个 Web ACL, 6 个关联资源

================================================================================
✓ 结果已保存到: waf_config_20260105_143022.json
================================================================================
```

### 第二步：分析 WAF 配置

**分析工具：`analyze_waf_config.py`**

#### 列出所有 Web ACL
```bash
python3 analyze_waf_config.py waf_config_20260105_143022.json --list
```

#### 分析规则统计
```bash
python3 analyze_waf_config.py waf_config_20260105_143022.json --analyze
```

输出示例：
```
================================================================================
规则分析
================================================================================

规则类型分布:
  Managed: AWS/AWSManagedRulesCommonRuleSet: 45
  Managed: AWS/AWSManagedRulesKnownBadInputsRuleSet: 30
  Rate-based: 12
  IP Set: 8
  Geo Match: 5

规则动作分布:
  Block: 67
  Allow: 18
  Count: 15
```

#### 分析关联资源统计
```bash
python3 analyze_waf_config.py waf_config_20260105_143022.json --resources
```

输出示例：
```
================================================================================
关联资源分析
================================================================================

资源统计:
  Web ACL 总数: 15
  有关联资源的 ACL: 12
  无关联资源的 ACL: 3
  关联资源总数: 28

资源类型分布:
  Application Load Balancer: 15
  CloudFront Distribution: 8
  REST API: 3
  Cognito User Pool: 2
```

#### 搜索特定 Web ACL
```bash
# 搜索名称包含 "api" 的 ACL
python3 analyze_waf_config.py waf_config_20260105_143022.json --search api

# 搜索名称包含 "cloudfront" 的 ACL
python3 analyze_waf_config.py waf_config_20260105_143022.json --search cloudfront
```

#### 导出为 CSV
```bash
python3 analyze_waf_config.py waf_config_20260105_143022.json --csv waf_report.csv
```

#### 综合分析
```bash
# 执行所有分析
python3 analyze_waf_config.py waf_config_20260105_143022.json
```

---

## ALB 工具使用指南（新增）

### 第一步：扫描 ALB 配置

**扫描工具：`alb_cli.py` 或 `get_alb_config.py`**

#### 交互式扫描（推荐）
```bash
python alb_cli.py scan --interactive
```

这个命令会：
1. ✅ 显示交互式菜单
2. ✅ 选择扫描模式（Quick/Standard/Full）
3. ✅ 自动加载配置文件或手动指定账户/区域

#### 三种扫描模式

**Quick 模式** - 快速 WAF 覆盖率审计
```bash
python alb_cli.py scan --mode quick
```
- ✅ ALB 基本信息（名称、状态、DNS、类型）
- ✅ WAF 关联状态
- ⏱️ 最快速度
- 💰 最少 API 调用

**Standard 模式（默认）** - 标准配置审计
```bash
python alb_cli.py scan --mode standard
# 或
python alb_cli.py scan
```
- ✅ Quick 模式的所有内容
- ✅ 监听器配置（协议、端口、证书）
- ✅ 目标组配置（健康检查设置）
- ✅ 安全组详情
- ⚖️ 平衡速度和详细度

**Full 模式** - 完整配置和健康状态
```bash
python alb_cli.py scan --mode full
```
- ✅ Standard 模式的所有内容
- ✅ 监听器规则详情（转发规则、条件）
- ✅ **实时目标健康状态**（healthy/unhealthy/draining）
- 📊 最详细信息
- ⏱️ 速度较慢，API 调用最多

#### 其他扫描选项
```bash
# 指定单个或多个账户
python alb_cli.py scan -p profile1 profile2 --mode standard

# 指定区域
python alb_cli.py scan -p my-profile -r us-east-1 us-west-2

# 启用调试模式
python alb_cli.py scan --debug

# 禁用并行扫描
python alb_cli.py scan --no-parallel
```

#### 输出示例
```
================================================================================
正在扫描账户: AdministratorAccess-813923830882
================================================================================
✓ 账户 ID: 813923830882

  扫描区域: us-east-1
    ✓ 发现 2 个负载均衡器
    • bedrock-proxy-no-peering (Network Load Balancer) - ✗ 无 WAF
    • for-graviton-jupyter-notebook (Application Load Balancer) - ✓ 有 WAF (lingoace-demo)

================================================================================
扫描摘要
================================================================================

账户 813923830882:
  - us-east-1: 2 个 ALB (1 个有 WAF, 1 个无 WAF)

总计: 2 个 ALB, 1 个有 WAF (50.0%), 1 个无 WAF (50.0%)

================================================================================
✓ 结果已保存到: alb_config_20260114_161119.json
================================================================================
```

### 第二步：分析 ALB 配置

**分析工具：`analyze_alb_config.py`**

#### 查看扫描信息和模式
```bash
# 所有分析命令都会自动显示扫描模式信息
python alb_cli.py analyze alb_config_*.json --stats
```

输出示例：
```
================================================================================
扫描信息
================================================================================

账户: 813923830882 (AdministratorAccess-813923830882)
  扫描时间: 2026-01-14T08:11:42.839488+00:00
  扫描模式: Full 模式（+ 监听器规则 + 目标健康状态）

================================================================================
高级统计（基于扫描模式）
================================================================================

监听器统计:
  总监听器数: 2
  协议分布:
    HTTP: 1
    TCP: 1

目标组统计:
  总目标组数: 2
  协议分布:
    HTTP: 1
    TCP: 1

监听器规则统计（Full 模式）:
  总规则数: 2

目标健康状态（Full 模式）:
  总目标数: 3
    ✅ healthy: 2 (66.7%)
    ⚠️ unhealthy: 1 (33.3%)
```

#### WAF 覆盖率分析（安全审计）
```bash
python alb_cli.py analyze alb_config_*.json --waf-coverage
```

输出示例：
```
================================================================================
WAF 覆盖率分析
================================================================================

按账户统计:

  账户 813923830882:
    总 ALB 数: 2
    有 WAF: 1 (50.0%)
    无 WAF: 1 (50.0%)

全局统计:
  总 ALB 数: 2
  有 WAF: 1 (50.0%)
  无 WAF: 1 (50.0%)
```

#### 列出未绑定 WAF 的 ALB（安全审计）
```bash
python alb_cli.py analyze alb_config_*.json --no-waf
```

输出示例：
```
================================================================================
未绑定 WAF 的 ALB（安全审计）
================================================================================

账户: 813923830882

  区域: us-east-1
    ⚠️  bedrock-proxy-no-peering
        类型: Network Load Balancer
        方案: internet-facing
        DNS: bedrock-proxy-no-peering-b5eb7bbcbcc3fccf.elb.us-east-1.amazonaws.com
```

#### 列出所有 ALB
```bash
python alb_cli.py analyze alb_config_*.json --list
```

#### 按类型/区域统计
```bash
python alb_cli.py analyze alb_config_*.json --by-type
python alb_cli.py analyze alb_config_*.json --by-region
```

#### 搜索特定 ALB
```bash
# 搜索名称包含 "notebook" 的 ALB
python alb_cli.py analyze alb_config_*.json --search notebook
```

#### 导出为 CSV
```bash
python alb_cli.py analyze alb_config_*.json --csv alb_report.csv
```

#### 综合分析
```bash
# 执行所有分析（包含扫描模式信息）
python alb_cli.py analyze alb_config_*.json
```

---

## Route53 工具使用指南（新增）

### 第一步：扫描 Route53 配置

**核心工具：`get_route53_config.py`**

Route53 是全局服务，工具会自动扫描所有 Public Hosted Zones 和 DNS 记录。

#### 使用配置文件扫描（推荐）
```bash
# 使用独立配置文件
python route53_cli.py scan

# 或使用统一配置文件（aws_multi_account_scan_config.json）
python route53_cli.py scan
```

#### 指定账户扫描
```bash
# 单个账户
python route53_cli.py scan -p AdministratorAccess-275261018177

# 多个账户
python route53_cli.py scan -p profile1 profile2 profile3
```

#### 其他扫描选项
```bash
# 启用调试模式（查看详细的 API 调用日志）
python route53_cli.py scan --debug

# 禁用并行扫描（串行处理，便于调试）
python route53_cli.py scan --no-parallel

# 指定输出文件名
python route53_cli.py scan -o my_route53_config.json
```

#### 输出示例
```
================================================================================
正在扫描账户: AdministratorAccess-813923830882
================================================================================
✓ 账户 ID: 813923830882

正在扫描 Hosted Zones...
    扫描公有 Zone: example.com.
    扫描公有 Zone: example.org.
    ⊘ 跳过私有 Zone (VPC level): internal.local.

✓ 扫描完成:
  - 公有 Hosted Zones: 2
  - 总 DNS 记录: 47

================================================================================
总体统计
================================================================================
扫描账户数: 1
公有 Hosted Zones: 2
总 DNS 记录: 47

================================================================================
✓ 结果已保存到: route53_config_20260114_180000.json
================================================================================
```

### 第二步：分析 Route53 配置

**分析工具：`analyze_route53_config.py`**

#### 列出所有 Hosted Zones
```bash
python route53_cli.py analyze route53_config_*.json --list
```

输出示例：
```
================================================================================
Hosted Zones 列表
================================================================================

账户: 813923830882 (AdministratorAccess-813923830882)
  扫描时间: 2026-01-14T10:00:00.000000+00:00

Zone 1: example.com.
  类型: 公有
  记录数: 25
  NS 服务器: ns-123.awsdns-12.com, ns-456.awsdns-45.org

Zone 2: example.org.
  类型: 公有
  记录数: 22
  NS 服务器: ns-789.awsdns-78.net, ns-012.awsdns-01.co.uk

总计: 2 个 Public Hosted Zones, 47 条 DNS 记录
```

#### 按 DNS 记录类型统计
```bash
python route53_cli.py analyze route53_config_*.json --by-record-type
```

输出示例：
```
================================================================================
DNS 记录类型统计
================================================================================

A 记录: 15 (31.9%)
AAAA 记录: 3 (6.4%)
CNAME 记录: 12 (25.5%)
MX 记录: 4 (8.5%)
TXT 记录: 8 (17.0%)
NS 记录: 4 (8.5%)
SOA 记录: 1 (2.1%)

总计: 47 条 DNS 记录
```

#### 按 Zone 类型统计
```bash
python route53_cli.py analyze route53_config_*.json --by-zone-type
```

输出示例：
```
================================================================================
Zone 类型统计
================================================================================

公有 Zones: 2 (100.0%)
  - 总记录数: 47
  - 平均每个 Zone: 23.5 条记录

总计: 2 个 Hosted Zones
```

#### 路由策略统计
```bash
python route53_cli.py analyze route53_config_*.json --routing-policies
```

输出示例：
```
================================================================================
路由策略统计
================================================================================

Simple (简单): 42 (89.4%)
Weighted (加权): 3 (6.4%)
Failover (故障转移): 2 (4.3%)

总计: 47 条 DNS 记录
```

#### 安全审计 - 查找缺少健康检查的记录
```bash
python route53_cli.py analyze route53_config_*.json --missing-health-checks
```

输出示例：
```
================================================================================
缺少健康检查的记录（安全审计）
================================================================================

⚠️  以下记录使用了高级路由策略但缺少健康检查:

Zone: example.com.
  - api.example.com (Failover: PRIMARY) - 无健康检查
  - api.example.com (Failover: SECONDARY) - 无健康检查

建议: 为故障转移和加权路由策略的记录配置健康检查，以确保高可用性。

总计: 2 条记录需要注意
```

#### 搜索功能
```bash
# 按名称搜索（支持模糊匹配）
python route53_cli.py analyze route53_config_*.json --search api

# 按记录值搜索（IP 地址、CNAME 目标等）
python route53_cli.py analyze route53_config_*.json --search-value 192.0.2.1
```

#### 导出 CSV
```bash
python route53_cli.py analyze route53_config_*.json --csv route53_report.csv
```

CSV 包含字段：
- Account_ID, Profile, Zone_Name, Zone_Type
- Record_Name, Record_Type, TTL, Value
- Alias_Target, Routing_Policy, Health_Check_ID

#### 综合分析（一次显示所有统计）
```bash
# 直接运行不带参数，显示所有基础统计
python route53_cli.py analyze route53_config_*.json
```

---

## 输出数据结构

### JSON 格式
```json
[
  {
    "profile": "AdministratorAccess-275261018177",
    "scan_time": "2026-01-05T14:30:22.123456",
    "account_info": {
      "account_id": "275261018177",
      "arn": "arn:aws:sts::275261018177:assumed-role/...",
      "user_id": "AROA..."
    },
    "regions": [
      {
        "region": "us-east-1",
        "cloudfront_acls": [
          {
            "summary": {
              "Name": "CloudFront-Protection",
              "Id": "a1b2c3d4-...",
              "ARN": "arn:aws:wafv2:us-east-1:..."
            },
            "detail": {
              "Name": "CloudFront-Protection",
              "Id": "a1b2c3d4-...",
              "Capacity": 500,
              "Rules": [
                {
                  "Name": "AWSManagedRulesCommonRuleSet",
                  "Priority": 0,
                  "Statement": {
                    "ManagedRuleGroupStatement": {
                      "VendorName": "AWS",
                      "Name": "AWSManagedRulesCommonRuleSet"
                    }
                  },
                  "Action": {
                    "Block": {}
                  }
                }
              ],
              "DefaultAction": {
                "Allow": {}
              }
            },
            "associated_resources": [
              {
                "arn": "arn:aws:cloudfront::275261018177:distribution/E1234567890ABC",
                "partition": "aws",
                "service": "cloudfront",
                "region": "",
                "account_id": "275261018177",
                "resource": "distribution/E1234567890ABC",
                "resource_type": "distribution",
                "resource_id": "E1234567890ABC",
                "friendly_type": "CloudFront Distribution",
                "resource_type_api": "CLOUDFRONT"
              },
              {
                "arn": "arn:aws:elasticloadbalancing:us-east-1:275261018177:loadbalancer/app/my-alb/1234567890abcdef",
                "partition": "aws",
                "service": "elasticloadbalancing",
                "region": "us-east-1",
                "account_id": "275261018177",
                "resource": "loadbalancer/app/my-alb/1234567890abcdef",
                "resource_type": "loadbalancer/app",
                "resource_id": "my-alb/1234567890abcdef",
                "friendly_type": "Application Load Balancer",
                "resource_type_api": "APPLICATION_LOAD_BALANCER"
              }
            ]
          }
        ],
        "regional_acls": [...]
      }
    ]
  }
]
```

### 关联资源字段说明

每个关联资源包含以下字段：

| 字段 | 说明 | 示例 |
|------|------|------|
| `arn` | 完整的资源 ARN | `arn:aws:elasticloadbalancing:us-east-1:...` |
| `partition` | AWS 分区 | `aws`, `aws-cn`, `aws-us-gov` |
| `service` | AWS 服务 | `elasticloadbalancing`, `cloudfront`, `apigateway` |
| `region` | AWS 区域 | `us-east-1`, `ap-northeast-1` |
| `account_id` | AWS 账户 ID | `275261018177` |
| `resource` | 资源标识符 | `loadbalancer/app/my-alb/...` |
| `resource_type` | 资源类型 | `loadbalancer/app`, `distribution` |
| `resource_id` | 资源 ID | `my-alb/1234567890abcdef` |
| `friendly_type` | 友好的资源类型名称 | `Application Load Balancer` |
| `resource_type_api` | AWS API 资源类型 | `APPLICATION_LOAD_BALANCER` |

## 调试和验证工具

### 工具 1：调试特定 Web ACL 的资源关联

**调试工具：`check_waf_resources.sh`**

当你发现某个 Web ACL 的资源关联不正确时，可以使用这个工具进行验证：

```bash
./check_waf_resources.sh <profile-name> <web-acl-name>
```

**示例：**
```bash
./check_waf_resources.sh AdministratorAccess-813923830882 waf-demo-juice-shop-for-xizhi
```

**这个工具会：**
1. 验证 AWS 访问权限
2. 查找指定的 Web ACL
3. 列出所有关联的资源（CloudFront、ALB 等）
4. 检查 CloudFront 分配的 WAF 关联情况

**使用场景：**
- ✅ 验证 WAF ACL 是否正确关联到资源
- ✅ 调试资源检测问题
- ✅ 快速检查单个 ACL 的状态

## 常见问题

### Q1: SSO Token 过期怎么办？
```bash
# 重新登录
aws sso login --profile AdministratorAccess-275261018177

# 然后重新运行脚本
python3 get_waf_config.py
```

### Q2: 如何只扫描生产环境账户？
```bash
# 只指定生产环境的 profile
python3 get_waf_config.py -p prod-account-1 prod-account-2
```

### Q3: 扫描很慢怎么办？
```bash
# 减少扫描的区域数量
python3 get_waf_config.py -r us-east-1 us-west-2

# 或者确保启用了并行模式（默认启用）
```

### Q4: 遇到权限错误？
检查你的权限集是否包含：
- `wafv2:ListWebACLs`
- `wafv2:GetWebACL`
- `sts:GetCallerIdentity`

### Q5: 如何获取 WAF Classic 的配置？
目前脚本只支持 WAF v2。如需 WAF Classic，需要修改代码使用 `waf` 和 `waf-regional` 客户端。

### Q6: 中国区域支持吗？
支持！只需在 `-r` 参数中指定中国区域：
```bash
python3 get_waf_config.py -r cn-north-1 cn-northwest-1 -p china-admin
```

### Q7: 支持哪些类型的关联资源？

工具自动检测以下 AWS 资源类型：

**CLOUDFRONT Scope**:
- CloudFront Distribution

**REGIONAL Scope**:
- Application Load Balancer (ALB)
- API Gateway REST API
- API Gateway HTTP/WebSocket API
- AWS AppSync GraphQL API
- Cognito User Pool
- AWS App Runner Service
- Verified Access Instance

### Q8: 为什么某些 Web ACL 显示 "无关联资源"？

可能的原因：
1. Web ACL 确实没有关联任何资源（可能是测试用的或待启用的）
2. 缺少必需的权限：
   - `wafv2:ListResourcesForWebACL` - 用于获取 Regional 资源
   - `cloudfront:ListDistributionsByWebACLId` - 用于获取 CloudFront 资源
3. 资源类型不在支持的列表中（较少见）

## 高级用法

### 定时任务
```bash
# 每天凌晨 2 点扫描
# 添加到 crontab
0 2 * * * cd /path/to/script && python3 get_waf_config.py -o daily_waf_$(date +\%Y\%m\%d).json
```

### 与其他工具集成
```python
import json

# 读取 WAF 配置
with open('waf_config.json', 'r') as f:
    waf_data = json.load(f)

# 自定义处理
for account in waf_data:
    # 你的逻辑
    pass
```

### 过滤特定资源
修改 `get_waf_config.py` 中的 `get_web_acls_in_region` 方法，添加过滤逻辑。

## 故障排查

### 日志级别
在脚本中添加调试信息：
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

### 测试单个账户
```bash
# 先测试单个账户单个区域
python3 get_waf_config.py \
  -p AdministratorAccess-275261018177 \
  -r us-east-1 \
  --no-parallel
```

## 安全建议

### ⚠️ 重要安全提醒

**输出文件包含敏感信息！**

WAF 工具生成的 JSON 文件包含：
- AWS 账户 ID
- 资源 ARN（包含账户、区域、资源 ID）
- Web ACL 配置详情
- 关联资源信息

ALB 工具生成的 JSON 文件包含：
- AWS 账户 ID
- ALB/NLB 配置详情（DNS、VPC、安全组）
- 监听器和目标组配置
- 目标健康状态（Full 模式）
- WAF 绑定信息

### 🔒 最佳实践

1. ⚠️ **不要将输出的 JSON 文件提交到 Git**
   ```bash
   # .gitignore 已配置忽略这些文件
   waf_config_*.json
   alb_config_*.json
   waf_*.csv
   alb_*.csv
   ```

2. ⚠️ **使用只读权限**
   - 工具只需要读取权限
   - 不需要 WAF 的写入权限
   - 建议使用自定义 IAM 策略限制权限

3. ⚠️ **定期轮换凭证**
   - 如果使用 IAM 用户，定期轮换访问密钥
   - SSO token 会自动过期（推荐）

4. ✅ **使用 SSO 而不是长期凭证**
   - 更安全的身份验证方式
   - 自动过期，减少凭证泄露风险
   - 便于集中管理访问权限

5. ✅ **限制访问范围**
   - 只扫描必要的账户和区域
   - 使用最小权限原则
   - 定期审计访问权限

### 🛡️ 分享代码前

如果要分享此代码给他人，**必须先清理敏感信息**：

```bash
# 删除所有包含敏感信息的输出文件
rm -f waf_config_*.json alb_config_*.json waf_*.csv alb_*.csv

# 检查 Git 状态，确保没有暂存敏感文件
git status
```

⚠️ **注意**：输出的 JSON 和 CSV 文件包含 AWS 账户 ID、资源 ARN、ALB 配置等敏感信息，不应提交到公开仓库。

## 贡献和反馈

如果你发现 bug 或有改进建议，欢迎反馈！

## 许可证

MIT License
