#!/bin/bash
# AWS WAF 配置提取工具 - 一站式扫描脚本
# 整合了环境检查、SSO 登录和配置扫描功能

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# 配置文件路径
CONFIG_FILE="waf_scan_config.json"

# 显示横幅
show_banner() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║       AWS WAF Multi-Account Configuration Scanner             ║${NC}"
    echo -e "${BLUE}║       AWS WAF 多账户配置扫描工具                                ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# 检查环境
check_environment() {
    echo -e "${CYAN}[1/6] 检查环境依赖...${NC}"

    local all_ok=true

    # 检查 Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version)
        echo -e "  ${GREEN}✓${NC} Python: $PYTHON_VERSION"
    else
        echo -e "  ${RED}✗${NC} Python 3 未安装"
        all_ok=false
    fi

    # 检查 boto3
    if python3 -c "import boto3" 2>/dev/null; then
        BOTO3_VERSION=$(python3 -c "import boto3; print(boto3.__version__)")
        echo -e "  ${GREEN}✓${NC} boto3: $BOTO3_VERSION"
    else
        echo -e "  ${RED}✗${NC} boto3 未安装"
        echo ""
        read -p "  是否现在安装 boto3? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "  ${CYAN}正在安装 boto3...${NC}"
            pip3 install boto3
            echo -e "  ${GREEN}✓${NC} boto3 安装完成"
        else
            echo -e "  ${YELLOW}请手动安装: pip3 install boto3${NC}"
            all_ok=false
        fi
    fi

    # 检查 AWS CLI
    if command -v aws &> /dev/null; then
        AWS_VERSION=$(aws --version 2>&1 | cut -d' ' -f1)
        echo -e "  ${GREEN}✓${NC} AWS CLI: $AWS_VERSION"
    else
        echo -e "  ${RED}✗${NC} AWS CLI 未安装"
        echo -e "  ${YELLOW}请访问: https://aws.amazon.com/cli/${NC}"
        all_ok=false
    fi

    echo ""

    if [ "$all_ok" = false ]; then
        echo -e "${RED}环境检查失败，请先安装缺失的依赖${NC}"
        exit 1
    fi
}

# 检查配置文件
check_config_file() {
    echo -e "${CYAN}[2/6] 检查配置文件...${NC}"

    if [ -f "$CONFIG_FILE" ]; then
        echo -e "  ${GREEN}✓${NC} 配置文件存在: $CONFIG_FILE"

        # 读取并显示配置信息
        PROFILE_COUNT=$(python3 -c "import json; f=open('$CONFIG_FILE'); c=json.load(f); print(len(c.get('profiles', [])))" 2>/dev/null || echo "0")
        REGION_COUNT=$(python3 -c "import json; f=open('$CONFIG_FILE'); c=json.load(f); print(len(c.get('regions', {}).get('common', [])))" 2>/dev/null || echo "0")

        echo -e "  ${GREEN}✓${NC} 配置的 AWS Profiles: $PROFILE_COUNT 个"
        echo -e "  ${GREEN}✓${NC} 默认扫描区域: $REGION_COUNT 个"

        CONFIG_EXISTS=true
    else
        echo -e "  ${YELLOW}⚠${NC}  配置文件不存在: $CONFIG_FILE"
        echo -e "  ${YELLOW}提示: 复制 waf_scan_config.json.example 并修改配置${NC}"
        CONFIG_EXISTS=false
    fi
    echo ""
}

# 检查 AWS 配置和 SSO 登录状态
check_aws_sso() {
    echo -e "${CYAN}[3/6] 检查 AWS 配置...${NC}"

    if [ ! -f ~/.aws/config ]; then
        echo -e "  ${RED}✗${NC} AWS 配置文件不存在"
        echo -e "  ${YELLOW}请先运行: aws configure sso${NC}"
        exit 1
    fi

    echo -e "  ${GREEN}✓${NC} AWS 配置文件存在"

    # 尝试列出 SSO profiles
    SSO_PROFILES=$(aws configure list-profiles 2>/dev/null | grep -i "administrator" || true)

    if [ -n "$SSO_PROFILES" ]; then
        PROFILE_COUNT=$(echo "$SSO_PROFILES" | wc -l | tr -d ' ')
        echo -e "  ${GREEN}✓${NC} 发现 $PROFILE_COUNT 个 SSO profiles"
    else
        echo -e "  ${YELLOW}⚠${NC}  未发现 SSO profiles"
    fi

    echo ""
}

# 检查 SSO 登录状态
check_sso_login() {
    echo -e "${CYAN}[4/6] 检查 SSO 登录状态...${NC}"

    # 尝试从配置文件获取第一个 profile
    if [ "$CONFIG_EXISTS" = true ]; then
        FIRST_PROFILE=$(python3 -c "import json; f=open('$CONFIG_FILE'); c=json.load(f); print(c.get('profiles', [''])[0])" 2>/dev/null || echo "")
    fi

    # 如果配置文件没有，从 AWS CLI 配置获取
    if [ -z "$FIRST_PROFILE" ]; then
        FIRST_PROFILE=$(aws configure list-profiles 2>/dev/null | grep -i "administratoraccess" | head -1 || echo "")
    fi

    if [ -z "$FIRST_PROFILE" ]; then
        echo -e "  ${YELLOW}⚠${NC}  未找到 SSO profile，将跳过登录检查"
        SSO_LOGGED_IN=false
        echo ""
        return
    fi

    if aws sts get-caller-identity --profile "$FIRST_PROFILE" &>/dev/null; then
        ACCOUNT_ID=$(aws sts get-caller-identity --profile "$FIRST_PROFILE" --query Account --output text)
        echo -e "  ${GREEN}✓${NC} SSO 已登录"
        echo -e "  ${GREEN}✓${NC} 测试账户: $ACCOUNT_ID (使用 profile: $FIRST_PROFILE)"
        SSO_LOGGED_IN=true
    else
        echo -e "  ${YELLOW}⚠${NC}  SSO 未登录或 token 已过期"
        echo ""
        read -p "  是否现在登录 AWS SSO? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo -e "  ${CYAN}正在登录...${NC}"
            aws sso login --profile "$FIRST_PROFILE"
            echo -e "  ${GREEN}✓${NC} 登录成功"
            SSO_LOGGED_IN=true
        else
            echo -e "  ${YELLOW}跳过登录，你可以稍后手动登录:${NC}"
            echo -e "  ${YELLOW}aws sso login --profile $FIRST_PROFILE${NC}"
            SSO_LOGGED_IN=false
        fi
    fi

    echo ""
}

# 检查工具脚本
check_scripts() {
    echo -e "${CYAN}[5/6] 检查工具脚本...${NC}"

    if [ -f "get_waf_config.py" ]; then
        echo -e "  ${GREEN}✓${NC} get_waf_config.py"
        chmod +x get_waf_config.py 2>/dev/null || true
    else
        echo -e "  ${RED}✗${NC} get_waf_config.py 不存在"
        exit 1
    fi

    if [ -f "analyze_waf_config.py" ]; then
        echo -e "  ${GREEN}✓${NC} analyze_waf_config.py"
        chmod +x analyze_waf_config.py 2>/dev/null || true
    else
        echo -e "  ${YELLOW}⚠${NC}  analyze_waf_config.py 不存在（可选）"
    fi

    echo ""
}

# 显示扫描选项
show_scan_options() {
    echo -e "${CYAN}[6/6] 准备扫描...${NC}"
    echo ""
    echo -e "${BLUE}请选择扫描模式:${NC}"
    echo ""
    echo -e "  ${GREEN}1)${NC} 快速扫描 - 使用配置文件（推荐）"
    echo -e "     自动使用 waf_scan_config.json 中的 profiles 和区域"
    echo ""
    echo -e "  ${GREEN}2)${NC} 快速测试 - 单账户单区域"
    echo -e "     仅扫描一个账户的 us-east-1 区域（最快）"
    echo ""
    echo -e "  ${GREEN}3)${NC} 自定义扫描 - 指定参数"
    echo -e "     手动指定要扫描的 profiles 和区域"
    echo ""
    echo -e "  ${GREEN}4)${NC} 调试模式扫描"
    echo -e "     启用详细日志，查看资源获取过程"
    echo ""
    echo -e "  ${GREEN}5)${NC} 查看帮助"
    echo ""
    echo -e "  ${GREEN}0)${NC} 退出"
    echo ""
}

# 执行扫描
execute_scan() {
    local mode=$1

    case $mode in
        1)
            echo -e "${CYAN}执行快速扫描（使用配置文件）...${NC}"
            echo -e "${YELLOW}命令: python3 get_waf_config.py${NC}"
            echo ""
            python3 get_waf_config.py
            ;;
        2)
            echo -e "${CYAN}执行快速测试扫描...${NC}"
            if [ -n "$FIRST_PROFILE" ]; then
                echo -e "${YELLOW}命令: python3 get_waf_config.py -p $FIRST_PROFILE -r us-east-1${NC}"
                echo ""
                python3 get_waf_config.py -p "$FIRST_PROFILE" -r us-east-1
            else
                echo -e "${RED}错误: 未找到可用的 AWS profile${NC}"
                exit 1
            fi
            ;;
        3)
            echo -e "${CYAN}自定义扫描${NC}"
            echo ""
            read -p "请输入 profile 名称（留空使用配置文件）: " CUSTOM_PROFILE
            read -p "请输入区域列表（用空格分隔，留空使用配置文件）: " CUSTOM_REGIONS

            CMD="python3 get_waf_config.py"
            if [ -n "$CUSTOM_PROFILE" ]; then
                CMD="$CMD -p $CUSTOM_PROFILE"
            fi
            if [ -n "$CUSTOM_REGIONS" ]; then
                CMD="$CMD -r $CUSTOM_REGIONS"
            fi

            echo ""
            echo -e "${YELLOW}命令: $CMD${NC}"
            echo ""
            eval $CMD
            ;;
        4)
            echo -e "${CYAN}执行调试模式扫描（使用配置文件）...${NC}"
            echo -e "${YELLOW}命令: python3 get_waf_config.py --debug${NC}"
            echo ""
            python3 get_waf_config.py --debug
            ;;
        5)
            echo ""
            python3 get_waf_config.py --help
            echo ""
            return
            ;;
        0)
            echo -e "${GREEN}退出${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}无效的选项${NC}"
            return
            ;;
    esac

    # 扫描完成后的提示
    if [ $? -eq 0 ]; then
        echo ""
        echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║              扫描完成！                                         ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
        echo ""

        # 查找最新的 JSON 文件
        LATEST_JSON=$(ls -t waf_config_*.json 2>/dev/null | head -1)
        if [ -n "$LATEST_JSON" ]; then
            echo -e "${CYAN}分析扫描结果:${NC}"
            echo ""
            echo -e "  # 查看所有 Web ACL"
            echo -e "  python3 analyze_waf_config.py $LATEST_JSON --list"
            echo ""
            echo -e "  # 分析关联资源"
            echo -e "  python3 analyze_waf_config.py $LATEST_JSON --resources"
            echo ""
            echo -e "  # 完整分析（规则+资源）"
            echo -e "  python3 analyze_waf_config.py $LATEST_JSON"
            echo ""
            echo -e "  # 导出为 CSV"
            echo -e "  python3 analyze_waf_config.py $LATEST_JSON --csv report.csv"
            echo ""
        fi
    else
        echo ""
        echo -e "${RED}扫描失败，请检查错误信息${NC}"
    fi
}

# 主函数
main() {
    show_banner

    # 执行所有检查
    check_environment
    check_config_file
    check_aws_sso
    check_sso_login
    check_scripts

    # 如果 SSO 未登录，给出提示
    if [ "$SSO_LOGGED_IN" = false ]; then
        echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
        echo -e "${YELLOW}⚠  警告: SSO 未登录，扫描可能会失败${NC}"
        echo -e "${YELLOW}════════════════════════════════════════════════════════════════${NC}"
        echo ""

        if [ -n "$FIRST_PROFILE" ]; then
            echo -e "${YELLOW}建议先登录:${NC}"
            echo -e "  aws sso login --profile $FIRST_PROFILE"
            echo ""
        fi

        read -p "是否继续？(y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 0
        fi
        echo ""
    fi

    # 显示扫描选项并执行
    while true; do
        show_scan_options
        read -p "请选择 [0-5]: " choice
        echo ""

        execute_scan "$choice"

        # 如果选择了退出或帮助，继续循环
        if [ "$choice" = "0" ] || [ "$choice" = "5" ]; then
            continue
        else
            # 其他选项执行完后询问是否继续
            echo ""
            read -p "是否执行其他操作？(y/n) " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                echo ""
                echo -e "${GREEN}感谢使用 AWS WAF 配置扫描工具！${NC}"
                exit 0
            fi
            echo ""
        fi
    done
}

# 运行主函数
main
