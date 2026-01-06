#!/bin/bash
# 手动检查 WAF Web ACL 的关联资源
# 用于验证工具是否正确获取了资源

set -e

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}WAF Web ACL 资源关联检查工具${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# 检查参数
if [ $# -lt 2 ]; then
    echo -e "${YELLOW}用法:${NC}"
    echo "  $0 <profile-name> <web-acl-name>"
    echo ""
    echo -e "${YELLOW}示例:${NC}"
    echo "  $0 AdministratorAccess-813923830882 waf-demo-juice-shop-for-xizhi"
    echo ""
    exit 1
fi

PROFILE=$1
WEB_ACL_NAME=$2
REGION="us-east-1"  # CLOUDFRONT scope 的 WAF 总是在 us-east-1

echo -e "${GREEN}配置信息:${NC}"
echo "  Profile: $PROFILE"
echo "  Web ACL: $WEB_ACL_NAME"
echo "  Region: $REGION"
echo ""

# 检查 SSO 登录状态
echo -e "${BLUE}[1/4] 检查 SSO 登录状态...${NC}"
if aws sts get-caller-identity --profile "$PROFILE" &>/dev/null; then
    ACCOUNT_ID=$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text)
    echo -e "  ${GREEN}✓${NC} 已登录，账户: $ACCOUNT_ID"
else
    echo -e "  ${RED}✗${NC} 未登录或 token 过期"
    echo ""
    read -p "是否现在登录? (y/n) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        aws sso login --profile "$PROFILE"
    else
        exit 1
    fi
fi
echo ""

# 获取 Web ACL 详情
echo -e "${BLUE}[2/4] 获取 Web ACL 详情...${NC}"

# 列出所有 CLOUDFRONT scope 的 Web ACL
WEB_ACLS=$(aws wafv2 list-web-acls \
    --scope CLOUDFRONT \
    --region "$REGION" \
    --profile "$PROFILE" \
    --output json 2>/dev/null)

if [ $? -ne 0 ]; then
    echo -e "  ${RED}✗${NC} 获取 Web ACL 列表失败"
    exit 1
fi

# 查找指定的 Web ACL
WEB_ACL_ID=$(echo "$WEB_ACLS" | jq -r ".WebACLs[] | select(.Name==\"$WEB_ACL_NAME\") | .Id")
WEB_ACL_ARN=$(echo "$WEB_ACLS" | jq -r ".WebACLs[] | select(.Name==\"$WEB_ACL_NAME\") | .ARN")

if [ -z "$WEB_ACL_ID" ]; then
    echo -e "  ${RED}✗${NC} 未找到名为 '$WEB_ACL_NAME' 的 Web ACL"
    echo ""
    echo -e "${YELLOW}可用的 Web ACLs:${NC}"
    echo "$WEB_ACLS" | jq -r '.WebACLs[] | "  - \(.Name) (ID: \(.Id))"'
    exit 1
fi

echo -e "  ${GREEN}✓${NC} 找到 Web ACL"
echo "  Name: $WEB_ACL_NAME"
echo "  ID: $WEB_ACL_ID"
echo "  ARN: $WEB_ACL_ARN"
echo ""

# 列出关联的资源
echo -e "${BLUE}[3/4] 列出关联的资源...${NC}"

RESOURCES=$(aws wafv2 list-resources-for-web-acl \
    --web-acl-arn "$WEB_ACL_ARN" \
    --region "$REGION" \
    --profile "$PROFILE" \
    --output json 2>&1)

if [ $? -ne 0 ]; then
    echo -e "  ${RED}✗${NC} 获取关联资源失败"
    echo ""
    echo -e "${YELLOW}错误信息:${NC}"
    echo "$RESOURCES"
    echo ""
    echo -e "${YELLOW}可能的原因:${NC}"
    echo "  1. 权限不足（需要 wafv2:ListResourcesForWebACL）"
    echo "  2. Web ACL 确实没有关联任何资源"
    exit 1
fi

RESOURCE_ARNS=$(echo "$RESOURCES" | jq -r '.ResourceArns[]' 2>/dev/null)
RESOURCE_COUNT=$(echo "$RESOURCES" | jq -r '.ResourceArns | length' 2>/dev/null)

if [ "$RESOURCE_COUNT" = "0" ] || [ -z "$RESOURCE_ARNS" ]; then
    echo -e "  ${YELLOW}⚠${NC}  此 Web ACL 未关联任何资源"
    echo ""
    echo -e "${YELLOW}完整 API 响应:${NC}"
    echo "$RESOURCES" | jq '.'
    echo ""
    echo -e "${YELLOW}说明:${NC}"
    echo "  这个 Web ACL 存在，但没有关联到任何 CloudFront 分配"
    echo "  您可以在 CloudFront 控制台为分配启用 WAF"
else
    echo -e "  ${GREEN}✓${NC} 找到 $RESOURCE_COUNT 个关联资源"
    echo ""
    echo -e "${GREEN}关联的资源:${NC}"
    echo "$RESOURCE_ARNS" | while read -r arn; do
        if [ -n "$arn" ]; then
            echo "  - $arn"
        fi
    done
fi
echo ""

# 检查 CloudFront 分配
echo -e "${BLUE}[4/4] 检查 CloudFront 分配...${NC}"

# 列出所有 CloudFront 分配
DISTRIBUTIONS=$(aws cloudfront list-distributions \
    --profile "$PROFILE" \
    --output json 2>/dev/null)

if [ $? -ne 0 ]; then
    echo -e "  ${YELLOW}⚠${NC}  无法列出 CloudFront 分配（可能没有权限）"
else
    DIST_COUNT=$(echo "$DISTRIBUTIONS" | jq -r '.DistributionList.Items | length' 2>/dev/null || echo "0")
    echo -e "  ${GREEN}✓${NC} 找到 $DIST_COUNT 个 CloudFront 分配"

    if [ "$DIST_COUNT" -gt 0 ]; then
        echo ""
        echo -e "${BLUE}检查哪些分配使用了此 Web ACL...${NC}"

        echo "$DISTRIBUTIONS" | jq -r '.DistributionList.Items[] | "\(.Id)|\(.DomainName)|\(.WebACLId // "none")"' | \
        while IFS='|' read -r dist_id domain web_acl_id; do
            if [ "$web_acl_id" = "$WEB_ACL_ARN" ] || [ "$web_acl_id" = "$WEB_ACL_ID" ]; then
                echo -e "  ${GREEN}✓${NC} 分配 $dist_id ($domain) 使用此 Web ACL"
            elif [ "$web_acl_id" = "none" ]; then
                echo -e "  ${YELLOW}-${NC} 分配 $dist_id ($domain) 未启用 WAF"
            fi
        done
    fi
fi

echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}检查完成${NC}"
echo -e "${BLUE}========================================${NC}"
