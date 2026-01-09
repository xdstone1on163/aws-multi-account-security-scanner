"""
WAF 资源关联检查模块
用于检查特定 Web ACL 的资源关联情况
完全替代 check_waf_resources.sh，纯 Python 实现，无需 jq
"""

import boto3
from typing import Dict, List, Optional
from colorama import init, Fore, Style

init(autoreset=True)  # Windows 兼容初始化


class ResourceChecker:
    """WAF 资源关联检查器（替代 check_waf_resources.sh）"""

    def __init__(self, profile: str, web_acl_name: str, region: str = 'us-east-1'):
        """
        初始化资源检查器

        Args:
            profile: AWS profile 名称
            web_acl_name: Web ACL 名称
            region: AWS 区域（默认 us-east-1，CloudFront 总是在此区域）
        """
        self.profile = profile
        self.web_acl_name = web_acl_name
        self.region = region
        self.session = boto3.Session(profile_name=profile)

    def verify_access(self) -> Optional[str]:
        """验证 AWS 访问权限（替代 check_waf_resources.sh:47-59）"""
        try:
            sts = self.session.client('sts')
            identity = sts.get_caller_identity()
            account_id = identity['Account']
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} 已认证，账户: {account_id}")
            return account_id
        except Exception as e:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} 无法访问 AWS API: {e}")
            print(f"\n{Fore.YELLOW}请先登录 AWS SSO:{Style.RESET_ALL}")
            print(f"  aws sso login --profile {self.profile}\n")
            return None

    def find_web_acl(self) -> Optional[Dict]:
        """查找指定的 Web ACL（替代 check_waf_resources.sh:77-86）"""
        wafv2 = self.session.client('wafv2', region_name=self.region)
        try:
            # 列出 CLOUDFRONT scope 的 Web ACL
            response = wafv2.list_web_acls(Scope='CLOUDFRONT')

            for acl in response.get('WebACLs', []):
                if acl['Name'] == self.web_acl_name:
                    print(f"  {Fore.GREEN}✓{Style.RESET_ALL} 找到 Web ACL")
                    print(f"  Name: {acl['Name']}")
                    print(f"  ID: {acl['Id']}")
                    print(f"  ARN: {acl['ARN']}")
                    return acl

            # 未找到，列出所有可用的 Web ACL
            print(f"  {Fore.RED}✗{Style.RESET_ALL} 未找到名为 '{self.web_acl_name}' 的 Web ACL\n")
            print(f"{Fore.YELLOW}可用的 Web ACLs:{Style.RESET_ALL}")
            if response.get('WebACLs'):
                for acl in response['WebACLs']:
                    print(f"  - {acl['Name']} (ID: {acl['Id']})")
            else:
                print(f"  {Fore.YELLOW}(没有找到任何 Web ACL){Style.RESET_ALL}")

            return None

        except Exception as e:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} 获取 Web ACL 列表失败: {e}")
            return None

    def list_associated_resources(self, web_acl_arn: str) -> List[str]:
        """列出关联的资源（替代 check_waf_resources.sh:97-116，无需 jq）"""
        wafv2 = self.session.client('wafv2', region_name=self.region)
        try:
            response = wafv2.list_resources_for_web_acl(
                WebACLArn=web_acl_arn,
                ResourceType='APPLICATION_LOAD_BALANCER'  # 先尝试 ALB
            )
            resources = response.get('ResourceArns', [])

            # 尝试其他资源类型（API Gateway, AppSync, etc.）
            resource_types = [
                'API_GATEWAY',
                'APPSYNC',
                'COGNITO_USER_POOL',
                'APP_RUNNER_SERVICE',
                'VERIFIED_ACCESS_INSTANCE'
            ]

            for resource_type in resource_types:
                try:
                    response = wafv2.list_resources_for_web_acl(
                        WebACLArn=web_acl_arn,
                        ResourceType=resource_type
                    )
                    resources.extend(response.get('ResourceArns', []))
                except Exception:
                    # 某些资源类型可能不支持
                    pass

            if resources:
                print(f"  {Fore.GREEN}✓{Style.RESET_ALL} 找到 {len(resources)} 个关联资源:")
                for arn in resources:
                    print(f"    - {arn}")
            else:
                print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL} 没有通过 WAFv2 API 找到直接关联的资源")
                print(f"    (某些资源类型如 CloudFront 需要单独检查)")

            return resources

        except Exception as e:
            print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL} 获取关联资源时出错: {e}")
            return []

    def check_cloudfront_distributions(self, web_acl_arn: str):
        """检查 CloudFront 分配（替代 check_waf_resources.sh:119-171）"""
        cf = self.session.client('cloudfront')
        try:
            # 使用 CloudFront API 直接查询（与 get_waf_config.py 一致）
            response = cf.list_distributions_by_web_acl_id(WebACLId=web_acl_arn)
            distribution_list = response.get('DistributionList', {})
            items = distribution_list.get('Items', [])

            if items:
                print(f"  {Fore.GREEN}✓{Style.RESET_ALL} 找到 {len(items)} 个 CloudFront 分配:")
                for dist in items:
                    print(f"    - ID: {dist['Id']}")
                    print(f"      Domain: {dist['DomainName']}")
                    print(f"      Status: {dist['Status']}")
                    print(f"      Enabled: {dist['Enabled']}")
                    print()
            else:
                print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL} 没有 CloudFront 分配使用此 Web ACL")

        except Exception as e:
            print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL} 无法检查 CloudFront 分配: {e}")

    def run(self):
        """执行完整的检查流程"""
        print(f"{Fore.BLUE}╔════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.BLUE}║       WAF Web ACL 资源关联检查工具                             ║{Style.RESET_ALL}")
        print(f"{Fore.BLUE}║       WAF Web ACL Resource Association Checker                 ║{Style.RESET_ALL}")
        print(f"{Fore.BLUE}╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

        print(f"{Fore.GREEN}配置信息:{Style.RESET_ALL}")
        print(f"  Profile: {self.profile}")
        print(f"  Web ACL: {self.web_acl_name}")
        print(f"  Region: {self.region}\n")

        # [1/4] 验证访问
        print(f"{Fore.BLUE}[1/4] 验证 AWS 访问权限...{Style.RESET_ALL}")
        account = self.verify_access()
        if not account:
            return

        print()

        # [2/4] 查找 Web ACL
        print(f"{Fore.BLUE}[2/4] 获取 Web ACL 详情...{Style.RESET_ALL}")
        acl = self.find_web_acl()
        if not acl:
            return

        print()

        # [3/4] 列出关联资源
        print(f"{Fore.BLUE}[3/4] 列出关联的资源（通过 WAFv2 API）...{Style.RESET_ALL}")
        resources = self.list_associated_resources(acl['ARN'])

        print()

        # [4/4] 检查 CloudFront
        print(f"{Fore.BLUE}[4/4] 检查 CloudFront 分配（通过 CloudFront API）...{Style.RESET_ALL}")
        self.check_cloudfront_distributions(acl['ARN'])

        print(f"\n{Fore.GREEN}检查完成！{Style.RESET_ALL}")
