#!/usr/bin/env python3
"""
AWS Multi-Account WAF Configuration Extractor

从多个 AWS member account 中获取 WAF v2 的 Web ACL 配置
使用 AWS Identity Center (SSO) 进行认证
"""

import boto3
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse


def load_config_file(config_path: str = 'waf_scan_config.json') -> Optional[Dict]:
    """
    从配置文件加载扫描配置

    Args:
        config_path: 配置文件路径

    Returns:
        配置字典，如果文件不存在则返回 None
    """
    if not os.path.exists(config_path):
        return None

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
        return config
    except Exception as e:
        print(f"⚠️  警告: 无法读取配置文件 {config_path}: {str(e)}")
        return None


class WAFConfigExtractor:
    """WAF 配置提取器"""

    # 常用的 AWS 区域列表
    COMMON_REGIONS = [
        'us-east-1',      # 美东（弗吉尼亚北部）
        'us-west-2',      # 美西（俄勒冈）
        'ap-northeast-1', # 亚太（东京）
        'ap-southeast-1', # 亚太（新加坡）
        'eu-west-1',      # 欧洲（爱尔兰）
        'eu-central-1',   # 欧洲（法兰克福）
    ]

    def __init__(self, profile_names: List[str], regions: List[str] = None, debug: bool = False):
        """
        初始化提取器

        Args:
            profile_names: SSO profile 名称列表
            regions: 要扫描的区域列表，默认使用 COMMON_REGIONS
            debug: 是否启用调试模式
        """
        self.profile_names = profile_names
        self.regions = regions or self.COMMON_REGIONS
        self.results = []
        self.debug = debug

    def get_account_info(self, session: boto3.Session) -> Dict[str, str]:
        """获取账户信息"""
        try:
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            return {
                'account_id': identity['Account'],
                'arn': identity['Arn'],
                'user_id': identity['UserId']
            }
        except Exception as e:
            return {'error': str(e)}

    def parse_resource_arn(self, arn: str) -> Dict[str, str]:
        """
        解析 AWS 资源 ARN，提取资源类型和名称

        Args:
            arn: AWS 资源 ARN

        Returns:
            包含资源类型、名称等信息的字典
        """
        try:
            # ARN 格式: arn:partition:service:region:account-id:resource-type/resource-id
            parts = arn.split(':')

            resource_info = {
                'arn': arn,
                'partition': parts[1] if len(parts) > 1 else '',
                'service': parts[2] if len(parts) > 2 else '',
                'region': parts[3] if len(parts) > 3 else '',
                'account_id': parts[4] if len(parts) > 4 else '',
                'resource': parts[5] if len(parts) > 5 else ''
            }

            # 解析资源类型和 ID
            if '/' in resource_info['resource']:
                resource_parts = resource_info['resource'].split('/', 1)
                resource_info['resource_type'] = resource_parts[0]
                resource_info['resource_id'] = resource_parts[1]
            else:
                resource_info['resource_type'] = resource_info['resource']
                resource_info['resource_id'] = ''

            # 根据服务类型提供友好的资源类型名称
            service_type_map = {
                'elasticloadbalancing': {
                    'loadbalancer/app': 'Application Load Balancer',
                    'loadbalancer/net': 'Network Load Balancer',
                    'loadbalancer': 'Classic Load Balancer'
                },
                'apigateway': {
                    'restapis': 'REST API',
                    'apis': 'HTTP/WebSocket API'
                },
                'appsync': {
                    'apis': 'GraphQL API'
                },
                'cloudfront': {
                    'distribution': 'CloudFront Distribution'
                },
                'cognito-idp': {
                    'userpool': 'Cognito User Pool'
                },
                'app-runner': {
                    'service': 'App Runner Service'
                },
                'verified-access': {
                    'instance': 'Verified Access Instance'
                }
            }

            service = resource_info['service']
            resource_type = resource_info['resource_type']

            if service in service_type_map and resource_type in service_type_map[service]:
                resource_info['friendly_type'] = service_type_map[service][resource_type]
            else:
                # 通用处理：将资源类型转换为友好名称
                resource_info['friendly_type'] = resource_type.replace('-', ' ').title()

            return resource_info

        except Exception as e:
            return {
                'arn': arn,
                'error': f'Failed to parse ARN: {str(e)}'
            }

    def get_associated_resources(self, wafv2_client, web_acl_arn: str, scope: str, debug: bool = False) -> List[Dict]:
        """
        获取 Web ACL 关联的 AWS 资源

        Args:
            wafv2_client: WAFv2 客户端
            web_acl_arn: Web ACL 的 ARN
            scope: CLOUDFRONT 或 REGIONAL
            debug: 是否显示调试信息

        Returns:
            关联资源列表
        """
        associated_resources = []

        # 如果是 CLOUDFRONT scope，获取 CloudFront 分配
        if scope == 'CLOUDFRONT':
            try:
                if debug:
                    print(f"      [DEBUG] 尝试获取 CLOUDFRONT 资源...")
                response = wafv2_client.list_resources_for_web_acl(
                    WebACLArn=web_acl_arn,
                    ResourceType='CLOUDFRONT'
                )
                resource_arns = response.get('ResourceArns', [])
                if debug:
                    print(f"      [DEBUG] 找到 {len(resource_arns)} 个 CLOUDFRONT 资源")
                for resource_arn in resource_arns:
                    resource_info = self.parse_resource_arn(resource_arn)
                    resource_info['resource_type_api'] = 'CLOUDFRONT'
                    associated_resources.append(resource_info)
            except Exception as e:
                if debug:
                    print(f"      [DEBUG] 获取 CLOUDFRONT 资源失败: {str(e)}")

        # 如果是 REGIONAL scope，获取所有支持的资源类型
        if scope == 'REGIONAL':
            resource_types = [
                'APPLICATION_LOAD_BALANCER',
                'API_GATEWAY',
                'APPSYNC',
                'APP_RUNNER_SERVICE',
                'COGNITO_USER_POOL',
                'VERIFIED_ACCESS_INSTANCE'
            ]

            for resource_type in resource_types:
                try:
                    if debug:
                        print(f"      [DEBUG] 尝试获取 {resource_type} 资源...")
                    response = wafv2_client.list_resources_for_web_acl(
                        WebACLArn=web_acl_arn,
                        ResourceType=resource_type
                    )
                    resource_arns = response.get('ResourceArns', [])
                    if debug and len(resource_arns) > 0:
                        print(f"      [DEBUG] 找到 {len(resource_arns)} 个 {resource_type} 资源")
                    for resource_arn in resource_arns:
                        resource_info = self.parse_resource_arn(resource_arn)
                        resource_info['resource_type_api'] = resource_type
                        associated_resources.append(resource_info)
                except Exception as e:
                    if debug:
                        print(f"      [DEBUG] 获取 {resource_type} 资源失败: {str(e)}")

        return associated_resources

    def get_web_acls_in_region(self, session: boto3.Session, region: str, scope: str) -> List[Dict]:
        """
        在指定区域获取 Web ACL 列表

        Args:
            session: boto3 会话
            region: AWS 区域
            scope: CLOUDFRONT 或 REGIONAL
        """
        web_acls = []

        try:
            wafv2 = session.client('wafv2', region_name=region)

            # 列出所有 Web ACL
            response = wafv2.list_web_acls(Scope=scope)

            for acl_summary in response.get('WebACLs', []):
                try:
                    # 获取详细配置
                    acl_detail = wafv2.get_web_acl(
                        Name=acl_summary['Name'],
                        Scope=scope,
                        Id=acl_summary['Id']
                    )

                    # 获取关联的资源
                    web_acl_arn = acl_summary.get('ARN')
                    associated_resources = []
                    if web_acl_arn:
                        associated_resources = self.get_associated_resources(
                            wafv2, web_acl_arn, scope, self.debug
                        )

                    web_acl_data = {
                        'summary': acl_summary,
                        'detail': acl_detail.get('WebACL', {}),
                        'lock_token': acl_detail.get('LockToken'),
                        'associated_resources': associated_resources
                    }

                    # 在摘要信息中添加资源数量
                    resource_count = len(associated_resources)
                    if resource_count > 0:
                        print(f"    ✓ 获取到 Web ACL: {acl_summary['Name']} ({resource_count} 个关联资源)")
                    else:
                        print(f"    ✓ 获取到 Web ACL: {acl_summary['Name']} (无关联资源)")

                    web_acls.append(web_acl_data)

                except Exception as e:
                    print(f"    ✗ 获取 Web ACL {acl_summary['Name']} 详情失败: {str(e)}")
                    web_acls.append({
                        'summary': acl_summary,
                        'error': str(e)
                    })

        except Exception as e:
            error_msg = str(e)
            # 如果是权限错误或资源不存在，记录但不中断
            if 'AccessDenied' in error_msg or 'UnauthorizedOperation' in error_msg:
                print(f"    - 无权限访问 {region} ({scope})")
            else:
                print(f"    ✗ 扫描 {region} ({scope}) 失败: {error_msg}")

        return web_acls

    def scan_account(self, profile_name: str) -> Dict[str, Any]:
        """
        扫描单个账户的所有区域

        Args:
            profile_name: AWS CLI profile 名称
        """
        print(f"\n{'='*80}")
        print(f"正在扫描账户: {profile_name}")
        print(f"{'='*80}")

        account_result = {
            'profile': profile_name,
            'scan_time': datetime.utcnow().isoformat(),
            'regions': []
        }

        try:
            # 创建会话
            session = boto3.Session(profile_name=profile_name)

            # 获取账户信息
            account_info = self.get_account_info(session)
            account_result['account_info'] = account_info

            if 'error' in account_info:
                print(f"✗ 无法获取账户信息: {account_info['error']}")
                return account_result

            print(f"✓ 账户 ID: {account_info['account_id']}")

            # 扫描每个区域
            for region in self.regions:
                print(f"\n  扫描区域: {region}")

                region_result = {
                    'region': region,
                    'cloudfront_acls': [],
                    'regional_acls': []
                }

                # CLOUDFRONT scope (只在 us-east-1 有效)
                if region == 'us-east-1':
                    print(f"    检查 CLOUDFRONT scope...")
                    region_result['cloudfront_acls'] = self.get_web_acls_in_region(
                        session, region, 'CLOUDFRONT'
                    )

                # REGIONAL scope
                print(f"    检查 REGIONAL scope...")
                region_result['regional_acls'] = self.get_web_acls_in_region(
                    session, region, 'REGIONAL'
                )

                # 只保存有 ACL 的区域
                if region_result['cloudfront_acls'] or region_result['regional_acls']:
                    account_result['regions'].append(region_result)

        except Exception as e:
            account_result['error'] = str(e)
            print(f"✗ 扫描账户失败: {str(e)}")

        return account_result

    def scan_all_accounts(self, parallel: bool = True) -> List[Dict]:
        """
        扫描所有配置的账户

        Args:
            parallel: 是否并行扫描多个账户
        """
        print(f"\n开始扫描 {len(self.profile_names)} 个账户...")
        print(f"扫描区域: {', '.join(self.regions)}")

        if parallel and len(self.profile_names) > 1:
            # 并行扫描
            with ThreadPoolExecutor(max_workers=3) as executor:
                futures = {
                    executor.submit(self.scan_account, profile): profile
                    for profile in self.profile_names
                }

                for future in as_completed(futures):
                    profile = futures[future]
                    try:
                        result = future.result()
                        self.results.append(result)
                    except Exception as e:
                        print(f"✗ 处理 {profile} 时出错: {str(e)}")
        else:
            # 串行扫描
            for profile in self.profile_names:
                result = self.scan_account(profile)
                self.results.append(result)

        return self.results

    def save_results(self, output_file: str = None):
        """保存结果到 JSON 文件"""
        if not output_file:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f'waf_config_{timestamp}.json'

        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.results, f, indent=2, ensure_ascii=False, default=str)

        print(f"\n{'='*80}")
        print(f"✓ 结果已保存到: {output_file}")
        print(f"{'='*80}")

        return output_file

    def print_summary(self):
        """打印扫描摘要"""
        print(f"\n{'='*80}")
        print("扫描摘要")
        print(f"{'='*80}")

        total_acls = 0
        total_resources = 0

        for account in self.results:
            account_id = account.get('account_info', {}).get('account_id', 'Unknown')
            print(f"\n账户 {account_id} ({account['profile']}):")

            for region_data in account.get('regions', []):
                cloudfront_acls = region_data.get('cloudfront_acls', [])
                regional_acls = region_data.get('regional_acls', [])

                cloudfront_count = len(cloudfront_acls)
                regional_count = len(regional_acls)

                if cloudfront_count > 0:
                    # 统计 CloudFront ACL 关联的资源
                    cf_resources = sum(len(acl.get('associated_resources', [])) for acl in cloudfront_acls)
                    print(f"  - {region_data['region']} (CLOUDFRONT): {cloudfront_count} 个 Web ACL, {cf_resources} 个关联资源")
                    total_acls += cloudfront_count
                    total_resources += cf_resources

                if regional_count > 0:
                    # 统计 Regional ACL 关联的资源
                    reg_resources = sum(len(acl.get('associated_resources', [])) for acl in regional_acls)
                    print(f"  - {region_data['region']} (REGIONAL): {regional_count} 个 Web ACL, {reg_resources} 个关联资源")
                    total_acls += regional_count
                    total_resources += reg_resources

        print(f"\n总计: {total_acls} 个 Web ACL, {total_resources} 个关联资源")


def main():
    parser = argparse.ArgumentParser(
        description='从多个 AWS 账户提取 WAF 配置',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例用法:

  # 使用配置文件 waf_scan_config.json（推荐）
  python3 get_waf_config.py

  # 扫描特定 profile
  python3 get_waf_config.py -p AdministratorAccess-275261018177

  # 扫描多个 profile
  python3 get_waf_config.py -p profile1 profile2 profile3

  # 只扫描特定区域（命令行参数优先于配置文件）
  python3 get_waf_config.py -r us-east-1 us-west-2

  # 使用配置文件的 profiles，但指定区域
  python3 get_waf_config.py -r us-east-1

  # 启用调试模式查看详细信息
  python3 get_waf_config.py --debug

  # 指定输出文件
  python3 get_waf_config.py -o my_waf_report.json

  # 串行扫描（不并行）
  python3 get_waf_config.py --no-parallel

配置文件:
  默认读取当前目录下的 waf_scan_config.json
  如果不存在，请复制 waf_scan_config.json.example 并修改
  命令行参数优先级高于配置文件
        """
    )

    parser.add_argument(
        '-p', '--profiles',
        nargs='+',
        help='要扫描的 AWS CLI profile 名称（默认从 waf_scan_config.json 读取）'
    )

    parser.add_argument(
        '-r', '--regions',
        nargs='+',
        help='要扫描的 AWS 区域列表（默认从配置文件读取 common 区域组）'
    )

    parser.add_argument(
        '-o', '--output',
        help='输出文件路径（默认: waf_config_YYYYMMDD_HHMMSS.json）'
    )

    parser.add_argument(
        '--no-parallel',
        action='store_true',
        help='禁用并行扫描'
    )

    parser.add_argument(
        '--debug',
        action='store_true',
        help='启用调试模式，显示详细的资源获取信息'
    )

    args = parser.parse_args()

    # 尝试从配置文件加载默认配置
    config = load_config_file()

    # 确定要使用的 profiles
    if args.profiles:
        profiles = args.profiles
    elif config and 'profiles' in config:
        # 从配置文件读取 profiles
        profiles = config['profiles']
        print(f"✓ 从配置文件加载了 {len(profiles)} 个 AWS profiles")
    else:
        # 如果既没有命令行参数，也没有配置文件
        print("❌ 错误: 未指定要扫描的 AWS profile")
        print("\n请选择以下方式之一:")
        print("  1. 使用命令行参数: python3 get_waf_config.py -p your-profile-name")
        print("  2. 创建配置文件: 复制 waf_scan_config.json.example 为 waf_scan_config.json 并配置")
        print("\n示例:")
        print("  python3 get_waf_config.py -p profile1 profile2 profile3")
        print("  python3 get_waf_config.py  # 使用配置文件中的 profiles")
        import sys
        sys.exit(1)

    # 确定要使用的区域
    if args.regions:
        regions = args.regions
    elif config and 'regions' in config and 'common' in config['regions']:
        # 从配置文件读取默认区域（使用 common 区域组）
        regions = config['regions']['common']
        print(f"✓ 从配置文件加载了 {len(regions)} 个扫描区域")
    else:
        # 使用代码中定义的默认区域
        regions = None

    # 创建提取器
    extractor = WAFConfigExtractor(
        profile_names=profiles,
        regions=regions,
        debug=args.debug
    )

    # 执行扫描
    try:
        extractor.scan_all_accounts(parallel=not args.no_parallel)
        extractor.print_summary()
        extractor.save_results(args.output)

    except KeyboardInterrupt:
        print("\n\n用户中断扫描")
        if extractor.results:
            print("保存已完成的部分结果...")
            extractor.save_results(args.output)
    except Exception as e:
        print(f"\n✗ 发生错误: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
