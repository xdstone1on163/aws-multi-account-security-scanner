#!/usr/bin/env python3
"""
AWS WAF 多账户配置工具 - 统一 CLI 入口
支持 Windows/macOS/Linux 跨平台

这是新的统一入口点，提供子命令架构：
- scan: 扫描 WAF 配置
- analyze: 分析结果
- check: 检查资源关联
- check-env: 检查环境依赖
"""

import sys
import argparse
import platform
import subprocess
from colorama import init, Fore, Style

# 从 core 模块导入
from core.waf_environment import EnvironmentChecker
from core.waf_interactive import InteractiveMenu
from core.waf_resource_checker import ResourceChecker

init(autoreset=True)  # Windows 兼容初始化


def main():
    parser = argparse.ArgumentParser(
        description='AWS WAF 多账户配置工具 - 跨平台统一 CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
示例:
  # 交互式扫描（推荐）
  python waf_cli.py scan --interactive

  # 使用配置文件扫描
  python waf_cli.py scan

  # 指定 profile 扫描
  python waf_cli.py scan -p AdministratorAccess-813923830882

  # 指定多个 profile 和区域
  python waf_cli.py scan -p profile1 profile2 -r us-east-1 us-west-2

  # 分析结果
  python waf_cli.py analyze waf_config_20260107.json --list

  # 检查资源关联
  python waf_cli.py check AdministratorAccess-813923830882 waf-demo-juice-shop

  # 检查环境
  python waf_cli.py check-env

更多信息: https://github.com/your-repo/waf-config-tool
        '''
    )

    subparsers = parser.add_subparsers(dest='command', help='子命令')

    # ===== scan 子命令 =====
    scan_parser = subparsers.add_parser('scan', help='扫描 WAF 配置')
    scan_parser.add_argument(
        '--interactive', '-i', action='store_true',
        help='交互式模式（类似 unix/waf_scan.sh）'
    )
    scan_parser.add_argument(
        '-p', '--profiles', nargs='+',
        help='AWS profile 名称（多个用空格分隔）'
    )
    scan_parser.add_argument(
        '-r', '--regions', nargs='+',
        help='AWS 区域（多个用空格分隔）'
    )
    scan_parser.add_argument(
        '-o', '--output',
        help='输出文件名'
    )
    scan_parser.add_argument(
        '--debug', action='store_true',
        help='调试模式'
    )
    scan_parser.add_argument(
        '--no-parallel', action='store_true',
        help='禁用并行扫描'
    )

    # ===== analyze 子命令 =====
    analyze_parser = subparsers.add_parser('analyze', help='分析 WAF 配置')
    analyze_parser.add_argument('json_file', help='配置 JSON 文件')
    analyze_parser.add_argument('--list', action='store_true', help='列出所有 ACL')
    analyze_parser.add_argument('--analyze', action='store_true', help='规则统计')
    analyze_parser.add_argument('--resources', action='store_true', help='资源分析')
    analyze_parser.add_argument('--search', metavar='PATTERN', help='搜索特定 ACL')
    analyze_parser.add_argument('--csv', metavar='FILE', help='导出为 CSV')

    # ===== check 子命令 =====
    check_parser = subparsers.add_parser('check', help='检查资源关联')
    check_parser.add_argument('profile', help='AWS profile 名称')
    check_parser.add_argument('web_acl_name', help='Web ACL 名称')
    check_parser.add_argument(
        '-r', '--region', default='us-east-1',
        help='AWS 区域（默认: us-east-1）'
    )

    # ===== check-env 子命令 =====
    subparsers.add_parser('check-env', help='检查环境依赖')

    args = parser.parse_args()

    # ===== 命令分发 =====
    if args.command == 'scan':
        handle_scan_command(args)
    elif args.command == 'analyze':
        handle_analyze_command(args)
    elif args.command == 'check':
        handle_check_command(args)
    elif args.command == 'check-env':
        handle_check_env_command()
    else:
        parser.print_help()
        sys.exit(1)


def handle_scan_command(args):
    """处理 scan 子命令"""
    if args.interactive:
        # 交互式模式（替代 unix/waf_scan.sh）
        menu = InteractiveMenu()
        menu.show_banner()

        # 环境检查
        print(f"{Fore.CYAN}[1/6] 检查环境依赖...{Style.RESET_ALL}")
        checker = EnvironmentChecker()
        all_passed = checker.run_all_checks(show_instructions=True)

        if not all_passed:
            print(f"{Fore.RED}环境检查失败，请先安装缺失的依赖{Style.RESET_ALL}")
            sys.exit(1)

        # 检查配置文件
        print(f"{Fore.CYAN}[2/6] 检查配置文件...{Style.RESET_ALL}")
        exists, profile_count, region_count = checker.check_config_file()
        if exists:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} 配置文件存在: waf_scan_config.json")
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} 配置的 AWS Profiles: {profile_count} 个")
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} 默认扫描区域: {region_count} 个")
        else:
            print(f"  {Fore.YELLOW}⚠{Style.RESET_ALL}  配置文件不存在: waf_scan_config.json")
            print(f"  {Fore.YELLOW}提示: 复制 waf_scan_config.json.example 并修改配置{Style.RESET_ALL}")

        print()

        # 运行交互式菜单
        menu.run_interactive_scan()
    else:
        # 非交互模式 - 直接调用 get_waf_config.py
        cmd = [sys.executable, 'get_waf_config.py']
        if args.profiles:
            cmd.extend(['-p'] + args.profiles)
        if args.regions:
            cmd.extend(['-r'] + args.regions)
        if args.output:
            cmd.extend(['-o', args.output])
        if args.debug:
            cmd.append('--debug')
        if args.no_parallel:
            cmd.append('--no-parallel')

        subprocess.run(cmd, shell=(platform.system() == 'Windows'))


def handle_analyze_command(args):
    """处理 analyze 子命令"""
    cmd = [sys.executable, 'analyze_waf_config.py', args.json_file]

    if args.list:
        cmd.append('--list')
    if args.analyze:
        cmd.append('--analyze')
    if args.resources:
        cmd.append('--resources')
    if args.search:
        cmd.extend(['--search', args.search])
    if args.csv:
        cmd.extend(['--csv', args.csv])

    subprocess.run(cmd, shell=(platform.system() == 'Windows'))


def handle_check_command(args):
    """处理 check 子命令"""
    checker = ResourceChecker(args.profile, args.web_acl_name, args.region)
    checker.run()


def handle_check_env_command():
    """处理 check-env 子命令"""
    print(f"{Fore.BLUE}╔════════════════════════════════════════╗{Style.RESET_ALL}")
    print(f"{Fore.BLUE}║  环境依赖检查工具                      ║{Style.RESET_ALL}")
    print(f"{Fore.BLUE}╚════════════════════════════════════════╝{Style.RESET_ALL}\n")

    checker = EnvironmentChecker()
    env = checker.detect_environment()

    print(f"{Fore.CYAN}检测到运行环境: {Fore.GREEN}{env}{Style.RESET_ALL}\n")
    print(f"{Fore.CYAN}检查必需依赖...{Style.RESET_ALL}")

    all_passed = checker.run_all_checks(show_instructions=True)

    if all_passed:
        print(f"{Fore.GREEN}✓ 所有依赖检查通过！{Style.RESET_ALL}\n")
    else:
        print(f"{Fore.RED}✗ 部分依赖缺失，请按照上述指令安装{Style.RESET_ALL}\n")
        sys.exit(1)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}用户中断{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}错误: {e}{Style.RESET_ALL}")
        sys.exit(1)
