"""
交互式菜单模块
提供类似 waf_scan.sh 的交互式用户界面
跨平台支持 Windows/macOS/Linux
"""

import sys
import os
import subprocess
import platform
from colorama import init, Fore, Style
from .waf_environment import EnvironmentChecker

init(autoreset=True)  # Windows 兼容初始化


class InteractiveMenu:
    """交互式扫描菜单"""

    def __init__(self):
        self.system = platform.system()
        self.checker = EnvironmentChecker()

    def show_banner(self):
        """显示横幅"""
        print(f"{Fore.BLUE}╔════════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        print(f"{Fore.BLUE}║       AWS WAF Multi-Account Configuration Scanner             ║{Style.RESET_ALL}")
        print(f"{Fore.BLUE}║       AWS WAF 多账户配置扫描工具                                ║{Style.RESET_ALL}")
        print(f"{Fore.BLUE}╚════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

    def show_menu(self):
        """显示主菜单"""
        print(f"{Fore.CYAN}请选择扫描模式:{Style.RESET_ALL}\n")
        print(f"  {Fore.GREEN}1){Style.RESET_ALL} 快速扫描 - 使用配置文件")
        print(f"  {Fore.GREEN}2){Style.RESET_ALL} 快速测试 - 单账户单区域")
        print(f"  {Fore.GREEN}3){Style.RESET_ALL} 自定义扫描 - 指定参数")
        print(f"  {Fore.GREEN}4){Style.RESET_ALL} 调试模式")
        print(f"  {Fore.GREEN}5){Style.RESET_ALL} 查看帮助")
        print(f"  {Fore.GREEN}0){Style.RESET_ALL} 退出\n")

    def get_choice(self) -> str:
        """获取用户选择"""
        try:
            return input(f"{Fore.YELLOW}请选择 [0-5]: {Style.RESET_ALL}").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{Fore.YELLOW}用户中断{Style.RESET_ALL}")
            sys.exit(0)

    def quick_scan(self):
        """快速扫描（使用配置文件）"""
        print(f"\n{Fore.CYAN}[执行] 快速扫描（使用配置文件）{Style.RESET_ALL}\n")

        # 检查配置文件
        exists, profile_count, region_count = self.checker.check_config_file()
        if not exists:
            print(f"{Fore.YELLOW}⚠  配置文件不存在: waf_scan_config.json{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}提示: 复制 waf_scan_config.json.example 并修改配置{Style.RESET_ALL}\n")
            input("按回车键返回...")
            return

        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} 配置文件存在")
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} 配置的 AWS Profiles: {profile_count} 个")
        print(f"  {Fore.GREEN}✓{Style.RESET_ALL} 默认扫描区域: {region_count} 个\n")

        # 调用 get_waf_config.py
        cmd = [sys.executable, 'get_waf_config.py']
        subprocess.run(cmd, shell=(self.system == 'Windows'))

    def quick_test(self):
        """快速测试（单账户单区域）"""
        print(f"\n{Fore.CYAN}[执行] 快速测试（单账户单区域）{Style.RESET_ALL}\n")

        profile = input("请输入 AWS Profile: ").strip()
        if not profile:
            print(f"{Fore.RED}错误: Profile 不能为空{Style.RESET_ALL}")
            input("按回车键返回...")
            return

        region = input("请输入 AWS Region (留空使用 us-east-1): ").strip()
        if not region:
            region = 'us-east-1'

        print(f"\n{Fore.CYAN}开始扫描...{Style.RESET_ALL}\n")

        cmd = [sys.executable, 'get_waf_config.py', '-p', profile, '-r', region]
        subprocess.run(cmd, shell=(self.system == 'Windows'))

    def custom_scan(self):
        """自定义扫描（交互式输入参数）"""
        print(f"\n{Fore.CYAN}[执行] 自定义扫描{Style.RESET_ALL}\n")

        # 获取 profiles
        profiles_input = input("请输入 AWS Profiles（多个用空格分隔）: ").strip()
        if not profiles_input:
            print(f"{Fore.RED}错误: Profiles 不能为空{Style.RESET_ALL}")
            input("按回车键返回...")
            return

        profiles = profiles_input.split()

        # 获取 regions
        regions_input = input("请输入 AWS Regions（多个用空格分隔，留空使用默认）: ").strip()
        regions = regions_input.split() if regions_input else []

        # 询问是否启用并行
        parallel_input = input("是否启用并行扫描? (Y/n): ").strip().lower()
        no_parallel = parallel_input == 'n'

        print(f"\n{Fore.CYAN}开始扫描...{Style.RESET_ALL}\n")

        cmd = [sys.executable, 'get_waf_config.py', '-p'] + profiles
        if regions:
            cmd.extend(['-r'] + regions)
        if no_parallel:
            cmd.append('--no-parallel')

        subprocess.run(cmd, shell=(self.system == 'Windows'))

    def debug_mode(self):
        """调试模式"""
        print(f"\n{Fore.CYAN}[执行] 调试模式{Style.RESET_ALL}\n")

        profiles_input = input("请输入 AWS Profiles（多个用空格分隔，留空使用配置文件）: ").strip()
        profiles = profiles_input.split() if profiles_input else []

        print(f"\n{Fore.CYAN}开始调试扫描...{Style.RESET_ALL}\n")

        cmd = [sys.executable, 'get_waf_config.py', '--debug']
        if profiles:
            cmd.extend(['-p'] + profiles)

        subprocess.run(cmd, shell=(self.system == 'Windows'))

    def show_help(self):
        """显示帮助信息"""
        print(f"\n{Fore.CYAN}=== AWS WAF 多账户配置扫描工具 ==={Style.RESET_ALL}\n")
        print(f"{Fore.YELLOW}功能说明:{Style.RESET_ALL}")
        print("  1. 快速扫描 - 使用 waf_scan_config.json 中的配置进行扫描")
        print("  2. 快速测试 - 指定单个 profile 和区域进行测试")
        print("  3. 自定义扫描 - 手动指定 profiles 和 regions")
        print("  4. 调试模式 - 启用详细日志输出\n")

        print(f"{Fore.YELLOW}输出文件:{Style.RESET_ALL}")
        print("  扫描结果会保存到 waf_config_YYYYMMDD_HHMMSS.json\n")

        print(f"{Fore.YELLOW}后续分析:{Style.RESET_ALL}")
        if self.system == 'Windows':
            print("  python waf_cli.py analyze <json文件> --list")
            print("  python waf_cli.py analyze <json文件> --resources")
        else:
            print("  python3 waf_cli.py analyze <json文件> --list")
            print("  python3 waf_cli.py analyze <json文件> --resources")

        print()
        input("按回车键返回...")

    def run_interactive_scan(self):
        """运行交互式扫描流程"""
        while True:
            self.show_menu()
            choice = self.get_choice()

            if choice == '0':
                print(f"{Fore.GREEN}退出程序{Style.RESET_ALL}")
                break
            elif choice == '1':
                self.quick_scan()
            elif choice == '2':
                self.quick_test()
            elif choice == '3':
                self.custom_scan()
            elif choice == '4':
                self.debug_mode()
            elif choice == '5':
                self.show_help()
            else:
                print(f"{Fore.RED}无效选择，请输入 0-5{Style.RESET_ALL}\n")
                input("按回车键继续...")

            # 每次操作后清屏（可选）
            # os.system('cls' if self.system == 'Windows' else 'clear')
