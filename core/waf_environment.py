"""
环境检查模块
用于检查 Python、boto3、AWS CLI 等依赖，以及 SSO 登录状态
跨平台支持 Windows/macOS/Linux
"""

import sys
import os
import shutil
import subprocess
import platform
import json
from typing import Tuple, Optional, Dict
from colorama import init, Fore, Style

init(autoreset=True)  # Windows 兼容初始化


class EnvironmentChecker:
    """环境依赖检查器"""

    def __init__(self):
        self.system = platform.system()

    def check_python_version(self) -> Tuple[bool, str]:
        """检查 Python 版本（需要 >= 3.7）"""
        version = sys.version_info
        if version >= (3, 7):
            return True, f"Python {version.major}.{version.minor}.{version.micro}"
        return False, f"Python 版本过低: {version.major}.{version.minor} (需要 >= 3.7)"

    def check_boto3(self) -> Tuple[bool, str]:
        """检查 boto3 是否安装"""
        try:
            import boto3
            return True, f"boto3 {boto3.__version__}"
        except ImportError:
            return False, "boto3 未安装"

    def check_aws_cli(self) -> Tuple[bool, str]:
        """检查 AWS CLI 是否在 PATH 中（跨平台）"""
        if shutil.which('aws'):
            try:
                # Windows 需要 shell=True
                result = subprocess.run(
                    ['aws', '--version'],
                    capture_output=True,
                    text=True,
                    shell=(self.system == 'Windows'),
                    timeout=10  # 增加超时到 10 秒
                )
                version_info = result.stderr.strip() if result.stderr else result.stdout.strip()
                return True, version_info.split()[0] if version_info else "AWS CLI"
            except subprocess.TimeoutExpired:
                return True, "AWS CLI (响应慢，但已安装)"
            except Exception as e:
                return True, f"AWS CLI (检查出错: {str(e)})"
        return False, "AWS CLI 未安装"

    def check_sso_login(self, profile: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        检查 SSO 登录状态

        Returns:
            (is_logged_in, account_id, error_message)
        """
        try:
            result = subprocess.run(
                ['aws', 'sts', 'get-caller-identity', '--profile', profile],
                capture_output=True,
                text=True,
                timeout=10,
                shell=(self.system == 'Windows')
            )

            if result.returncode == 0:
                identity = json.loads(result.stdout)
                return True, identity['Account'], None
            else:
                error_msg = result.stderr.strip() if result.stderr else "未知错误"
                return False, None, error_msg

        except subprocess.TimeoutExpired:
            return False, None, "请求超时"
        except FileNotFoundError:
            return False, None, "AWS CLI 未安装"
        except json.JSONDecodeError:
            return False, None, "返回数据格式错误"
        except Exception as e:
            return False, None, str(e)

    def detect_environment(self) -> str:
        """检测运行环境"""
        if self.system == 'Windows':
            # 检测是否在 WSL 中运行
            if 'microsoft' in platform.uname().release.lower():
                return 'WSL'
            # 检测 PowerShell 或 CMD
            if os.environ.get('PSModulePath'):
                return 'PowerShell'
            return 'CMD'
        elif self.system == 'Darwin':
            return 'macOS'
        elif self.system == 'Linux':
            return 'Linux'
        return 'Unknown'

    def get_install_instructions(self) -> Dict[str, str]:
        """返回平台特定的安装指令"""
        env = self.detect_environment()

        instructions = {
            'boto3': {
                'Windows': 'pip install boto3',
                'PowerShell': 'pip install boto3',
                'CMD': 'pip install boto3',
                'WSL': 'pip3 install boto3',
                'macOS': 'pip3 install boto3',
                'Linux': 'pip3 install boto3',
                'Unknown': 'pip install boto3'
            },
            'aws_cli': {
                'Windows': 'https://awscli.amazonaws.com/AWSCLIV2.msi',
                'PowerShell': 'https://awscli.amazonaws.com/AWSCLIV2.msi',
                'CMD': 'https://awscli.amazonaws.com/AWSCLIV2.msi',
                'WSL': 'https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html',
                'macOS': 'brew install awscli 或 https://awscli.amazonaws.com/AWSCLIV2.pkg',
                'Linux': 'https://docs.aws.amazon.com/cli/latest/userguide/install-cliv2-linux.html',
                'Unknown': 'https://aws.amazon.com/cli/'
            }
        }

        return {k: v.get(env, v['Unknown']) for k, v in instructions.items()}

    def run_all_checks(self, show_instructions: bool = True) -> bool:
        """
        运行所有环境检查

        Args:
            show_instructions: 是否显示安装指令

        Returns:
            所有检查是否通过
        """
        all_passed = True

        # 检查 Python
        passed, message = self.check_python_version()
        if passed:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {message}")
        else:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} {message}")
            all_passed = False

        # 检查 boto3
        passed, message = self.check_boto3()
        if passed:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {message}")
        else:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} {message}")
            all_passed = False

        # 检查 AWS CLI
        passed, message = self.check_aws_cli()
        if passed:
            print(f"  {Fore.GREEN}✓{Style.RESET_ALL} {message}")
        else:
            print(f"  {Fore.RED}✗{Style.RESET_ALL} {message}")
            all_passed = False

        # 显示安装指令
        if not all_passed and show_instructions:
            print(f"\n{Fore.YELLOW}安装指令:{Style.RESET_ALL}")
            env = self.detect_environment()
            print(f"  检测到运行环境: {Fore.CYAN}{env}{Style.RESET_ALL}\n")

            instructions = self.get_install_instructions()

            if not self.check_boto3()[0]:
                print(f"  安装 boto3:")
                print(f"    {instructions['boto3']}")

            if not self.check_aws_cli()[0]:
                print(f"  安装 AWS CLI:")
                print(f"    {instructions['aws_cli']}")

        print()
        return all_passed

    def check_config_file(self, config_path: str = 'waf_scan_config.json') -> Tuple[bool, Optional[int], Optional[int]]:
        """
        检查配置文件是否存在

        Returns:
            (exists, profile_count, region_count)
        """
        if not os.path.exists(config_path):
            return False, None, None

        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)

            profile_count = len(config.get('profiles', []))
            region_count = len(config.get('regions', {}).get('common', []))

            return True, profile_count, region_count
        except Exception:
            return False, None, None
