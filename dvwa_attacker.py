#!/usr/bin/env python3
"""
DVWA Attack Automation Tool
2SeC Project - Attack Log Generation Module
Author: Hwang Jun-ha
"""

import sys
import os
import readline
from datetime import datetime
from modules import sql_injection, xss_attack, cmd_injection, file_upload
from modules import post_exploit, pivoting, cloud_exploit, privilege_escalation
from utils import logger, session_manager

# 컬러 출력을 위한 ANSI 코드
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    CYAN = '\033[96m'

class DVWAAttacker:
    """대화형 DVWA 공격 도구"""

    def __init__(self):
        self.session = None
        self.target = None
        self.username = None
        self.password = None
        self.security_level = 'low'
        self.delay = 1
        self.verbose = False
        self.log_dir = 'logs'
        self.connected = False

    def print_banner(self):
        """배너 출력"""
        banner = f"""
{Colors.HEADER}{'='*70}
    ____  ____       ______ __          _
   / __ \/ __/___   / ____// /_  ____ _(_)___
  / /_/ /\ \/ _ \ / /    / __ \/ __ `/ / __ \\
 / ____/___/  __// /___ / / / / /_/ / / / / /
/_/   /____/\___/ \____//_/ /_/\__,_/_/_/ /_/

    2SeC Attack Automation Tool v1.0
    DVWA Penetration Testing Framework

    작성자: 황준하 (2SeC Team)
    목적: SIEM 로그 생성을 위한 침투테스트 자동화
{'='*70}{Colors.END}

{Colors.CYAN}명령어 도움말을 보려면 'help'를 입력하세요.{Colors.END}
        """
        print(banner)

    def print_help(self):
        """도움말 출력"""
        help_text = f"""
{Colors.BOLD}사용 가능한 명령어:{Colors.END}

{Colors.CYAN}[연결 관리]{Colors.END}
  connect <url> <username> <password>  - DVWA에 연결 (예: connect http://192.168.1.100/dvwa admin password)
  disconnect                           - 연결 해제
  status                              - 현재 연결 상태 확인
  set security <level>                - 보안 레벨 설정 (low/medium/high)
  set delay <seconds>                 - 요청 간 지연 시간 설정

{Colors.CYAN}[공격 모듈]{Colors.END}
  attack sqli                         - SQL Injection 공격 실행
  attack xss                          - XSS 공격 실행
  attack cmdi                         - Command Injection 공격 실행
  attack upload                       - File Upload 공격 실행
  attack all                          - 모든 기본 공격 실행

{Colors.CYAN}[고급 공격]{Colors.END}
  post-exploit                        - Post-Exploitation 실행
  pivoting                            - 피버팅 및 데이터 탈취 실행
  cloud-exploit                       - AWS IMDS 탈취 및 클라우드 메타데이터 수집
  privesc                             - 권한 상승 및 루트 권한 획득 시도

{Colors.CYAN}[기타]{Colors.END}
  logs                                - 로그 파일 목록 보기
  show last-log                       - 마지막 로그 파일 내용 보기
  verbose <on/off>                    - 상세 출력 모드 토글
  clear                               - 화면 지우기
  help                                - 도움말 보기
  exit, quit                          - 프로그램 종료

{Colors.YELLOW}사용 예시:{Colors.END}
  2sechain> connect http://192.168.1.100/dvwa admin password
  2sechain> set security low
  2sechain> attack sqli
  2sechain> post-exploit
  2sechain> exit
        """
        print(help_text)

    def print_status(self):
        """현재 상태 출력"""
        print(f"\n{Colors.BOLD}[현재 상태]{Colors.END}")
        print(f"  타겟: {Colors.GREEN if self.connected else Colors.RED}{self.target or '연결 안됨'}{Colors.END}")
        print(f"  사용자: {self.username or 'N/A'}")
        print(f"  보안 레벨: {self.security_level.upper()}")
        print(f"  지연 시간: {self.delay}초")
        print(f"  상세 모드: {'ON' if self.verbose else 'OFF'}")
        print(f"  로그 디렉토리: {self.log_dir}/")
        print()

    def cmd_connect(self, args):
        """DVWA 연결"""
        if len(args) < 3:
            print(f"{Colors.RED}[!] 사용법: connect <url> <username> <password>{Colors.END}")
            return

        self.target = args[0]
        self.username = args[1]
        self.password = args[2]

        print(f"{Colors.YELLOW}[*] {self.target}에 연결 중...{Colors.END}")

        try:
            # 로거 초기화
            os.makedirs(self.log_dir, exist_ok=True)
            log_file = os.path.join(self.log_dir,
                                   f'attack_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
            logger.init_logger(log_file, self.verbose)

            # 세션 생성
            self.session = session_manager.DVWASession(
                self.target,
                self.username,
                self.password,
                self.security_level
            )

            if self.session.login():
                self.connected = True
                print(f"{Colors.GREEN}[+] 연결 성공!{Colors.END}")
                print(f"{Colors.GREEN}[+] 로그인: {self.username}{Colors.END}")
                print(f"{Colors.GREEN}[+] 보안 레벨: {self.security_level.upper()}{Colors.END}")
                print(f"{Colors.BLUE}[*] 로그 파일: {log_file}{Colors.END}")
            else:
                print(f"{Colors.RED}[!] 로그인 실패{Colors.END}")
                self.connected = False

        except Exception as e:
            print(f"{Colors.RED}[!] 연결 실패: {str(e)}{Colors.END}")
            self.connected = False

    def cmd_disconnect(self):
        """연결 해제"""
        if not self.connected:
            print(f"{Colors.YELLOW}[!] 연결된 세션이 없습니다.{Colors.END}")
            return

        if self.session:
            self.session.logout()

        self.connected = False
        self.session = None
        print(f"{Colors.GREEN}[+] 연결 해제됨{Colors.END}")

    def cmd_set(self, args):
        """설정 변경"""
        if len(args) < 2:
            print(f"{Colors.RED}[!] 사용법: set <옵션> <값>{Colors.END}")
            return

        option = args[0].lower()
        value = args[1]

        if option == 'security':
            if value.lower() in ['low', 'medium', 'high']:
                self.security_level = value.lower()
                print(f"{Colors.GREEN}[+] 보안 레벨: {self.security_level.upper()}{Colors.END}")

                if self.connected and self.session:
                    self.session.set_security_level(self.security_level)
            else:
                print(f"{Colors.RED}[!] 유효하지 않은 보안 레벨{Colors.END}")

        elif option == 'delay':
            try:
                self.delay = int(value)
                print(f"{Colors.GREEN}[+] 지연 시간: {self.delay}초{Colors.END}")
            except ValueError:
                print(f"{Colors.RED}[!] 숫자를 입력하세요{Colors.END}")

        else:
            print(f"{Colors.RED}[!] 알 수 없는 옵션: {option}{Colors.END}")

    def cmd_attack(self, args):
        """공격 실행"""
        if not self.connected:
            print(f"{Colors.RED}[!] 먼저 타겟에 연결하세요 (connect 명령어 사용){Colors.END}")
            return

        if len(args) < 1:
            print(f"{Colors.RED}[!] 사용법: attack <모듈>{Colors.END}")
            print(f"{Colors.YELLOW}[*] 사용 가능한 모듈: sqli, xss, cmdi, upload, all{Colors.END}")
            return

        attack_type = args[0].lower()

        if attack_type == 'sqli':
            print(f"{Colors.YELLOW}[*] SQL Injection 공격 시작...{Colors.END}")
            result = sql_injection.run_attack(self.session, self.delay)
            self._print_result(result)

        elif attack_type == 'xss':
            print(f"{Colors.YELLOW}[*] XSS 공격 시작...{Colors.END}")
            result = xss_attack.run_attack(self.session, self.delay)
            self._print_result(result)

        elif attack_type == 'cmdi':
            print(f"{Colors.YELLOW}[*] Command Injection 공격 시작...{Colors.END}")
            result = cmd_injection.run_attack(self.session, self.delay)
            self._print_result(result)

        elif attack_type == 'upload':
            print(f"{Colors.YELLOW}[*] File Upload 공격 시작...{Colors.END}")
            result = file_upload.run_attack(self.session, self.delay)
            self._print_result(result)

        elif attack_type == 'all':
            print(f"{Colors.YELLOW}[*] 모든 공격 모듈 실행...{Colors.END}\n")

            results = {}
            results['sqli'] = sql_injection.run_attack(self.session, self.delay)
            results['xss'] = xss_attack.run_attack(self.session, self.delay)
            results['cmdi'] = cmd_injection.run_attack(self.session, self.delay)
            results['upload'] = file_upload.run_attack(self.session, self.delay)

            self._print_all_results(results)

        else:
            print(f"{Colors.RED}[!] 알 수 없는 공격 모듈: {attack_type}{Colors.END}")

    def cmd_post_exploit(self):
        """Post-Exploitation"""
        if not self.connected:
            print(f"{Colors.RED}[!] 먼저 타겟에 연결하세요{Colors.END}")
            return

        print(f"{Colors.YELLOW}[*] Post-Exploitation 시작...{Colors.END}")
        result = post_exploit.run_attack(self.session, self.delay)
        self._print_result(result)

    def cmd_pivoting(self):
        """피버팅"""
        if not self.connected:
            print(f"{Colors.RED}[!] 먼저 타겟에 연결하세요{Colors.END}")
            return

        print(f"{Colors.YELLOW}[*] 피버팅 및 데이터 탈취 시작...{Colors.END}")
        result = pivoting.run_attack(self.session, self.delay)

    def cmd_cloud_exploit(self):
        """AWS IMDS 탈취"""
        if not self.connected:
            print(f"{Colors.RED}[!] 먼저 타겟에 연결하세요{Colors.END}")
            return

        print(f"{Colors.YELLOW}[*] AWS IMDS 탈취 및 클라우드 메타데이터 수집 시작...{Colors.END}")
        result = cloud_exploit.run_attack(self.session, self.delay)
        self._print_result(result)

    def cmd_privesc(self):
        """권한 상승"""
        if not self.connected:
            print(f"{Colors.RED}[!] 먼저 타겟에 연결하세요{Colors.END}")
            return

        print(f"{Colors.YELLOW}[*] 권한 상승 및 루트 권한 획득 시도...{Colors.END}")
        result = privilege_escalation.run_attack(self.session, self.delay)
        self._print_result(result)

    def cmd_logs(self):
        """로그 파일 목록"""
        if not os.path.exists(self.log_dir):
            print(f"{Colors.YELLOW}[!] 로그 디렉토리가 없습니다.{Colors.END}")
            return

        log_files = sorted([f for f in os.listdir(self.log_dir) if f.endswith('.log')])

        if not log_files:
            print(f"{Colors.YELLOW}[!] 로그 파일이 없습니다.{Colors.END}")
            return

        print(f"\n{Colors.BOLD}[로그 파일 목록]{Colors.END}")
        for i, log_file in enumerate(log_files, 1):
            filepath = os.path.join(self.log_dir, log_file)
            size = os.path.getsize(filepath)
            print(f"  {i}. {log_file} ({size} bytes)")
        print()

    def cmd_show_last_log(self):
        """마지막 로그 보기"""
        if not os.path.exists(self.log_dir):
            print(f"{Colors.YELLOW}[!] 로그 디렉토리가 없습니다.{Colors.END}")
            return

        log_files = sorted([f for f in os.listdir(self.log_dir) if f.endswith('.log')])

        if not log_files:
            print(f"{Colors.YELLOW}[!] 로그 파일이 없습니다.{Colors.END}")
            return

        last_log = os.path.join(self.log_dir, log_files[-1])

        print(f"\n{Colors.BOLD}[{log_files[-1]}]{Colors.END}\n")
        with open(last_log, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            for line in lines[-20:]:  # 마지막 20줄만 표시
                print(line.rstrip())
        print()

    def cmd_verbose(self, args):
        """상세 모드 토글"""
        if len(args) > 0:
            value = args[0].lower()
            if value in ['on', 'true', '1']:
                self.verbose = True
            elif value in ['off', 'false', '0']:
                self.verbose = False
        else:
            self.verbose = not self.verbose

        print(f"{Colors.GREEN}[+] 상세 모드: {'ON' if self.verbose else 'OFF'}{Colors.END}")

    def _print_result(self, result):
        """공격 결과 출력"""
        if result['success']:
            print(f"\n{Colors.GREEN}[+] 공격 성공: {result['successful']}/{result['attempts']}{Colors.END}\n")
        else:
            print(f"\n{Colors.RED}[-] 공격 실패: {result['successful']}/{result['attempts']}{Colors.END}\n")

    def _print_all_results(self, results):
        """전체 결과 출력"""
        print(f"\n{Colors.HEADER}{'='*60}")
        print("공격 결과 요약")
        print(f"{'='*60}{Colors.END}\n")

        for attack_type, result in results.items():
            status_color = Colors.GREEN if result['success'] else Colors.RED
            status = "성공" if result['success'] else "실패"
            print(f"{status_color}[{status}] {attack_type.upper()}: "
                  f"{result['attempts']}개 시도, {result['successful']}개 성공{Colors.END}")
        print()

    def run(self):
        """메인 루프"""
        self.print_banner()

        while True:
            try:
                # 프롬프트 표시
                if self.connected:
                    prompt = f"{Colors.GREEN}2sechain{Colors.END} ({Colors.CYAN}{self.target}{Colors.END})> "
                else:
                    prompt = f"{Colors.RED}2sechain{Colors.END}> "

                command = input(prompt).strip()

                if not command:
                    continue

                # 명령어 파싱
                parts = command.split()
                cmd = parts[0].lower()
                args = parts[1:]

                # 명령어 실행
                if cmd in ['exit', 'quit']:
                    if self.connected:
                        self.cmd_disconnect()
                    print(f"{Colors.YELLOW}[*] 종료합니다.{Colors.END}")
                    break

                elif cmd == 'help':
                    self.print_help()

                elif cmd == 'connect':
                    self.cmd_connect(args)

                elif cmd == 'disconnect':
                    self.cmd_disconnect()

                elif cmd == 'status':
                    self.print_status()

                elif cmd == 'set':
                    self.cmd_set(args)

                elif cmd == 'attack':
                    self.cmd_attack(args)

                elif cmd == 'post-exploit':
                    self.cmd_post_exploit()

                elif cmd == 'pivoting':
                    self.cmd_pivoting()

                elif cmd == 'cloud-exploit':
                    self.cmd_cloud_exploit()

                elif cmd == 'privesc':
                    self.cmd_privesc()

                elif cmd == 'logs':
                    self.cmd_logs()

                elif cmd == 'show' and len(args) > 0 and args[0] == 'last-log':
                    self.cmd_show_last_log()

                elif cmd == 'verbose':
                    self.cmd_verbose(args)

                elif cmd == 'clear':
                    os.system('clear' if os.name != 'nt' else 'cls')

                else:
                    print(f"{Colors.RED}[!] 알 수 없는 명령어: {cmd}{Colors.END}")
                    print(f"{Colors.YELLOW}[*] 'help'를 입력하여 사용 가능한 명령어를 확인하세요.{Colors.END}")

            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[!] Ctrl+C를 눌렀습니다. 'exit'를 입력하여 종료하세요.{Colors.END}")

            except Exception as e:
                print(f"{Colors.RED}[!] 오류 발생: {str(e)}{Colors.END}")

def main():
    """메인 함수"""
    attacker = DVWAAttacker()
    attacker.run()

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] 프로그램을 종료합니다.{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Colors.RED}[!] 예상치 못한 오류: {str(e)}{Colors.END}")
        sys.exit(1)
