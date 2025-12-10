"""
Logging Utility
공격 로그 생성 및 관리 유틸리티
"""

import logging
import os
from datetime import datetime

# 글로벌 로거 인스턴스
_logger = None

def init_logger(log_file, verbose=False):
    """
    로거 초기화

    Args:
        log_file: 로그 파일 경로
        verbose: 상세 로그 출력 여부
    """
    global _logger

    # 로거 생성
    _logger = logging.getLogger('DVWA_Attacker')
    _logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    # 기존 핸들러 제거
    _logger.handlers = []

    # 파일 핸들러
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)

    # 포맷 설정
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)

    _logger.addHandler(file_handler)

    # 초기화 로그
    _logger.info('='*80)
    _logger.info('DVWA Attack Automation Tool - 로그 시작')
    _logger.info('2SeC Project - Attack Log Generation Module')
    _logger.info('='*80)

def log_attack(attack_type, status, details, status_code=0, response_length=0):
    """
    공격 로그 기록

    Args:
        attack_type: 공격 타입 (SQL_INJECTION, XSS, CMDI 등)
        status: 상태 (SUCCESS, FAILED, ERROR)
        details: 상세 내용
        status_code: HTTP 상태 코드
        response_length: 응답 길이
    """
    if _logger is None:
        return

    # 로그 메시지 구성
    log_msg = f"{attack_type:<20} | {status:<10} | {details}"

    if status_code > 0:
        log_msg += f" | HTTP {status_code} | {response_length} bytes"

    # 상태에 따라 로그 레벨 설정
    if status == 'SUCCESS':
        _logger.info(log_msg)
    elif status == 'FAILED':
        _logger.warning(log_msg)
    elif status == 'ERROR':
        _logger.error(log_msg)
    else:
        _logger.debug(log_msg)

def log_session(action, details):
    """
    세션 관련 로그 기록

    Args:
        action: 동작 (LOGIN, LOGOUT, SET_SECURITY_LEVEL 등)
        details: 상세 내용
    """
    if _logger is None:
        return

    _logger.info(f"SESSION | {action:<20} | {details}")

def log_custom(level, message):
    """
    커스텀 로그 기록

    Args:
        level: 로그 레벨 (INFO, WARNING, ERROR, DEBUG)
        message: 로그 메시지
    """
    if _logger is None:
        return

    if level.upper() == 'INFO':
        _logger.info(message)
    elif level.upper() == 'WARNING':
        _logger.warning(message)
    elif level.upper() == 'ERROR':
        _logger.error(message)
    elif level.upper() == 'DEBUG':
        _logger.debug(message)

def log_summary(total_attacks, successful_attacks, attack_breakdown):
    """
    공격 결과 요약 로그 기록

    Args:
        total_attacks: 총 공격 시도 수
        successful_attacks: 성공한 공격 수
        attack_breakdown: 공격 유형별 통계 딕셔너리
    """
    if _logger is None:
        return

    _logger.info('='*80)
    _logger.info('공격 결과 요약')
    _logger.info('='*80)
    _logger.info(f"총 공격 시도: {total_attacks}회")
    _logger.info(f"성공한 공격: {successful_attacks}회")
    _logger.info(f"성공률: {(successful_attacks/total_attacks*100):.2f}%")
    _logger.info('-'*80)

    for attack_type, stats in attack_breakdown.items():
        _logger.info(
            f"{attack_type:<20} | "
            f"시도: {stats['attempts']:>3}회 | "
            f"성공: {stats['successful']:>3}회 | "
            f"성공률: {(stats['successful']/stats['attempts']*100 if stats['attempts'] > 0 else 0):>5.1f}%"
        )

    _logger.info('='*80)

def close_logger():
    """로거 종료"""
    if _logger is not None:
        _logger.info('='*80)
        _logger.info('로그 기록 종료')
        _logger.info('='*80)

        for handler in _logger.handlers:
            handler.close()
