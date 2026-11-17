"""졸업작품용 소규모 연결 점검 규칙. 악성 여부를 확정하지 않습니다."""
from ipaddress import ip_address


def judge(local_port, remote_ip, remote_port):
    """Return a label and a short, explainable reason."""
    try:
        address = ip_address(remote_ip)
    except ValueError:
        return '주의', '상대 주소를 확인할 수 없음'
    if address.is_loopback:
        return '정상', '내 PC 내부 통신'
    if local_port in (21, 23) or remote_port in (21, 23):
        return '주의', 'FTP/Telnet 포트: 평문 통신 여부 확인'
    if address.is_global and (local_port in (445, 3389) or remote_port in (445, 3389)):
        return '주의', '공인 IP와 파일 공유/원격 데스크톱 통신'
    return '정상', '현재 점검 규칙에 해당하지 않음'
