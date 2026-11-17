"""psutil로 현재 TCP 연결과 PC 전체 송수신량을 읽습니다."""
from dataclasses import dataclass
from time import monotonic
import psutil
from rules import judge


@dataclass
class Connection:
    program: str
    local: str
    remote: str
    state: str
    verdict: str
    reason: str


@dataclass
class Snapshot:
    rows: list
    sent: int
    received: int
    taken_at: float


def endpoint(address):
    host = f'[{address.ip}]' if ':' in address.ip else address.ip
    return f'{host}:{address.port}'


def snapshot():
    connections = psutil.net_connections(kind='tcp')
    counters = psutil.net_io_counters()
    taken_at = monotonic()
    if counters is None:
        raise RuntimeError('네트워크 사용량을 읽을 수 없습니다.')
    names, rows = {}, []
    for connection in connections:
        # LISTEN은 상대와 통신 중인 연결이 아니므로 목록에서 제외합니다.
        if not connection.raddr or not connection.laddr:
            continue
        pid = connection.pid
        if pid not in names:
            try:
                names[pid] = psutil.Process(pid).name() if pid else '소유 프로그램 미상'
            except (psutil.Error, OSError):
                names[pid] = '조회 불가'
        verdict, reason = judge(connection.laddr.port, connection.raddr.ip, connection.raddr.port)
        rows.append(Connection(f'{names[pid]} ({pid if pid else "?"})',
                               endpoint(connection.laddr), endpoint(connection.raddr),
                               connection.status, verdict, reason))
    rows.sort(key=lambda row: (row.verdict != '주의', row.program.casefold(), row.remote))
    return Snapshot(rows, counters.bytes_sent, counters.bytes_recv, taken_at)


def rates(previous, current):
    if previous is None or current.taken_at <= previous.taken_at:
        return 0.0, 0.0
    elapsed = current.taken_at - previous.taken_at
    return (max(0, current.sent - previous.sent) / elapsed,
            max(0, current.received - previous.received) / elapsed)
