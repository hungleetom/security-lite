import unittest
from types import SimpleNamespace
from unittest.mock import patch
import psutil
from rules import judge
from monitor import Snapshot, rates, snapshot, endpoint


class SimpleTests(unittest.TestCase):
    def test_regular_https(self):
        self.assertEqual(judge(51000, '1.1.1.1', 443)[0], '정상')

    def test_loopback(self):
        self.assertEqual(judge(51000, '127.0.0.1', 23)[0], '정상')

    def test_telnet(self):
        self.assertEqual(judge(51000, '192.168.1.5', 23)[0], '주의')

    def test_public_rdp(self):
        self.assertEqual(judge(51000, '1.1.1.1', 3389)[0], '주의')

    def test_incoming_smb(self):
        self.assertEqual(judge(445, '1.1.1.1', 51000)[0], '주의')

    def test_private_smb(self):
        self.assertEqual(judge(51000, '192.168.1.5', 445)[0], '정상')

    def test_ipv6(self):
        self.assertEqual(judge(51000, '2606:4700:4700::1111', 3389)[0], '주의')

    def test_rates(self):
        self.assertEqual(rates(Snapshot([], 100, 200, 1), Snapshot([], 300, 600, 3)), (100, 200))

    def test_counter_reset(self):
        self.assertEqual(rates(Snapshot([], 500, 500, 1), Snapshot([], 1, 1, 2)), (0, 0))

    def test_first_sample(self):
        self.assertEqual(rates(None, Snapshot([], 100, 100, 1)), (0, 0))

    def test_duplicate_time(self):
        self.assertEqual(rates(Snapshot([], 100, 100, 1), Snapshot([], 200, 200, 1)), (0, 0))

    def test_mapped_loopback(self):
        self.assertEqual(judge(51000, '::ffff:127.0.0.1', 23)[0], '정상')

    def test_bad_address(self):
        self.assertEqual(judge(51000, 'invalid', 443)[0], '주의')


def connection(pid=123, remote=True):
    return SimpleNamespace(pid=pid, status='ESTABLISHED',
                           laddr=SimpleNamespace(ip='127.0.0.1', port=50000),
                           raddr=SimpleNamespace(ip='127.0.0.1', port=8000) if remote else ())


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.connections = patch('monitor.psutil.net_connections', return_value=[connection()]).start()
        self.counters = patch('monitor.psutil.net_io_counters', return_value=SimpleNamespace(bytes_sent=100, bytes_recv=200)).start()
        self.addCleanup(patch.stopall)

    def test_timestamp_precedes_slow_program_lookup(self):
        clock = [5.0]

        def slow_process(pid):
            clock[0] += 10
            return SimpleNamespace(name=lambda: 'browser.exe')

        with patch('monitor.monotonic', side_effect=lambda: clock[0]), patch('monitor.psutil.Process', side_effect=slow_process):
            result = snapshot()
        self.assertEqual(result.taken_at, 5.0)
        self.assertEqual(result.rows[0].program, 'browser.exe (123)')

    def test_missing_owner_is_not_idle_process(self):
        self.connections.return_value = [connection(0), connection(None)]
        with patch('monitor.psutil.Process') as process:
            result = snapshot()
        process.assert_not_called()
        self.assertTrue(all(row.program == '소유 프로그램 미상 (?)' for row in result.rows))

    def test_exited_or_inaccessible_process_keeps_connection(self):
        for error in (psutil.NoSuchProcess(123), psutil.AccessDenied(123)):
            with self.subTest(error=type(error).__name__), patch('monitor.psutil.Process', side_effect=error):
                result = snapshot()
                self.assertEqual(len(result.rows), 1)
                self.assertIn('조회 불가', result.rows[0].program)

    def test_listener_is_not_a_remote_connection(self):
        self.connections.return_value = [connection(remote=False)]
        self.assertEqual(snapshot().rows, [])

    def test_missing_counters_is_an_error(self):
        self.counters.return_value = None
        with self.assertRaises(RuntimeError):
            snapshot()

    def test_collection_access_failure_is_not_empty_success(self):
        self.connections.side_effect = psutil.AccessDenied()
        with self.assertRaises(psutil.AccessDenied):
            snapshot()

    def test_ipv6_endpoint_is_unambiguous(self):
        self.assertEqual(endpoint(SimpleNamespace(ip='::1', port=443)), '[::1]:443')


if __name__ == '__main__':
    unittest.main()
