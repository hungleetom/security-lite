import unittest
from rules import judge
from monitor import Snapshot, rates


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


if __name__ == '__main__':
    unittest.main()
