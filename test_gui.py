"""실제 Tk 이벤트 루프를 사용하는 회귀 검증. Windows 데스크톱에서 실행합니다."""
import threading
import subprocess
import sys
import tempfile
from pathlib import Path
import time
import unittest
from unittest.mock import patch
from main import App
from monitor import Snapshot, Connection


def sample(name='browser.exe', taken_at=1):
    return Snapshot([Connection(name, '127.0.0.1:50000', '127.0.0.1:8000',
                               'ESTABLISHED', '정상', '내 PC 내부 통신')], 100, 200, taken_at)


class GuiTests(unittest.TestCase):
    def setUp(self):
        self.app = App()
        self.app.withdraw()
        self.app.update_idletasks()
        self.addCleanup(self.app.destroy)

    def pump_until(self, predicate):
        deadline = time.monotonic() + 4
        while not predicate():
            self.app.update()
            if time.monotonic() >= deadline:
                self.fail('GUI 작업 완료 시간 초과')
            time.sleep(.01)

    def test_selection_survives_refresh_and_new_rows(self):
        old = sample()
        self.app.show(old)
        self.app.tree.selection_set(self.app.tree.get_children()[0])
        new = sample(taken_at=3)
        new.rows.insert(0, sample('new.exe').rows[0])
        self.app.show(new)
        selected = self.app.tree.selection()
        self.assertEqual(len(selected), 1)
        self.assertEqual(self.app.tree.item(selected[0], 'values')[0], 'browser.exe')

    def test_minimum_window_keeps_footer_and_table_visible(self):
        self.app.deiconify()
        self.app.geometry('820x430')
        self.app.update()
        body = self.app.tree.master.master
        footer = body.grid_slaves(row=5, column=0)[0]
        self.assertTrue(footer.winfo_ismapped())
        self.assertLessEqual(footer.winfo_y() + footer.winfo_height(), body.winfo_height())
        self.assertGreater(self.app.tree.winfo_height(), 60)
        self.assertLessEqual(footer.winfo_reqwidth(), body.winfo_width())

    def test_stop_ignores_inflight_sample(self):
        release = threading.Event()
        self.addCleanup(release.set)
        with patch('main.snapshot', side_effect=lambda: (release.wait(3), sample())[1]):
            self.app.toggle()
            self.app.toggle()
            release.set()
            self.pump_until(lambda: not self.app.busy)
        self.assertIsNone(self.app.latest)
        self.assertFalse(self.app.tree.get_children())

    def test_restart_clears_old_rows_and_ignores_old_result(self):
        old_release, new_release, new_started = (threading.Event() for _ in range(3))
        self.addCleanup(old_release.set)
        self.addCleanup(new_release.set)
        calls = [0]

        def collect():
            calls[0] += 1
            if calls[0] == 1:
                old_release.wait(3)
                return sample('old.exe', 2)
            new_started.set()
            new_release.wait(3)
            return sample('fresh.exe', 3)

        self.app.show(sample('stale.exe'))
        with patch('main.snapshot', side_effect=collect):
            self.app.toggle()
            self.assertIsNone(self.app.latest)
            self.assertFalse(self.app.tree.get_children())
            self.app.toggle()
            self.app.toggle()
            old_release.set()
            self.pump_until(new_started.is_set)
            self.assertIsNone(self.app.latest)
            self.assertFalse(self.app.tree.get_children())
            new_release.set()
            self.pump_until(lambda: self.app.latest is not None)
        self.assertEqual(self.app.latest.rows[0].program, 'fresh.exe')

    def test_failure_clears_success_and_can_restart(self):
        with patch('main.snapshot', side_effect=RuntimeError('조회 실패 예시')):
            self.app.toggle()
            self.pump_until(lambda: not self.app.busy)
        self.assertFalse(self.app.running)
        self.assertIsNone(self.app.latest)
        self.assertIn('조회 실패', self.app.status.get())
        with patch('main.snapshot', return_value=sample()):
            self.app.toggle()
            self.pump_until(lambda: self.app.latest is not None)
        self.assertTrue(self.app.running)

    def test_consecutive_samples_update_speed(self):
        self.app.show(sample())
        new = sample(taken_at=3)
        new.sent += 2048
        new.received += 4096
        self.app.show(new)
        self.assertIn('송신  1.0 KB/s', self.app.traffic.get())
        self.assertIn('수신  2.0 KB/s', self.app.traffic.get())

    def test_close_cancels_poll_and_collection_timers(self):
        with patch('main.snapshot', return_value=sample()):
            self.app.toggle()
            self.pump_until(lambda: self.app.latest is not None)
        jobs = (self.app.poll_job, self.app.collect_job)
        self.app.destroy()
        pending = self.app.tk.call('after', 'info')
        self.assertTrue(all(job not in pending for job in jobs if job))


class SmokeFailureTests(unittest.TestCase):
    def test_bad_report_path_exits_instead_of_hanging(self):
        with tempfile.TemporaryDirectory() as folder:
            result = subprocess.run([sys.executable, str(Path(__file__).with_name('main.py')),
                                     '--smoke-test', '--report', str(Path(folder) / 'missing' / 'report.json')],
                                    capture_output=True, timeout=20)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'FileNotFoundError', result.stderr)


if __name__ == '__main__':
    unittest.main()
