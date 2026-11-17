"""보안관제Lite 간단 버전: python main.py"""
import argparse
from dataclasses import astuple
import json
from pathlib import Path
import queue
import threading
from contextlib import ExitStack
from time import monotonic
import tkinter as tk
from tkinter import ttk
from monitor import snapshot, rates


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('보안관제Lite · 간단 버전 1.1')
        self.geometry('1100x590')
        self.minsize(820, 430)
        self.running = False
        self.closed = False
        self.busy = False
        self.generation = 0
        self.previous = None
        self.latest = None
        self.result = queue.Queue()
        self.poll_job = self.collect_job = None
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('.', font=('맑은 고딕', 10))
        style.configure('Treeview', rowheight=29)
        body = ttk.Frame(self, padding=16)
        body.pack(fill='both', expand=True)
        body.columnconfigure(0, weight=1)
        body.rowconfigure(3, weight=1)
        top = ttk.Frame(body)
        top.grid(row=0, column=0, sticky='ew')
        ttk.Label(top, text='보안관제Lite', font=('맑은 고딕', 19, 'bold')).pack(side='left')
        self.button = ttk.Button(top, text='모니터링 시작', command=self.toggle)
        self.button.pack(side='right')
        self.traffic = tk.StringVar(value='송신  —     수신  —')
        ttk.Label(body, textvariable=self.traffic, font=('맑은 고딕', 13), padding=(0, 15)).grid(row=1, column=0, sticky='w')
        ttk.Label(body, text='현재 PC의 TCP 연결 · 약 2초마다 갱신 · 주의 연결을 위에 표시합니다.').grid(row=2, column=0, sticky='w', pady=(0, 8))
        columns = ('program', 'local', 'remote', 'state', 'verdict', 'reason')
        headings = ('프로그램 (PID)', '내 PC 주소:포트', '상대 주소:포트', '연결 상태', '판정', '이유')
        widths = (175, 165, 165, 110, 65, 300)
        table = ttk.Frame(body)
        table.grid(row=3, column=0, sticky='nsew')
        self.tree = ttk.Treeview(table, columns=columns, show='headings')
        for column, title, width in zip(columns, headings, widths):
            self.tree.heading(column, text=title)
            self.tree.column(column, width=width, minwidth=60, stretch=(column == 'reason'))
        self.tree.tag_configure('주의', background='#fff0dc', foreground='#7c4000')
        sy = ttk.Scrollbar(table, orient='vertical', command=self.tree.yview)
        sx = ttk.Scrollbar(table, orient='horizontal', command=self.tree.xview)
        self.tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.tree.grid(row=0, column=0, sticky='nsew')
        sy.grid(row=0, column=1, sticky='ns')
        sx.grid(row=1, column=0, sticky='ew')
        table.rowconfigure(0, weight=1)
        table.columnconfigure(0, weight=1)
        self.status = tk.StringVar(value='시작 버튼을 누르면 실제 연결을 확인합니다.')
        status_label = ttk.Label(body, textvariable=self.status, padding=(0, 10), wraplength=780)
        status_label.grid(row=4, column=0, sticky='w')
        note = ttk.Label(body, text='정상 = 점검 규칙에 걸리지 않음 / 주의 = 확인 필요. 안전·악성 확정 판정은 아닙니다.\n송수신량은 PC 전체 네트워크 합계입니다. 연결별 패킷 내용과 공격 여부는 검사하지 않습니다.', wraplength=780)
        note.grid(row=5, column=0, sticky='w')
        body.bind('<Configure>', lambda event: [label.configure(wraplength=max(100, event.width - 32)) for label in (status_label, note)])
        self.poll_job = self.after(100, self.poll)
        self.protocol('WM_DELETE_WINDOW', self.destroy)

    def toggle(self):
        self.generation += 1
        self.running = not self.running
        self.previous = None
        if self.collect_job:
            self.after_cancel(self.collect_job)
            self.collect_job = None
        self.button.configure(text='모니터링 중지' if self.running else '모니터링 시작')
        self.status.set('연결 정보를 읽는 중…' if self.running else '중지됨 · 마지막 목록을 표시합니다.')
        self.traffic.set('송신  —     수신  —')
        if self.running:
            self.latest = None
            self.tree.delete(*self.tree.get_children())
            self.collect(self.generation)

    def collect(self, generation):
        if not self.running or generation != self.generation:
            return
        if self.busy:
            self.collect_job = self.after(100, lambda: self.collect(generation))
            return
        self.busy = True

        def work():
            try:
                self.result.put((generation, snapshot(), None))
            except Exception as exc:
                self.result.put((generation, None, str(exc)))
        threading.Thread(target=work, daemon=True).start()

    def poll(self):
        try:
            generation, current, error = self.result.get_nowait()
        except queue.Empty:
            pass
        else:
            self.busy = False
            if self.running and generation == self.generation:
                if error:
                    self.running = False
                    self.button.configure(text='모니터링 시작')
                    self.tree.delete(*self.tree.get_children())
                    self.latest = self.previous = None
                    self.traffic.set('송신  —     수신  —')
                    self.status.set(f'조회 실패: {error}. 권한 또는 네트워크 상태를 확인하세요.')
                else:
                    self.show(current)
                    self.collect_job = self.after(2000, lambda: self.collect(generation))
        self.poll_job = self.after(100, self.poll)

    def destroy(self):
        if self.closed:
            return
        self.closed = True
        self.running = False
        self.generation += 1
        for job in (self.poll_job, self.collect_job):
            if job:
                self.after_cancel(job)
        super().destroy()

    def show(self, current):
        sent, received = rates(self.previous, current)
        self.traffic.set(f'송신  {sent / 1024:,.1f} KB/s     수신  {received / 1024:,.1f} KB/s' if self.previous else '송신·수신 속도 계산 중… 다음 갱신에서 표시합니다.')
        self.previous = self.latest = current
        selected = {tuple(self.tree.item(i, 'values')[:3]) for i in self.tree.selection()}
        position = self.tree.yview()[0]
        self.tree.delete(*self.tree.get_children())
        for row in current.rows:
            values = astuple(row)
            item = self.tree.insert('', 'end', values=values, tags=(row.verdict,))
            if values[:3] in selected:
                self.tree.selection_add(item)
        self.tree.yview_moveto(position)
        cautions = sum(row.verdict == '주의' for row in current.rows)
        self.status.set(f'연결 {len(current.rows)}개 · 정상 {len(current.rows) - cautions}개 · 주의 {cautions}개')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--smoke-test', action='store_true')
    parser.add_argument('--report', default='smoke.json')
    args = parser.parse_args()
    app = App()
    if args.smoke_test:
        smoke_test(app, args.report)
        return
    app.mainloop()


def smoke_test(app, report_path):
    """Verify two live samples using only a temporary loopback connection."""
    import socket
    report = {'started': True, 'live_local_connection_found': False, 'rates_updated': False}
    samples = []
    deadline = monotonic() + 15
    try:
        with ExitStack() as sockets:
            listener = sockets.enter_context(socket.socket())
            listener.bind(('127.0.0.1', 0))
            listener.listen(1)
            client = sockets.enter_context(socket.create_connection(listener.getsockname(), timeout=2))
            listener.settimeout(2)
            peer, _ = listener.accept()
            sockets.enter_context(peer)
            address = f'127.0.0.1:{listener.getsockname()[1]}'
            # Move a small local payload; no external server is contacted.
            client.sendall(b'local test')
            peer.recv(1024)
            app.toggle()

            def check():
                if app.latest and (not samples or app.latest.taken_at != samples[-1].taken_at):
                    samples.append(app.latest)
                if len(samples) < 2 and app.running and monotonic() < deadline:
                    app.after(100, check)
                    return
                report.update(live_local_connection_found=bool(app.latest and any(address in (r.local, r.remote) for r in app.latest.rows)),
                              rates_updated=len(samples) >= 2 and 'KB/s' in app.traffic.get(),
                              rows_rendered=len(app.tree.get_children()), single_window=True)
                app.quit()
            app.after(100, check)
            app.mainloop()
        Path(report_path).write_text(json.dumps(report, indent=2), encoding='utf-8')
    finally:
        app.destroy()
    if not report['live_local_connection_found'] or not report['rates_updated']:
        raise RuntimeError('실제 연결 수집 또는 연속 갱신 검증 실패')


if __name__ == '__main__':
    main()
