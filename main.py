"""보안관제Lite 간단 버전: python main.py"""
import argparse
from dataclasses import astuple
import json
from pathlib import Path
import queue
import threading
import tkinter as tk
from tkinter import ttk
from monitor import snapshot, rates


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('보안관제Lite · 간단 버전')
        self.geometry('1100x590')
        self.minsize(820, 430)
        self.running = False
        self.busy = False
        self.generation = 0
        self.previous = None
        self.latest = None
        self.result = queue.Queue()
        style = ttk.Style(self)
        style.theme_use('clam')
        style.configure('.', font=('맑은 고딕', 10))
        style.configure('Treeview', rowheight=29)
        body = ttk.Frame(self, padding=16)
        body.pack(fill='both', expand=True)
        top = ttk.Frame(body)
        top.pack(fill='x')
        ttk.Label(top, text='보안관제Lite', font=('맑은 고딕', 19, 'bold')).pack(side='left')
        self.button = ttk.Button(top, text='모니터링 시작', command=self.toggle)
        self.button.pack(side='right')
        self.traffic = tk.StringVar(value='송신  —     수신  —')
        ttk.Label(body, textvariable=self.traffic, font=('맑은 고딕', 13), padding=(0, 15)).pack(anchor='w')
        ttk.Label(body, text='현재 PC의 TCP 연결 · 2초마다 갱신 · 주의 연결을 위에 표시합니다.').pack(anchor='w', pady=(0, 8))
        columns = ('program', 'local', 'remote', 'state', 'verdict', 'reason')
        headings = ('프로그램 (PID)', '내 PC 주소:포트', '상대 주소:포트', '연결 상태', '판정', '이유')
        widths = (175, 165, 165, 110, 65, 300)
        table = ttk.Frame(body)
        table.pack(fill='both', expand=True)
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
        ttk.Label(body, textvariable=self.status, padding=(0, 10)).pack(anchor='w')
        ttk.Label(body, text='정상 = 점검 규칙에 걸리지 않음 / 주의 = 확인 필요. 안전·악성 확정 판정은 아닙니다.\n송수신량은 PC 전체 네트워크 합계입니다. 연결별 패킷 내용과 공격 여부는 검사하지 않습니다.', wraplength=1000).pack(anchor='w')
        self.after(100, self.poll)

    def toggle(self):
        self.generation += 1
        self.running = not self.running
        self.previous = None
        self.button.configure(text='모니터링 중지' if self.running else '모니터링 시작')
        self.status.set('연결 정보를 읽는 중…' if self.running else '중지됨 · 마지막 목록을 표시합니다.')
        self.traffic.set('송신  —     수신  —')
        if self.running:
            self.collect(self.generation)

    def collect(self, generation):
        if not self.running or generation != self.generation:
            return
        if self.busy:
            self.after(100, lambda: self.collect(generation))
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
                    self.after(2000, lambda: self.collect(generation))
        self.after(100, self.poll)

    def show(self, current):
        sent, received = rates(self.previous, current)
        self.traffic.set(f'송신  {sent / 1024:,.1f} KB/s     수신  {received / 1024:,.1f} KB/s' if self.previous else '송신·수신 속도 계산 중… 다음 갱신에서 표시합니다.')
        self.previous = self.latest = current
        self.tree.delete(*self.tree.get_children())
        for row in current.rows:
            self.tree.insert('', 'end', values=astuple(row), tags=(row.verdict,))
        cautions = sum(row.verdict == '주의' for row in current.rows)
        self.status.set(f'연결 {len(current.rows)}개 · 정상 {len(current.rows) - cautions}개 · 주의 {cautions}개')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--smoke-test', action='store_true')
    parser.add_argument('--report', default='smoke.json')
    args = parser.parse_args()
    app = App()
    if args.smoke_test:
        # Local-only connection proves collection works without contacting a server.
        import socket
        listener = socket.socket()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        client = socket.create_connection(listener.getsockname())
        peer, _ = listener.accept()
        app.toggle()
        attempts = [0]

        def check():
            attempts[0] += 1
            if app.latest is None and attempts[0] < 100:
                app.after(100, check)
                return
            found = bool(app.latest and any(f'127.0.0.1:{listener.getsockname()[1]}' in (r.local, r.remote) for r in app.latest.rows))
            report = {'started': True, 'live_local_connection_found': found,
                      'rows_rendered': len(app.tree.get_children()), 'single_window': True}
            Path(args.report).write_text(json.dumps(report, indent=2), encoding='utf-8')
            peer.close()
            client.close()
            listener.close()
            app.destroy()
        app.after(100, check)
    app.mainloop()
    if args.smoke_test:
        report = json.loads(Path(args.report).read_text(encoding='utf-8'))
        if not report['live_local_connection_found']:
            raise RuntimeError('실제 로컬 연결 수집 검증 실패')


if __name__ == '__main__':
    main()
