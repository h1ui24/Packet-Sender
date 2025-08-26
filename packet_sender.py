#!/usr/bin/env python3
# packet_sender.py

import sys
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QLineEdit, QLabel, QComboBox, QVBoxLayout, QTextEdit
)
from scapy.all import *

class PacketSender(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Packet Sender')

        # 목적지 IP
        self.ip_label = QLabel('목적지 IP:')
        self.ip_input = QLineEdit()

        # 출발지 포트
        self.sport_label = QLabel('출발지 포트:')
        self.sport_input = QLineEdit()
        self.sport_input.setText('12345')  # 기본값

        # 목적지 포트
        self.dport_label = QLabel('목적지 포트:')
        self.dport_input = QLineEdit()
        self.dport_input.setText('53')     # 기본값

        # 프로토콜 선택 (TCP 제거)
        self.proto_label = QLabel('프로토콜:')
        self.proto_combo = QComboBox()
        self.proto_combo.addItems(['UDP', 'ICMP'])

        # Payload 입력 (예시 추가)
        self.payload_label = QLabel('Payload (hex, 예: \\x9f\\x4f\\x00\\x00\\)')
        self.payload_input = QTextEdit()

        # 전송 버튼
        self.send_btn = QPushButton('패킷 전송하기')
        self.send_btn.clicked.connect(self.send_packet)

        # 결과 표시
        self.result_label = QLabel('결과: -')

        # 레이아웃 구성
        layout = QVBoxLayout()
        layout.addWidget(self.ip_label)
        layout.addWidget(self.ip_input)
        layout.addWidget(self.sport_label)
        layout.addWidget(self.sport_input)
        layout.addWidget(self.dport_label)
        layout.addWidget(self.dport_input)
        layout.addWidget(self.proto_label)
        layout.addWidget(self.proto_combo)
        layout.addWidget(self.payload_label)
        layout.addWidget(self.payload_input)
        layout.addWidget(self.send_btn)
        layout.addWidget(self.result_label)

        self.setLayout(layout)
        self.resize(400, 500)
        self.show()

    def send_packet(self):
        ip = self.ip_input.text()
        sport = int(self.sport_input.text()) if self.sport_input.text() else 12345
        dport = int(self.dport_input.text()) if self.dport_input.text() else 53
        proto = self.proto_combo.currentText()

        # \x 제거
        payload_str = self.payload_input.toPlainText().replace('\\x', '')

        try:
            payload = bytes.fromhex(payload_str)
        except ValueError:
            self.result_label.setText('결과: Payload hex 포맷 오류!')
            return

        pkt = IP(dst=ip)
        if proto == 'UDP':
            pkt /= UDP(sport=sport, dport=dport)/Raw(load=payload)
        elif proto == 'ICMP':
            pkt /= ICMP()/Raw(load=payload)

        try:
            send(pkt, verbose=False)
            self.result_label.setText('결과: 패킷 전송 성공!')
        except Exception as e:
            self.result_label.setText(f'결과: 전송 실패! {e}')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = PacketSender()
    sys.exit(app.exec_())
