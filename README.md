# Packet Capture & Parser for IDS

Module thu thập packet từ live traffic hoặc file PCAP, phân tích IPv4,
TCP, UDP, HTTP/1.x, DNS và SMTP, sau đó xuất dữ liệu chuẩn hóa dưới
định dạng JSON Lines.

## Yêu cầu

- Python 3.12+
- Quyền root hoặc Linux capabilities khi live capture

## Cài đặt

```bash
python -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt

