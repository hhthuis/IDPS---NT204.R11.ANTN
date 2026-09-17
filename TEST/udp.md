# TC-03: UDP data

## Mục đích

Kiểm tra pipeline parse được UDP packet và trích xuất đúng địa chỉ IP, port,
UDP length và payload.

## Dữ liệu kiểm thử

- Ngày kiểm thử: 17/09/2026.
- Dữ liệu được sinh bằng Scapy từ `tests/generate_transport_pcap.py`.
- PCAP đầu vào: [transport-test.pcap](transport-test.pcap).
- JSONL đầu ra: [transport-test.jsonl](transport-test.jsonl).
- Event được đối chiếu: 5.
- Hướng truyền: `10.0.0.3:53000 → 10.0.0.4:9999`.
- Payload: `hello udp`.

## Cách chạy

```bash
source venv/bin/activate
python -m tests.generate_transport_pcap
python main.py --pcap TEST/transport-test.pcap --output TEST/transport-test.jsonl
python -m pytest -v tests/test_pcap_pipeline.py::test_udp_data
```

## Kết quả mong đợi

- Transport protocol là `UDP`.
- Source port là `53000`, destination port là `9999`.
- UDP length là 17 byte, gồm header 8 byte và payload 9 byte.
- Payload Base64 giải mã thành `hello udp`.
- `parse_status` bằng `ok` và `errors` rỗng.

## Kết quả thực tế

- Event 5: UDP `53000 → 9999`.
- UDP length: 17 byte.
- Payload length: 9 byte.
- Text preview và dữ liệu giải mã từ Base64 bằng `hello udp`.
- Pytest: `PASSED`.
- Log: [udp-result.txt](udp-result.txt).

## Kết luận

Đạt. Pipeline trích xuất đúng UDP metadata và giữ nguyên payload.
