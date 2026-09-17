# TC-02: TCP data

## Mục đích

Kiểm tra pipeline parse được TCP packet có payload, giữ đúng TCP flags,
sequence number, độ dài payload, text preview và dữ liệu Base64.

## Dữ liệu kiểm thử

- Ngày kiểm thử: 17/09/2026.
- Dữ liệu được sinh bằng Scapy từ `tests/generate_transport_pcap.py`.
- PCAP đầu vào: [transport-test.pcap](transport-test.pcap).
- JSONL đầu ra: [transport-test.jsonl](transport-test.jsonl).
- Event được đối chiếu: 4.
- Hướng truyền: `10.0.0.1:51000 → 10.0.0.2:8080`.
- Payload: `GET / HTTP/1.1\r\nHost: example.test\r\n\r\n`.

## Cách chạy

```bash
source venv/bin/activate
python -m tests.generate_transport_pcap
python main.py --pcap TEST/transport-test.pcap --output TEST/transport-test.jsonl
python -m pytest -v tests/test_pcap_pipeline.py::test_tcp_data
```

## Kết quả mong đợi

- Transport protocol là `TCP`.
- TCP flags là `PSH, ACK`.
- Sequence number là `1001`.
- Payload length là 38 byte.
- Payload Base64 giải mã trở lại đúng dữ liệu ban đầu.
- `parse_status` bằng `ok` và `errors` rỗng.
- Application protocol được detector nhận diện là `HTTP` dù dùng port 8080.
- Các trường HTTP chi tiết chưa được parse.

## Kết quả thực tế

- Event 4: TCP `51000 → 8080`.
- Flags: `PSH, ACK`.
- Payload length: 38 byte.
- Text preview và dữ liệu giải mã từ Base64 khớp payload đầu vào.
- Application protocol: `HTTP`.
- Pytest: `PASSED`.
- Log: [tcp-data-result.txt](tcp-data-result.txt).

## Kết luận

Đạt. Pipeline giữ nguyên payload TCP, trích xuất đúng các trường transport và
detector nhận diện payload là HTTP. Test này chưa được tính là HTTP GET parser
vì method, target, headers và body chưa được trích xuất.
