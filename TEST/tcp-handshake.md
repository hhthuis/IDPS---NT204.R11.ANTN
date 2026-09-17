# TC-01: TCP handshake

## Mục đích

Kiểm tra pipeline đọc đúng ba packet thiết lập kết nối TCP gồm SYN,
SYN/ACK và ACK; đồng thời trích xuất đúng địa chỉ IP, port, sequence number,
acknowledgment number và TCP flags.

## Dữ liệu kiểm thử

- Ngày kiểm thử: 17/09/2026.
- Dữ liệu được sinh bằng Scapy từ `tests/generate_transport_pcap.py`.
- PCAP đầu vào: [transport-test.pcap](transport-test.pcap).
- JSONL đầu ra: [transport-test.jsonl](transport-test.jsonl).
- Các event được đối chiếu: 1, 2 và 3.
- Client: `10.0.0.1:51000`.
- Server: `10.0.0.2:8080`.

## Cách chạy

```bash
source venv/bin/activate
python -m tests.generate_transport_pcap
python main.py --pcap TEST/transport-test.pcap --output TEST/transport-test.jsonl
python -m pytest -v tests/test_pcap_pipeline.py::test_tcp_handshake
```

## Kết quả mong đợi

| Event | Hướng | Flags | Sequence | Acknowledgment | Payload |
|---|---|---|---:|---:|---:|
| 1 | Client → Server | SYN | 1000 | 0 | 0 byte |
| 2 | Server → Client | SYN, ACK | 2000 | 1001 | 0 byte |
| 3 | Client → Server | ACK | 1001 | 2001 | 0 byte |

Mỗi event phải có `parse_status` bằng `ok` và danh sách `errors` rỗng.

## Kết quả thực tế

- Event 1: TCP `51000 → 8080`, flags `SYN`, payload 0 byte.
- Event 2: TCP `8080 → 51000`, flags `SYN, ACK`, payload 0 byte.
- Event 3: TCP `51000 → 8080`, flags `ACK`, payload 0 byte.
- Pytest: `PASSED`.
- Log: [tcp-handshake-result.txt](tcp-handshake-result.txt).

## Kết luận

Đạt. Pipeline nhận diện đúng ba packet của TCP handshake và các trường kiểm
tra đều khớp với dữ liệu mong đợi.

## Phạm vi

Test xác minh việc parse từng packet handshake. Chương trình chưa có module
theo dõi trạng thái của toàn bộ kết nối TCP.
