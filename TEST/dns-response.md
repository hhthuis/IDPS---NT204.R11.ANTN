# TC-08: DNS response

## Mục đích

Kiểm tra pipeline nhận diện và parse DNS response, bao gồm transaction ID,
flags, response code và ít nhất một answer record.

## Dữ liệu kiểm thử

- Ngày kiểm thử: 17/09/2026.
- Script sinh dữ liệu: `tests/generate_dns_response_pcap.py`.
- PCAP đầu vào: [dns-response.pcap](dns-response.pcap).
- JSONL đầu ra: [dns-response.jsonl](dns-response.jsonl).
- DNS server: `10.0.0.53:53`.
- Client: `10.0.0.1:53000`.
- Transaction ID: `0x1234`.
- Answer: `example.test A 192.0.2.10`.
- TTL: 300 giây.

## Cách chạy

```bash
source venv/bin/activate
python -m tests.generate_dns_response_pcap
python main.py --pcap TEST/dns-response.pcap --output TEST/dns-response.jsonl
python -m pytest -v tests/test_dns_response.py
```

## Kết quả mong đợi

- Application protocol: `DNS`.
- Message kind: `response`.
- Transaction ID: `4660` (`0x1234`).
- Opcode: `QUERY`.
- Response code: `NOERROR`.
- Authoritative answer: `true`.
- Recursion desired và recursion available: `true`.
- Question count: 1.
- Answer count: 1.
- Answer name: `example.test`.
- Answer type: `A`, type code 1.
- Answer class: `IN`, class code 1.
- TTL: 300.
- Answer data: `192.0.2.10`.
- `message_complete`: `true`.
- `parse_status`: `ok` và `errors` rỗng.

## Kết quả thực tế

DNS response được parse đúng và answer record khớp hoàn toàn với dữ liệu đầu
vào. Pytest trả về `PASSED`.

Log: [dns-response-result.txt](dns-response-result.txt).

## Kết luận

Đạt. Pipeline parse thành công DNS response và ít nhất một answer record.
