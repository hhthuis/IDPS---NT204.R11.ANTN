# TC-07: DNS query

## Mục đích

Kiểm tra pipeline nhận diện và parse DNS query, bao gồm transaction ID,
flags, domain, query type và query class.

## Dữ liệu kiểm thử

- Ngày kiểm thử: 17/09/2026.
- Script sinh dữ liệu: `tests/generate_dns_query_pcap.py`.
- PCAP đầu vào: [dns-query.pcap](dns-query.pcap).
- JSONL đầu ra: [dns-query.jsonl](dns-query.jsonl).
- Client: `10.0.0.1:53000`.
- DNS server: `10.0.0.53:53`.
- Transaction ID: `0x1234`.
- Domain: `example.test`.
- Query type: `A`.

## Cách chạy

```bash
source venv/bin/activate
python -m tests.generate_dns_query_pcap
python main.py --pcap TEST/dns-query.pcap --output TEST/dns-query.jsonl
python -m pytest -v tests/test_dns_query.py
```

## Kết quả mong đợi

- Application protocol: `DNS`.
- Message kind: `query`.
- Transaction ID: `4660` (`0x1234`).
- Opcode: `QUERY`.
- Response code: `NOERROR`.
- Recursion desired: `true`.
- Question count: 1.
- Answer count: 0.
- Question name: `example.test`.
- Question type: `A`, type code 1.
- Question class: `IN`, class code 1.
- `message_complete`: `true`.
- `parse_status`: `ok` và `errors` rỗng.

## Kết quả thực tế

Tất cả trường của DNS header và question record khớp kết quả mong đợi.
Pytest trả về `PASSED`.

Log: [dns-query-result.txt](dns-query-result.txt).

## Kết luận

Đạt. Pipeline parse thành công domain và query type của DNS query.
