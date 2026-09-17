# TC-06: HTTP response

## Mục đích

Kiểm tra pipeline nhận diện và parse HTTP response, bao gồm HTTP version,
status code, reason phrase, headers và response body.

## Dữ liệu kiểm thử

- Ngày kiểm thử: 17/09/2026.
- Script sinh dữ liệu: `tests/generate_http_response_pcap.py`.
- PCAP đầu vào: [http-response.pcap](http-response.pcap).
- JSONL đầu ra: [http-response.jsonl](http-response.jsonl).
- Server: `10.0.0.2:8080`.
- Client: `10.0.0.1:51002`.

HTTP payload:

```http
HTTP/1.1 200 OK
Server: IDS-Test/1.0
Content-Type: text/plain; charset=utf-8
Content-Length: 11

Hello, IDS!
```

## Cách chạy

```bash
source venv/bin/activate
python -m tests.generate_http_response_pcap
python main.py --pcap TEST/http-response.pcap --output TEST/http-response.jsonl
python -m pytest -v tests/test_http_response.py
```

## Kết quả mong đợi

- Application protocol: `HTTP`.
- Message kind: `response`.
- Version: `HTTP/1.1`.
- Status code: `200`.
- Reason phrase: `OK`.
- Server header: `IDS-Test/1.0`.
- Content-Type: `text/plain; charset=utf-8`.
- Content-Length và body length: 11 byte.
- Body: `Hello, IDS!`.
- `message_complete`: `true`.
- `parse_status`: `ok` và `errors` rỗng.

## Kết quả thực tế

Tất cả trường, headers và response body khớp kết quả mong đợi. Pytest trả về
`PASSED`.

Log: [http-response-result.txt](http-response-result.txt).

## Kết luận

Đạt. Pipeline parse thành công HTTP response, status code và body.
