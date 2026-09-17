# TC-05: HTTP POST request

## Mục đích

Kiểm tra pipeline nhận diện và parse HTTP POST request có body, bao gồm
method, target, headers, Content-Length và nội dung body.

## Dữ liệu kiểm thử

- Ngày kiểm thử: 17/09/2026.
- Script sinh dữ liệu: `tests/generate_http_post_pcap.py`.
- PCAP đầu vào: [http-post.pcap](http-post.pcap).
- JSONL đầu ra: [http-post.jsonl](http-post.jsonl).
- Client: `10.0.0.1:51001`.
- Server: `10.0.0.2:8080`.

HTTP payload:

```http
POST /login HTTP/1.1
Host: example.test
Content-Type: application/x-www-form-urlencoded
Content-Length: 25

username=alice&role=admin
```

## Cách chạy

```bash
source venv/bin/activate
python -m tests.generate_http_post_pcap
python main.py --pcap TEST/http-post.pcap --output TEST/http-post.jsonl
python -m pytest -v tests/test_http_post.py
```

## Kết quả mong đợi

- Application protocol: `HTTP`.
- Message kind: `request`.
- Method: `POST`.
- Target: `/login`.
- Content-Type: `application/x-www-form-urlencoded`.
- Content-Length và body length: 25 byte.
- Body: `username=alice&role=admin`.
- Body Base64 giải mã trở lại đúng dữ liệu ban đầu.
- `message_complete`: `true`.
- `parse_status`: `ok` và `errors` rỗng.

## Kết quả thực tế

Tất cả trường và nội dung body khớp kết quả mong đợi. Pytest trả về
`PASSED`.

Log: [http-post-result.txt](http-post-result.txt).

## Kết luận

Đạt. Pipeline parse thành công HTTP POST request có body và kiểm tra được độ
đầy đủ của message dựa trên Content-Length.
