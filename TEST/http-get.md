# TC-04: HTTP GET request

## Mục đích

Kiểm tra pipeline nhận diện và parse HTTP GET request, bao gồm method,
request target, HTTP version và headers. Request sử dụng port 8080 để xác
minh detector không phụ thuộc tuyệt đối vào port 80.

## Dữ liệu kiểm thử

- Ngày kiểm thử: 17/09/2026.
- Script sinh dữ liệu: `tests/generate_http_get_pcap.py`.
- PCAP đầu vào: [http-get.pcap](http-get.pcap).
- JSONL đầu ra: [http-get.jsonl](http-get.jsonl).
- Client: `10.0.0.1:51000`.
- Server: `10.0.0.2:8080`.

HTTP payload:

```http
GET /products?id=10 HTTP/1.1
Host: example.test
User-Agent: IDS-Test/1.0
Accept: */*
```

## Cách chạy

```bash
source venv/bin/activate
python -m tests.generate_http_get_pcap
python main.py --pcap TEST/http-get.pcap --output TEST/http-get.jsonl
python -m pytest -v tests/test_http_get.py
```

## Kết quả mong đợi

- Application protocol: `HTTP`.
- Message kind: `request`.
- Method: `GET`.
- Target: `/products?id=10`.
- Version: `HTTP/1.1`.
- Header `Host`: `example.test`.
- Body length: 0 byte.
- `message_complete`: `true`.
- `parse_status`: `ok` và `errors` rỗng.

## Kết quả thực tế

Tất cả trường khớp với kết quả mong đợi. HTTP được nhận diện đúng trên port
8080 và pytest trả về `PASSED`.

Log: [http-get-result.txt](http-get-result.txt).

## Kết luận

Đạt. Pipeline parse thành công HTTP GET request và các headers được chuẩn hóa
về tên chữ thường.
