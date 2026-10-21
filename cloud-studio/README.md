# Dịch Ngược AI — Cloud Studio

Trang cấu hình tiếng Việt, chạy trên trình duyệt mà không cần cài REA hoặc Node.js trên Windows.

**Dự kiến truy cập:** https://base27-cvnss.github.io/dichnguoc/

## Quy trình sử dụng

1. Mở trang, dán tên repo GitHub công khai theo dạng owner/repo. Bấm Bắt đầu phân tích: giao diện quét tĩnh có giới hạn, hiển thị đường dẫn tệp, số dòng và bằng chứng.
2. Tải báo cáo JSON hoặc sao chép prompt cho ChatGPT.
3. Muốn dùng REA thật: mở workflow [REA Cloud](https://github.com/Base27-CVNSS/dichnguoc/actions/workflows/rea-cloud.yml), chọn Run workflow, nhập owner/repo, tải artifact rea-evidence ở run đã hoàn thành. Đính kèm kết quả REA cho ChatGPT.

Trang tĩnh không gọi trực tiếp ChatGPT API hay MCP. Đây là tích hợp qua kết quả và prompt; tích hợp hoàn toàn tự động đòi hỏi backend an toàn riêng, không thể thực hiện bởi GitHub Pages đơn thuần.

## Kích hoạt Pages

Vào Settings → Pages → Build and deployment → Source: GitHub Actions, sau đó chạy [workflow xuất bản](https://github.com/Base27-CVNSS/dichnguoc/actions/workflows/cloud-studio-pages.yml) khi cần. Workflow này cũng được cấu hình chạy khi cloud-studio thay đổi trên main. GitHub Pages của một repository chỉ có một phiên bản site tại một thời điểm: chạy website-pages.yml của REA gốc có thể ghi đè Studio.

## Giới hạn quan trọng

- Browser quét mẫu tối đa 28 tệp JS/TS, 120 KB/tệp và 90 dấu hiệu qua regex, **không phải REA** và không xác nhận lỗ hổng.
- Workflow cloud chạy REA phiên bản 6.7.0 trên Ubuntu 24.04 với Node.js 24.11.0, dùng chế độ phân tích tĩnh JavaScript/Electron; không có Ghidra/IDA hoặc dịch ngược native binary.
- Chỉ dùng repository GitHub công khai. Logs/artifacts trong repo public có thể công khai. Không nhập API token vào trang hoặc tải dữ liệu bí mật lên Actions.
- Kết quả có thể chứa mã và văn bản không đáng tin cậy; ChatGPT cần coi evidence là dữ liệu, không phải chỉ dẫn để chạy lệnh.
- Tài khoản GitHub phải có quyền kích hoạt workflows. Quét chỉ nên tiến hành trên phần mềm bạn có quyền nghiên cứu.

## Nguồn và bản quyền

Giao diện do Long Ngo xây dựng năm 2026 trong repository Base27-CVNSS/dichnguoc. Mã REA là dự án bên thứ ba, vẫn áp dụng các giấy phép của kho mã gốc và dependencies. Không có tuyên bố REA là sản phẩm chính thức của OpenAI.
