# NOVA MART: checker, scoreboard và vận hành

Tài liệu triển khai đầy đủ ở [docs/DEPLOYMENT.vi.md](../docs/DEPLOYMENT.vi.md). Hệ thống dùng SQLite cho trạng thái cuộc thi ở Windows backend và SQLite độc lập cho từng instance bán hàng trên VM. Không cần dựng MySQL/PostgreSQL cho bản chạy đơn máy này.

## Lịch và cách tính điểm

Mặc định cuộc thi kéo dài 60 phút: 2 round × 30 phút, mỗi round 15 tick × 120 giây. Round 1 chấm `shop01`; round 2 chấm `shop02`. Backend chọn service và deadline bằng đồng hồ của nó.

Checker chạy đầu mỗi tick cho từng đội: xác minh sandbox/service identity, đăng ký tài khoản khách của tick, giải CAPTCHA theo phép tính, đăng nhập, tạo đơn mang flag bí mật rồi đọc lại đơn. UP được tính khi toàn bộ luồng thành công; DOWN, MUMBLE, ERROR hoặc không có kết quả trước deadline được 0 SLA ở tick đó. Kết quả ghi một lần theo `(tick, team)`.

Flag được đặt trong `private_note` của đơn hàng. TTL mặc định 3 tick và kết thúc khi round đổi service. Capture hợp lệ: đội tấn công +100, đội sở hữu −100. Nộp lặp, tự nộp, flag hết hạn hoặc đơn chưa được checker xác nhận đều không có điểm. Giá trị flag/password chỉ được gửi cho checker đã xác thực; scoreboard công khai chỉ có đội, tick, mã đơn và điểm.

## Năm lỗ hổng có thể bật/tắt

Trong `deployment.json`, mỗi service NOVA MART có đủ năm khóa boolean `vulnerabilities`:

| Khóa | Hành vi thử thách | Hướng vá để kiểm tra đội phòng thủ |
|---|---|---|
| `sqli` | Catalog search ghép trực tiếp input vào truy vấn SQLite; có thể đọc `orders.private_note`. | Dùng parameter binding cho `LIKE ?`. |
| `captcha_bypass` | Login chấp nhận `captcha_verified=1` thay cho challenge một lần. | Chỉ chấp nhận CAPTCHA ID còn hạn và đáp án phía server. |
| `xss` | Nội dung review được render như HTML. | Escape nội dung theo HTML context; không chèn string vào DOM. |
| `csrf` | Bỏ qua token; `GET /api/orders/share` làm thay đổi quyền chia sẻ. | Từ chối GET có side effect, yêu cầu token bí mật và kiểm tra Origin. |
| `brute_force` | Không giới hạn login; tài khoản `merchant` dùng mật khẩu yếu được chọn trong `market00`–`market31`. | Giới hạn thử sai theo tài khoản/IP; dùng mật khẩu mạnh và cảnh báo. |

Khi thay khóa bằng `false`, health và checker chức năng vẫn phải chạy. Checker tạo buyer riêng, không dùng tài khoản merchant hay endpoint đặc quyền.

## Cấu hình, preflight và start

Sau allocation mới, dùng đúng `user-config` của sandbox mới:

```powershell
.\Configure-Deployment.ps1 -SshConfig "$env:USERPROFILE\.ssh\<CURRENT-ALLOCATION-user-config>" -Access local -EventId nova-demo-01
.\CyberRangeCZ-Windows-Gateway\Test-CTFGateway.ps1 -CheckSsh
```

`Configure-Deployment.ps1` đọc ID allocation, sinh config gateway và URL checker, tạo SQLite trung tâm cùng token trong runtime riêng, rồi để event ở READY. Xác minh host fingerprint theo gateway guide trước khi accept. `local` chỉ mở listener loopback trên máy vận hành.

Chạy preflight trước khi bắt đầu đồng hồ:

```powershell
py -3 -m gameserver.worker --preflight
```

Nếu mọi đội UP, mở stack:

```powershell
.\gameserver\Start-Stack.ps1
```

Stack khởi động/reuse gateway, chạy preflight, mở API và checker rồi bắt đầu 60 phút. Bảng công khai ở `http://127.0.0.1:9000/` (hoặc backend port đã cấu hình); monitor ban tổ chức ở `/monitor`.

Muốn cho máy đội truy cập gateway, cấu hình `-Access lan -GatewayIp auto -ClientCidr <CIDR-DA-XAC-NHAN>` rồi mở firewall đúng CIDR bằng `Apply-GatewayFirewall.ps1`. Đừng mở phạm vi Internet rộng. Phát URL gateway từng đội và scoreboard sau khi test từ chính mạng thi.

## Token đội và trang giám sát

Runtime nằm trong `gameserver/runtime-sla-<event-id>`. Ban tổ chức đọc file `teams/team01.json` tương ứng và phát riêng trường `token` cho đội đó qua kênh bảo mật; không đưa file `config.json`, `worker.json`, `operator.json` hoặc database cho thí sinh. Monitor token nằm trong `monitor.json`; chỉ người vận hành được dùng. Hai trang không cần cài thêm database service.

Scoreboard công khai tự refresh trạng thái tick, service, SLA, điểm attack/defense, lịch sử checker và captures. Biểu mẫu nộp flag dùng Bearer team token; giới hạn là 60 lần/phút/đội. Monitor yêu cầu organizer monitor token và hiển thị heartbeat worker, kết quả checker gần nhất, tick lỗi do scheduler và số bản ghi SQLite. Monitor không cho xem flag/password.

## Dữ liệu trung tâm và dữ liệu shop

`competition.sqlite` nằm trong runtime Windows riêng, journal mode WAL. Backend là tiến trình duy nhất mở file; worker và giao diện gọi API. Các bảng chính: `event`, `teams`, `services`, `competition_rounds`, `ticks`, `tick_checks`, `tick_flags`, `tick_captures`, `tick_submissions`, `worker_status`, `audit`. UNIQUE/PRIMARY KEY chống ghi kết quả/capture hai lần.

Mỗi VM và mỗi service có SQLite riêng dưới `/var/lib/idor-free-lab/<service-id>/service.sqlite`. Hai round không dùng chung DB đơn hàng. Web app chạy bằng `free-lab-web`, không chạy root. Mật khẩu và flag của cuộc thi nằm trong runtime trung tâm; giữ ACL runtime chỉ cho tài khoản vận hành.

Sao lưu database đang chạy bằng SQLite backup API:

```powershell
py -3 -m gameserver.control backup --destination "D:\CTF-backups\nova-demo-01.sqlite"
py -3 -m gameserver.control finish
```

Destination phải là file mới ở thư mục backup đã có. Bảo vệ backup như dữ liệu organizer; chỉ restore cùng cấu hình và event ID gốc.

## API dành cho vận hành

- Public: `GET /health`, `/api/scoreboard`, `/api/checks`, `/api/attack-data`.
- Checker Bearer: `GET /api/checker/plan`, `POST /api/checker/result`, `POST /api/checker/heartbeat`.
- Đội Bearer: `POST /api/submit`.
- Monitor Bearer: `GET /api/monitor`.
- Admin Bearer: `POST /api/admin/start` hoặc `/api/admin/finish` với JSON `{}`.

`worker` tự poll theo deadline; nếu máy vận hành ngủ hoặc mất mạng, tick không có kết quả được ghi `ERROR` với 0 SLA. Khởi động lại worker không phát lại điểm đã ghi. Có thể kiểm tra trạng thái không chạm pool bằng `py -3 -m gameserver.demo --fast`; demo dùng VM giả lập trong loopback, tăng tốc 30 tick thành khoảng 2,5 phút.

## Phạm vi xác minh

Unit/HTTP tests chạy local xác nhận các lỗ hổng bật/tắt, luồng đặt đơn flag, chấm capture, hạn flag, token monitor và xử lý tick DOWN. `py -3 -m gameserver.definition` kiểm tra file sinh. GitHub workflow chạy kiểm tra Ansible syntax trên Linux. Các phép thử local không chứng minh CyberRangeCZ đã tạo VM; cần allocation mới để xác nhận image/flavor, user-access SSH, gateway forward và service thật.
