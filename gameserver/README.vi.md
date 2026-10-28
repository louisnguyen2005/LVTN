# Checker tự động theo tick và database SLA

## Lịch đang áp dụng

- Cuộc thi 60 phút, gồm 2 round, mỗi round 30 phút.
- Mỗi round chọn một service; mỗi service có thông tin 5 lỗ hổng theo cấu hình bài.
- Một tick dài 2 phút. Mỗi round có 15 tick; toàn cuộc thi có 30 tick.
- Round 1: tick 1–15, service01. Round 2: tick 16–30, service02.
- Worker tự lấy kế hoạch từ backend, kiểm tra service của từng đội một lần ở đầu mỗi tick, rồi POST kết quả vào API/database.
- Mặc định UP được 1 SLA/tick; DOWN được 0. MUMBLE/ERROR cũng nhận 0. Điểm UP có thể chọn khi setup bằng `--sla-points`.
- Mỗi cặp đội/tick chỉ ghi một kết quả; gửi lại không cộng trùng. Nếu DOWN rồi hồi phục trong cùng tick thì kết quả tick đã ghi giữ nguyên; tick tiếp theo được kiểm tra lại độc lập.
- Nếu không nhận được kết quả trước khi hết tick, backend ghi ERROR với SLA 0 và nguồn scheduler. Kết quả gửi muộn bị từ chối. Điều này giúp phân biệt worker bị gián đoạn với service thực sự DOWN.

Ví dụ: t=0 bắt đầu tick 1; t=120s bắt đầu tick 2; t=1800s chuyển round 2 / tick 16 / service02; t=3600s kết thúc sau 30 tick. Deadline dựa vào đồng hồ backend. Thời gian không dừng khi Windows sleep hay worker bị tắt.

## Chạy demo ngay khi chưa có sandbox

Từ thư mục gốc project:

```powershell
py -3 -m gameserver.demo
```

Mở `http://127.0.0.1:19000/`. Demo chạy đúng lịch 1 giờ. Nó tự dựng hai service mô phỏng riêng cho mỗi đội bằng HTTP local và database riêng; backend/worker tự khởi động. Checker chỉ đo service được chọn ở round hiện tại. Sau khi thi xong, web vẫn mở để xem điểm; Ctrl+C dừng toàn bộ demo.

Để nhìn đủ 30 tick và chuyển round nhanh hơn:

```powershell
py -3 -m gameserver.demo --fast
```

Chế độ fast tăng tốc 60 lần: tick 2 giây, round 30 giây, tổng 60 giây; vẫn đúng 2 round và 30 tick. Web hiển thị thời gian demo thực tế. Mỗi lần chạy tạo thư mục `gameserver/runtime-demo-.../event/`, không dùng chung dữ liệu của giải thật.

Demo mặc định giả lập team02/service01 trả HTTP 503 ở tick 3: trạng thái DOWN, SLA 0. Tick 4 tự phục hồi và checker ghi UP/SLA 1. Kết thúc đủ 30 tick, team02 có 29/30 SLA, ba đội còn lại 30/30 nếu không có gián đoạn. Dùng `--no-outage` nếu muốn tất cả service luôn UP; dùng `--exit-after-finish` để tự đóng demo sau khi hoàn tất.

Thông tin “5 lỗ hổng” là metadata của bài dịch vụ. Demo mô phỏng lịch, chuyển service và SLA, chưa cài đặt 5 lỗ hổng thật cho mỗi service. Checker health không thử khai thác các lỗ hổng.

## Khi có sandbox thật

1. Bật allocation CyberRangeCZ; tải SSH ZIP đúng allocation và cấu hình gateway như tài liệu Word. IP gateway phải thuộc máy Windows hiện tại.
2. Chuẩn bị hai service thật và các port forward của chúng. Checker chuyển URL kiểm tra khi đổi round; nó không tự provision/bật/tắt service bên trong VM.
3. Tạo config service từ file mẫu:

```powershell
Copy-Item gameserver\services.example.json gameserver\services.json
notepad gameserver\services.json
```

File mẫu đã điền round 1 bằng các cổng hiện có 8011–8014. Round 2 để placeholder vì chưa có địa chỉ dịch vụ thật; phải điền URL `/health` và identity đúng của mỗi đội. Nếu round 2 dùng port khác thì thêm map tương ứng vào gateway config. Không dùng port ví dụ chưa triển khai. Service đang được chọn cần sẵn sàng trước tick đầu tiên của round đó.

Mỗi service có id, name, vulnerability_count=5, check và targets cho team01–team04. Thứ tự hai service trong JSON là thứ tự round. `expected_sandbox_suffix` được setup ghép với UUID allocation hiện tại. Endpoint health cần trả HTTP 200, JSON `status=ok` và `sandbox` đúng identity. HTTP 5xx/timeout được coi DOWN; phản hồi sai định dạng/identity là MUMBLE, cũng có SLA 0.

`check: health` là chế độ mặc định, chỉ đọc `/health` và không yêu cầu tickets-v2. Có thể dùng `check: functional` cho ServiceDesk để kiểm tra login alice, danh sách/đọc ticket; lúc đó mỗi target cần thêm password web tương ứng. File services.json bị Git ignore vì có thể chứa credential.

4. Tạo event/database mới theo lịch đã chốt:

```powershell
py -3 -m gameserver.setup --event-id sla-training-001 --services-config gameserver/services.json
```

Mặc định tạo `gameserver/runtime-sla/`, 2 round x 1800 giây, tick 120 giây, UP=1. Nếu thư mục đã có dữ liệu, chọn một directory/event-id mới; setup không ghi đè:

```powershell
py -3 -m gameserver.setup --directory gameserver/runtime-sla-002 --event-id sla-training-002 `
  --services-config gameserver/services.json --round-seconds 1800 --max-rounds 2 --tick-seconds 120 --sla-points 1
```

Database/cấu hình của event cũ vẫn gắn với luật cũ; không sửa config trực tiếp để gán lại dữ liệu cho lịch mới. Giữ runtime riêng cho mỗi event/allocation.

5. Chạy gateway, rồi kiểm tra service của round 1 trước khi bắt đầu:

```powershell
py -3 -m gameserver.worker --preflight
```

Preflight chỉ đo service đầu tiên vì service round 2 có thể chưa được bật. Nó không tính SLA của cuộc thi. Sau khi sẵn sàng, dùng một lệnh để chạy stack và bắt đầu thời gian:

```powershell
.\gameserver\Start-Stack.ps1
```

Nếu gateway đã chạy, có thể chỉ bật backend/worker:

```powershell
.\gameserver\Start-Competition.ps1 -StartEvent
```

Mở `http://127.0.0.1:9000/`. Giữ cửa sổ chạy. Với directory mới, truyền `-RuntimeDir gameserver/runtime-sla-002`. Khi đủ 30 tick, worker dừng nhận kế hoạch; scoreboard vẫn đọc được.

## Tự động và vận hành

- `Start-Stack.ps1` bật gateway khi chưa có listener, rồi backend/worker; kiểm tra IP và preflight trước khi start event mới.
- `Register-Competition.ps1` tùy chọn đăng ký Start-Stack ở lần đăng nhập Windows sau. Cần đúng mạng, SSH host keys đã xác minh và Python trong PATH. Thử thủ công trước khi đăng ký.
- Worker poll backend mỗi giây nhưng chỉ gọi service một lần cho mỗi đội/tick; các poll khác trả jobs rỗng. Kết quả DOWN vẫn được ghi nhận và tick sau tiếp tục kiểm tra.
- Lịch được lưu DB: restart không đặt lại tick hay điểm. Các tick bỏ lỡ được ghi SLA 0; không lấy kết quả tick mới bù tick cũ.
- Đội không cần nộp flag/token để xem bảng SLA. API ghi kết quả chỉ dành cho checker có Bearer token riêng.
- Log Start script: `gameserver/runtime-sla/logs/`. JSON kết quả được in bởi worker; nguồn dữ liệu bảng SLA là SQLite qua API.

Nếu cần máy khác xem dashboard, khởi chạy với `-BindAddress 0.0.0.0` và tạo Windows Firewall rule TCP 9000 chỉ cho CIDR đã xác nhận. Checker/admin vẫn có thể dùng loopback. Không chia sẻ runtime/config.json, worker.json, operator.json hoặc DB vì chúng chứa bí mật của ban vận hành.

## Database và API

Các bảng SLA: event, teams, services, competition_rounds, ticks, tick_checks. Một row tick_checks có tick, team, status, detail, elapsed_ms, checked_at, sla_points, source. Round và service lấy qua bảng ticks; PRIMARY KEY(tick,team) ngăn ghi điểm hai lần. Các bảng thử nghiệm flag của phiên bản trước không tham gia event mode=sla.

Public GET `/api/scoreboard`: round, tick, tick_in_round, deadline, service hiện tại, SLA từng đội. GET `/api/checks`: lịch sử tick/service/status/SLA. Các payload công khai không chứa password hay token.

Checker GET `/api/checker/plan`: jobs cho tick/service hiện tại. Checker POST `/api/checker/result`: `{tick, team, service_id, status, detail, elapsed_ms}`. Cả hai cần checker token. Sai service hoặc quá deadline bị từ chối. Admin POST `/api/admin/start` hoặc `/api/admin/finish` cần admin token; start lặp lại không xóa điểm/đặt lại đồng hồ.

```powershell
py -3 -m gameserver.control finish
py -3 -m gameserver.control backup --destination "D:\CTF-backups\sla-event.sqlite"
```

Thư mục backup phải tồn tại và có quyền riêng tư, file đích chưa tồn tại. Backup dùng SQLite API để giữ snapshot nhất quán kể cả khi có WAL. Dừng backend/worker trước khi restore cùng cấu hình gốc.

## Các kiểm tra tự động

```powershell
py -3 -m unittest discover -s tests -v
```

Test dùng HTTP server thực và đồng hồ điều khiển để đi hết 1 giờ mà không phải chờ: đúng 2 round/30 tick; chuyển service ở tick 16; DOWN ở tick 3 cho SLA 0 rồi hồi phục ở tick 4; gửi lại không cộng trùng; phản hồi sai identity; tick mất kết quả/quá hạn; restart DB; kết thúc sớm không tạo kết quả cho các tick tương lai; preflight không phụ thuộc service round 2.
