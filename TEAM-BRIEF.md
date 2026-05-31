# TEAM-BRIEF — Bàn giao review: Komorebi Affiliate Tracker

Tài liệu này dành cho **đội UI/UX** và **đội Security & QA** để review trước khi deploy lên production. Toàn bộ F1–F20 đã build xong và pass test local (chi tiết deploy: xem `DEPLOY-F1-F17.md` và `DEPLOY-F18-F20.md`).

> ⚠️ **Chưa deploy.** Bắt buộc qua review UI/UX và sign-off Security & QA mới được lên production.

---

## 1. Tổng quan dự án

**Komorebi Affiliate Tracker** là hệ thống theo dõi affiliate/CPA tự xây cho Komorebi Media (lĩnh vực chính: offer vay tiền — loan). Hệ thống làm các việc:
- Tạo **tracking link** cho publisher, ghi nhận **click** (kèm geo/thiết bị).
- Nhận **postback (S2S)** từ advertiser/MMP khi có conversion, tính **payout** cho publisher.
- Quản lý **advertiser, publisher, gán chiến dịch, thanh toán, hóa đơn, đối soát (reconciliation)**.
- Cổng **publisher portal** để publisher xem số liệu, và trang **admin** để vận hành.

**Tech stack:**
- Backend: **Node.js (≥ 22.5)** + **Express**.
- Database: **SQLite** qua `node:sqlite` (built-in, không cần better-sqlite3).
- Bảo mật/middleware: **Helmet**, **express-session**, CSRF tự xây, rate limiting tự xây.
- Khác: **nodemailer** (email), **geoip-lite** (geo), **multer** (upload CSV), **node-cron**.
- Frontend: **HTML render từ server** (template string trong Node, không có React/Vue). CSS inline + vài file JS nhỏ.
- Production: chạy bằng **PM2** (`ecosystem.config.js`), sau reverse proxy (nginx/caddy) cho HTTPS.

---

## 2. Những gì đã build (20 features, theo nhóm)

**A. Tài khoản & trải nghiệm publisher**
- **F1 — Đổi mật khẩu:** publisher tự đổi mật khẩu trong tab Profile.
- **F2 — Quên/khôi phục mật khẩu:** link "Forgot password" ở trang login; gửi link reset qua email (hoặc admin lấy token nếu chưa cấu hình email); link hết hạn sau 24h, dùng 1 lần.
- **F17 — Cải thiện trải nghiệm publisher:** tab Profile, hiển thị email, breakdown payout theo % khoản vay, cột loan_amount/revenue, nhãn "Updated", bảng cuộn ngang trên mobile, banner "kỳ thanh toán kế tiếp".

**B. Gán chiến dịch & thanh toán**
- **F3 — Gán publisher ↔ advertiser:** admin gán quyền chạy chiến dịch; có **override payout**, **khoảng thời gian hiệu lực**, **giới hạn conversion/tháng**. Publisher chỉ thấy chiến dịch được gán; postback chỉ chấp nhận khi đã gán.
- **F4 — Nhiều "goal" conversion:** mỗi advertiser có thể có nhiều sự kiện trả thưởng (vd: đăng ký, giải ngân) với payout riêng theo `event`.
- **F12 — Giới hạn conversion theo advertiser:** trần conversion/tháng; chạm trần thì tự **tạm dừng advertiser** và cảnh báo Telegram (80% và 100%).
- **F13/F14 — Payout theo %:** payout có thể là **% của số tiền vay (`loan_amount`)** thay vì số cố định.

**C. Tracking & tích hợp**
- **F7 — Sub-parameters:** truyền và lưu `sub1…sub5`, `subpub`, chuyển tiếp qua postback; báo cáo theo `sub1` cho publisher.
- **F8 — Tracking nâng cao:** lưu thêm `gclid`, `fbclid`, `referrer`.
- **F9 — Transaction ID:** nhận và lưu `transaction_id`; đối soát có thể khớp theo transaction_id hoặc click_id.
- **F10 — Tham số AppsFlyer/Adjust:** nhận và map các tham số (campaign/adgroup/creative/network).
- **F11 — Hết hạn click:** từ chối postback nếu click quá cũ (mặc định 30 ngày, cấu hình theo advertiser).
- **F20 — Tích hợp MMP (AppsFlyer):** lưu credentials (token mã hóa), "Test connection", và **đồng bộ thủ công** kéo sự kiện 24h gần nhất để tự duyệt/từ chối conversion; có dashboard log đồng bộ.

**D. Marketplace & Smart Links**
- **F5 — Smart Links:** 1 link `/go/:publisher` tự điều hướng theo **quốc gia + thiết bị** (theo rule ưu tiên), fallback về advertiser được gán.
- **F6 — Marketplace:** trang công khai liệt kê chiến dịch public; publisher đăng nhập rồi "Apply"; admin duyệt/từ chối, duyệt thì tự tạo gán.

**E. Chống gian lận & báo cáo**
- **F15 — Phát hiện trùng user:** nếu cùng `user_id` đã convert ở advertiser đó → đánh dấu **duplicate, payout = 0** (vẫn ghi nhận, không trả tiền). Admin có thể override.
- **F16 — Báo cáo biên lợi nhuận:** lưu `revenue` (tiền advertiser trả Komorebi), hiển thị **revenue / payout / margin / margin %** trên dashboard admin.

**F. Bảo mật (F18/F19)**
- Hardening session (timeout, SameSite), **HMAC chữ ký postback**, che PII trong audit log, health-check secrets, rate limiting nâng cao, làm sạch input, security headers.

---

## 3. Hướng dẫn chạy local để review

**Prerequisites**
- **Node.js ≥ 22.5** (bắt buộc — dùng module `node:sqlite`). Kiểm tra: `node -v`.
- Clone repo về máy.

```bash
git clone <repo-url> komorebi-affiliate
cd komorebi-affiliate
npm ci                 # cài dependencies
```

**Khởi động server local** (tạo file `affiliate.db` mới tự động nếu chưa có):
```bash
ADMIN_USER=admin ADMIN_PASS=testpass123 SESSION_SECRET=dev-only-secret \
  BASE_URL=http://localhost:3000 POSTBACK_WHITELIST_ENABLED=false \
  node server.js
```
- `POSTBACK_WHITELIST_ENABLED=false` để test postback từ localhost (production thì bật whitelist IP của AppsFlyer/Adjust).
- 💡 **Mẹo cho UI/UX:** session tự logout sau **5 phút** không hoạt động. Nếu thấy phiền khi review, thêm `ADMIN_IDLE_SECONDS=3600` (1 giờ). **Lưu ý:** đội Security & QA thì **không** dùng mẹo này — phải test đúng hành vi 5 phút.

**Các URL chính** (mặc định `PORT=3000`):
| Khu vực | URL |
|---|---|
| Admin | `http://localhost:3000/admin` |
| Publisher login | `http://localhost:3000/publisher/login` |
| Publisher đăng ký | `http://localhost:3000/publisher/register` |
| Marketplace (public) | `http://localhost:3000/marketplace` |
| Tài liệu | `http://localhost:3000/docs` |
| Health check | `http://localhost:3000/health` |

**Tài khoản test**
- **Admin:** `admin` / `testpass123` (lấy từ biến môi trường ở trên).
- **Publisher:** đăng ký tại `/publisher/register` → trạng thái **pending** → admin duyệt ở `/admin/publishers` → mới đăng nhập được. (Hoặc admin tạo trực tiếp ở `/admin/publishers/new`.)

**Tạo dữ liệu mẫu để review đủ luồng** (làm theo thứ tự):
1. Đăng nhập admin → tạo 1 **advertiser** (`/admin/advertisers/new`) có Offer URL + payout.
2. Tạo/duyệt 1 **publisher**.
3. Mở publisher đó (`/admin/publishers/:id/edit`) → **gán advertiser** (Assign) → (tuỳ chọn) thêm **Smart Link rule**, đặt **postback_secret**, hoặc cấu hình **MMP**.
4. Lấy tracking link, mở thử `/track/<slug>?pub=<publisher>` để tạo click, rồi gọi `/postback/<slug>?click_id=...&event=sale` để tạo conversion.
5. Đăng nhập publisher portal để xem số liệu.

---

## 4. Checklist cho đội UI/UX

- [ ] **Mobile responsive:** publisher portal + admin trên màn hình hẹp; bảng dài phải cuộn ngang được (không tràn layout).
- [ ] **Onboarding:** checklist "Getting Started" trên dashboard publisher rõ ràng, đúng trạng thái.
- [ ] **Publisher transparency:** trang Conversions (cột loan_amount/revenue khi có), Payments (banner kỳ thanh toán kế tiếp), breakdown theo `sub1`, dòng tính payout theo % (vd `50,000,000 VND × 2.75% = 1,375,000 VND`).
- [ ] **Marketplace UX:** thẻ chiến dịch (tên, category, payout, mô tả, quốc gia); các trạng thái nút **Apply / Already running / Application pending**; khi chưa login bấm Apply phải chuyển sang login rồi quay lại.
- [ ] **Smart Links:** trang quản lý rule ở admin (`/admin/publishers/:id/smart-links`) — thêm/xoá rule dễ hiểu, hiển thị link `/go/...`.
- [ ] **Profile / đổi mật khẩu:** luồng đổi mật khẩu (thông báo lỗi/success), hiển thị email.
- [ ] **Quên/reset mật khẩu:** link ở trang login, trang nhập email, trang đặt mật khẩu mới, thông báo link hết hạn.
- [ ] **Form admin nhiều field mới:** trang sửa advertiser (payout type, cap, marketplace, postback security, MMP) và publisher — bố cục, nhóm field, copy.
- [ ] **MMP sync dashboard:** bảng log, nút "Run Sync Now".
- [ ] **Nhất quán & wording:** thông báo lỗi/thành công, nhãn nút, tiếng Việt/Anh, định dạng tiền (USD vs VND — xem mục 6).

---

## 5. Checklist cho đội Security & QA

- [ ] **Session timeout 5 phút:** cả admin và publisher tự logout sau 5 phút không hoạt động → redirect về login kèm thông báo. (Có thể rút ngắn để test: chạy server với `ADMIN_IDLE_SECONDS=10`.)
- [ ] **Session cookie:** `SameSite=Strict`, `HttpOnly`; session ID được regenerate sau khi login.
- [ ] **HMAC postback:** advertiser có `postback_secret` → postback **thiếu/sai `sig` = 403**, **đúng `sig` = 200**; advertiser không set secret → vẫn nhận postback (backward compatible). Công thức: `sig = HMAC-SHA256(secret, click_id+event+payout)` hex.
- [ ] **Rate limiting:** global 100/phút/IP; **`/postback/*` = 300/phút** (tách riêng global); `/marketplace/apply` = 10/phút; login sai **5 lần/15 phút → khoá**.
- [ ] **CSRF:** mọi form POST admin + form đổi mật khẩu publisher cần token; thiếu token → **403**.
- [ ] **Input validation:** field POST **> 2000 ký tự → 400**; null byte bị loại bỏ.
- [ ] **PII masking trong audit log:** số điện thoại (`0967***857`), email (`c***@komorebimedia.com`), API key (`kom_live_***`) — kiểm tra bảng `audit_log`.
- [ ] **MMP credentials:** token lưu **mã hóa** (`enc:v1:` trong DB) khi có `MMP_ENCRYPTION_KEY`; "Test connection" trả ok/lỗi đúng; nếu **không** set key → lưu plaintext + cảnh báo lúc khởi động.
- [ ] **Các luồng từ chối (rejection):** publisher chưa gán → **403**; click hết hạn → **410**; advertiser chạm cap → **429 + tự tạm dừng**; ngoài khoảng hiệu lực assignment → **403**; trùng user → ghi **duplicate, payout 0**; (production) postback ngoài IP whitelist → **403**.
- [ ] **Lộ secret:** `/health` chỉ trả boolean (không trả giá trị secret); token MMP che mặc định; security headers (`Permissions-Policy`, **HSTS**, CSP, `X-Content-Type-Options`) có mặt.

---

## 6. Những điểm cần đặc biệt chú ý (Claude Code đã flag khi build)

1. **Đơn vị tiền USD vs VND:** payout hiển thị `$` ở nhiều chỗ, nhưng breakdown theo % khoản vay hiển thị **VND** (theo yêu cầu). Cần review thống nhất cách hiển thị/đơn vị cho offer loan VN.
2. **HMAC base string:** ghép `click_id + event + payout` **không có ký tự phân tách**; `event` mặc định `sale`, `payout` mặc định rỗng nếu thiếu. **Cần xác nhận khớp với cách MMP/advertiser ký** trước khi bật secret cho advertiser thật.
3. **Mapping cột AppsFlyer (F20):** hiện đọc cột `click_id` và `status`/`af_status` từ CSV. **Cần đối chiếu với file export AppsFlyer thật** — đây là chỗ dễ phải chỉnh nhất khi chạy dữ liệu thật.
4. **Token MMP hiển thị trong form:** trang sửa advertiser hiển thị token đã giải mã (dạng ẩn, có nút Show/Hide — giống pattern API key cũ). Security cần đánh giá việc đưa secret vào HTML cho admin đã đăng nhập.
5. **Cap đếm theo "approved":** cả cap advertiser (F12) và cap publisher (F3) chỉ đếm conversion **đã duyệt** → mang tính "hồi tố" (không chặn ngay lúc nhận postback, chỉ chặn sau khi đã có đủ conversion được duyệt). Đây là theo yêu cầu — QA cần hiểu để test đúng.
6. **Reset cap tự kích hoạt lại advertiser:** khi đổi `cap_reset_month`, advertiser được set lại `active` (ghi đè trạng thái submit).
7. **`countries_allowed` chỉ để hiển thị** trên marketplace — **không** chặn theo quốc gia.
8. **HSTS "dính" trên trình duyệt:** sau khi gửi, trình duyệt ép HTTPS tới 1 năm (gồm subdomain). Khó gỡ sau rollback — phải giữ HTTPS. (Chi tiết ở `DEPLOY-F18-F20.md`.)
9. **`MMP_ENCRYPTION_KEY` phải ổn định & backup:** mất/đổi key → không giải mã được token đã lưu, phải nhập lại.
10. **`/go/:publisher`** dùng **username** của publisher làm slug.
11. **Session 24h + idle 5 phút:** cookie tối đa 24h, nhưng không hoạt động 5 phút là logout.

---

## 7. Quy trình sign-off

1. **Đội UI/UX review trước** → ghi nhận issue/feedback (dùng checklist mục 4).
2. **Đội Security & QA review sau** → test theo checklist mục 5 + xác nhận các điểm ở mục 6.
3. **Chỉ deploy khi CẢ HAI đội pass.** Sau khi pass, deploy theo `DEPLOY-F1-F17.md` (cho F1–F17) và `DEPLOY-F18-F20.md` (cho F18–F20) — nhớ **backup DB** và **set `MMP_ENCRYPTION_KEY`, `BASE_URL`** trước khi chạy.

> Lưu ý: các file test (`e2e.test.js`, `sec.test.js`, `mmp.test.js`) **tuyệt đối không chạy trên production** — chúng tạo dữ liệu mẫu, gọi mock và làm cạn rate limiter. Chỉ chạy trên DB nháp/staging.

---

## 8. Liên hệ

Mọi câu hỏi về dự án/bàn giao: **chi@komorebimedia.com**
