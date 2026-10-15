/*
 * point.js  --  client cho Cổng tra cứu điểm MeKoData
 * ---------------------------------------------------------------------------
 * Toàn bộ dữ liệu điểm đi qua các endpoint JSON dưới đây. File này được nạp
 * lại mỗi lần làm mới trang (Cache-Control: no-store), nên bản đồ API luôn
 * hiển thị trong phần "Nguồn" (Sources) của trình duyệt.
 *
 *   API.me            GET  /api/me             -> hồ sơ sinh viên đang đăng nhập
 *   API.myScores      GET  /api/scores         -> DANH SÁCH điểm của chính bạn
 *   API.scoreDetail   GET  /api/scores/{id}    -> CHI TIẾT 1 bản ghi theo recordId
 *
 * Ghi chú nội bộ (dev):
 *   - recordId của sinh viên được cấp tuần tự, bắt đầu từ 1001.
 *   - Endpoint /api/scores/{id} trả về bản ghi theo recordId. (TODO bảo mật:
 *     hiện chưa kiểm tra bản ghi có thuộc về người đang đăng nhập hay không.)
 *   - Bản ghi kiểm toán / giáo vụ ("audit") nằm ở dải recordId 9000+. Mỗi bản
 *     ghi audit có trường "remark" chứa ghi chú của phòng giáo vụ và KHÔNG được
 *     liệt kê trong /api/scores của bất kỳ sinh viên nào.
 *
 * => 4 bước gợi ý: (1) đăng nhập & làm mới để nạp point.js, đọc bản đồ API;
 *    (2) GET /api/me rồi GET /api/scores để biết recordId của mình;
 *    (3) đổi recordId ở /api/scores/{id} để đọc bản ghi của người khác (IDOR);
 *    (4) truy vấn bản ghi audit ở dải 9000+ để lấy remark ẩn.
 */
const API = {
  me:          '/api/me',
  myScores:    '/api/scores',
  scoreDetail: id => '/api/scores/' + id,
  login:       '/login',
  logout:      '/logout',
};

const el = id => document.getElementById(id);
let selectedId;

async function request(path, body) {
  const options = body ? {method: 'POST', body: new URLSearchParams(body)} : {};
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) { if (response.status === 401) showLogin(); throw new Error(data.error || 'Không thể hoàn thành yêu cầu'); }
  return data;
}

function showLogin() {
  el('login-card').hidden = false; el('workspace').hidden = true;
  el('logout').hidden = true; el('detail').hidden = true; selectedId = undefined;
}

async function openScore(id) {
  try {
    const record = await request(API.scoreDetail(id));
    selectedId = id;
    el('detail').hidden = false;
    el('score-title').textContent = record.subject + ' · #' + record.record_id;
    el('score-content').textContent = JSON.stringify(record, null, 2);
  } catch (error) { el('workspace-message').textContent = error.message; }
}

async function refresh() {
  const me = await request(API.me);
  const scores = await request(API.myScores);
  el('login-card').hidden = true; el('workspace').hidden = false; el('logout').hidden = false;
  el('identity').textContent = 'Sinh viên: ' + me.name + ' (MSSV ' + me.student_id + ' · ' + me.class + ')';
  el('scores').replaceChildren();
  el('workspace-message').textContent = '';
  for (const record of scores) {
    const row = document.createElement('tr');
    const id = document.createElement('td');
    const subject = document.createElement('td');
    const score = document.createElement('td');
    const button = document.createElement('button');
    button.type = 'button'; button.className = 'link';
    button.textContent = '#' + record.record_id;
    button.onclick = () => openScore(record.record_id);
    id.append(button);
    subject.textContent = record.subject;
    score.textContent = record.score;
    row.append(id, subject, score);
    el('scores').append(row);
  }
}

el('login').onsubmit = async event => {
  event.preventDefault();
  el('login-message').textContent = '';
  try { await request(API.login, new FormData(event.target)); event.target.reset(); await refresh(); }
  catch (error) { el('login-message').textContent = error.message; }
};
el('logout').onclick = async () => {
  try { await request(API.logout, {}); showLogin(); }
  catch (error) { el('workspace-message').textContent = error.message; }
};
el('refresh').onclick = () => refresh().catch(error => el('workspace-message').textContent = error.message);
refresh().catch(() => {});
