const msg = document.getElementById("tg-msg");
const codeBox = document.getElementById("tg-code");

const openBlock = document.getElementById("tg-open");
const tgLink = document.getElementById("tg-link");
const tgQr = document.getElementById("tg-qr");
const copyBtn = document.getElementById("tg-copy");

let lastCode = null;

const startBtn = document.getElementById("tg-start");
const finishBtn = document.getElementById("tg-finish");
const unlinkBtn = document.getElementById("tg-unlink");

function setMsg(text) {
  if (msg) msg.textContent = text;
}

async function postJson(url, body) {
  const resp = await fetch(url, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await resp.json().catch(() => ({}));
  if (!resp.ok) throw new Error(data.detail || "Ошибка");
  return data;
}

if (startBtn) {
  startBtn.addEventListener("click", async () => {
    setMsg("Генерируем код...");
    try {
      const data = await postJson("/telegram/link/start");

      lastCode = data.code;

      if (codeBox) {
        codeBox.style.display = "block";
        codeBox.innerHTML = `
          <div class="kv-row"><div class="kv-key">Код</div><div class="kv-val"><b>${data.code}</b></div></div>
          <div class="kv-row"><div class="kv-key">Действует до</div><div class="kv-val">${data.expires_at}</div></div>
          <div class="kv-row"><div class="kv-key">Что сделать</div><div class="kv-val">
            1) Откройте бота и нажмите <b>Start</b><br>
            2) Отправьте ему код сообщением: <b>${data.code}</b><br>
            3) Нажмите <b>«Проверить привязку»</b> на сайте
          </div></div>
        `;
      }

      if (openBlock) openBlock.style.display = "block";
      if (tgLink && data.bot_link) tgLink.href = data.bot_link;
      if (tgQr && data.qr_url) tgQr.src = data.qr_url;

      setMsg("Код готов. Отправьте его боту сообщением и нажмите «Проверить привязку».");

    } catch (e) {
      setMsg("Ошибка: " + e.message);
    }
  });
}

if (copyBtn) {
  copyBtn.addEventListener("click", async () => {
    if (!lastCode) {
      setMsg("Сначала получите код.");
      return;
    }
    try {
      await navigator.clipboard.writeText(lastCode);
      setMsg("Код скопирован ✅ Теперь отправьте его боту сообщением.");
    } catch {
      setMsg("Не удалось скопировать (браузер запретил). Скопируйте вручную.");
    }
  });
}

if (finishBtn) {
  finishBtn.addEventListener("click", async () => {
    setMsg("Проверяем привязку...");
    try {
      const data = await postJson("/telegram/link/finish");
      if (data.ok) {
        setMsg("✅ Telegram привязан. Можно отправлять отчёты.");
        setTimeout(() => location.reload(), 500);
      } else {
        setMsg(data.detail || "Код не найден. Отправьте код боту сообщением и попробуйте снова.");
      }
    } catch (e) {
      setMsg("Ошибка: " + e.message);
    }
  });
}

if (unlinkBtn) {
  unlinkBtn.addEventListener("click", async () => {
    setMsg("Отвязываем...");
    try {
      await postJson("/telegram/unlink");
      setMsg("✅ Отвязано");
      setTimeout(() => location.reload(), 500);
    } catch (e) {
      setMsg("Ошибка: " + e.message);
    }
  });
}