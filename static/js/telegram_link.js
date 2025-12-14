const msg = document.getElementById("tg-msg");
const codeBox = document.getElementById("tg-code");

document.getElementById("tg-start").addEventListener("click", async () => {
  msg.textContent = "Генерируем код...";
  try {
    const resp = await fetch("/telegram/link/start", { method: "POST" });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "Ошибка");

    codeBox.style.display = "block";
    codeBox.innerHTML = `
      <div class="kv-row"><div class="kv-key">Код</div><div class="kv-val"><b>${data.code}</b></div></div>
      <div class="kv-row"><div class="kv-key">Действует до</div><div class="kv-val">${data.expires_at}</div></div>
      <div class="kv-row"><div class="kv-key">Что сделать</div><div class="kv-val">Напишите боту: <b>/start ${data.code}</b></div></div>
    `;
    msg.textContent = "Код готов. Отправьте его боту и нажмите «Проверить привязку».";
  } catch (e) {
    msg.textContent = "Ошибка: " + e.message;
  }
});

document.getElementById("tg-finish").addEventListener("click", async () => {
  msg.textContent = "Проверяем привязку...";
  try {
    const resp = await fetch("/telegram/link/finish", { method: "POST" });
    const data = await resp.json();
    if (!resp.ok) throw new Error(data.detail || "Ошибка");

    if (data.ok) {
      msg.textContent = "✅ Telegram привязан. Можно отправлять отчёты.";
      // обновить страницу чтобы показать статус
      setTimeout(() => location.reload(), 600);
    } else {
      msg.textContent = data.detail || "Не найдено. Проверьте /start <код> и попробуйте снова.";
    }
  } catch (e) {
    msg.textContent = "Ошибка: " + e.message;
  }
});