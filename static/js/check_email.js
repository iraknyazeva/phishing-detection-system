let lastEmailResult = null;

function statusToLabel(status) {
  switch (status) {
    case "clean": return "Безопасно";
    case "suspicious": return "Подозрительно";
    case "malicious":
    case "dangerous": return "Опасно";
    default: return status ?? "unknown";
  }
}

function statusToClass(status) {
  switch (status) {
    case "clean": return "status-clean";
    case "suspicious": return "status-suspicious";
    case "malicious":
    case "dangerous": return "status-malicious";
    default: return "";
  }
}

function safeNum(v, digits = 2) {
  const n = Number(v);
  if (Number.isNaN(n)) return "—";
  return n.toFixed(digits);
}

function metric(icon, title, value, subtitle) {
  return `
    <div class="metric-card">
      <div class="metric-top">
        <div style="display:flex;align-items:center;gap:10px">
          <div class="metric-icon">${icon}</div>
          <div>
            <div class="metric-title">${title}</div>
            <div class="metric-value">${value}</div>
          </div>
        </div>
      </div>
      ${subtitle ? `<div class="metric-sub">${subtitle}</div>` : ``}
    </div>
  `;
}

function kvRow(key, val) {
  return `<div class="kv-row"><div class="kv-key">${key}</div><div class="kv-val">${val ?? "—"}</div></div>`;
}

function downloadJson(data, filenamePrefix = "email_result") {
  const ts = new Date().toISOString().replace(/[:.]/g, "-");
  const filename = `${filenamePrefix}_${ts}.json`;
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json;charset=utf-8" });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();

  URL.revokeObjectURL(url);
}

function renderEmailResult(container, data) {
  lastEmailResult = data;

  container.style.display = "block";
  container.innerHTML = "";

  const header = document.createElement("div");
  header.className = "result-header";

  const badge = document.createElement("span");
  badge.className = "status-badge " + statusToClass(data.status);
  badge.textContent = statusToLabel(data.status);

  const score = document.createElement("span");
  score.textContent = `Риск: ${safeNum(data.risk_score, 2)}`;

  header.appendChild(badge);
  header.appendChild(score);
  container.appendChild(header);

  const main = document.createElement("div");
  main.style.fontSize = "13px";
  main.style.color = "#9ca3af";
  main.textContent = `Тема: ${data.email_subject ?? "—"}`;
  container.appendChild(main);

  const urlsCount = Array.isArray(data.extracted_urls)
    ? data.extracted_urls.length
    : (typeof data.extracted_urls === "string" && data.extracted_urls !== "null")
      ? 1
      : 0;

  const indCount = Array.isArray(data.matched_indicators) ? data.matched_indicators.length : 0;

  const metricsHtml = `
    <div class="metrics">
      ${metric("🧮", "Risk score", safeNum(data.risk_score, 2), "Итоговый балл риска")}
      ${metric("🧭", "Статус", statusToLabel(data.status), "Сводный вердикт системы")}
      ${metric("⏱️", "Время", `${safeNum(data.analysis_duration, 2)} c`, "Сколько занял анализ")}
      ${metric("📎", "Размер", data.email_size ? `${data.email_size} байт` : "—", "Размер письма")}
      ${metric("🔗", "Ссылки", `${urlsCount}`, "Количество найденных URL")}
      ${metric("🏷️", "Индикаторы", `${indCount}`, "Сработавшие признаки/правила")}
    </div>
  `;
  const metricsWrap = document.createElement("div");
  metricsWrap.innerHTML = metricsHtml;
  container.appendChild(metricsWrap);

  const details = document.createElement("div");
  details.className = "kv";
  details.innerHTML = `
    ${kvRow("From", data.email_from)}
    ${kvRow("To", data.email_to)}
    ${kvRow("Message-ID", data.message_id)}
    ${kvRow("Confidence", safeNum(data.confidence, 2))}
  `;
  container.appendChild(details);

  const actions = document.createElement("div");
  actions.className = "actions-row";

  const downloadBtn = document.createElement("button");
  downloadBtn.type = "button";
  downloadBtn.className = "btn-secondary";
  downloadBtn.textContent = "Скачать JSON";
  downloadBtn.addEventListener("click", () => {
    if (lastEmailResult) downloadJson(lastEmailResult, "email_result");
  });

  const toggle = document.createElement("button");
  toggle.type = "button";
  toggle.className = "btn-secondary";
  toggle.textContent = "Показать JSON";

  const jsonBlock = document.createElement("pre");
  jsonBlock.className = "json-block";
  jsonBlock.style.display = "none";
  jsonBlock.textContent = JSON.stringify(data, null, 2);

  toggle.addEventListener("click", () => {
    const visible = jsonBlock.style.display === "block";
    jsonBlock.style.display = visible ? "none" : "block";
    toggle.textContent = visible ? "Показать JSON" : "Скрыть JSON";
  });

  actions.appendChild(downloadBtn);
  actions.appendChild(toggle);
  container.appendChild(actions);
  container.appendChild(jsonBlock);

  // показать блок отправки email после успешного анализа
  const sendBlock = document.getElementById("send-email-block");
  const sendMsg = document.getElementById("send-email-msg");
  if (sendBlock) {
    sendBlock.style.display = "block";
    if (sendMsg) sendMsg.textContent = "";
  }
}

async function handleEmailSubmit(e) {
  e.preventDefault();
  const fileInput = document.getElementById("eml-file");
  const emailBtn = document.getElementById("email-btn");
  const result = document.getElementById("email-result");
  const error = document.getElementById("email-error");

  error.textContent = "";
  result.style.display = "none";

  if (!fileInput.files.length) {
    error.textContent = "Выберите .eml файл для проверки.";
    return;
  }

  emailBtn.disabled = true;
  emailBtn.textContent = "Проверка...";

  try {
    const formData = new FormData();
    formData.append("file", fileInput.files[0]);

    const resp = await fetch("/analyze/email", { method: "POST", body: formData });
    if (!resp.ok) throw new Error(`Ошибка сервера: ${resp.status}`);

    const data = await resp.json();
    renderEmailResult(result, data);
  } catch (err) {
    error.textContent = "Ошибка при отправке запроса: " + err.message;
  } finally {
    emailBtn.disabled = false;
    emailBtn.textContent = "Проверить";
  }
}

document.getElementById("email-form").addEventListener("submit", handleEmailSubmit);

// Отправка результата на почту
const sendBtn = document.getElementById("send-email-btn");
if (sendBtn) {
  sendBtn.addEventListener("click", async () => {
    const email = document.getElementById("send-email-email")?.value?.trim();
    const msg = document.getElementById("send-email-msg");

    if (!email) {
      if (msg) msg.textContent = "Введите email.";
      return;
    }
    if (!lastEmailResult) {
      if (msg) msg.textContent = "Сначала выполните проверку письма.";
      return;
    }

    if (msg) msg.textContent = "Отправка...";
    try {
      const resp = await fetch("/send-report", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ email, type: "email", result: lastEmailResult })
      });

      if (msg) msg.textContent = resp.ok ? "Отправлено ✅" : "Ошибка отправки ❌";
    } catch (e) {
      if (msg) msg.textContent = "Ошибка отправки ❌";
    }
  });
}

// Отправка результата в Telegram (chat_id берётся на сервере из telegram_links)
const sendTgBtn = document.getElementById("send-email-tg-btn");
if (sendTgBtn) {
  sendTgBtn.addEventListener("click", async () => {
    const msg = document.getElementById("send-email-msg");

    if (!lastEmailResult) {
      if (msg) msg.textContent = "Сначала выполните проверку письма.";
      return;
    }

    if (msg) msg.textContent = "Отправка в Telegram...";
    try {
      const resp = await fetch("/send-report/telegram", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ type: "email", result: lastEmailResult })
      });

      if (resp.ok) {
        if (msg) msg.textContent = "Отправлено в Telegram ✅";
      } else {
        const data = await resp.json().catch(() => ({}));
        if (msg) msg.textContent = data.detail || "Ошибка отправки в Telegram ❌ (возможно Telegram не привязан)";
      }
    } catch (e) {
      if (msg) msg.textContent = "Ошибка отправки в Telegram ❌";
    }
  });
}