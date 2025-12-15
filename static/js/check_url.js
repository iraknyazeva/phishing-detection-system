let lastUrlResult = null;

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

function downloadJson(data, filenamePrefix = "url_result") {
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

function renderUrlResult(container, data) {
  lastUrlResult = data;

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

  const urlLine = document.createElement("div");
  urlLine.style.fontSize = "13px";
  urlLine.style.color = "#9ca3af";
  urlLine.textContent = `URL: ${data.url ?? "—"}`;
  container.appendChild(urlLine);

  let dns = data.domain_analysis;
  let ssl = data.ssl_analysis;
  try { if (typeof dns === "string") dns = JSON.parse(dns); } catch {}
  try { if (typeof ssl === "string") ssl = JSON.parse(ssl); } catch {}

  const resolvable = dns?.resolvable;
  const ip = dns?.ip;
  const sslValid = ssl?.valid;
  const daysLeft = ssl?.days_left;

  const metricsHtml = `
    <div class="metrics">
      ${metric("🧮", "Risk score", safeNum(data.risk_score, 2), "Итоговый балл риска")}
      ${metric("🧭", "Статус", statusToLabel(data.status), "Сводный вердикт системы")}
      ${metric("⏱️", "Время", `${safeNum(data.analysis_duration, 2)} c`, "Сколько занял анализ")}
      ${metric("🌐", "DNS", resolvable === true ? "OK" : resolvable === false ? "Проблема" : "—", ip ? `IP: ${ip}` : "Результат DNS")}
      ${metric("🔒", "SSL", sslValid === true ? "VALID" : sslValid === false ? "INVALID" : "—", (typeof daysLeft === "number") ? `Дней до истечения: ${daysLeft}` : "Проверка сертификата")}
      ${metric("🏷️", "Домен", data.domain ?? "—", "Домен из URL")}
    </div>
  `;
  const metricsWrap = document.createElement("div");
  metricsWrap.innerHTML = metricsHtml;
  container.appendChild(metricsWrap);

  const details = document.createElement("div");
  details.className = "kv";
  details.innerHTML = `
    ${kvRow("Нормализованный URL", data.normalized_url)}
    ${kvRow("Final URL", data.final_url)}
    ${kvRow("Redirect chain", Array.isArray(data.redirect_chain) ? data.redirect_chain.join(" → ") : (data.redirect_chain ?? "—"))}
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
    if (lastUrlResult) downloadJson(lastUrlResult, "url_result");
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

  // показать блок отправки email
  const sendBlock = document.getElementById("send-url-block");
  const sendMsg = document.getElementById("send-url-msg");
  if (sendBlock) {
    sendBlock.style.display = "block";
    if (sendMsg) sendMsg.textContent = "";
  }
}

async function handleUrlSubmit(e) {
  e.preventDefault();
  const urlInput = document.getElementById("url-input");
  const urlBtn = document.getElementById("url-btn");
  const result = document.getElementById("url-result");
  const error = document.getElementById("url-error");

  error.textContent = "";
  result.style.display = "none";

  if (!urlInput.value.trim()) {
    error.textContent = "Введите URL для проверки.";
    return;
  }

  urlBtn.disabled = true;
  urlBtn.textContent = "Проверка...";

  try {
    const formData = new FormData();
    formData.append("url", urlInput.value.trim());

    const resp = await fetch("/analyze/url", { method: "POST", body: formData });
    if (!resp.ok) throw new Error(`Ошибка сервера: ${resp.status}`);

    const data = await resp.json();
    renderUrlResult(result, data);
  } catch (err) {
    error.textContent = "Ошибка при отправке запроса: " + err.message;
  } finally {
    urlBtn.disabled = false;
    urlBtn.textContent = "Проверить";
  }
}

document.getElementById("url-form").addEventListener("submit", handleUrlSubmit);

// Отправка результата на почту
const sendBtn = document.getElementById("send-url-btn");
if (sendBtn) {
  sendBtn.addEventListener("click", async () => {
    const email = document.getElementById("send-url-email")?.value?.trim();
    const msg = document.getElementById("send-url-msg");

    if (!email) {
      if (msg) msg.textContent = "Введите email.";
      return;
    }
    if (!lastUrlResult) {
      if (msg) msg.textContent = "Сначала выполните проверку URL.";
      return;
    }

    if (msg) msg.textContent = "Отправка...";
    try {
      const resp = await fetch("/send-report", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ email, type: "url", result: lastUrlResult })
      });

      if (msg) msg.textContent = resp.ok ? "Отправлено ✅" : "Ошибка отправки ❌";
    } catch (e) {
      if (msg) msg.textContent = "Ошибка отправки ❌";
    }
  });
}


// Отправка результата в Telegram (chat_id берётся на сервере из telegram_links)
const sendTgBtn = document.getElementById("send-url-tg-btn");
if (sendTgBtn) {
  sendTgBtn.addEventListener("click", async () => {
    const msg = document.getElementById("send-url-msg");

    if (!lastUrlResult) {
      if (msg) msg.textContent = "Сначала выполните проверку URL.";
      return;
    }

    if (msg) msg.textContent = "Отправка в Telegram...";
    try {
      const resp = await fetch("/send-report/telegram", {
        method: "POST",
        headers: {"Content-Type": "application/json"},
        body: JSON.stringify({ type: "url", result: lastUrlResult })
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

(async () => {
  try {
    const r = await fetch("/telegram/status");
    const s = await r.json();
    if (!s.linked) {
      const btn = document.getElementById("send-url-tg-btn");
      if (btn) btn.style.display = "none";
    }
  } catch (_) {}
})();




// ===== Batch URL check =====
document.addEventListener("DOMContentLoaded", () => {
  const batchFile = document.getElementById("batch-file");
  const batchRun = document.getElementById("batch-run");
  const batchError = document.getElementById("batch-error");
  const batchProgress = document.getElementById("batch-progress");
  const batchTable = document.getElementById("batch-table");
  const batchTbody = document.getElementById("batch-tbody");

  if (!batchRun) return; // если на странице нет блока — просто выходим

  function addRow(url, status, risk) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td style="padding:8px;border-top:1px solid #1e293b">${escapeHtml(url)}</td>
      <td style="padding:8px;border-top:1px solid #1e293b">${escapeHtml(String(status ?? ""))}</td>
      <td style="padding:8px;border-top:1px solid #1e293b">${escapeHtml(String(risk ?? ""))}</td>
    `;
    batchTbody.appendChild(tr);
  }

  function escapeHtml(s) {
    return String(s)
      .replaceAll("&", "&amp;")
      .replaceAll("<", "&lt;")
      .replaceAll(">", "&gt;")
      .replaceAll('"', "&quot;")
      .replaceAll("'", "&#039;");
  }

  batchRun.addEventListener("click", async () => {
    batchError.textContent = "";
    batchProgress.textContent = "";
    batchTbody.innerHTML = "";
    batchTable.style.display = "none";

    const f = batchFile.files && batchFile.files[0];
    if (!f) {
      batchError.textContent = "Выбери файл (.txt / .csv) со ссылками (каждая с новой строки).";
      return;
    }

    let text = "";
    try {
      text = await f.text();
    } catch (e) {
      batchError.textContent = "Не удалось прочитать файл.";
      return;
    }

    const urls = text
      .split(/\r?\n/)
      .map(x => x.trim())
      .filter(x => x && !x.startsWith("#"));

    if (urls.length === 0) {
      batchError.textContent = "Файл пустой или в нём нет строк с URL.";
      return;
    }

    batchTable.style.display = "";
    batchRun.disabled = true;

    for (let i = 0; i < urls.length; i++) {
      const url = urls[i];
      batchProgress.textContent = `Проверяю ${i + 1} / ${urls.length}...`;

      try {
        const body = new URLSearchParams();
        body.set("url", url);

        const r = await fetch("/analyze/url", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body
        });

        if (!r.ok) {
          const t = await r.text();
          addRow(url, `HTTP ${r.status}`, t.slice(0, 120));
          continue;
        }

        const data = await r.json();
        addRow(url, data.status, data.risk_score);
      } catch (e) {
        addRow(url, "error", String(e));
      }
    }

    batchProgress.textContent = `Готово: ${urls.length} шт.`;
    batchRun.disabled = false;
  });
});