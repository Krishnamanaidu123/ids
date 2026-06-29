async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  return response.json();
}

function setText(id, value) {
  document.getElementById(id).textContent = value;
}

function renderAlerts(alerts) {
  const body = document.getElementById("alerts-body");
  body.innerHTML = "";
  alerts.slice(0, 20).forEach((alert) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${alert.timestamp}</td>
      <td class="severity-${alert.severity}">${alert.severity}</td>
      <td>${alert.source_ip}</td>
      <td>${alert.rule}</td>
    `;
    body.appendChild(row);
  });
}

function renderEvents(events) {
  const body = document.getElementById("events-body");
  body.innerHTML = "";
  events.slice(0, 20).forEach((event) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${event.timestamp}</td>
      <td>${event.source_ip}</td>
      <td>${event.event_type}</td>
      <td>${event.path}</td>
      <td>${event.status}</td>
    `;
    body.appendChild(row);
  });
}

async function refreshDashboard() {
  const [statusData, eventsData, alertsData] = await Promise.all([
    fetchJson("/api/status"),
    fetchJson("/api/events"),
    fetchJson("/api/alerts"),
  ]);

  setText("monitoring-state", statusData.monitoring ? "Running" : "Stopped");
  setText("total-events", statusData.total_events);
  setText("total-alerts", statusData.total_alerts);
  setText("high-alerts", statusData.high_severity_alerts);

  renderEvents(eventsData.events || []);
  renderAlerts(alertsData.alerts || []);
}

async function loadRules() {
  const rules = await fetchJson("/api/rules");
  document.getElementById("failed_login_threshold").value = rules.failed_login_threshold;
  document.getElementById("failed_login_window_seconds").value = rules.failed_login_window_seconds;
  document.getElementById("burst_threshold").value = rules.burst_threshold;
  document.getElementById("burst_window_seconds").value = rules.burst_window_seconds;
}

document.getElementById("start-btn").addEventListener("click", async () => {
  await fetchJson("/api/control/start", { method: "POST" });
  refreshDashboard();
});

document.getElementById("stop-btn").addEventListener("click", async () => {
  await fetchJson("/api/control/stop", { method: "POST" });
  refreshDashboard();
});

document.getElementById("rules-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await fetchJson("/api/rules", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      failed_login_threshold: Number(document.getElementById("failed_login_threshold").value),
      failed_login_window_seconds: Number(
        document.getElementById("failed_login_window_seconds").value
      ),
      burst_threshold: Number(document.getElementById("burst_threshold").value),
      burst_window_seconds: Number(document.getElementById("burst_window_seconds").value),
    }),
  });
  refreshDashboard();
});

loadRules();
refreshDashboard();
setInterval(refreshDashboard, 3000);
