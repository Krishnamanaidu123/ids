import random
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from typing import Any, Dict, List

from flask import Flask, jsonify, render_template, request


app = Flask(__name__)


class IDSEngine:
    """Simple in-memory IDS simulation engine for dashboard demos."""

    def __init__(self) -> None:
        self.events: deque[Dict[str, Any]] = deque(maxlen=200)
        self.alerts: deque[Dict[str, Any]] = deque(maxlen=200)
        self.rules: Dict[str, Any] = {
            "failed_login_threshold": 4,
            "failed_login_window_seconds": 60,
            "burst_threshold": 20,
            "burst_window_seconds": 30,
            "sensitive_paths": ["/admin", "/wp-login", "/.env"],
        }
        self.monitoring = False
        self.total_events = 0
        self.total_alerts = 0
        self.high_severity_alerts = 0
        self._thread: threading.Thread | None = None
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def start(self) -> bool:
        with self._lock:
            if self.monitoring:
                return False
            self.monitoring = True
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._run_loop, daemon=True)
            self._thread.start()
        return True

    def stop(self) -> bool:
        with self._lock:
            if not self.monitoring:
                return False
            self.monitoring = False
            self._stop_event.set()
        return True

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "monitoring": self.monitoring,
                "total_events": self.total_events,
                "total_alerts": self.total_alerts,
                "high_severity_alerts": self.high_severity_alerts,
            }

    def recent_events(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(reversed(self.events))

    def recent_alerts(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(reversed(self.alerts))

    def update_rules(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            for key in (
                "failed_login_threshold",
                "failed_login_window_seconds",
                "burst_threshold",
                "burst_window_seconds",
            ):
                if key in payload:
                    self.rules[key] = max(1, int(payload[key]))
        return self.rules

    def _run_loop(self) -> None:
        # Periodically generate synthetic events while monitoring is enabled.
        while not self._stop_event.is_set():
            event = self._generate_event()
            self._ingest_event(event)
            time.sleep(1.0)

    def _generate_event(self) -> Dict[str, Any]:
        ip = random.choice(
            [
                "10.0.0.12",
                "10.0.0.23",
                "172.16.0.44",
                "192.168.1.51",
                "203.0.113.9",
            ]
        )
        event_type = random.choices(
            ["request", "failed_login", "sensitive_access", "success_login"],
            weights=[70, 15, 10, 5],
            k=1,
        )[0]

        path = random.choice(["/", "/home", "/products", "/api/login"])
        status = 200
        if event_type == "failed_login":
            path = "/login"
            status = 401
        elif event_type == "sensitive_access":
            path = random.choice(self.rules["sensitive_paths"])
            status = 403

        return {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_ip": ip,
            "event_type": event_type,
            "path": path,
            "status": status,
            "message": f"{event_type} on {path}",
        }

    def _ingest_event(self, event: Dict[str, Any]) -> None:
        with self._lock:
            self.events.append(event)
            self.total_events += 1

            now_ts = datetime.utcnow().timestamp()
            recent_failed: defaultdict[str, int] = defaultdict(int)
            recent_all: defaultdict[str, int] = defaultdict(int)

            for item in self.events:
                item_ts = datetime.fromisoformat(item["timestamp"].replace("Z", "")).timestamp()
                if now_ts - item_ts <= self.rules["failed_login_window_seconds"] and item["event_type"] == "failed_login":
                    recent_failed[item["source_ip"]] += 1
                if now_ts - item_ts <= self.rules["burst_window_seconds"]:
                    recent_all[item["source_ip"]] += 1

            self._check_sensitive_path(event)
            self._check_failed_login_threshold(event["source_ip"], recent_failed[event["source_ip"]], event)
            self._check_burst_activity(event["source_ip"], recent_all[event["source_ip"]], event)

    def _create_alert(self, severity: str, rule: str, source_ip: str, event: Dict[str, Any]) -> None:
        alert = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "severity": severity,
            "rule": rule,
            "source_ip": source_ip,
            "event_path": event["path"],
            "event_type": event["event_type"],
        }
        self.alerts.append(alert)
        self.total_alerts += 1
        if severity == "high":
            self.high_severity_alerts += 1

    def _check_sensitive_path(self, event: Dict[str, Any]) -> None:
        if event["path"] in self.rules["sensitive_paths"]:
            self._create_alert(
                severity="medium",
                rule="Sensitive path access",
                source_ip=event["source_ip"],
                event=event,
            )

    def _check_failed_login_threshold(self, source_ip: str, failed_count: int, event: Dict[str, Any]) -> None:
        if failed_count >= self.rules["failed_login_threshold"]:
            self._create_alert(
                severity="high",
                rule=f"Failed logins >= {self.rules['failed_login_threshold']}",
                source_ip=source_ip,
                event=event,
            )

    def _check_burst_activity(self, source_ip: str, request_count: int, event: Dict[str, Any]) -> None:
        if request_count >= self.rules["burst_threshold"]:
            self._create_alert(
                severity="medium",
                rule=f"Burst activity >= {self.rules['burst_threshold']}",
                source_ip=source_ip,
                event=event,
            )


engine = IDSEngine()


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    return jsonify(engine.status())


@app.route("/api/events")
def api_events():
    return jsonify({"events": engine.recent_events()})


@app.route("/api/alerts")
def api_alerts():
    return jsonify({"alerts": engine.recent_alerts()})


@app.route("/api/control/start", methods=["POST"])
def api_start():
    started = engine.start()
    return jsonify({"monitoring": True, "changed": started})


@app.route("/api/control/stop", methods=["POST"])
def api_stop():
    stopped = engine.stop()
    return jsonify({"monitoring": False, "changed": stopped})


@app.route("/api/rules", methods=["GET", "POST"])
def api_rules():
    if request.method == "GET":
        return jsonify(engine.rules)

    payload = request.get_json(silent=True) or {}
    updated = engine.update_rules(payload)
    return jsonify(updated)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
