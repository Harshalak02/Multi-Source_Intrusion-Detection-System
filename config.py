NETWORK_SENSOR_PORT = 9001
HOST_SENSOR_PORT = 9002

# Detection Thresholds & Windows
TIME_WINDOW = 60                 # seconds (sliding window for rate limits)
PORT_SCAN_THRESHOLD = 10         # distinct ports from single IP
CONNECTION_RATE_THRESHOLD = 20   # connections from single IP
REPLAY_WINDOW = 30               # seconds
BRUTE_FORCE_THRESHOLD = 5        # failed logins from a single user
ALERT_COOLDOWN = 10              # seconds to suppress identical alerts
PORT_SCAN_ALERT_COOLDOWN = 20    # suppress repeated scan alerts per source IP

# Lists
SUSPICIOUS_PROCESSES = [
    "nc", "ncat", "netcat", "nmap", "masscan", 
    "hydra", "john", "sqlmap", "mimikatz", "reverse_shell"
]

# Severity Thresholds (for correlation engine)
CRITICAL_THRESHOLD = 8.0
HIGH_THRESHOLD     = 5.0
MEDIUM_THRESHOLD   = 3.0
LOW_THRESHOLD      = 1.0
MAX_EVENT_TYPE_COUNT_PER_WINDOW = 5

# Anomaly Detector Configs
BASELINE_WINDOW_SIZE = 20
ANOMALY_MIN_BASELINE_POINTS = 5      # Minimum samples before Z-score is computed
ANOMALY_Z_THRESHOLD = 2.5
ANOMALY_CHECK_INTERVAL = 5
ANOMALY_EPSILON = 0.0001             # Small constant to prevent division-by-zero in Z-score

# Event Weights (for scoring model)
EVENT_WEIGHTS = {
    "port_scan":            3.0,
    "high_traffic":         2.0,
    "replay_detected":      2.5,
    "failed_login":         1.5,
    "brute_force_burst":    4.0,
    "suspicious_process":   3.5,
    "privilege_escalation": 5.0,
    "connection_attempt":   0.0, # changed from 0.5 to 0.0
    "noise":                0.0, # changed from 0.1 to 0.0
    "anomaly_detected":     2.0,
}

DEBUG_VERBOSE = False            # set True for per-event debug prints
DEBUG_MIN_INTERVAL_SEC = 2.0   # throttle compact debug per entity
