import uuid
import time

# Network event types
EVENT_PORT_SCAN          = "port_scan"
EVENT_CONNECTION_ATTEMPT = "connection_attempt"
EVENT_HIGH_TRAFFIC       = "high_traffic"
EVENT_REPLAY_DETECTED    = "replay_detected"

# Host event types
EVENT_FAILED_LOGIN       = "failed_login"
EVENT_SUCCESSFUL_LOGIN   = "successful_login"
EVENT_SUSPICIOUS_PROCESS = "suspicious_process"
EVENT_USER_CREATED       = "user_created"
EVENT_PRIVILEGE_ESCALATION = "privilege_escalation"

# Synthetic/noise event types
EVENT_NOISE              = "noise"

REQUIRED_FIELDS = [
    "event_id", "timestamp", "source", "event_type",
    "src_ip", "dst_ip", "src_port", "dst_port",
    "protocol", "username", "process_name", "description", "extra"
]

def validate_event(event: dict) -> bool:
    """
    Checks that every required field is present in the event dict.
    Also validates specific enumerations like the source field.
    """
    for field in REQUIRED_FIELDS:
        if field not in event:
            raise ValueError(f"Missing field in event: {field}")
            
    if event["source"] not in ("network", "host"):
        raise ValueError("Invalid source field. Must be 'network' or 'host'.")
        
    return True

def make_event(source, event_type, description, **kwargs) -> dict:
    """
    Factory function to create a valid event.
    Pass any extra fields as kwargs.
    """
    event = {
        "event_id":     str(uuid.uuid4()),
        "timestamp":    time.time(),
        "source":       source,
        "event_type":   event_type,
        "src_ip":       kwargs.get("src_ip", None),
        "dst_ip":       kwargs.get("dst_ip", None),
        "src_port":     kwargs.get("src_port", None),
        "dst_port":     kwargs.get("dst_port", None),
        "protocol":     kwargs.get("protocol", None),
        "username":     kwargs.get("username", None),
        "process_name": kwargs.get("process_name", None),
        "description":  description,
        "extra":        kwargs.get("extra", {})
    }
    validate_event(event)
    return event
