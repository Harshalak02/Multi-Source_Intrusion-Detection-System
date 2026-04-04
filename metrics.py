import time

class MetricsCollector:
    def __init__(self):
        self.alerts = []          # List of all alert dicts raised
        self.scenario_labels = {} # { scenario_name: "attack" or "benign" }
        self.current_scenario = None
        self.latency_markers = {} # { scenario_name: start_time }
        self.start_time = time.time()

    def start_scenario(self, name, label):
        """Call this at the beginning of each scenario."""
        self.current_scenario = name
        self.scenario_labels[name] = label
        self.latency_markers[name] = time.time()

    def record_alert(self, alert):
        alert["scenario"] = self.current_scenario
        self.alerts.append(alert)

    def compute_metrics(self):
        TP = FP = FN = TN = 0
        latencies = []

        for scenario_name, label in self.scenario_labels.items():
            alerts_in_scenario = [a for a in self.alerts if a.get("scenario") == scenario_name]
            high_severity = [a for a in alerts_in_scenario if a["severity"] in ("High", "Critical")]

            if label == "attack":
                if high_severity:
                    TP += len(high_severity)
                    latency = high_severity[0]["timestamp"] - self.latency_markers[scenario_name]
                    latencies.append(latency)
                else:
                    FN += 1
            elif label == "benign":
                if high_severity:
                    FP += len(high_severity)
                else:
                    TN += 1

        precision = TP / (TP + FP) if (TP + FP) > 0 else 0.0
        recall    = TP / (TP + FN) if (TP + FN) > 0 else 0.0
        f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
        fpr       = FP / (FP + TN) if (FP + TN) > 0 else 0.0
        fnr       = FN / (FN + TP) if (FN + TP) > 0 else 0.0
        avg_lat   = sum(latencies) / len(latencies) if latencies else 0.0

        return {
            "TP": TP, "FP": FP, "FN": FN, "TN": TN,
            "Precision": precision,
            "Recall": recall,
            "F1": f1,
            "FPR": fpr,
            "FNR": fnr,
            "Avg_Latency_sec": avg_lat
        }

    def print_report(self):
        import psutil
        import os
        m = self.compute_metrics()
        cpu = psutil.cpu_percent(interval=1)
        mem = psutil.Process(os.getpid()).memory_info().rss / (1024 * 1024)

        report = f"""
======================================
 IDS METRICS REPORT
======================================
 True Positives  (TP): {m['TP']}
 False Positives (FP): {m['FP']}
 False Negatives (FN): {m['FN']}
 True Negatives  (TN): {m['TN']}
--------------------------------------
 Precision:      {m['Precision']:.4f}
 Recall:         {m['Recall']:.4f}
 F1-Score:       {m['F1']:.4f}
 FP Rate:        {m['FPR']:.4f}
 FN Rate:        {m['FNR']:.4f}
--------------------------------------
 Avg Alert Latency: {m['Avg_Latency_sec']:.3f} sec
 CPU Usage:         {cpu:.1f}%
 Memory Usage:      {mem:.1f} MB
======================================
"""
        print(report)
        with open("logs/metrics_report.txt", "w") as f:
            f.write(report)
