# 🛡️ SNS Lab 4: Multi-Source IDS - Ultra In-depth "Bro-Style" Explanation

Bhai, tu tension mat le, tera poora assignment ekdum chill scene mein samjhata hoon. Dekh, ye IDS (Intrusion Detection System) sirf ek "software" nahi hai, ye tere system ka "Bodyguard" hai. Professor chahte hain ki tu ek aisa system banaye jo dimaag lagaye, na ki sirf chillaye (i.e., reduces False Positives).

Chal, ek-ek karke poori kundli kholte hain.

---

## 🧭 1. Assignment Ka Main Purpose (The "Logic")
Assignment ka main goal hai **"Multi-Source Corroboration"**. 
* **Simple bhasha mein:** Agar ek sensor bole "Daya, darwaza khula hai," toh wo important hai. Par agar Network sensor bole "IP 1.2.3.4 ajeeb hai" AND Host sensor bole "IP 1.2.3.4 ne login fail kiya," toh Daya ko pata hai ki ye pakka chor hai. 
* Humne **Scoring Model** use kiya hai. Har badmaashi ka ek weight hai. Jab weight ek limit (Threshold) cross karta hai, tabhi `Critical` alert aata hai.

---

## 📂 2. File-by-File Walkthrough (Tera Code Kya Kar Raha Hai?)

### ⚙️ `config.py` (The Control Room)
Ye tere system ka dimaag ka wo hissa hai jahan saari values fixed hain. Thresholds, ports, aur weights sab yahan hain.
* **Kyu?** Taaki agar tujhe port scan ki limit 10 se 20 karni ho, toh tujhe poora code nahi chhedna padega.

### 📜 `schema.py` (The Universal Language)
Bhai, agar sensors alag language mein baat karenge toh Engine pagal ho jayega. 
* **`make_event()`**: Ye ek factory hai. Jo bhi sensor data bhejega, ye usko ek standard JSON format mein lapet ke dega.
* **`validate_event()`**: Ye check karta hai ki koi event "adhura" toh nahi hai. UUID, Timestamp, Source (network/host) — sab mandatory hai.

### 🌐 `network_sensor.py` (The Gatekeeper)
Ye bahar se aane wale traffic ko monitor karta hai. 
* **Rule 1 (Port Scan):** Ye track karta hai ki ek IP kitne ports check kar raha hai. 
* **Rule 2 (High Traffic):** Agar ek hi IP se itni saari requests aayein ki system dher ho jaye.
* **Rule 3 (Replay):** Hum packets ka MD5 hash banate hain. Agar "wahi" packet thodi der baad phir dikha, toh samajh lo replay attack hai.

### 💻 `host_sensor.py` (The Internal Spy)
Ye OS ke andar ki khabrein deta hai.
* **Rule 4 (Brute Force):** Kisi ne 5 baar galat password dala? Toh flag fire hoga.
* **Rule 5 (Suspicious Process):** Agar kisi ne `nmap` ya `reverse_shell` chalane ki koshish ki, ye usko turant pakad lega.
* **Rule 6 (Privilege Escalation):** Ye smart rule hai. Agar login success hua par usse pehle usi IP se bohot saare login fails aaye they, toh samajh lo hacker ne password guess kar liya!

### 🧠 `correlation_engine.py` (The Actual Brain)
Ye sabse important file hai. Ye saare sensors se data leta hai.
* **Sliding Window:** Ye sirf pichle 60 seconds ka data dekhta hai. Purana kachra saaf karta rehta hai.
* **Corroboration Logic:** Agar Network aur Host dono se dhuaan uth raha hai, tabhi ye `Critical` fire karega. Warna max `High`.
* **Multi-step checking:** Ye dekhta hai ki kya Port Scan karne wali IP hi Brute Force kar rahi hai? Agar haan, toh ye confirm attack hai.

### 📊 `anomaly_detector.py` (The Math Genius)
Ye rules pe nahi, balki patterns pe chalta hai using **Z-Score**.
* **Formula:** `z = (current_val - mean) / std_dev`.
* Simple logic: Agar roz 5 login fails aate hain aur achanak se 500 aane lagein, toh ye statistical outlier hai. Anomaly detector chilla dega "KUCH TOH GADBAD HAI!"

### 📢 `alert_manager.py` (The PR Officer)
Alerts ko manage karta hai.
* **Deduplication:** Agar ek hi severity ka alert baar-baar aa raha hai, ye tujhe baar-baar pareshan nahi karega (Cooldown period).
* **Logging:** Ye computer screen pe mast colors (Red/Yellow) dikhata hai aur `logs/alerts.json` mein save karta hai.

---

## 🔄 3. How Everything is Interconnected? (Flow of Events)

1. **Simulator** (Hacker) packets bhejta hai TCP ports (9001/9002) par.
2. **Sensors** (Net/Host) usse pakadte hain, `schema.py` se valid JSON banate hain, aur ek **Queue** mein daal dete hain.
3. **Queue** se **Correlation Engine** wo event uthata hai.
4. Engine apna **Sliding Window buffer** check karta hai aur scoring karta hai.
5. Saath hi saath, **Anomaly Detector** stats check karke apne events Queue mein daalta hai.
6. Agar score threshold phada, toh Engine **Alert Manager** ko call karta hai.
7. Manager screen pe alert print karta hai aur metrics update karta hai.

---

## ✅ 4. Summary of PDF Requirements (Kya Humne Sab Kiya?)

| Requirement | How we did it? |
| :--- | :--- |
| **No IDS Frameworks** | Poora Python code khud likha using `socket` and `threading`. |
| **Critical = 2 Sources** | Engine check karta hai `both_sources_active` flag before raising Critical. |
| **At least 6 Rules** | 3 in Network (Scan, Rate, Replay) + 3 in Host (Brute, Process, PrivEsc). |
| **Anomaly Module** | Statistical Z-score module implemented in `anomaly_detector.py`. |
| **Sliding Window** | `window_buffer` in `correlation_engine.py` handles the 60s window. |
| **Menu-driven Simulator** | `attack_simulator.py` handles the terminal menu loop. |
| **JSON Schema** | `schema.py` ensures strict consistency across systems. |

---

## 💡 Engineering "Bro" Advice
Bhai, viva mein agar Sir poochein ki **"False Positive"** kaise roka, toh bolna: 
> *"Sir, humne correlation engine mein corroboration lagaya hai. Jab tak dono independent channels (Network aur Host) se confirmation nahi milti ya koi confirmed multi-step pattern nahi dikhta, hum severity ko High se Critical nahi karte. Plus, anomaly detector stats se check karta hai patterns na ki sirf static rules."*

**Bas bhai, tu itna samajh le, tera lab assignment sorted hai! PC pe `python3 main.py` chala aur maze kar.** 🚀
