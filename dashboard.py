"""Interactive NIDS dashboard for authorized captures."""
from __future__ import annotations
import json
import tempfile
from pathlib import Path
import pandas as pd
import streamlit as st
from nids.detector import detect
from nids.pcap import read_pcap
from nids.history import save_scan, list_scans

st.set_page_config(page_title="Sentinel | Network IDS", page_icon="🛡️", layout="wide")
st.title("🛡️ Sentinel — Network Intrusion Detection")
st.caption("PCAP analysis • explainable alerts • local SQLite history • defensive portfolio project")
st.warning("Only inspect traffic you own or have explicit permission to monitor. Detection is heuristic, not proof of an attack.")
with st.sidebar:
    st.header("Detection settings")
    window = st.number_input("Window (seconds)", min_value=1, value=10)
    scan = st.number_input("Distinct destination/port pairs", min_value=1, value=12)
    syn = st.number_input("SYN packets per window", min_value=1, value=80)
    volume = st.number_input("Packets per window", min_value=1, value=500)
    st.caption("History is stored locally at ~/.nids_portfolio/alerts.sqlite3")

tab1, tab2, tab3 = st.tabs(["Analyze capture", "Alert history", "Live capture guide"])
with tab1:
    upload = st.file_uploader("Upload a PCAP or PCAPNG", type=["pcap", "pcapng", "cap"])
    if upload and upload.size > 20 * 1024 * 1024:
        st.error("Capture exceeds the 20 MB upload limit.")
        st.stop()
    if upload:
        suffix = Path(upload.name).suffix.lower()
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(upload.getvalue())
            path = Path(tmp.name)
        try:
            records = read_pcap(str(path))
            alerts = detect(records, int(window), int(scan), int(syn), int(volume))
        except Exception as exc:
            st.error(f"Analysis failed: {exc}")
            st.stop()
        finally:
            path.unlink(missing_ok=True)
        a, b, c = st.columns(3)
        a.metric("IP packets", len(records))
        b.metric("Alerts", len(alerts))
        c.metric("Unique sources", len({p.src for p in records}))
        if records:
            st.subheader("Traffic overview")
            df = pd.DataFrame([{"time": pd.to_datetime(p.timestamp, unit="s", utc=True),
                                "source": p.src, "protocol": p.protocol, "bytes": p.size} for p in records])
            left, right = st.columns(2)
            with left:
                st.markdown("**Packets by protocol**")
                st.bar_chart(df["protocol"].value_counts())
            with right:
                st.markdown("**Top source IPs**")
                st.bar_chart(df["source"].value_counts().head(10))
            st.markdown("**Packets over time**")
            st.line_chart(df.set_index("time").resample("10s").size().rename("packets"))
        if alerts:
            st.subheader("Security alerts")
            frame = pd.DataFrame([a.to_dict() for a in alerts])
            severity = st.multiselect("Filter by severity", sorted(frame.severity.unique()), default=sorted(frame.severity.unique()))
            filtered = frame[frame.severity.isin(severity)]
            st.dataframe(filtered, use_container_width=True)
            st.bar_chart(frame["severity"].value_counts())
            st.download_button("Download alerts CSV", frame.to_csv(index=False), "alerts.csv", "text/csv")
            st.download_button("Download alerts JSON", json.dumps([a.to_dict() for a in alerts], indent=2), "alerts.json", "application/json")
        else:
            st.success("No configured thresholds triggered; this does not guarantee safe traffic.")
        if st.button("Save analysis to local history", type="primary"):
            scan_id = save_scan(upload.name, records, alerts)
            st.success(f"Saved scan #{scan_id}. Open Alert history to review it.")
with tab2:
    if st.button("Refresh history"):
        st.rerun()
    history = list_scans()
    if history:
        st.dataframe(pd.DataFrame([{k: v for k, v in row.items() if k != "alerts_json"} for row in history]), use_container_width=True)
        chosen = st.selectbox("Inspect scan", history, format_func=lambda r: f"#{r['id']} {r['capture_name']} — {r['created_at']}")
        saved = json.loads(chosen["alerts_json"])
        if saved:
            st.dataframe(pd.DataFrame(saved), use_container_width=True)
        else:
            st.info("No alerts in this scan")
    else:
        st.info("No scans saved yet. Analyze a capture and click Save analysis.")
with tab3:
    st.markdown("""**Live capture is opt-in and runs only on your own or authorized interfaces.**

Use the CLI from another Terminal to record a short capture, then upload the resulting file in the first tab.

```bash
python -m nids.capture --list-interfaces
python -m nids.capture --interface en0 --seconds 15 --output my_capture.pcap
```

On macOS, packet capture may require elevated permissions. Do not run the dashboard with sudo.
The interface name `en0` is only an example; choose an interface you own or are authorized to monitor.
""")
