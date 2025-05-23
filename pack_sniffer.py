import streamlit as st
import pandas as pd
import plotly.express as px
from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import deque, defaultdict
from datetime import datetime
import threading
import os
import time  # Added for proper refresh control

# --- Packet Processor ---
class PacketProcessor:
    def __init__(self, max_packets=10000):
        self.protocol_map = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}
        self.packet_data = deque(maxlen=max_packets)
        self.start_time = datetime.now()
        self.threats = {'syn_flood': defaultdict(int), 'port_scan': defaultdict(int)}
        self.stats = {'total_packets': 0, 'total_bytes': 0, 'protocol_dist': defaultdict(int)}
        self.lock = threading.Lock() #one thread at a time / prevents data corruption and race conditions.

    def get_protocol(self, proto):
        return self.protocol_map.get(proto, f'Unknown({proto})')

    def detect_threats(self, pkt):
        if TCP in pkt:
            if pkt[TCP].flags == 'S':
                with self.lock:
                    self.threats['syn_flood'][pkt[IP].src] += 1
            if pkt[TCP].flags in ['S', 'F']:
                with self.lock:
                    self.threats['port_scan'][(pkt[IP].src, pkt[IP].dst)] += 1

    def process(self, pkt):
        if IP not in pkt:
            return
        try:
            info = {
                'timestamp': datetime.fromtimestamp(pkt.time),  # Use packet timestamp
                'source': pkt[IP].src,
                'destination': pkt[IP].dst,
                'protocol': self.get_protocol(pkt[IP].proto),
                'size': len(pkt),
                'time_relative': (datetime.now() - self.start_time).total_seconds()
            }
            
            for layer in [TCP, UDP, ICMP]:
                if layer in pkt:
                    info['src_port'] = pkt[layer].sport if hasattr(pkt[layer], 'sport') else None
                    info['dst_port'] = pkt[layer].dport if hasattr(pkt[layer], 'dport') else None
                    break

            with self.lock:  # Thread-safe data updates
                self.packet_data.append(info)
                self.stats['total_packets'] += 1
                self.stats['total_bytes'] += info['size']
                self.stats['protocol_dist'][info['protocol']] += 1

            self.detect_threats(pkt)
        except Exception as e:
            st.error(f"Error processing packet: {str(e)}")

    @property
    def dataframe(self):
        with self.lock:
            return pd.DataFrame(self.packet_data) if self.packet_data else pd.DataFrame()

# --- Dashboard UI ---
def show_metrics(processor):
    col1, col2, col3, col4 = st.columns(4)
    with processor.lock:
        col1.metric("Total Packets", processor.stats['total_packets'])
        col2.metric("Total Traffic", f"{processor.stats['total_bytes']/1e6:.2f} MB")
        duration = (datetime.now() - processor.start_time).total_seconds()
        col3.metric("Duration", f"{duration:.2f}s")
        throughput = processor.stats['total_packets'] / duration if duration > 0 else 0
        col4.metric("Throughput", f"{throughput:.1f} pkt/s")

def show_threats(processor):
    alerts = []
    with processor.lock:
        for src, count in processor.threats['syn_flood'].items():
            if count > 100:
                alerts.append(f"⚠️ SYN Flood: {src} ({count})")
        for (src, dst), count in processor.threats['port_scan'].items():
            if count > 100:
                alerts.append(f"⚠️ Port Scan: {src} → {dst} ({count})")
    st.sidebar.markdown("\n\n".join(alerts or ["✅ No active threats detected"]))

def show_packet_table(df):
    st.subheader("Packet Inspector")
    if not df.empty and 'timestamp' in df.columns:
        st.dataframe(df.sort_values('timestamp', ascending=False).head(50), use_container_width=True, height=458)
    else:
        st.info("No packets captured yet")

# packet capture control
def packet_capture(processor, interface="en0"):
    try:
        sniff(prn=processor.process, store=False, iface=interface)
    except Exception as e:
        st.error(f"Packet capture error: {str(e)}")

def main():
    st.set_page_config(page_title="Network Dashboard", layout="wide")
    st.title("REAL-TIME NETWORK PACKET SNIFFING 📡")
    st.sidebar.header("STATUS")

    if 'processor' not in st.session_state:
        st.session_state.processor = PacketProcessor(max_packets=50000)
        st.session_state.capture_thread = threading.Thread(      # Proper thread management
            target=packet_capture,
            args=(st.session_state.processor, "en0"), 
            daemon=True
        )
        st.session_state.capture_thread.start()

    processor = st.session_state.processor
    show_metrics(processor)
    show_threats(processor)
    
    df = processor.dataframe

    show_packet_table(df)
    
    time.sleep(3)  # Refresh every 3 seconds
    st.rerun()

if __name__ == "__main__":
    main()
