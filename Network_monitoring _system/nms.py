import signal
import sys
import os
from scapy.all import sniff, wrpcap, DNS, IP, TCP, UDP
import matplotlib.pyplot as plt
from collections import defaultdict, Counter
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog, font
from threading import Thread
import time
import pandas as pd
from PIL import Image, ImageTk

# Data structures
packets = []
src_ip_counts = Counter()
domain_counts = Counter()
domain_traffic = defaultdict(lambda: defaultdict(int))  # User IP -> Domain -> Traffic
traffic_limits = defaultdict(int)  # User IP -> Traffic Limit
capture_active = False
sniffer_thread = None

# Create directories if they don't exist
if not os.path.exists('graphs'):
    os.makedirs('graphs')
if not os.path.exists('captures'):
    os.makedirs('captures')

# Supported protocol filters with descriptions
PROTOCOL_FILTERS = {
    "all": "All network traffic",
    "tcp": "Transmission Control Protocol",
    "udp": "User Datagram Protocol",
    "icmp": "Internet Control Message Protocol",
    "arp": "Address Resolution Protocol",
    "http": "Hypertext Transfer Protocol",
    "https": "HTTP Secure (port 443)",
    "dns": "Domain Name System",
    "ftp": "File Transfer Protocol",
    "ssh": "Secure Shell (port 22)",
    "smtp": "Simple Mail Transfer Protocol (port 25)",
    "dhcp": "Dynamic Host Configuration Protocol",
    "igmp": "Internet Group Management Protocol",
    "ipv6": "Internet Protocol version 6",
    "icmpv6": "ICMP for IPv6",
    "ospf": "Open Shortest Path First",
    "snmp": "Simple Network Management Protocol",
    "ntp": "Network Time Protocol",
    "bgp": "Border Gateway Protocol"
}

class NetworkMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Network Traffic Monitor")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        # Configure styles
        self.style = ttk.Style()
        self.style.theme_use('clam')
        
        # Custom colors
        bg_color = '#f5f5f5'
        header_color = '#3a7ebf'
        button_color = '#5c9eed'
        
        self.style.configure('.', background=bg_color)
        self.style.configure('TFrame', background=bg_color)
        self.style.configure('TLabel', background=bg_color, font=('Segoe UI', 10))
        self.style.configure('TButton', font=('Segoe UI', 10), background=button_color)
        self.style.configure('Header.TLabel', font=('Segoe UI', 12, 'bold'), foreground='white', background=header_color)
        self.style.configure('Treeview', font=('Consolas', 9), rowheight=25)
        self.style.configure('Treeview.Heading', font=('Segoe UI', 10, 'bold'))
        self.style.map('TButton', background=[('active', '#4a8ddd')])
        
        # Main container
        self.main_frame = ttk.Frame(root)
        self.main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header
        self.header_frame = ttk.Frame(self.main_frame, style='Header.TFrame')
        self.header_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.title_label = ttk.Label(self.header_frame, text="NETWORK TRAFFIC MONITOR", style='Header.TLabel')
        self.title_label.pack(fill=tk.X, padx=10, pady=10)
        
        # Control panel
        self.control_frame = ttk.LabelFrame(self.main_frame, text="Capture Controls", padding=10)
        self.control_frame.pack(fill=tk.X, pady=5)
        
        # Protocol filter
        ttk.Label(self.control_frame, text="Protocol Filter:").grid(row=0, column=0, sticky=tk.W, padx=5)
        self.protocol_var = tk.StringVar()
        self.protocol_combo = ttk.Combobox(self.control_frame, textvariable=self.protocol_var, 
                                         values=list(PROTOCOL_FILTERS.keys()), state="readonly", width=15)
        self.protocol_combo.set("all")
        self.protocol_combo.grid(row=0, column=1, sticky=tk.W, padx=5)
        
        # Protocol description
        self.protocol_desc = ttk.Label(self.control_frame, text=PROTOCOL_FILTERS["all"], wraplength=400)
        self.protocol_desc.grid(row=0, column=2, columnspan=3, sticky=tk.W, padx=5)
        
        # Traffic limit controls
        ttk.Label(self.control_frame, text="IP Address:").grid(row=1, column=0, sticky=tk.W, padx=5)
        self.ip_entry = ttk.Entry(self.control_frame, width=15)
        self.ip_entry.grid(row=1, column=1, sticky=tk.W, padx=5)
        
        ttk.Label(self.control_frame, text="Traffic Limit (bytes):").grid(row=1, column=2, sticky=tk.W, padx=5)
        self.limit_entry = ttk.Entry(self.control_frame, width=15)
        self.limit_entry.grid(row=1, column=3, sticky=tk.W, padx=5)
        
        self.set_limit_btn = ttk.Button(self.control_frame, text="Set Limit", command=self.set_traffic_limit)
        self.set_limit_btn.grid(row=1, column=4, padx=5)
        
        # Capture buttons
        button_frame = ttk.Frame(self.control_frame)
        button_frame.grid(row=2, column=0, columnspan=5, pady=10)
        
        self.start_btn = ttk.Button(button_frame, text="▶ Start Capture", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(button_frame, text="■ Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.save_btn = ttk.Button(button_frame, text="💾 Save & Generate Graphs", command=self.graceful_shutdown)
        self.save_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(button_frame, text="🗑️ Clear Data", command=self.clear_data)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Packet display
        self.packet_frame = ttk.LabelFrame(self.main_frame, text="Captured Packets", padding=10)
        self.packet_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create Treeview with scrollbars
        self.tree_scroll = ttk.Scrollbar(self.packet_frame)
        self.tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.packet_tree = ttk.Treeview(
            self.packet_frame,
            yscrollcommand=self.tree_scroll.set,
            columns=('Source', 'Destination', 'Protocol', 'Domain', 'Length'),
            selectmode='extended'
        )
        self.packet_tree.pack(fill=tk.BOTH, expand=True)
        
        # Configure columns
        self.packet_tree.column('#0', width=0, stretch=tk.NO)
        self.packet_tree.column('Source', anchor=tk.W, width=150)
        self.packet_tree.column('Destination', anchor=tk.W, width=150)
        self.packet_tree.column('Protocol', anchor=tk.W, width=80)
        self.packet_tree.column('Domain', anchor=tk.W, width=200)
        self.packet_tree.column('Length', anchor=tk.E, width=80)
        
        # Create headings
        self.packet_tree.heading('#0', text='', anchor=tk.W)
        self.packet_tree.heading('Source', text='Source IP', anchor=tk.W)
        self.packet_tree.heading('Destination', text='Destination IP', anchor=tk.W)
        self.packet_tree.heading('Protocol', text='Protocol', anchor=tk.W)
        self.packet_tree.heading('Domain', text='Domain', anchor=tk.W)
        self.packet_tree.heading('Length', text='Length', anchor=tk.E)
        
        # Configure scrollbar
        self.tree_scroll.config(command=self.packet_tree.yview)
        
        # Status bar
        self.status_frame = ttk.Frame(self.main_frame)
        self.status_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready to capture network traffic")
        self.status_bar = ttk.Label(
            self.status_frame,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            padding=5
        )
        self.status_bar.pack(fill=tk.X)
        
        # Configure grid weights
        self.control_frame.grid_columnconfigure(2, weight=1)
        
        # Protocol selection event
        self.protocol_combo.bind("<<ComboboxSelected>>", self.update_protocol_desc)
        
        # Handle window close
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
    
    def update_protocol_desc(self, event=None):
        selected = self.protocol_var.get()
        self.protocol_desc.config(text=PROTOCOL_FILTERS.get(selected, "Unknown protocol"))
    
    def update_status(self, message):
        self.status_var.set(message)
        self.root.update_idletasks()
    
    def add_packet_to_tree(self, source, destination, protocol, domain, length):
        self.packet_tree.insert(
            '', 
            tk.END, 
            values=(source, destination, protocol, domain, length)
        )
        # Auto-scroll to the new item
        self.packet_tree.see(self.packet_tree.get_children()[-1])
    
    def clear_data(self):
        global packets, src_ip_counts, domain_counts, domain_traffic
        
        packets = []
        src_ip_counts = Counter()
        domain_counts = Counter()
        domain_traffic = defaultdict(lambda: defaultdict(int))
        
        self.packet_tree.delete(*self.packet_tree.get_children())
        self.update_status("Data cleared. Ready to start new capture.")
    
    def set_traffic_limit(self):
        user_ip = self.ip_entry.get()
        limit = self.limit_entry.get()
        
        if not user_ip or not limit:
            messagebox.showerror("Error", "Please enter both IP address and traffic limit")
            return
        
        try:
            limit = int(limit)
            traffic_limits[user_ip] = limit
            messagebox.showinfo("Success", f"Set traffic limit of {limit} bytes for {user_ip}")
        except ValueError:
            messagebox.showerror("Error", "Invalid limit. Please enter a number.")
    
    def start_capture(self):
        global capture_active, sniffer_thread
        
        if capture_active:
            messagebox.showwarning("Warning", "Capture is already running")
            return
        
        protocol_filter = self.protocol_var.get()
        filter_expression = self.get_filter_expression(protocol_filter)
        
        capture_active = True
        
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.save_btn.config(state=tk.DISABLED)
        self.clear_btn.config(state=tk.DISABLED)
        
        self.update_status(f"Capturing {protocol_filter} packets...")
        
        # Start capture in a separate thread
        sniffer_thread = Thread(target=self.start_packet_capture, args=(filter_expression,), daemon=True)
        sniffer_thread.start()
    
    def get_filter_expression(self, protocol):
        """Convert protocol name to BPF filter expression"""
        protocol = protocol.lower()
        
        filter_map = {
            "all": None,
            "tcp": "tcp",
            "udp": "udp",
            "icmp": "icmp",
            "arp": "arp",
            "http": "tcp port 80",
            "https": "tcp port 443",
            "dns": "udp port 53 or tcp port 53",
            "ftp": "tcp port 21",
            "ssh": "tcp port 22",
            "smtp": "tcp port 25",
            "dhcp": "udp port 67 or udp port 68",
            "igmp": "igmp",
            "ipv6": "ip6",
            "icmpv6": "icmp6",
            "ospf": "proto 89",
            "snmp": "udp port 161 or udp port 162",
            "ntp": "udp port 123",
            "bgp": "tcp port 179"
        }
        
        return filter_map.get(protocol, None)
    
    def stop_capture(self):
        global capture_active
        
        if not capture_active:
            return
        
        capture_active = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.save_btn.config(state=tk.NORMAL)
        self.clear_btn.config(state=tk.NORMAL)
        self.update_status(f"Capture stopped. Captured {len(packets)} packets.")
    
    def start_packet_capture(self, filter_expression=None):
        try:
            if filter_expression:
                sniff(filter=filter_expression, prn=self.packet_callback, stop_filter=lambda x: not capture_active)
            else:
                sniff(prn=self.packet_callback, stop_filter=lambda x: not capture_active)
        except Exception as e:
            self.update_status(f"Error: {str(e)}")
            self.stop_capture()
    
    def packet_callback(self, packet):
        try:
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                packet_len = len(packet)
                domain = ""

                # Get protocol name
                if packet.haslayer(TCP):
                    proto_name = "TCP"
                elif packet.haslayer(UDP):
                    proto_name = "UDP"
                else:
                    proto_name = str(proto)

                # Track domain if DNS query
                if packet.haslayer(DNS) and packet[DNS].qr == 0:
                    try:
                        domain = packet[DNS].qd.qname.decode('utf-8').rstrip(".")
                        domain_counts[domain] += 1
                        domain_traffic[src_ip][domain] += packet_len
                    except:
                        domain = "Malformed DNS"

                # Update UI
                self.root.after(0, self.add_packet_to_tree, src_ip, dst_ip, proto_name, domain, packet_len)

                # Count source IP
                src_ip_counts[src_ip] += 1

                # Check traffic limit
                if src_ip in traffic_limits:
                    total_usage = sum(domain_traffic[src_ip].values())
                    if total_usage > traffic_limits[src_ip]:
                        alert_msg = f"ALERT: {src_ip} exceeded traffic limit ({traffic_limits[src_ip]} bytes)!"
                        self.root.after(0, self.update_status, alert_msg)
                        self.root.after(0, messagebox.showwarning, "Traffic Limit Exceeded", alert_msg)

                # Save the packet
                packets.append(packet)
        except Exception as e:
            self.root.after(0, self.update_status, f"Error processing packet: {e}")
    
    def display_graphs(self):
        self.update_status("Generating graphs...")
        
        try:
            # Source IP graph
            if src_ip_counts:
                plt.figure(figsize=(12, 6))
                df = pd.DataFrame.from_dict(src_ip_counts, orient='index', columns=['Count'])
                df.sort_values('Count', ascending=False).head(20).plot(kind='bar', ax=plt.gca())
                plt.xlabel("Source IP")
                plt.ylabel("Packet Count")
                plt.title("Top 20 Source IPs by Packet Count")
                plt.xticks(rotation=45, ha='right')
                plt.tight_layout()
                plt.savefig("graphs/source_ip_traffic.png", dpi=100)
                plt.close()
            
            # Domain count graph
            if domain_counts:
                plt.figure(figsize=(12, 6))
                df = pd.DataFrame.from_dict(domain_counts, orient='index', columns=['Count'])
                df.sort_values('Count', ascending=False).head(20).plot(kind='bar', ax=plt.gca())
                plt.xlabel("Domain Name")
                plt.ylabel("DNS Query Count")
                plt.title("Top 20 Domains by DNS Query Count")
                plt.xticks(rotation=45, ha='right')
                plt.tight_layout()
                plt.savefig("graphs/domain_counts.png", dpi=100)
                plt.close()
            
            # Domain traffic graph
            if domain_traffic:
                plt.figure(figsize=(14, 8))
                
                # Flatten the nested dictionary
                traffic_data = []
                for ip, domains in domain_traffic.items():
                    for domain, traffic in domains.items():
                        traffic_data.append({'IP': ip, 'Domain': domain, 'Traffic': traffic})
                
                if traffic_data:
                    df = pd.DataFrame(traffic_data)
                    top_traffic = df.groupby('Domain')['Traffic'].sum().nlargest(20)
                    
                    top_traffic.plot(kind='bar', ax=plt.gca())
                    plt.xlabel("Domain")
                    plt.ylabel("Traffic (bytes)")
                    plt.title("Top 20 Domains by Traffic Volume")
                    plt.xticks(rotation=45, ha='right')
                    plt.tight_layout()
                    plt.savefig("graphs/domain_traffic.png", dpi=100)
                    plt.close()
            
            self.update_status("Graphs generated successfully")
            return True
        except Exception as e:
            self.update_status(f"Error generating graphs: {str(e)}")
            return False
    
    def graceful_shutdown(self):
        global capture_active
        
        if capture_active:
            self.stop_capture()
            time.sleep(0.5)
        
        if packets:
            try:
                default_filename = f"capture_{time.strftime('%Y%m%d_%H%M%S')}.pcap"
                file_path = filedialog.asksaveasfilename(
                    defaultextension=".pcap",
                    filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
                    initialdir="captures",
                    initialfile=default_filename
                )
                
                if file_path:
                    wrpcap(file_path, packets)
                    self.update_status(f"Saved {len(packets)} packets to {file_path}")
                    
                    if self.display_graphs():
                        messagebox.showinfo(
                            "Success", 
                            f"Saved {len(packets)} packets to:\n{file_path}\n\n"
                            "Graphs generated in 'graphs' folder"
                        )
                    else:
                        messagebox.showwarning(
                            "Warning", 
                            f"Saved {len(packets)} packets but there was an issue generating graphs"
                        )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save data: {str(e)}")
        else:
            messagebox.showinfo("Info", "No packets captured to save")
    
    def on_close(self):
        if messagebox.askokcancel("Quit", "Do you want to quit the application?"):
            self.graceful_shutdown()
            self.root.destroy()

def main():
    root = tk.Tk()
    
    # Set window icon if available
    try:
        root.iconbitmap('network_icon.ico')
    except:
        pass
    
    app = NetworkMonitorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
