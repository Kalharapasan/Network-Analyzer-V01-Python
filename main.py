import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import socket
import struct
import time
import subprocess
import platform
import psutil
import json
from datetime import datetime
from collections import defaultdict
import re

class NetworkTrafficAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2c3e50')
        
        # Data storage
        self.traffic_data = []
        self.ip_addresses = set()
        self.mac_addresses = set()
        self.connections = defaultdict(int)
        self.protocols = defaultdict(int)
        self.is_monitoring = False
        self.monitoring_thread = None
        
        self.setup_ui()
        self.refresh_network_info()
        
    def setup_ui(self):
        # Main frame
        main_frame = tk.Frame(self.root, bg='#2c3e50')
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Title
        title_label = tk.Label(main_frame, text="Network Traffic Analyzer", 
                              font=('Arial', 20, 'bold'), fg='#ecf0f1', bg='#2c3e50')
        title_label.pack(pady=(0, 10))
        
        # Control buttons frame
        control_frame = tk.Frame(main_frame, bg='#2c3e50')
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Start/Stop monitoring button
        self.monitor_btn = tk.Button(control_frame, text="Start Monitoring", 
                                   command=self.toggle_monitoring,
                                   bg='#27ae60', fg='white', font=('Arial', 12, 'bold'),
                                   padx=20, pady=5)
        self.monitor_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Refresh button
        refresh_btn = tk.Button(control_frame, text="Refresh Network Info", 
                              command=self.refresh_network_info,
                              bg='#3498db', fg='white', font=('Arial', 12, 'bold'),
                              padx=20, pady=5)
        refresh_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Clear logs button
        clear_btn = tk.Button(control_frame, text="Clear Logs", 
                            command=self.clear_logs,
                            bg='#e74c3c', fg='white', font=('Arial', 12, 'bold'),
                            padx=20, pady=5)
        clear_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        # Status label
        self.status_label = tk.Label(control_frame, text="Status: Stopped", 
                                   fg='#e74c3c', bg='#2c3e50', font=('Arial', 12, 'bold'))
        self.status_label.pack(side=tk.RIGHT)
        
        # Notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Configure notebook style
        style = ttk.Style()
        style.configure('TNotebook.Tab', padding=[12, 8])
        
        self.create_network_info_tab()
        self.create_traffic_monitor_tab()
        self.create_connections_tab()
        self.create_statistics_tab()
        
    def create_network_info_tab(self):
        # Network Info Tab
        info_frame = tk.Frame(self.notebook, bg='#34495e')
        self.notebook.add(info_frame, text="Network Info")
        
        # Network interfaces
        interfaces_label = tk.Label(info_frame, text="Network Interfaces", 
                                  font=('Arial', 14, 'bold'), fg='#ecf0f1', bg='#34495e')
        interfaces_label.pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        self.interfaces_tree = ttk.Treeview(info_frame, columns=('Interface', 'IP', 'MAC', 'Status'), 
                                          show='headings', height=8)
        self.interfaces_tree.heading('Interface', text='Interface')
        self.interfaces_tree.heading('IP', text='IP Address')
        self.interfaces_tree.heading('MAC', text='MAC Address')
        self.interfaces_tree.heading('Status', text='Status')
        self.interfaces_tree.pack(fill=tk.X, padx=10, pady=5)
        
        # Network statistics
        stats_label = tk.Label(info_frame, text="Network Statistics", 
                             font=('Arial', 14, 'bold'), fg='#ecf0f1', bg='#34495e')
        stats_label.pack(anchor=tk.W, padx=10, pady=(20, 5))
        
        self.stats_text = scrolledtext.ScrolledText(info_frame, height=10, 
                                                  bg='#2c3e50', fg='#ecf0f1',
                                                  font=('Courier', 10))
        self.stats_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
    def create_traffic_monitor_tab(self):
        # Traffic Monitor Tab
        traffic_frame = tk.Frame(self.notebook, bg='#34495e')
        self.notebook.add(traffic_frame, text="Traffic Monitor")
        
        # Traffic log
        log_label = tk.Label(traffic_frame, text="Real-time Traffic Log", 
                           font=('Arial', 14, 'bold'), fg='#ecf0f1', bg='#34495e')
        log_label.pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        self.traffic_log = scrolledtext.ScrolledText(traffic_frame, height=25, 
                                                   bg='#2c3e50', fg='#00ff00',
                                                   font=('Courier', 9))
        self.traffic_log.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
    def create_connections_tab(self):
        # Connections Tab
        conn_frame = tk.Frame(self.notebook, bg='#34495e')
        self.notebook.add(conn_frame, text="Active Connections")
        
        conn_label = tk.Label(conn_frame, text="Active Network Connections", 
                            font=('Arial', 14, 'bold'), fg='#ecf0f1', bg='#34495e')
        conn_label.pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        self.connections_tree = ttk.Treeview(conn_frame, 
                                           columns=('Local', 'Remote', 'Protocol', 'Status', 'PID'), 
                                           show='headings', height=20)
        self.connections_tree.heading('Local', text='Local Address')
        self.connections_tree.heading('Remote', text='Remote Address')
        self.connections_tree.heading('Protocol', text='Protocol')
        self.connections_tree.heading('Status', text='Status')
        self.connections_tree.heading('PID', text='Process ID')
        
        # Add scrollbar to connections tree
        conn_scrollbar = ttk.Scrollbar(conn_frame, orient=tk.VERTICAL, command=self.connections_tree.yview)
        self.connections_tree.configure(yscrollcommand=conn_scrollbar.set)
        
        self.connections_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(10, 0), pady=5)
        conn_scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 10), pady=5)
        
    def create_statistics_tab(self):
        # Statistics Tab
        stats_frame = tk.Frame(self.notebook, bg='#34495e')
        self.notebook.add(stats_frame, text="Statistics")
        
        # Protocol statistics
        proto_label = tk.Label(stats_frame, text="Protocol Statistics", 
                             font=('Arial', 14, 'bold'), fg='#ecf0f1', bg='#34495e')
        proto_label.pack(anchor=tk.W, padx=10, pady=(10, 5))
        
        self.protocol_tree = ttk.Treeview(stats_frame, columns=('Protocol', 'Count', 'Percentage'), 
                                        show='headings', height=8)
        self.protocol_tree.heading('Protocol', text='Protocol')
        self.protocol_tree.heading('Count', text='Packet Count')
        self.protocol_tree.heading('Percentage', text='Percentage')
        self.protocol_tree.pack(fill=tk.X, padx=10, pady=5)
        
        # Top communicators
        top_label = tk.Label(stats_frame, text="Top Communicators", 
                           font=('Arial', 14, 'bold'), fg='#ecf0f1', bg='#34495e')
        top_label.pack(anchor=tk.W, padx=10, pady=(20, 5))
        
        self.top_tree = ttk.Treeview(stats_frame, columns=('IP', 'Packets', 'Data'), 
                                   show='headings', height=8)
        self.top_tree.heading('IP', text='IP Address')
        self.top_tree.heading('Packets', text='Packet Count')
        self.top_tree.heading('Data', text='Data Volume')
        self.top_tree.pack(fill=tk.X, padx=10, pady=5)
        
    def refresh_network_info(self):
        """Refresh network interface information"""
        # Clear existing data
        for item in self.interfaces_tree.get_children():
            self.interfaces_tree.delete(item)
        
        # Get network interfaces
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        
        for interface_name, addresses in interfaces.items():
            ip_addr = "N/A"
            mac_addr = "N/A"
            
            for addr in addresses:
                if addr.family == socket.AF_INET:
                    ip_addr = addr.address
                elif addr.family == psutil.AF_LINK:
                    mac_addr = addr.address
            
            status = "Up" if stats.get(interface_name, {}).isup else "Down"
            self.interfaces_tree.insert('', 'end', values=(interface_name, ip_addr, mac_addr, status))
        
        # Update network statistics
        self.update_network_stats()
        self.update_active_connections()
        
    def update_network_stats(self):
        """Update network statistics display"""
        try:
            net_io = psutil.net_io_counters()
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            
            stats_text = f"""
Network I/O Statistics:
{'='*50}
Bytes Sent: {self.format_bytes(net_io.bytes_sent)}
Bytes Received: {self.format_bytes(net_io.bytes_recv)}
Packets Sent: {net_io.packets_sent:,}
Packets Received: {net_io.packets_recv:,}
Errors In: {net_io.errin}
Errors Out: {net_io.errout}
Drops In: {net_io.dropin}
Drops Out: {net_io.dropout}

System Information:
{'='*50}
CPU Usage: {cpu_percent}%
Memory Usage: {memory.percent}%
Available Memory: {self.format_bytes(memory.available)}
Total Memory: {self.format_bytes(memory.total)}

Network Interfaces Count: {len(psutil.net_if_addrs())}
Active Connections: {len(psutil.net_connections())}
"""
            
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, stats_text)
            
        except Exception as e:
            self.stats_text.delete(1.0, tk.END)
            self.stats_text.insert(1.0, f"Error updating stats: {str(e)}")
    
    def update_active_connections(self):
        """Update active connections display"""
        # Clear existing connections
        for item in self.connections_tree.get_children():
            self.connections_tree.delete(item)
        
        try:
            connections = psutil.net_connections(kind='inet')
            for conn in connections:
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"
                protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                status = conn.status if conn.status else "N/A"
                pid = conn.pid if conn.pid else "N/A"
                
                self.connections_tree.insert('', 'end', 
                                           values=(local_addr, remote_addr, protocol, status, pid))
        except Exception as e:
            self.connections_tree.insert('', 'end', 
                                       values=(f"Error: {str(e)}", "", "", "", ""))
    
    def toggle_monitoring(self):
        """Start or stop network monitoring"""
        if not self.is_monitoring:
            self.start_monitoring()
        else:
            self.stop_monitoring()
    
    def start_monitoring(self):
        """Start network traffic monitoring"""
        self.is_monitoring = True
        self.monitor_btn.config(text="Stop Monitoring", bg='#e74c3c')
        self.status_label.config(text="Status: Monitoring", fg='#27ae60')
        
        # Start monitoring thread
        self.monitoring_thread = threading.Thread(target=self.monitor_traffic, daemon=True)
        self.monitoring_thread.start()
        
        # Start periodic updates
        self.update_display()
    
    def stop_monitoring(self):
        """Stop network traffic monitoring"""
        self.is_monitoring = False
        self.monitor_btn.config(text="Start Monitoring", bg='#27ae60')
        self.status_label.config(text="Status: Stopped", fg='#e74c3c')
    
    def monitor_traffic(self):
        """Monitor network traffic (simplified simulation)"""
        while self.is_monitoring:
            try:
                # Simulate network traffic monitoring
                # In a real implementation, you would use raw sockets or packet capture libraries
                current_time = datetime.now().strftime("%H:%M:%S")
                
                # Get current network stats
                net_io = psutil.net_io_counters()
                connections = psutil.net_connections(kind='inet')
                
                # Log network activity
                log_entry = f"[{current_time}] Network Activity - "
                log_entry += f"Bytes In: {self.format_bytes(net_io.bytes_recv)}, "
                log_entry += f"Bytes Out: {self.format_bytes(net_io.bytes_sent)}, "
                log_entry += f"Active Connections: {len(connections)}\n"
                
                # Add to traffic log
                self.root.after(0, self.add_to_traffic_log, log_entry)
                
                # Update connection statistics
                for conn in connections:
                    if conn.raddr:
                        remote_ip = conn.raddr.ip
                        self.ip_addresses.add(remote_ip)
                        self.connections[remote_ip] += 1
                        
                        protocol = "TCP" if conn.type == socket.SOCK_STREAM else "UDP"
                        self.protocols[protocol] += 1
                
                time.sleep(2)  # Update every 2 seconds
                
            except Exception as e:
                error_msg = f"[{current_time}] Monitoring Error: {str(e)}\n"
                self.root.after(0, self.add_to_traffic_log, error_msg)
                time.sleep(5)
    
    def add_to_traffic_log(self, message):
        """Add message to traffic log"""
        self.traffic_log.insert(tk.END, message)
        self.traffic_log.see(tk.END)
        
        # Keep only last 1000 lines
        lines = self.traffic_log.get(1.0, tk.END).split('\n')
        if len(lines) > 1000:
            self.traffic_log.delete(1.0, f"{len(lines)-1000}.0")
    
    def update_display(self):
        """Update display with current statistics"""
        if self.is_monitoring:
            self.update_protocol_stats()
            self.update_top_communicators()
            self.update_active_connections()
            
            # Schedule next update
            self.root.after(5000, self.update_display)  # Update every 5 seconds
    
    def update_protocol_stats(self):
        """Update protocol statistics"""
        # Clear existing data
        for item in self.protocol_tree.get_children():
            self.protocol_tree.delete(item)
        
        total_packets = sum(self.protocols.values())
        if total_packets > 0:
            for protocol, count in self.protocols.items():
                percentage = (count / total_packets) * 100
                self.protocol_tree.insert('', 'end', 
                                        values=(protocol, count, f"{percentage:.1f}%"))
    
    def update_top_communicators(self):
        """Update top communicators display"""
        # Clear existing data
        for item in self.top_tree.get_children():
            self.top_tree.delete(item)
        
        # Sort connections by count
        sorted_connections = sorted(self.connections.items(), 
                                  key=lambda x: x[1], reverse=True)[:10]
        
        for ip, count in sorted_connections:
            # Simulate data volume (in real implementation, you'd track actual bytes)
            data_volume = count * 1024  # Simplified calculation
            self.top_tree.insert('', 'end', 
                               values=(ip, count, self.format_bytes(data_volume)))
    
    def clear_logs(self):
        """Clear all logs and statistics"""
        self.traffic_log.delete(1.0, tk.END)
        self.traffic_data.clear()
        self.ip_addresses.clear()
        self.mac_addresses.clear()
        self.connections.clear()
        self.protocols.clear()
        
        # Clear trees
        for item in self.protocol_tree.get_children():
            self.protocol_tree.delete(item)
        for item in self.top_tree.get_children():
            self.top_tree.delete(item)
        
        messagebox.showinfo("Success", "All logs and statistics have been cleared.")
    
    def format_bytes(self, bytes_value):
        """Format bytes into human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"

def main():
    # Check if running as administrator/root for advanced features
    try:
        root = tk.Tk()
        app = NetworkTrafficAnalyzer(root)
        
        # Add some helpful information
        info_text = """
Network Traffic Analyzer - User Guide:
=====================================
1. Click 'Start Monitoring' to begin traffic analysis
2. Use different tabs to view various network information
3. 'Network Info' shows your network interfaces and system stats
4. 'Traffic Monitor' displays real-time network activity
5. 'Active Connections' shows current network connections
6. 'Statistics' provides protocol and communication statistics

Note: For advanced packet capture features, run as administrator/root.
Some features may require additional permissions or libraries.
"""
        
        print(info_text)
        root.mainloop()
        
    except Exception as e:
        print(f"Error starting application: {e}")
        messagebox.showerror("Error", f"Failed to start application: {e}")

if __name__ == "__main__":
    main()