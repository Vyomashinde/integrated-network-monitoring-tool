from flask import Flask, render_template, jsonify, request
import subprocess
import json
from scapy.all import *
import time
from datetime import datetime
import threading
import speedtest
import nmap
import netifaces
import psutil
import socket
import ipaddress

app = Flask(__name__)

logs = []

def packet_callback(pkt):
    if IP in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst
        proto = 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else 'ICMP' if ICMP in pkt else 'Other'
        timestamp = datetime.now().isoformat()
        logs.append({'src': src, 'dst': dst, 'proto': proto, 'timestamp': timestamp})

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/latency/<host>')
def latency(host):
    data = get_latency(host)
    return jsonify(data)

def get_latency(host):
    try:
        result = subprocess.run(['ping', '-n', '10', host], capture_output=True, text=True, timeout=30)
        lines = result.stdout.split('\n')
        latencies = []
        sent = 0
        received = 0
        for line in lines:
            if 'Reply from' in line and 'time=' in line:
                time_str = line.split('time=')[1].split('ms')[0]
                latencies.append(float(time_str))
                received += 1
            if 'Packets: Sent' in line:
                sent = int(line.split('Sent = ')[1].split(',')[0])
        if latencies:
            avg = sum(latencies) / len(latencies)
            packet_loss = (sent - received) / sent * 100 if sent > 0 else 0
            jitter = max(latencies) - min(latencies) if len(latencies) > 1 else 0
            return {'avg_latency': round(avg, 2), 'packet_loss': round(packet_loss, 2), 'jitter': round(jitter, 2)}
        else:
            return {'error': 'No response'}
    except Exception as e:
        return {'error': str(e)}

@app.route('/api/devices')
def devices():
    devs = scan_lan()
    return jsonify(devs)

def scan_lan():
    try:
        local_ip = socket.gethostbyname(socket.gethostname())
        network = '.'.join(local_ip.split('.')[:3]) + '.0/24'
    except:
        network = '192.168.1.0/24'  # fallback
    ans, unans = arping(network, timeout=2)
    devices = []
    for sent, received in ans:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'status': 'active'})
    return devices

@app.route('/api/start_capture')
def start_capture():
    global logs
    logs = []
    def capture():
        sniff(prn=packet_callback, timeout=10, store=0)
    threading.Thread(target=capture).start()
    return jsonify({'status': 'Capture started for 10 seconds'})

@app.route('/api/logs')
def get_logs():
    return jsonify(logs)

@app.route('/api/protocol_analysis')
def api_protocol_analysis():
    tcp = sum(1 for l in logs if l['proto'] == 'TCP')
    udp = sum(1 for l in logs if l['proto'] == 'UDP')
    icmp = sum(1 for l in logs if l['proto'] == 'ICMP')
    return jsonify({'TCP': tcp, 'UDP': udp, 'ICMP': icmp})

@app.route('/api/verify/<host>')
def verify(host):
    result = subprocess.run(['ping', '-n', '4', host], capture_output=True, text=True)
    return jsonify({'output': result.stdout})

@app.route('/api/bandwidth')
def bandwidth():
    try:
        st = speedtest.Speedtest()
        st.get_best_server()
        download = st.download() / 1e6  # Mbps
        upload = st.upload() / 1e6
        return jsonify({'download': round(download, 2), 'upload': round(upload, 2)})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/port_scan/<host>')
def port_scan(host):
    try:
        nm = nmap.PortScanner()
        # limit scan duration so the request doesn't hang indefinitely; skip host discovery
        # ``--host-timeout`` stops scanning if the host does not respond within 10 seconds.
        # ``-Pn`` makes nmap treat all hosts as up which is usually fine for remote targets.
        nm.scan(host, '1-1024', arguments='-Pn --host-timeout 10s')
        open_ports = []
        # If the scan didn't return any hosts we treat it as a timeout/unreachable error
        if not nm.all_hosts():
            return jsonify({'error': 'No hosts found – target may be unreachable or scan timed out'})
        for h in nm.all_hosts():
            for proto in nm[h].all_protocols():
                lport = nm[h][proto].keys()
                for port in lport:
                    if nm[h][proto][port]['state'] == 'open':
                        open_ports.append({'port': port, 'service': nm[h][proto][port]['name']})
        return jsonify({'open_ports': open_ports})
    except Exception as e:
        # detect common nmap not installed error messages
        err_str = str(e).lower()
        if 'not found in path' in err_str or 'nmap program was not found' in err_str:
            return jsonify({'error': 'Nmap is not installed or not in PATH. Please install Nmap from https://nmap.org/download.html'})
        else:
            return jsonify({'error': str(e)})

@app.route('/api/dns_lookup/<domain>')
def dns_lookup(domain):
    try:
        ip = socket.gethostbyname(domain)
        return jsonify({'ip': ip})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/traceroute/<host>')
def traceroute_route(host):
    try:
        # Check if host is a valid IP address
        try:
            ipaddress.ip_address(host)
            target = host  # Use IP directly
        except ValueError:
            # It's a hostname, try to resolve it
            try:
                target = socket.gethostbyname(host)
            except socket.gaierror:
                return jsonify({'error': f'Unable to resolve hostname: {host}'})

        # Perform traceroute
        res, unans = traceroute(target, maxttl=20, timeout=2)
        hops = []
        for sent, received in res:
            rtt = (received.time - sent.sent_time) * 1000 if received.time else None
            hops.append({'ttl': sent.ttl, 'ip': received.src, 'rtt': round(rtt, 2) if rtt else 'N/A'})

        if not hops:
            return jsonify({'error': 'No route found or traceroute timed out'})

        return jsonify({'hops': hops})
    except Exception as e:
        return jsonify({'error': f'Traceroute failed: {str(e)}'})

@app.route('/api/interfaces')
def interfaces():
    try:
        ifaces = []
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            iface_info = {'name': iface}
            if netifaces.AF_INET in addrs:
                iface_info['ip'] = addrs[netifaces.AF_INET][0]['addr']
            if netifaces.AF_LINK in addrs:
                iface_info['mac'] = addrs[netifaces.AF_LINK][0]['addr']
            ifaces.append(iface_info)
        return jsonify(ifaces)
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/system_stats')
def system_stats():
    try:
        cpu = psutil.cpu_percent(interval=1)
        net = psutil.net_io_counters()
        return jsonify({'cpu_usage': round(cpu, 2), 'bytes_sent': net.bytes_sent, 'bytes_recv': net.bytes_recv})
    except Exception as e:
        return jsonify({'error': str(e)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)