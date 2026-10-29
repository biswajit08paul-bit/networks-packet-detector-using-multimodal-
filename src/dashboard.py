"""
Real-time IDS Dashboard - Modern Professional UI
"""

import sys
import os
import socket
import time
from datetime import datetime
from flask import Flask, render_template_string, jsonify, request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from src.live_capture import LiveCapture

app = Flask(__name__)
capture = LiveCapture()


@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)


@app.route('/api/status')
def get_status():
    return jsonify(capture.get_status())


@app.route('/api/interfaces')
def get_interfaces():
    return jsonify({'interfaces': capture.get_interfaces()})


@app.route('/api/devices')
def get_devices():
    return jsonify({'devices': capture.get_devices()})


@app.route('/api/alerts')
def get_alerts():
    with capture.lock:
        return jsonify({'alerts': list(capture.alerts[:50])})


@app.route('/api/network_info')
def get_network_info():
    status = capture.get_status()
    return jsonify({
        'hostname': socket.gethostname(),
        'local_ip': capture.local_ip,
        'monitoring': capture.monitoring,
        'interface': capture.interface,
        'total_devices': status['total_devices'],
        'total_packets': status['total_packets'],
        'total_bytes': status['total_bytes'],
        'total_alerts': status['total_alerts']
    })


@app.route('/api/start', methods=['POST'])
def start_monitoring():
    data = request.get_json(silent=True) or {}
    iface = data.get('interface')
    capture.interface = iface if iface else None
    ok = capture.start_background()
    return jsonify({
        'started': ok,
        'interface': capture.interface,
        'error': getattr(capture, 'last_error', None)
    })


@app.route('/api/stop', methods=['POST'])
def stop_monitoring():
    capture.stop()
    return jsonify({'stopped': True})


@app.route('/api/scan', methods=['POST'])
def scan_network():
    try:
        discovered = capture.scan_network()
        for dev in discovered:
            ip = dev['ip']
            with capture.lock:
                if ip not in capture.devices:
                    is_local = (ip == capture.local_ip)
                    is_gw = (ip == capture.gateway_ip)
                    role = 'Host (You)' if is_local else ('Gateway' if is_gw else 'External')
                    init_status = 'protected' if is_local else 'normal'

                    capture.devices[ip] = {
                        'ip': ip,
                        'mac': dev.get('mac', 'Unknown'),
                        'hostname': dev.get('hostname', 'Unknown'),
                        'role': role,
                        'is_local': is_local,
                        'packets_sent': 0,
                        'packets_received': 0,
                        'bytes_sent': 0,
                        'bytes_received': 0,
                        'first_seen': time.time(),
                        'last_seen': time.time(),
                        'threats': 0,
                        'status': init_status,
                        'alerts': []
                    }
                else:
                    capture.devices[ip]['mac'] = dev.get('mac', capture.devices[ip].get('mac', 'Unknown'))
                    capture.devices[ip]['hostname'] = dev.get('hostname', capture.devices[ip].get('hostname', 'Unknown'))
        return jsonify({'devices': capture.get_devices(), 'scanned': len(discovered)})
    except Exception as e:
        return jsonify({'error': str(e), 'devices': capture.get_devices()}), 500


@app.route('/api/demo_threat', methods=['POST'])
def demo_threat():
    data = request.get_json(silent=True) or {}
    threat_type = data.get('type', 'phishing').lower()

    if threat_type == 'phishing':
        attacker_ip = '198.51.100.77'
        attacker_host = 'Suspicious Phishing Host (evil-bank-login.xyz)'
        alert_name = 'phishing'
        detail = 'Fishy credential harvester / deceptive payload packet intercepted on port 443'
        confidence = 0.94
        action_desc = 'Quarantined suspicious payload, isolated attacker IP, protected host.'
    elif threat_type == 'scanning':
        attacker_ip = '192.0.2.45'
        attacker_host = 'Rogue Network Scanner (recon-probe.ru)'
        alert_name = 'scanning'
        detail = 'Rapid multi-port reconnaissance probe: 35 stealth SYN probes within 5 seconds'
        confidence = 0.96
        action_desc = 'Blacklisted probing IP, logged scanning vector, shielded open ports.'
    elif threat_type == 'ddos':
        attacker_ip = '203.0.113.88'
        attacker_host = 'Mirai-Style Botnet Zombie'
        alert_name = 'ddos'
        detail = 'High-rate SYN connection storm detected: 480 connections/sec attempt'
        confidence = 0.98
        action_desc = 'Rate-limited connection storm, dropped rogue SYN packets, preserved bandwidth.'
    else:  # backdoor / exploit
        attacker_ip = '198.51.100.12'
        attacker_host = 'Command & Control Exploit Node'
        alert_name = 'backdoor'
        detail = 'Malicious reverse shell / backdoor injection attempt detected'
        confidence = 0.92
        action_desc = 'Blocked exploit handshake, flagged C2 signature, host integrity verified.'

    now = time.time()
    with capture.lock:
        capture.devices[attacker_ip] = {
            'ip': attacker_ip,
            'mac': '02:42:c0:a8:01:5a',
            'hostname': attacker_host,
            'role': 'External',
            'is_local': False,
            'packets_sent': 52,
            'packets_received': 0,
            'bytes_sent': 4180,
            'bytes_received': 0,
            'first_seen': now,
            'last_seen': now,
            'threats': 1,
            'status': 'threat',
            'alerts': []
        }
        capture.flow_count += 1
        capture.classified_count += 1
        capture.total_packets += 52
        capture.total_bytes += 4180

    capture._raise_alert(
        src=attacker_ip,
        dst=capture.local_ip,
        attack_type=alert_name,
        detail=detail,
        confidence=confidence
    )

    return jsonify({
        'success': True,
        'attacker_ip': attacker_ip,
        'attacker_host': attacker_host,
        'target_ip': capture.local_ip,
        'attack_type': alert_name,
        'detail': detail,
        'action_desc': action_desc,
        'confidence': confidence
    })


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Real-Time IDS Dashboard</title>
    <style>
        :root { --bg:#0f172a; --card:#1e293b; --border:#334155; --text:#f8fafc; --muted:#94a3b8; --accent:#38bdf8; --success:#22c55e; --danger:#ef4444; --warning:#f59e0b; }
        * { box-sizing:border-box; margin:0; padding:0; }
        body { font-family:'Segoe UI',sans-serif; background:var(--bg); color:var(--text); padding:24px; }
        header { display:flex; justify-content:space-between; align-items:center; margin-bottom:24px; padding-bottom:16px; border-bottom:1px solid var(--border); flex-wrap:wrap; gap:16px; }
        .header-title h1 { color:var(--accent); font-size:1.75rem; margin-bottom:4px; display:flex; align-items:center; gap:10px; }
        .header-title .subtitle { color:var(--muted); font-size:0.92rem; }
        .banner { background:rgba(245,158,11,0.15); border:1px solid rgba(245,158,11,0.4); color:#fbbf24; padding:12px 16px; border-radius:8px; margin-bottom:20px; font-size:0.9rem; display:none; align-items:center; gap:10px; }
        .toolbar { display:flex; gap:16px; margin-bottom:24px; flex-wrap:wrap; align-items:flex-start; }
        .iface-container { flex:1; min-width:300px; }
        .iface-title { font-weight:600; margin-bottom:8px; color:var(--muted); font-size:0.85rem; }
        .interface-list { border:1px solid var(--border); border-radius:8px; max-height:180px; overflow-y:auto; background:#0f172a; }
        .interface-item { padding:10px 14px; border-bottom:1px solid var(--border); cursor:pointer; display:flex; justify-content:space-between; align-items:center; transition:background 0.15s; }
        .interface-item:last-child { border-bottom:none; }
        .interface-item:hover { background:#334155; }
        .interface-item.selected { background:#1e40af; color:#fff; }
        .interface-item.selected .iface-desc { color:#93c5fd; }
        .iface-name { font-weight:600; font-size:0.9rem; }
        .iface-desc { font-size:0.8rem; color:var(--muted); }
        .iface-ip { font-size:0.8rem; font-family:monospace; color:var(--accent); }
        .btn-group { display:flex; gap:10px; margin-top:24px; }
        .btn { padding:10px 18px; border:none; border-radius:8px; font-weight:600; font-size:0.9rem; cursor:pointer; transition:all 0.2s; display:inline-flex; align-items:center; gap:6px; }
        .btn:disabled { opacity:0.55; cursor:not-allowed; }
        .btn-primary { background:var(--accent); color:#0f172a; }
        .btn-primary:hover:not(:disabled) { background:#7dd3fc; }
        .btn-danger { background:var(--danger); color:#fff; }
        .btn-danger:hover:not(:disabled) { background:#dc2626; }
        .btn-outline { background:transparent; color:var(--text); border:1px solid var(--border); }
        .btn-outline:hover:not(:disabled) { border-color:var(--accent); color:var(--accent); }
        .btn-sm { padding:6px 12px; font-size:0.8rem; }
        .btn-warning { background:#f59e0b; color:#0f172a; font-weight:700; }
        .btn-warning:hover:not(:disabled) { background:#fbbf24; }
        .demo-box { display:flex; align-items:center; gap:10px; background:rgba(245,158,11,0.1); border:1px solid rgba(245,158,11,0.3); padding:8px 14px; border-radius:10px; }
        .demo-title { font-size:0.75rem; font-weight:700; color:#fbbf24; text-transform:uppercase; letter-spacing:0.04em; }
        .demo-select { background:#0f172a; color:#f8fafc; border:1px solid #475569; border-radius:6px; padding:7px 10px; font-size:0.85rem; cursor:pointer; }
        .panel-group { display:grid; grid-template-columns:repeat(auto-fit,minmax(280px,1fr)); gap:16px; margin-bottom:24px; }
        .card { background:var(--card); border:1px solid var(--border); border-radius:12px; padding:20px; box-shadow:0 4px 6px -1px rgba(0,0,0,0.3); }
        .card h2 { font-size:0.85rem; text-transform:uppercase; letter-spacing:0.05em; color:var(--muted); margin-bottom:14px; display:flex; align-items:center; gap:8px; }
        .stat-row { display:flex; justify-content:space-between; align-items:baseline; margin-bottom:10px; font-size:0.95rem; }
        .stat-value { font-size:1.5rem; font-weight:700; font-variant-numeric:tabular-nums; }
        .stat-label { color:var(--muted); font-size:0.85rem; }
        .badge { display:inline-flex; align-items:center; gap:6px; padding:4px 10px; border-radius:20px; font-size:0.75rem; font-weight:700; text-transform:uppercase; }
        .badge-active { background:rgba(34,197,94,0.15); color:var(--success); border:1px solid rgba(34,197,94,0.3); }
        .badge-inactive { background:rgba(239,68,68,0.15); color:var(--danger); border:1px solid rgba(239,68,68,0.3); }
        .badge-threat { background:rgba(239,68,68,0.18); color:var(--danger); border:1px solid rgba(239,68,68,0.4); }
        .badge-normal { background:rgba(34,197,94,0.15); color:var(--success); border:1px solid rgba(34,197,94,0.3); }
        .badge-protected { background:rgba(56,189,248,0.15); color:var(--accent); border:1px solid rgba(56,189,248,0.4); }
        .badge-suspicious { background:rgba(245,158,11,0.15); color:var(--warning); border:1px solid rgba(245,158,11,0.3); }
        .badge-info { background:rgba(56,189,248,0.15); color:var(--accent); }
        .role-tag { font-size:0.75rem; padding:3px 8px; border-radius:12px; font-weight:600; text-transform:uppercase; letter-spacing:0.04em; display:inline-block; }
        .role-host { background:#0369a1; color:#f0f9ff; }
        .role-gw { background:#334155; color:#cbd5e1; }
        .role-ext { background:#1e293b; color:#94a3b8; border:1px solid #475569; }
        .row-local { background:rgba(56,189,248,0.05); }
        .row-local td:first-child { border-left:3px solid var(--accent); }
        .section-title { font-size:1rem; font-weight:600; margin-bottom:12px; color:var(--text); display:flex; justify-content:space-between; align-items:center; }
        table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--border); border-radius:8px; overflow:hidden; margin-top:8px; }
        th { background:#0f172a; color:var(--muted); font-size:0.75rem; text-transform:uppercase; letter-spacing:0.05em; padding:12px; text-align:left; border-bottom:1px solid var(--border); }
        td { padding:12px; border-bottom:1px solid var(--border); font-size:0.9rem; }
        tr:last-child td { border-bottom:none; }
        tr:hover { background:#334155; }
        .mono { font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,monospace; font-size:0.85rem; }
        .bytes-sent { color:var(--accent); } .bytes-recv { color:var(--success); } .pkts { color:var(--text); font-variant-numeric:tabular-nums; }
        .alerts-list { display:flex; flex-direction:column; gap:10px; max-height:400px; overflow-y:auto; background:#0f172a; border:1px solid var(--border); border-radius:8px; padding:12px; }
        .alert-item { background:var(--card); border-left:4px solid var(--danger); padding:12px 14px; border-radius:0 8px 8px 0; font-size:0.88rem; animation:slideIn 0.3s ease; }
        @keyframes slideIn { from { opacity:0; transform:translateX(10px); } to { opacity:1; transform:translateX(0); } }
        .alert-time { color:var(--muted); font-size:0.75rem; margin-bottom:4px; display:block; }
        .alert-type { font-weight:700; color:var(--danger); }
        .alert-detail { margin-top:6px; color:var(--text); line-height:1.4; }
        .alert-confidence { font-size:0.75rem; color:var(--muted); margin-top:6px; display:inline-block; }
        .empty-state { color:var(--muted); text-align:center; padding:30px; font-size:0.9rem; }
        .spinner { display:inline-block; width:14px; height:14px; border:2px solid rgba(255,255,255,0.3); border-top-color:#fff; border-radius:50%; animation:spin 0.8s linear infinite; }
        @keyframes spin { to { transform:rotate(360deg); } }

        /* Real-time Reaction Toast */
        .reaction-toast { position:fixed; top:24px; right:24px; background:#1e293b; border:1px solid #ef4444; border-left:6px solid #ef4444; border-radius:10px; box-shadow:0 12px 30px rgba(0,0,0,0.6); padding:16px 20px; max-width:440px; z-index:99999; display:none; animation:slideDown 0.35s cubic-bezier(0.16, 1, 0.3, 1); }
        @keyframes slideDown { from { opacity:0; transform:translateY(-20px); } to { opacity:1; transform:translateY(0); } }
        .toast-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:8px; }
        .toast-title { font-weight:700; color:#ef4444; font-size:0.95rem; display:flex; align-items:center; gap:6px; }
        .toast-close { background:transparent; border:none; color:var(--muted); font-size:1.1rem; cursor:pointer; }
        .toast-close:hover { color:#fff; }
        .toast-body { font-size:0.88rem; line-height:1.4; color:var(--text); }
        .toast-highlight { background:#0f172a; padding:6px 10px; border-radius:6px; margin:8px 0; font-family:monospace; font-size:0.82rem; border:1px solid var(--border); }
        .toast-action { color:#38bdf8; font-weight:600; font-size:0.82rem; display:flex; align-items:center; gap:5px; margin-top:6px; }
    </style>
</head>
<body>

<!-- Real-time Threat Reaction Toast -->
<div id="reactionToast" class="reaction-toast">
    <div class="toast-header">
        <span class="toast-title">&#9889; Threat Intercepted &amp; Defended!</span>
        <button class="toast-close" onclick="closeToast()">&times;</button>
    </div>
    <div class="toast-body">
        <div id="toastDetail">A suspicious packet was analyzed and blocked by the IDS engine.</div>
        <div class="toast-highlight" id="toastMeta">Attacker: 198.51.100.77 &rarr; Target: You</div>
        <div class="toast-action" id="toastAction">&#128737;&#65039; Host Defended &bull; Attacker Quarantined in Threat Table</div>
    </div>
</div>

<header>
    <div class="header-title">
        <h1>&#128737;&#65039; Real-Time Intrusion Detection System</h1>
        <div class="subtitle">Live network monitoring &#8226; Per-device traffic &#8226; ML-based threat defense</div>
    </div>
    
    <!-- Top-Right Demo Simulation Option -->
    <div class="demo-box">
        <div>
            <div class="demo-title">&#9889; Threat Simulation Demo</div>
            <select id="demoThreatType" class="demo-select">
                <option value="phishing">&#127907; Fishy / Phishing Payload</option>
                <option value="scanning">&#128269; Port Scan Probe</option>
                <option value="ddos">&#128165; DDoS SYN Flood</option>
                <option value="backdoor">&#128027; Backdoor / C2 Exploit</option>
            </select>
        </div>
        <button class="btn btn-warning" id="demoThreatBtn" style="margin-top:16px;">
            &#9889; Simulate Attack
        </button>
    </div>
</header>

<div id="adminNotice" class="banner">
    <strong>&#9888;&#65039; Permission Notice:</strong>
    <span id="adminNoticeMsg">Packet capture requires Administrator privileges for Npcap on Windows.</span>
</div>

<div class="toolbar">
    <div class="iface-container">
        <div class="iface-title">Network Interface</div>
        <div id="interfaceList" class="interface-list"></div>
    </div>
    <div class="btn-group">
        <button class="btn btn-primary" id="startBtn">&#9654; Start Monitoring</button>
        <button class="btn btn-danger" id="stopBtn" disabled>&#9632; Stop Monitoring</button>
        <button class="btn btn-outline btn-sm" id="scanBtn">&#128269; Rescan Network</button>
    </div>
</div>

<div class="panel-group">
    <div class="card">
        <h2>System Status</h2>
        <div class="stat-row"><span class="stat-label">Status</span><span id="statusBadge" class="badge badge-inactive">&#9632; INACTIVE</span></div>
        <div class="stat-row"><span class="stat-label">Interface</span><span id="interfaceStat">--</span></div>
        <div class="stat-row"><span class="stat-label">Device Protection</span><span class="badge badge-protected">&#128737;&#65039; ACTIVE DEFENSE</span></div>
        <div class="stat-row"><span class="stat-label">Flows Analyzed</span><span id="flowValue" class="stat-value">0</span></div>
        <div class="stat-row"><span class="stat-label">Threat Alerts</span><span id="alertValue" class="stat-value">0</span></div>
    </div>
    <div class="card">
        <h2>Network Overview</h2>
        <div class="stat-row"><span class="stat-label">Host PC</span><span id="netHostname" style="font-weight:600;">--</span></div>
        <div class="stat-row"><span class="stat-label">Local IP</span><span id="netLocalIp" class="mono" style="color:var(--accent);">--</span></div>
        <div class="stat-row"><span class="stat-label">Total Packets</span><span id="totalPackets" class="stat-value">0</span></div>
        <div class="stat-row"><span class="stat-label">Total Bytes</span><span id="totalBytes" class="stat-value">0 B</span></div>
    </div>
</div>

<div class="panel-group" style="grid-template-columns:1fr;">
    <div class="card">
        <div class="section-title">
            <span>Connected Devices &amp; Traffic</span>
            <span id="deviceCountBadge" class="badge badge-info">0 devices</span>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Type / Role</th>
                    <th>IP Address</th>
                    <th>MAC Address</th>
                    <th>Hostname</th>
                    <th>Packets Sent</th>
                    <th>Packets Received</th>
                    <th>Bytes Sent</th>
                    <th>Bytes Received</th>
                    <th>Threats</th>
                    <th>Status</th>
                    <th>Last Seen</th>
                </tr>
            </thead>
            <tbody id="devicesTable">
                <tr><td colspan="11" class="empty-state">Loading devices...</td></tr>
            </tbody>
        </table>
    </div>
</div>

<div class="panel-group" style="grid-template-columns:1fr;">
    <div class="card">
        <div class="section-title">
            <span>Threat Alerts &amp; Incidents</span>
            <span id="alertCountBadge" class="badge badge-info">0</span>
        </div>
        <div id="alertsList" class="alerts-list">
            <div class="empty-state">No alerts yet. Monitoring live network traffic.</div>
        </div>
    </div>
</div>

<script>
    let updateInterval = null;
    let selectedInterface = null;
    let toastTimeout = null;

    async function fetchJSON(url, opts = {}) {
        const res = await fetch(url, opts);
        if (!res.ok) {
            const err = await res.json().catch(() => ({}));
            throw new Error(err.error || 'HTTP ' + res.status);
        }
        return res.json();
    }

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    function escapeHtml(text) {
        if (text == null) return '';
        const div = document.createElement('div');
        div.textContent = String(text);
        return div.innerHTML;
    }

    function showToast(title, meta, action) {
        const toast = document.getElementById('reactionToast');
        document.getElementById('toastDetail').innerHTML = title;
        document.getElementById('toastMeta').innerHTML = meta;
        document.getElementById('toastAction').innerHTML = '&#128737;&#65039; ' + action;
        toast.style.display = 'block';

        if (toastTimeout) clearTimeout(toastTimeout);
        toastTimeout = setTimeout(() => {
            toast.style.display = 'none';
        }, 8000);
    }

    function closeToast() {
        document.getElementById('reactionToast').style.display = 'none';
    }

    async function loadInterfaces() {
        try {
            const data = await fetchJSON('/api/interfaces');
            const list = document.getElementById('interfaceList');
            list.innerHTML = '';
            const ifaces = data.interfaces || [];
            if (ifaces.length === 0) {
                list.innerHTML = '<div style="padding:10px; color:var(--muted); font-size:0.85rem;">No interfaces found</div>';
                return;
            }
            ifaces.forEach((iface, i) => {
                const div = document.createElement('div');
                const isSelected = selectedInterface ? (selectedInterface === iface.name) : (i === 0);
                if (isSelected && !selectedInterface) selectedInterface = iface.name;
                div.className = 'interface-item' + (isSelected ? ' selected' : '');
                div.onclick = () => selectInterface(iface.name);
                div.innerHTML =
                    '<div>' +
                    '<div class="iface-name">' + escapeHtml(iface.name || 'Unknown') + '</div>' +
                    '<div class="iface-desc">' + escapeHtml(iface.description || '') + '</div>' +
                    '</div>' +
                    '<div class="iface-ip">' + (iface.ip ? iface.ip : 'None') + '</div>';
                list.appendChild(div);
            });
        } catch (e) {
            console.error('Failed to load interfaces', e);
        }
    }

    function selectInterface(name) {
        selectedInterface = name;
        document.querySelectorAll('.interface-item').forEach(el => {
            const elName = el.querySelector('.iface-name');
            const isSel = elName && elName.textContent === name;
            el.classList.toggle('selected', isSel);
        });
        const ifaceStat = document.getElementById('interfaceStat');
        if (ifaceStat) ifaceStat.textContent = name;
    }

    async function loadStatus() {
        try {
            const data = await fetchJSON('/api/status');
            const badge = document.getElementById('statusBadge');
            const startBtn = document.getElementById('startBtn');
            const stopBtn = document.getElementById('stopBtn');
            const adminNotice = document.getElementById('adminNotice');
            const adminMsg = document.getElementById('adminNoticeMsg');

            if (data.error) {
                adminNotice.style.display = 'flex';
                adminMsg.textContent = data.error;
            } else {
                adminNotice.style.display = 'none';
            }

            if (data.monitoring) {
                badge.textContent = '▶ ACTIVE';
                badge.className = 'badge badge-active';
                startBtn.disabled = true;
                stopBtn.disabled = false;
            } else {
                badge.textContent = '■ INACTIVE';
                badge.className = 'badge badge-inactive';
                startBtn.disabled = false;
                stopBtn.disabled = true;
            }
            document.getElementById('interfaceStat').textContent = data.interface || selectedInterface || 'Not selected';
            document.getElementById('flowValue').textContent = data.flow_count || 0;
            document.getElementById('alertValue').textContent = data.total_alerts || 0;
        } catch (e) {
            console.error('Status load failed', e);
        }
    }

    async function loadNetworkInfo() {
        try {
            const data = await fetchJSON('/api/network_info');
            document.getElementById('netHostname').textContent = data.hostname || '--';
            document.getElementById('netLocalIp').textContent = data.local_ip || '--';
            document.getElementById('totalPackets').textContent = (data.total_packets || 0).toLocaleString();
            document.getElementById('totalBytes').textContent = formatBytes(data.total_bytes || 0);
        } catch (e) {
            console.error('Network info load failed', e);
        }
    }

    async function loadDevices() {
        try {
            const data = await fetchJSON('/api/devices');
            const tbody = document.getElementById('devicesTable');
            const badge = document.getElementById('deviceCountBadge');
            const devices = data.devices || [];
            badge.textContent = devices.length + ' device' + (devices.length !== 1 ? 's' : '');
            if (devices.length === 0) {
                tbody.innerHTML = '<tr><td colspan="11" class="empty-state">No devices detected yet. Click Start Monitoring or Rescan Network.</td></tr>';
                return;
            }
            tbody.innerHTML = '';
            devices.forEach(d => {
                const isLocal = d.is_local;
                let statusBadge = '';
                if (d.status === 'protected' || isLocal) {
                    statusBadge = '<span class="badge badge-protected">&#128737;&#65039; PROTECTED</span>';
                } else if (d.status === 'threat') {
                    statusBadge = '<span class="badge badge-threat">&#9888;&#65039; THREAT</span>';
                } else if (d.status === 'suspicious') {
                    statusBadge = '<span class="badge badge-suspicious">&#9889; SUSPICIOUS</span>';
                } else {
                    statusBadge = '<span class="badge badge-normal">&#9679; NORMAL</span>';
                }

                let roleTag = '';
                if (isLocal) {
                    roleTag = '<span class="role-tag role-host">&#128187; Host (You)</span>';
                } else if (d.role === 'Gateway') {
                    roleTag = '<span class="role-tag role-gw">&#127760; Gateway</span>';
                } else {
                    roleTag = '<span class="role-tag role-ext">&#128225; External</span>';
                }

                const row = document.createElement('tr');
                if (isLocal) row.className = 'row-local';
                row.innerHTML =
                    '<td>' + roleTag + '</td>' +
                    '<td class="mono">' + escapeHtml(d.ip || '--') + '</td>' +
                    '<td class="mono">' + escapeHtml(d.mac || '--') + '</td>' +
                    '<td>' + escapeHtml(d.hostname || 'Unknown') + '</td>' +
                    '<td class="pkts">' + (d.packets_sent || 0).toLocaleString() + '</td>' +
                    '<td class="pkts">' + (d.packets_received || 0).toLocaleString() + '</td>' +
                    '<td class="bytes-sent format-bytes">' + formatBytes(d.bytes_sent || 0) + '</td>' +
                    '<td class="bytes-recv format-bytes">' + formatBytes(d.bytes_received || 0) + '</td>' +
                    '<td>' + (d.threats || 0) + '</td>' +
                    '<td>' + statusBadge + '</td>' +
                    '<td>' + (d.last_seen || '--') + '</td>';
                tbody.appendChild(row);
            });
        } catch (e) {
            console.error('Devices load failed', e);
        }
    }

    async function loadAlerts() {
        try {
            const data = await fetchJSON('/api/alerts');
            const list = document.getElementById('alertsList');
            const badge = document.getElementById('alertCountBadge');
            const alerts = data.alerts || [];
            badge.textContent = alerts.length;
            if (alerts.length === 0) {
                list.innerHTML = '<div class="empty-state">No alerts yet. Monitoring live network traffic.</div>';
                return;
            }
            list.innerHTML = alerts.map(a =>
                '<div class="alert-item">' +
                '<span class="alert-time">' + escapeHtml(a.timestamp || '--') + '</span>' +
                '<strong class="alert-type">&#9888;&#65039; ' + escapeHtml(a.type || 'UNKNOWN').toUpperCase() + '</strong>' +
                '<div class="alert-detail">' +
                '<strong>Attacker (Source):</strong> ' + escapeHtml(a.src_label || a.src_ip || '--') +
                ' &rarr; <strong>Target:</strong> ' + escapeHtml(a.dst_label || a.dst_ip || '--') +
                '<br><span style="color:var(--muted); font-size:0.82rem;">' + escapeHtml(a.detail || '') + '</span>' +
                '</div>' +
                '<span class="alert-confidence">ML Confidence: ' + ((a.confidence || 0) * 100).toFixed(1) + '%</span>' +
                '</div>'
            ).join('');
        } catch (e) {
            console.error('Alerts load failed', e);
        }
    }

    async function updateAll() {
        await loadStatus();
        await loadNetworkInfo();
        await loadDevices();
        await loadAlerts();
    }

    // Simulate Threat / Demo Action
    document.getElementById('demoThreatBtn').addEventListener('click', async () => {
        const btn = document.getElementById('demoThreatBtn');
        const threatType = document.getElementById('demoThreatType').value;
        const originalText = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Simulating...';

        try {
            const res = await fetchJSON('/api/demo_threat', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ type: threatType })
            });

            if (res.success) {
                // Show reaction toast immediately
                showToast(
                    '<strong>Alert Type:</strong> ' + escapeHtml(res.attack_type.toUpperCase()) + '<br>' + escapeHtml(res.detail),
                    'Attacker: <strong>' + escapeHtml(res.attacker_ip) + '</strong> (' + escapeHtml(res.attacker_host) + ') &rarr; Target: <strong>' + escapeHtml(res.target_ip) + ' (Your PC)</strong>',
                    res.action_desc
                );
                // Immediately refresh table and alerts list
                await updateAll();
            }
        } catch (e) {
            alert('Simulation error: ' + e.message);
        } finally {
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    });

    document.getElementById('startBtn').addEventListener('click', async () => {
        const startBtn = document.getElementById('startBtn');
        startBtn.disabled = true;
        try {
            const res = await fetchJSON('/api/start', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ interface: selectedInterface || null })
            });
            if (res.error) {
                const adminNotice = document.getElementById('adminNotice');
                const adminMsg = document.getElementById('adminNoticeMsg');
                adminNotice.style.display = 'flex';
                adminMsg.textContent = res.error;
            }
            await updateAll();
        } catch (e) {
            alert('Failed to start monitoring: ' + e.message);
            startBtn.disabled = false;
        }
    });

    document.getElementById('stopBtn').addEventListener('click', async () => {
        try {
            await fetchJSON('/api/stop', { method: 'POST' });
            await updateAll();
        } catch (e) {
            alert('Failed to stop monitoring: ' + e.message);
        }
    });

    document.getElementById('scanBtn').addEventListener('click', async () => {
        const btn = document.getElementById('scanBtn');
        const original = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner"></span> Scanning...';
        try {
            await fetchJSON('/api/scan', { method: 'POST' });
            await loadDevices();
        } catch (e) {
            console.error(e);
        } finally {
            btn.disabled = false;
            btn.innerHTML = original;
        }
    });

    // Initial load
    loadInterfaces().then(updateAll);
    updateInterval = setInterval(updateAll, 2000);
</script>
</body>
</html>
"""

if __name__ == '__main__':
    app.run(debug=True, host='127.0.0.1', port=5000)
