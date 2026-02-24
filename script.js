// Global variables
let deviceCount = 0;
let systemLoad = 'Loading...';

// Utility functions
function showLoading(buttonId) {
    const btn = document.getElementById(buttonId);
    if (btn) {
        btn.classList.add('loading');
        btn.querySelector('.spinner-border')?.classList.remove('d-none');
    }
}

function hideLoading(buttonId) {
    const btn = document.getElementById(buttonId);
    if (btn) {
        btn.classList.remove('loading');
        btn.querySelector('.spinner-border')?.classList.add('d-none');
    }
}

function showResult(containerId, content, isError = false) {
    const container = document.getElementById(containerId);
    if (container) {
        container.innerHTML = content;
        container.className = `result-container ${isError ? 'border-danger' : 'border-success'}`;
        container.style.display = 'block';
    }
}

function clearResult(containerId) {
    const container = document.getElementById(containerId);
    if (container) {
        container.innerHTML = '';
        container.style.display = 'none';
    }
}

// Dashboard functions
function quickNetworkCheck() {
    // Test connectivity to google.com
    showLoading('latencyBtn');
    fetch('/api/latency/google.com')
        .then(response => response.json())
        .then(data => {
            hideLoading('latencyBtn');
            if (data.error) {
                document.getElementById('connectionStatus').className = 'badge bg-danger';
                document.getElementById('connectionStatus').textContent = 'Offline';
                alert('Network connectivity check failed: ' + data.error);
            } else {
                document.getElementById('connectionStatus').className = 'badge bg-success';
                document.getElementById('connectionStatus').textContent = 'Online';
                alert(`Network check successful!\nLatency: ${data.avg_latency}ms\nPacket Loss: ${data.packet_loss}%`);
            }
        })
        .catch(error => {
            hideLoading('latencyBtn');
            document.getElementById('connectionStatus').className = 'badge bg-danger';
            document.getElementById('connectionStatus').textContent = 'Error';
            alert('Network check failed: ' + error.message);
        });
}

function quickSecurityScan() {
    const localIP = prompt('Enter your local IP address for security scan (e.g., 192.168.1.100):');
    if (localIP) {
        document.getElementById('scanHost').value = localIP;
        scanPorts();
    }
}

// Initialize dashboard on page load
document.addEventListener('DOMContentLoaded', function() {
    // Load initial system stats
    getSystemStats();

    // Set up smooth scrolling for navbar links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth',
                    block: 'start'
                });
            }
        });
    });
});

function measureLatency() {
    const host = document.getElementById('latencyHost').value.trim();
    if (!host) {
        alert('Please enter a host IP address or hostname');
        return;
    }

    showLoading('latencyBtn');
    clearResult('latencyResult');

    fetch(`/api/latency/${encodeURIComponent(host)}`)
        .then(response => response.json())
        .then(data => {
            hideLoading('latencyBtn');
            if (data.error) {
                showResult('latencyResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>${data.error}</div>`, true);
            } else {
                const result = `
                    <div class="alert alert-success">
                        <h6 class="alert-heading"><i class="bi bi-check-circle me-2"></i>Latency Test Results</h6>
                        <hr>
                        <div class="row">
                            <div class="col-sm-4"><strong>Average Latency:</strong><br>${data.avg_latency} ms</div>
                            <div class="col-sm-4"><strong>Packet Loss:</strong><br>${data.packet_loss}%</div>
                            <div class="col-sm-4"><strong>Jitter:</strong><br>${data.jitter} ms</div>
                        </div>
                    </div>`;
                showResult('latencyResult', result);
            }
        })
        .catch(error => {
            hideLoading('latencyBtn');
            showResult('latencyResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>Error: ${error.message}</div>`, true);
        });
}

function discoverDevices() {
    showLoading('devicesBtn');
    clearResult('devicesResult');

    fetch('/api/devices')
        .then(response => response.json())
        .then(data => {
            hideLoading('devicesBtn');
            deviceCount = data.length;
            document.getElementById('deviceCount').textContent = `${deviceCount} devices found`;

            if (data.length === 0) {
                showResult('devicesResult', '<div class="alert alert-warning"><i class="bi bi-info-circle me-2"></i>No devices found. Make sure you are running as administrator and Npcap is installed.</div>', true);
            } else {
                let html = `
                    <div class="alert alert-info"><i class="bi bi-hdd-network me-2"></i>Found ${data.length} active device(s) on your network</div>
                    <div class="table-responsive">
                        <table class="table table-striped table-hover">
                            <thead class="table-primary">
                                <tr>
                                    <th><i class="bi bi-hash me-1"></i>#</th>
                                    <th><i class="bi bi-router me-1"></i>IP Address</th>
                                    <th><i class="bi bi-macbook me-1"></i>MAC Address</th>
                                    <th><i class="bi bi-circle-fill text-success me-1"></i>Status</th>
                                </tr>
                            </thead>
                            <tbody>`;
                data.forEach((d, index) => {
                    html += `<tr>
                                <td>${index + 1}</td>
                                <td><code>${d.ip}</code></td>
                                <td><code>${d.mac}</code></td>
                                <td><span class="badge bg-success">${d.status}</span></td>
                            </tr>`;
                });
                html += '</tbody></table></div>';
                showResult('devicesResult', html);
            }
        })
        .catch(error => {
            hideLoading('devicesBtn');
            showResult('devicesResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>Error fetching devices: ${error.message}</div>`, true);
        });
}

function startCapture() {
    showLoading('captureBtn');
    fetch('/api/start_capture')
        .then(response => response.json())
        .then(data => {
            hideLoading('captureBtn');
            alert(data.status + '\n\nThe capture will run for 10 seconds in the background.');
            // Auto-refresh logs after capture
            setTimeout(() => {
                getLogs();
            }, 11000);
        })
        .catch(error => {
            hideLoading('captureBtn');
            alert('Error starting capture: ' + error.message);
        });
}

function getLogs() {
    showLoading('logsBtn');
    clearResult('logsResult');

    fetch('/api/logs')
        .then(response => response.json())
        .then(data => {
            hideLoading('logsBtn');
            if (data.length === 0) {
                showResult('logsResult', '<div class="alert alert-info"><i class="bi bi-info-circle me-2"></i>No packet logs available. Start a capture first.</div>');
            } else {
                let html = `
                    <div class="alert alert-info"><i class="bi bi-activity me-2"></i>Captured ${data.length} packet(s)</div>
                    <div class="table-responsive">
                        <table class="table table-striped table-hover">
                            <thead class="table-warning">
                                <tr>
                                    <th><i class="bi bi-clock me-1"></i>Timestamp</th>
                                    <th><i class="bi bi-arrow-right-circle me-1"></i>Source IP</th>
                                    <th><i class="bi bi-arrow-left-circle me-1"></i>Destination IP</th>
                                    <th><i class="bi bi-diagram-3 me-1"></i>Protocol</th>
                                </tr>
                            </thead>
                            <tbody>`;
                data.forEach(l => {
                    html += `<tr>
                                <td><small>${new Date(l.timestamp).toLocaleString()}</small></td>
                                <td><code>${l.src}</code></td>
                                <td><code>${l.dst}</code></td>
                                <td><span class="badge bg-secondary">${l.proto}</span></td>
                            </tr>`;
                });
                html += '</tbody></table></div>';
                showResult('logsResult', html);
            }
        })
        .catch(error => {
            hideLoading('logsBtn');
            showResult('logsResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>Error fetching logs: ${error.message}</div>`, true);
        });
}

function getProtocolAnalysis() {
    showLoading('protocolBtn');
    clearResult('protocolResult');

    fetch('/api/protocol_analysis')
        .then(response => response.json())
        .then(data => {
            hideLoading('protocolBtn');
            const total = data.TCP + data.UDP + data.ICMP;
            const result = `
                <div class="alert alert-warning">
                    <h6 class="alert-heading"><i class="bi bi-bar-chart me-2"></i>Protocol Distribution</h6>
                    <hr>
                    <div class="row text-center">
                        <div class="col-sm-4">
                            <div class="border rounded p-2">
                                <h4 class="text-primary">${data.TCP}</h4>
                                <small class="text-muted">TCP</small>
                            </div>
                        </div>
                        <div class="col-sm-4">
                            <div class="border rounded p-2">
                                <h4 class="text-success">${data.UDP}</h4>
                                <small class="text-muted">UDP</small>
                            </div>
                        </div>
                        <div class="col-sm-4">
                            <div class="border rounded p-2">
                                <h4 class="text-info">${data.ICMP}</h4>
                                <small class="text-muted">ICMP</small>
                            </div>
                        </div>
                    </div>
                    <small class="text-muted">Total packets analyzed: ${total}</small>
                </div>`;
            showResult('protocolResult', result);
            document.getElementById('protocolResult').classList.remove('d-none');
        })
        .catch(error => {
            hideLoading('protocolBtn');
            showResult('protocolResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>Error: ${error.message}</div>`, true);
        });
}

function clearLogs() {
    clearResult('logsResult');
    clearResult('protocolResult');
    document.getElementById('protocolResult').classList.add('d-none');

    // Show a brief confirmation message
    showResult('logsResult', '<div class="alert alert-success"><i class="bi bi-check-circle me-2"></i>Logs cleared successfully</div>');

    // Hide the confirmation after 2 seconds
    setTimeout(() => {
        clearResult('logsResult');
    }, 2000);
}

function testBandwidth() {
    showLoading('bandwidthBtn');
    clearResult('bandwidthResult');

    fetch('/api/bandwidth')
        .then(response => response.json())
        .then(data => {
            hideLoading('bandwidthBtn');
            if (data.error) {
                showResult('bandwidthResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>${data.error}</div>`, true);
            } else {
                const result = `
                    <div class="alert alert-success">
                        <h6 class="alert-heading"><i class="bi bi-speedometer me-2"></i>Speed Test Results</h6>
                        <hr>
                        <div class="row text-center">
                            <div class="col-sm-6">
                                <div class="border rounded p-3">
                                    <i class="bi bi-download text-success" style="font-size: 2rem;"></i>
                                    <h3 class="text-success">${data.download}</h3>
                                    <small class="text-muted">Mbps Download</small>
                                </div>
                            </div>
                            <div class="col-sm-6">
                                <div class="border rounded p-3">
                                    <i class="bi bi-upload text-primary" style="font-size: 2rem;"></i>
                                    <h3 class="text-primary">${data.upload}</h3>
                                    <small class="text-muted">Mbps Upload</small>
                                </div>
                            </div>
                        </div>
                    </div>`;
                showResult('bandwidthResult', result);
            }
        })
        .catch(error => {
            hideLoading('bandwidthBtn');
            showResult('bandwidthResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>Error: ${error.message}</div>`, true);
        });
}

function scanPorts() {
    const host = document.getElementById('scanHost').value.trim();
    if (!host) {
        alert('Please enter a host IP address or hostname');
        return;
    }

    showLoading('scanBtn');
    clearResult('scanResult');

    fetch(`/api/port_scan/${encodeURIComponent(host)}`)
        .then(response => response.json())
        .then(data => {
            hideLoading('scanBtn');
            if (data.error) {
                showResult('scanResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>${data.error}</div>`, true);
            } else {
                if (data.open_ports.length === 0) {
                    showResult('scanResult', '<div class="alert alert-info"><i class="bi bi-info-circle me-2"></i>No open ports found in the range 1-1024.</div>');
                } else {
                    let html = `
                        <div class="alert alert-danger"><i class="bi bi-shield-exclamation me-2"></i>Found ${data.open_ports.length} open port(s) on ${host}</div>
                        <div class="table-responsive">
                            <table class="table table-striped table-hover">
                                <thead class="table-danger">
                                    <tr>
                                        <th><i class="bi bi-hash me-1"></i>Port</th>
                                        <th><i class="bi bi-tag me-1"></i>Service</th>
                                        <th><i class="bi bi-circle-fill text-danger me-1"></i>Status</th>
                                    </tr>
                                </thead>
                                <tbody>`;
                    data.open_ports.forEach(p => {
                        html += `<tr>
                                    <td><code>${p.port}</code></td>
                                    <td>${p.service}</td>
                                    <td><span class="badge bg-danger">Open</span></td>
                                </tr>`;
                    });
                    html += '</tbody></table></div>';
                    showResult('scanResult', html);
                }
            }
        })
        .catch(error => {
            hideLoading('scanBtn');
            showResult('scanResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>Error: ${error.message}</div>`, true);
        });
}

function dnsLookup() {
    const domain = document.getElementById('dnsDomain').value.trim();
    if (!domain) {
        alert('Please enter a domain name');
        return;
    }

    showLoading('dnsBtn');
    clearResult('dnsResult');

    fetch(`/api/dns_lookup/${encodeURIComponent(domain)}`)
        .then(response => response.json())
        .then(data => {
            hideLoading('dnsBtn');
            if (data.error) {
                showResult('dnsResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>${data.error}</div>`, true);
            } else {
                const result = `
                    <div class="alert alert-info">
                        <h6 class="alert-heading"><i class="bi bi-globe me-2"></i>DNS Lookup Result</h6>
                        <hr>
                        <div class="row">
                            <div class="col-sm-6"><strong>Domain:</strong><br>${domain}</div>
                            <div class="col-sm-6"><strong>IP Address:</strong><br><code>${data.ip}</code></div>
                        </div>
                    </div>`;
                showResult('dnsResult', result);
            }
        })
        .catch(error => {
            hideLoading('dnsBtn');
            showResult('dnsResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>Error: ${error.message}</div>`, true);
        });
}

function traceroute() {
    const host = document.getElementById('traceHost').value.trim();
    if (!host) {
        alert('Please enter a host IP address or hostname');
        return;
    }

    showLoading('traceBtn');
    clearResult('traceResult');

    fetch(`/api/traceroute/${encodeURIComponent(host)}`)
        .then(response => response.json())
        .then(data => {
            hideLoading('traceBtn');
            if (data.error) {
                showResult('traceResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>${data.error}</div>`, true);
            } else {
                let html = `
                    <div class="alert alert-dark"><i class="bi bi-diagram-3 me-2"></i>Traceroute to ${host} (${data.hops.length} hops)</div>
                    <div class="table-responsive">
                        <table class="table table-striped table-hover">
                            <thead class="table-dark">
                                <tr>
                                    <th><i class="bi bi-hash me-1"></i>Hop</th>
                                    <th><i class="bi bi-router me-1"></i>IP Address</th>
                                    <th><i class="bi bi-stopwatch me-1"></i>RTT (ms)</th>
                                </tr>
                            </thead>
                            <tbody>`;
                data.hops.forEach(h => {
                    html += `<tr>
                                <td>${h.ttl}</td>
                                <td><code>${h.ip}</code></td>
                                <td>${h.rtt}</td>
                            </tr>`;
                });
                html += '</tbody></table></div>';
                showResult('traceResult', html);
            }
        })
        .catch(error => {
            hideLoading('traceBtn');
            showResult('traceResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>Error: ${error.message}</div>`, true);
        });
}

function getInterfaces() {
    showLoading('interfacesBtn');
    clearResult('interfacesResult');

    fetch('/api/interfaces')
        .then(response => response.json())
        .then(data => {
            hideLoading('interfacesBtn');
            if (data.error) {
                showResult('interfacesResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>${data.error}</div>`, true);
            } else {
                let html = `
                    <div class="alert alert-secondary"><i class="bi bi-ethernet me-2"></i>Network Interfaces (${data.length} found)</div>
                    <div class="table-responsive">
                        <table class="table table-striped table-hover">
                            <thead class="table-secondary">
                                <tr>
                                    <th><i class="bi bi-tag me-1"></i>Name</th>
                                    <th><i class="bi bi-router me-1"></i>IP Address</th>
                                    <th><i class="bi bi-macbook me-1"></i>MAC Address</th>
                                </tr>
                            </thead>
                            <tbody>`;
                data.forEach(i => {
                    html += `<tr>
                                <td><code>${i.name}</code></td>
                                <td><code>${i.ip || 'N/A'}</code></td>
                                <td><code>${i.mac || 'N/A'}</code></td>
                            </tr>`;
                });
                html += '</tbody></table></div>';
                showResult('interfacesResult', html);
            }
        })
        .catch(error => {
            hideLoading('interfacesBtn');
            showResult('interfacesResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>Error: ${error.message}</div>`, true);
        });
}

function getSystemStats() {
    showLoading('statsBtn');
    clearResult('statsResult');

    fetch('/api/system_stats')
        .then(response => response.json())
        .then(data => {
            hideLoading('statsBtn');
            if (data.error) {
                showResult('statsResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>${data.error}</div>`, true);
                document.getElementById('systemLoad').textContent = 'Error';
            } else {
                systemLoad = `${data.cpu_usage}% CPU`;
                document.getElementById('systemLoad').textContent = systemLoad;

                const result = `
                    <div class="alert alert-success">
                        <h6 class="alert-heading"><i class="bi bi-cpu me-2"></i>System Statistics</h6>
                        <hr>
                        <div class="row text-center">
                            <div class="col-sm-4">
                                <div class="border rounded p-2">
                                    <i class="bi bi-cpu text-warning" style="font-size: 1.5rem;"></i>
                                    <h5 class="text-warning">${data.cpu_usage}%</h5>
                                    <small class="text-muted">CPU Usage</small>
                                </div>
                            </div>
                            <div class="col-sm-4">
                                <div class="border rounded p-2">
                                    <i class="bi bi-arrow-up-circle text-success" style="font-size: 1.5rem;"></i>
                                    <h5 class="text-success">${(data.bytes_sent / 1024 / 1024).toFixed(2)} MB</h5>
                                    <small class="text-muted">Data Sent</small>
                                </div>
                            </div>
                            <div class="col-sm-4">
                                <div class="border rounded p-2">
                                    <i class="bi bi-arrow-down-circle text-info" style="font-size: 1.5rem;"></i>
                                    <h5 class="text-info">${(data.bytes_recv / 1024 / 1024).toFixed(2)} MB</h5>
                                    <small class="text-muted">Data Received</small>
                                </div>
                            </div>
                        </div>
                    </div>`;
                showResult('statsResult', result);
            }
        })
        .catch(error => {
            hideLoading('statsBtn');
            showResult('statsResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>Error: ${error.message}</div>`, true);
            document.getElementById('systemLoad').textContent = 'Error';
        });
}

function verifyResult() {
    const host = document.getElementById('verifyHost').value.trim();
    if (!host) {
        alert('Please enter a host IP address or hostname');
        return;
    }

    showLoading('verifyBtn');
    clearResult('verifyResult');

    fetch(`/api/verify/${encodeURIComponent(host)}`)
        .then(response => response.json())
        .then(data => {
            hideLoading('verifyBtn');
            const result = `
                <div class="alert alert-secondary">
                    <h6 class="alert-heading"><i class="bi bi-terminal me-2"></i>System Ping Output</h6>
                    <hr>
                    <pre class="bg-light p-2 rounded" style="font-size: 0.8rem; white-space: pre-wrap;">${data.output}</pre>
                </div>`;
            showResult('verifyResult', result);
        })
        .catch(error => {
            hideLoading('verifyBtn');
            showResult('verifyResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>Error: ${error.message}</div>`, true);
        });
}

function dnsLookup() {
    const domain = document.getElementById('dnsDomain').value;
    fetch(`/api/dns_lookup/${domain}`)
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                document.getElementById('dnsResult').innerHTML = `<p class="text-danger">${data.error}</p>`;
            } else {
                document.getElementById('dnsResult').innerHTML = `<p>IP Address: ${data.ip}</p>`;
            }
        });
}

function traceroute() {
    const host = document.getElementById('traceHost').value.trim();
    if (!host) {
        alert('Please enter a host IP address or hostname');
        return;
    }

    showLoading('traceBtn');
    clearResult('traceResult');

    fetch(`/api/traceroute/${encodeURIComponent(host)}`)
        .then(response => response.json())
        .then(data => {
            hideLoading('traceBtn');
            if (data.error) {
                showResult('traceResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>${data.error}</div>`, true);
            } else {
                let html = `
                    <div class="alert alert-dark"><i class="bi bi-diagram-3 me-2"></i>Traceroute to ${host} (${data.hops.length} hops)</div>
                    <div class="table-responsive">
                        <table class="table table-striped table-hover">
                            <thead class="table-dark">
                                <tr>
                                    <th><i class="bi bi-hash me-1"></i>Hop</th>
                                    <th><i class="bi bi-router me-1"></i>IP Address</th>
                                    <th><i class="bi bi-stopwatch me-1"></i>RTT (ms)</th>
                                </tr>
                            </thead>
                            <tbody>`;
                data.hops.forEach(h => {
                    html += `<tr>
                                <td>${h.ttl}</td>
                                <td><code>${h.ip}</code></td>
                                <td>${h.rtt}</td>
                            </tr>`;
                });
                html += '</tbody></table></div>';
                showResult('traceResult', html);
            }
        })
        .catch(error => {
            hideLoading('traceBtn');
            showResult('traceResult', `<div class="alert alert-danger"><i class="bi bi-exclamation-triangle me-2"></i>Error: ${error.message}</div>`, true);
        });
}

function getInterfaces() {
    fetch('/api/interfaces')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                document.getElementById('interfacesResult').innerHTML = `<p class="text-danger">${data.error}</p>`;
            } else {
                let html = '<table class="table table-striped"><thead><tr><th>Name</th><th>IP</th><th>MAC</th></tr></thead><tbody>';
                data.forEach(i => {
                    html += `<tr><td>${i.name}</td><td>${i.ip || 'N/A'}</td><td>${i.mac || 'N/A'}</td></tr>`;
                });
                html += '</tbody></table>';
                document.getElementById('interfacesResult').innerHTML = html;
            }
        });
}

function getSystemStats() {
    fetch('/api/system_stats')
        .then(response => response.json())
        .then(data => {
            if (data.error) {
                document.getElementById('statsResult').innerHTML = `<p class="text-danger">${data.error}</p>`;
            } else {
                document.getElementById('statsResult').innerHTML = `<p>CPU Usage: ${data.cpu_usage}%, Bytes Sent: ${data.bytes_sent}, Bytes Received: ${data.bytes_recv}</p>`;
            }
        });
}