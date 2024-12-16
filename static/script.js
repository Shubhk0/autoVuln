document.getElementById('scanForm').addEventListener('submit', function(e) {
    e.preventDefault();
    
    const url = document.getElementById('url').value.trim();
    if (!url) {
        showError('Please enter a valid URL');
        return;
    }

    // Normalize URL
    const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;
    
    const checks = {
        xss: document.getElementById('checkXSS').checked,
        sql: document.getElementById('checkSQL').checked,
        ssl: document.getElementById('checkSSL').checked,
        headers: document.getElementById('checkHeaders').checked,
        csrf: document.getElementById('checkCSRF').checked,
        clickjacking: document.getElementById('checkClickjacking').checked
    };
    
    startScan(normalizedUrl, checks);
});

document.getElementById('quickScanBtn').addEventListener('click', function() {
    const url = document.getElementById('url').value.trim();
    if (!url) {
        showError('Please enter a URL first');
        return;
    }
    
    // Enable all checks for quick scan
    const checks = {
        'xss': true,
        'sql': true,
        'csrf': true,
        'headers': true,
        'ssl': true,
        'clickjacking': true
    };
    
    // Normalize URL
    const normalizedUrl = url.startsWith('http') ? url : `https://${url}`;
    
    // Update UI to show all checks are enabled
    Object.keys(checks).forEach(check => {
        const checkbox = document.getElementById(`check${check.toUpperCase()}`);
        if (checkbox) {
            checkbox.checked = true;
        }
    });
    
    // Start the scan
    startScan(normalizedUrl, checks);
});

function startScan(url, checks) {
    const statusDiv = document.getElementById('scanStatus');
    const resultsDiv = document.getElementById('results');
    
    statusDiv.classList.remove('d-none');
    resultsDiv.innerHTML = '';
    
    // Show loading state with progress bar
    statusDiv.innerHTML = `
        <div class="card bg-light">
            <div class="card-body">
                <h5 class="card-title">
                    <i class="fa fa-cog fa-spin"></i> Scan in Progress
                </h5>
                <div class="d-flex flex-column">
                    <div class="scan-stage mb-2">
                        <span id="currentStage">Initializing scan...</span>
                    </div>
                    <div class="progress" style="height: 20px;">
                        <div id="scanProgress" 
                             class="progress-bar progress-bar-striped progress-bar-animated" 
                             role="progressbar" 
                             style="width: 0%" 
                             aria-valuenow="0" 
                             aria-valuemin="0" 
                             aria-valuemax="100">0%</div>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    // Start the scan
    fetch('/scan', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            url: url,
            checks: checks
        })
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(data => {
        if (data.scan_id) {
            pollStatus(data.scan_id);
        } else {
            showError('Failed to start scan: No scan ID received');
        }
    })
    .catch(error => {
        showError(`Error starting scan: ${error.message}`);
    });
}

function pollStatus(scanId) {
    const statusCheck = setInterval(() => {
        fetch(`/status/${scanId}`)
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                if (!data) {
                    throw new Error('No data received from status check');
                }
                
                updateProgress(data);
                
                if (data.status === 'completed') {
                    clearInterval(statusCheck);
                    setTimeout(() => {
                        displayResults(data);
                        const statusDiv = document.getElementById('scanStatus');
                        if (statusDiv) {
                            statusDiv.classList.add('d-none');
                        }
                    }, 1000); // Small delay to show 100% completion
                } else if (data.status === 'error') {
                    clearInterval(statusCheck);
                    showError(data.error || 'An error occurred during the scan');
                    const statusDiv = document.getElementById('scanStatus');
                    if (statusDiv) {
                        statusDiv.classList.add('d-none');
                    }
                }
            })
            .catch(error => {
                clearInterval(statusCheck);
                showError(`Error checking scan status: ${error.message}`);
                const statusDiv = document.getElementById('scanStatus');
                if (statusDiv) {
                    statusDiv.classList.add('d-none');
                }
            });
    }, 1000);
}

function updateProgress(data) {
    const progressBar = document.getElementById('scanProgress');
    const currentStage = document.getElementById('currentStage');
    
    if (progressBar && currentStage) {
        progressBar.style.width = `${data.progress}%`;
        progressBar.setAttribute('aria-valuenow', data.progress);
        progressBar.textContent = `${Math.round(data.progress)}%`;
        
        currentStage.innerHTML = `
            <div class="d-flex justify-content-between align-items-center">
                <span><i class="fa fa-cog fa-spin me-2"></i>${data.current_stage || 'Processing...'}</span>
                <small class="text-muted">${data.current_module || ''}</small>
            </div>
            <div class="module-status">
                Completed modules: ${Array.from(data.modules_completed || []).join(', ') || 'None'}
            </div>
        `;
    }
}

function displayResults(data) {
    const resultsDiv = document.getElementById('results');
    
    if (!data.vulnerabilities || data.vulnerabilities.length === 0) {
        resultsDiv.innerHTML = `
            <div class="alert alert-success">
                <h4 class="alert-heading"><i class="fa fa-check-circle"></i> Scan Completed Successfully!</h4>
                <p>No vulnerabilities were found for ${escapeHtml(data.url)}</p>
                <hr>
                <p class="mb-0">All security checks were performed successfully.</p>
            </div>
        `;
        return;
    }

    // Group vulnerabilities by severity
    const grouped = {
        High: [],
        Medium: [],
        Low: []
    };
    
    data.vulnerabilities.forEach(vuln => {
        grouped[vuln.severity].push(vuln);
    });

    let html = `
        <div class="scan-summary">
            <h4><i class="fa fa-chart-bar"></i> Scan Summary</h4>
            <div class="scan-stats">
                <div class="stat-card">
                    <div class="text-danger">High Risk</div>
                    <div class="stat-value">${grouped.High.length}</div>
                </div>
                <div class="stat-card">
                    <div class="text-warning">Medium Risk</div>
                    <div class="stat-value">${grouped.Medium.length}</div>
                </div>
                <div class="stat-card">
                    <div class="text-info">Low Risk</div>
                    <div class="stat-value">${grouped.Low.length}</div>
                </div>
                <div class="stat-card">
                    <div class="text-secondary">Scan Duration</div>
                    <div class="stat-value">${data.stats.duration}s</div>
                </div>
            </div>
        </div>
        <h4><i class="fa fa-exclamation-triangle"></i> Vulnerabilities Found</h4>
    `;

    ['High', 'Medium', 'Low'].forEach(severity => {
        if (grouped[severity].length > 0) {
            grouped[severity].forEach(vuln => {
                const description = escapeHtml(vuln.description.split('\n')[0]);
                html += `
                    <div class="card vulnerability-card ${severity.toLowerCase()}">
                        <div class="card-body">
                            <h5 class="card-title">
                                ${severity === 'High' ? '<i class="fa fa-radiation text-danger"></i>' :
                                  severity === 'Medium' ? '<i class="fa fa-exclamation-triangle text-warning"></i>' :
                                  '<i class="fa fa-info-circle text-info"></i>'}
                                ${description}
                                <span class="vulnerability-badge badge-${severity.toLowerCase()}">${severity}</span>
                                <button class="btn btn-sm btn-outline-secondary copy-button" 
                                        onclick="copyToClipboard(this, '${encodeURIComponent(vuln.description)}')">
                                    <i class="fa fa-copy"></i> Copy
                                </button>
                            </h5>
                            <div class="vulnerability-details">${formatVulnerabilityDetails(vuln.description)}</div>
                            <div class="text-muted mt-2">
                                <small>Detected at: ${escapeHtml(vuln.timestamp)}</small>
                            </div>
                        </div>
                    </div>
                `;
            });
        }
    });

    resultsDiv.innerHTML = html;
}

function formatVulnerabilityDetails(description) {
    // Escape HTML characters
    const escapeHtml = (text) => {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    };

    return description.split('\n').map(line => {
        if (line.includes(':')) {
            const [key, ...value] = line.split(':');
            return `<strong>${escapeHtml(key)}:</strong>${escapeHtml(value.join(':'))}`;
        }
        return escapeHtml(line);
    }).join('\n');
}

function copyToClipboard(button, text) {
    const decoded = decodeURIComponent(text);
    navigator.clipboard.writeText(decoded).then(() => {
        const originalText = button.innerHTML;
        button.innerHTML = '<i class="fa fa-check"></i> Copied!';
        setTimeout(() => {
            button.innerHTML = originalText;
        }, 2000);
    });
}

function showError(message) {
    const resultsDiv = document.getElementById('results');
    resultsDiv.innerHTML = `
        <div class="alert alert-danger">
            <h4 class="alert-heading">Error</h4>
            <p>${message}</p>
        </div>
    `;
}

function initReportsTable() {
    const searchInput = document.getElementById('reportSearch');
    if (searchInput) {
        searchInput.addEventListener('keyup', function() {
            const searchTerm = this.value.toLowerCase();
            const rows = document.querySelectorAll('table tbody tr');
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchTerm) ? '' : 'none';
            });
        });
    }

    const sortButtons = document.querySelectorAll('.sort-btn');
    sortButtons.forEach(button => {
        button.addEventListener('click', function() {
            const column = this.dataset.column;
            const tbody = document.querySelector('table tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            
            rows.sort((a, b) => {
                const aValue = a.querySelector(`td[data-${column}]`).dataset[column];
                const bValue = b.querySelector(`td[data-${column}]`).dataset[column];
                return aValue.localeCompare(bValue);
            });
            
            if (this.dataset.order === 'asc') {
                rows.reverse();
                this.dataset.order = 'desc';
                this.innerHTML = `${this.textContent.split('▼')[0]} ▼`;
            } else {
                this.dataset.order = 'asc';
                this.innerHTML = `${this.textContent.split('▲')[0]} ▲`;
            }
            
            tbody.innerHTML = '';
            rows.forEach(row => tbody.appendChild(row));
        });
    });
}

document.addEventListener('DOMContentLoaded', initReportsTable); 