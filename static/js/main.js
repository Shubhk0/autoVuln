// Main JavaScript functionality for the vulnerability scanner

document.addEventListener('DOMContentLoaded', function() {
    console.log('DOM loaded, initializing scanner...');
    
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Form submission handler
    const scanForm = document.getElementById('scanForm');
    if (scanForm) {
        console.log('Found scan form, attaching submit handler');
        scanForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            await startScan();
        });
    }

    // Quick scan button handler
    const quickScanBtn = document.getElementById('quickScanBtn');
    if (quickScanBtn) {
        quickScanBtn.addEventListener('click', async function() {
            const url = document.getElementById('url').value;
            if (!url) {
                showError('Please enter a URL first');
                return;
            }
            
            // Check all checkboxes
            document.querySelectorAll('input[name="checks"]').forEach(cb => cb.checked = true);
            
            // Start the scan
            await startScan();
        });
    }
});

// Get CSRF token
function getCsrfToken() {
    const token = document.querySelector('meta[name="csrf-token"]');
    return token ? token.getAttribute('content') : '';
}

// Get selected vulnerability checks
function getSelectedChecks() {
    return Array.from(document.querySelectorAll('input[name="checks"]:checked')).map(cb => cb.value);
}

// Show error message
function showError(message) {
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-danger alert-dismissible fade show';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    document.querySelector('.container').insertBefore(alertDiv, document.querySelector('.container').firstChild);
}

// Show success message
function showSuccess(message) {
    const alertDiv = document.createElement('div');
    alertDiv.className = 'alert alert-success alert-dismissible fade show';
    alertDiv.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;
    document.querySelector('.container').insertBefore(alertDiv, document.querySelector('.container').firstChild);
}

// Show scan progress
function showScanProgress() {
    const progressBox = document.getElementById('scanProgressBox');
    if (progressBox) {
        progressBox.style.display = 'block';
    }
}

// Hide scan progress
function hideScanProgress() {
    const progressBox = document.getElementById('scanProgressBox');
    if (progressBox) {
        progressBox.style.display = 'none';
    }
}

// Update progress bar
function updateProgress(progress) {
    const progressBar = document.getElementById('scanProgress');
    const statusText = document.getElementById('scanStatus');
    
    if (progressBar && statusText) {
        progressBar.style.width = `${progress}%`;
        progressBar.setAttribute('aria-valuenow', progress);
        progressBar.textContent = `${progress}%`;
        
        if (progress === 100) {
            statusText.textContent = 'Scan completed!';
            setTimeout(hideScanProgress, 2000);
        } else {
            statusText.textContent = `Scanning... ${progress}%`;
        }
    }
}

// Start a new scan
async function startScan() {
    const url = document.getElementById('url').value;
    const checks = getSelectedChecks();
    
    if (!url) {
        showError('Please enter a URL to scan');
        return;
    }
    
    if (checks.length === 0) {
        showError('Please select at least one vulnerability check');
        return;
    }
    
    try {
        showScanProgress();
        updateProgress(0);
        
        const response = await fetch('/start_scan', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': getCsrfToken()
            },
            body: JSON.stringify({ url, checks })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to start scan');
        }
        
        // Start polling for scan status
        pollScanStatus(data.scan_id);
        
    } catch (error) {
        showError('Error starting scan: ' + error.message);
        hideScanProgress();
    }
}

// Poll for scan status
async function pollScanStatus(scanId) {
    try {
        const response = await fetch(`/scan/${scanId}/status`);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error('Error checking scan status');
        }
        
        updateProgress(data.progress || 0);
        
        if (data.status === 'completed') {
            showSuccess('Scan completed successfully!');
            setTimeout(() => {
                window.location.reload();
            }, 2000);
        } else if (data.status === 'error') {
            showError('Scan failed: ' + (data.error || 'Unknown error'));
            hideScanProgress();
        } else {
            // Continue polling
            setTimeout(() => pollScanStatus(scanId), 1000);
        }
    } catch (error) {
        showError('Error checking scan status: ' + error.message);
        hideScanProgress();
    }
}

// View scan details
async function viewScanDetails(scanId) {
    try {
        const response = await fetch(`/scan/${scanId}/details`);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to fetch scan details');
        }
        
        // Update modal content
        document.getElementById('detailTargetUrl').textContent = data.url;
        document.getElementById('detailStatus').textContent = data.status;
        document.getElementById('detailStartTime').textContent = new Date(data.start_time).toLocaleString();
        document.getElementById('detailEndTime').textContent = data.end_time ? new Date(data.end_time).toLocaleString() : 'N/A';
        
        // Update vulnerabilities list
        const vulnList = document.getElementById('vulnerabilitiesList');
        vulnList.innerHTML = '';
        
        if (data.results && data.results.length > 0) {
            data.results.forEach((vuln, index) => {
                // Create reproduction steps HTML if available
                let reproductionStepsHtml = '';
                if (vuln.reproduction_steps && vuln.reproduction_steps.length > 0) {
                    reproductionStepsHtml = `
                        <div class="mt-3">
                            <h6>How to Reproduce:</h6>
                            <ol class="list-group list-group-numbered">
                                ${vuln.reproduction_steps.map(step => 
                                    `<li class="list-group-item">${escapeHtml(step)}</li>`
                                ).join('')}
                            </ol>
                        </div>
                    `;
                }
                
                const vulnHtml = `
                    <div class="accordion-item">
                        <h2 class="accordion-header" id="heading${index}">
                            <button class="accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse${index}">
                                <span class="badge ${getSeverityClass(vuln.severity)} me-2">${vuln.severity}</span>
                                ${escapeHtml(vuln.vulnerability_type)}
                            </button>
                        </h2>
                        <div id="collapse${index}" class="accordion-collapse collapse" data-bs-parent="#vulnerabilitiesList">
                            <div class="accordion-body">
                                <p><strong>Description:</strong> ${escapeHtml(vuln.description)}</p>
                                
                                ${vuln.evidence ? `
                                <div class="mt-3">
                                    <h6>Evidence:</h6>
                                    <pre class="bg-light p-2"><code>${escapeHtml(JSON.stringify(vuln.evidence, null, 2))}</code></pre>
                                </div>` : ''}
                                
                                ${reproductionStepsHtml}
                                
                                <div class="text-muted small mt-3">
                                    Found at: ${new Date(vuln.timestamp).toLocaleString()}
                                </div>
                            </div>
                        </div>
                    </div>
                `;
                vulnList.innerHTML += vulnHtml;
            });
        } else {
            vulnList.innerHTML = '<p class="text-muted">No vulnerabilities found.</p>';
        }
        
        // Show the modal
        const modal = new bootstrap.Modal(document.getElementById('scanDetailsModal'));
        modal.show();
        
    } catch (error) {
        showError('Error loading scan details: ' + error.message);
    }
}

function getSeverityClass(severity) {
    switch (severity.toLowerCase()) {
        case 'critical':
            return 'bg-danger';
        case 'high':
            return 'bg-warning text-dark';
        case 'medium':
            return 'bg-info text-dark';
        case 'low':
            return 'bg-success';
        default:
            return 'bg-secondary';
    }
}

function escapeHtml(unsafe) {
    return unsafe
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

// Download scan report
async function downloadReport() {
    if (!currentScanId) {
        showError('No scan selected');
        return;
    }
    
    try {
        const response = await fetch(`/scan/${currentScanId}/report`);
        
        if (!response.ok) {
            throw new Error('Failed to download report');
        }
        
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `scan_report_${currentScanId}.pdf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        a.remove();
        
    } catch (error) {
        showError('Error downloading report: ' + error.message);
    }
}

// Global variable for status polling
let statusPollInterval = null;

// Get CSRF token from hidden input
function getCsrfToken() {
    return document.querySelector('input[name="csrf_token"]').value;
}

// Get all available checks
function getAllChecks() {
    return ['xss', 'sql', 'ssl', 'headers', 'csrf', 'clickjacking'];
}

// Load reports on page load
async function loadReports() {
    const container = document.getElementById('reportsContainer');
    if (!container) return;
    
    try {
        const response = await fetch('/reports', {
            headers: {
                'X-Requested-With': 'XMLHttpRequest',
                'X-CSRFToken': getCsrfToken()
            }
        });
        
        if (!response.ok) {
            throw new Error('Failed to load reports');
        }
        
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'Failed to load reports');
        }
        
        // Clear loading spinner
        container.innerHTML = '';
        
        if (data.reports.length === 0) {
            container.innerHTML = '<div class="text-center text-muted">No scan reports found</div>';
            return;
        }
        
        // Get templates
        const reportTemplate = document.getElementById('reportTemplate');
        const vulnTemplate = document.getElementById('vulnerabilityTemplate');
        
        // Render each report
        data.reports.forEach(report => {
            const reportElement = reportTemplate.content.cloneNode(true);
            const reportCard = reportElement.querySelector('.report-card');
            
            reportCard.dataset.reportId = report.id;
            reportCard.querySelector('.report-url').textContent = report.url;
            reportCard.querySelector('.report-start-time').textContent = report.start_time || 'N/A';
            
            // Add status badge
            const statusBadge = reportCard.querySelector('.report-status-badge');
            statusBadge.className = `badge ${getStatusBadgeClass(report.status)}`;
            statusBadge.textContent = report.status;
            
            // Add error message if present
            if (report.error) {
                reportCard.querySelector('.report-error').textContent = report.error;
            }
            
            // Add vulnerabilities
            const vulnContainer = reportCard.querySelector('.vulnerabilities-container');
            report.vulnerabilities.forEach(vuln => {
                const vulnElement = vulnTemplate.content.cloneNode(true);
                
                vulnElement.querySelector('.vulnerability-type').textContent = vuln.type;
                vulnElement.querySelector('.vulnerability-severity').textContent = vuln.severity;
                vulnElement.querySelector('.vulnerability-severity').className += ` bg-${getSeverityClass(vuln.severity)}`;
                vulnElement.querySelector('.vulnerability-description').textContent = vuln.description;
                
                if (vuln.evidence) {
                    vulnElement.querySelector('code').textContent = JSON.stringify(vuln.evidence, null, 2);
                }
                
                vulnContainer.appendChild(vulnElement);
            });
            
            container.appendChild(reportElement);
        });
        
    } catch (error) {
        console.error('Error loading reports:', error);
        container.innerHTML = `
            <div class="alert alert-danger" role="alert">
                <i class="bi bi-exclamation-triangle-fill"></i> Failed to load reports: ${error.message}
            </div>
        `;
    }
}

// Get appropriate badge class for scan status
function getStatusBadgeClass(status) {
    switch (status.toLowerCase()) {
        case 'completed':
            return 'bg-success';
        case 'in_progress':
            return 'bg-primary';
        case 'failed':
            return 'bg-danger';
        default:
            return 'bg-secondary';
    }
}

// Get appropriate badge class for vulnerability severity
function getSeverityClass(severity) {
    switch (severity.toLowerCase()) {
        case 'critical':
            return 'danger';
        case 'high':
            return 'warning text-dark';
        case 'medium':
            return 'info text-dark';
        case 'low':
            return 'success';
        default:
            return 'secondary';
    }
}

// Toggle vulnerability evidence
function toggleEvidence(button) {
    const vulnItem = button.closest('.vulnerability-item');
    const evidence = vulnItem.querySelector('.vulnerability-evidence');
    
    if (evidence.classList.contains('d-none')) {
        evidence.classList.remove('d-none');
        button.textContent = 'Hide Details';
    } else {
        evidence.classList.add('d-none');
        button.textContent = 'Show Details';
    }
}

// Export scan results
document.querySelectorAll('.export-csv, .export-pdf').forEach(button => {
    button.addEventListener('click', function() {
        const scanId = this.dataset.scanId;
        const format = this.classList.contains('export-csv') ? 'csv' : 'pdf';
        window.location.href = `/reports/${scanId}/export/${format}`;
    });
});

// View scan results
document.querySelectorAll('.view-results').forEach(button => {
    button.addEventListener('click', async function() {
        const scanId = this.dataset.scanId;
        
        try {
            const response = await fetch(`/reports/${scanId}`);
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.error || 'Failed to load scan results');
            }
            
            // Display results in modal
            const vulnerabilitiesList = document.getElementById('vulnerabilitiesList');
            vulnerabilitiesList.innerHTML = '';
            
            if (data.vulnerabilities && data.vulnerabilities.length > 0) {
                data.vulnerabilities.forEach(vuln => {
                    const card = document.createElement('div');
                    card.className = 'card mb-3';
                    card.innerHTML = `
                        <div class="card-body">
                            <h6 class="card-title d-flex justify-content-between align-items-center">
                                <span>${vuln.type}</span>
                                <span class="badge bg-${getSeverityClass(vuln.severity)}">${vuln.severity}</span>
                            </h6>
                            <p class="card-text">${vuln.description}</p>
                            ${vuln.evidence ? `
                                <div class="mt-2">
                                    <small class="text-muted">Evidence:</small>
                                    <pre class="mt-1 bg-light p-2 rounded"><code>${JSON.stringify(vuln.evidence, null, 2)}</code></pre>
                                </div>
                            ` : ''}
                        </div>
                    `;
                    vulnerabilitiesList.appendChild(card);
                });
            } else {
                vulnerabilitiesList.innerHTML = '<div class="alert alert-info">No vulnerabilities found.</div>';
            }
            
            // Show the modal
            new bootstrap.Modal(document.getElementById('resultsModal')).show();
            
        } catch (error) {
            showError('Error loading scan results: ' + error.message);
        }
    });
});
