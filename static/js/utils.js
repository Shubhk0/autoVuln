// Show loading overlay
function showLoading(message = 'Loading...') {
    const overlay = document.getElementById('loadingOverlay');
    const loadingMessage = document.getElementById('loadingMessage');
    loadingMessage.textContent = message;
    overlay.style.display = 'flex';
}

// Hide loading overlay
function hideLoading() {
    const overlay = document.getElementById('loadingOverlay');
    overlay.style.display = 'none';
}

// Show toast notification
function showToast(title, message, type = 'info') {
    const toast = document.querySelector('.toast');
    const toastTitle = document.getElementById('toastTitle');
    const toastMessage = document.getElementById('toastMessage');
    
    toastTitle.textContent = title;
    toastMessage.textContent = message;
    
    // Set toast color based on type
    toast.className = `toast ${type}`;
    
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
}

// Initialize tooltips
document.addEventListener('DOMContentLoaded', function() {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});

// Smooth scroll to element
function scrollToElement(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        element.scrollIntoView({ behavior: 'smooth' });
    }
}

// Format date
function formatDate(dateString) {
    const options = { 
        year: 'numeric', 
        month: 'short', 
        day: 'numeric', 
        hour: '2-digit', 
        minute: '2-digit' 
    };
    return new Date(dateString).toLocaleDateString('en-US', options);
}

// Get CSRF token from meta tag
function getCsrfToken() {
    const metaTag = document.querySelector('meta[name="csrf-token"]');
    if (!metaTag) {
        console.error('CSRF meta tag not found');
        return null;
    }
    const token = metaTag.content;
    if (!token) {
        console.error('CSRF token is empty');
        return null;
    }
    return token;
}

// Add CSRF token to fetch headers
function addCsrfHeader(headers = {}) {
    const token = getCsrfToken();
    if (!token) {
        console.error('Could not get CSRF token');
        throw new Error('CSRF token not available');
    }
    return {
        ...headers,
        'X-CSRF-Token': token
    };
}

function showError(message, title = 'Error') {
    console.error(message);
    showToast(title, message, 'error');
    const errorAlert = document.createElement('div');
    errorAlert.className = 'alert alert-danger alert-dismissible fade show';
    errorAlert.innerHTML = `
        <i class="fa fa-exclamation-circle"></i> ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.querySelector('.container').insertBefore(errorAlert, document.querySelector('.card'));
}

function showSuccess(message, title = 'Success') {
    showToast(title, message, 'success');
}
  