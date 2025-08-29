// ScamShield AI - Frontend JavaScript

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    const tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Auto-dismiss alerts after 5 seconds
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(function(alert) {
        setTimeout(function() {
            const bsAlert = new bootstrap.Alert(alert);
            if (alert.classList.contains('show')) {
                bsAlert.close();
            }
        }, 5000);
    });

    // Form validation enhancements
    const forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });

    // URL validation for URL analysis form
    const urlInput = document.getElementById('input');
    if (urlInput && urlInput.type === 'url') {
        urlInput.addEventListener('input', function() {
            const url = this.value.trim();
            if (url && !url.startsWith('http://') && !url.startsWith('https://')) {
                this.setCustomValidity('URL must start with http:// or https://');
            } else {
                this.setCustomValidity('');
            }
        });
    }

    // Phone number formatting for phone verification
    const phoneInput = document.querySelector('input[type="tel"]');
    if (phoneInput) {
        phoneInput.addEventListener('input', function() {
            let value = this.value.replace(/\D/g, '');
            if (value.length >= 10) {
                // Format as (XXX) XXX-XXXX for US numbers
                if (value.length === 10) {
                    this.value = `(${value.slice(0,3)}) ${value.slice(3,6)}-${value.slice(6)}`;
                } else if (value.length === 11 && value.startsWith('1')) {
                    this.value = `+1 (${value.slice(1,4)}) ${value.slice(4,7)}-${value.slice(7,11)}`;
                }
            }
        });
    }

    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({
                    behavior: 'smooth'
                });
            }
        });
    });

    // Loading state management
    function setLoadingState(button, isLoading) {
        if (isLoading) {
            button.disabled = true;
            const originalText = button.innerHTML;
            button.setAttribute('data-original-text', originalText);
            
            if (button.id === 'analyzeBtn') {
                button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Analyzing...';
            } else if (button.id === 'verifyBtn') {
                button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Verifying...';
            } else if (button.id === 'scanBtn') {
                button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Scanning...';
            } else {
                button.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Processing...';
            }
        } else {
            button.disabled = false;
            const originalText = button.getAttribute('data-original-text');
            if (originalText) {
                button.innerHTML = originalText;
            }
        }
    }

    // Copy to clipboard functionality
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(function() {
            // Show success message
            const toast = document.createElement('div');
            toast.className = 'toast align-items-center text-white bg-success border-0 position-fixed bottom-0 end-0 m-3';
            toast.setAttribute('role', 'alert');
            toast.innerHTML = `
                <div class="d-flex">
                    <div class="toast-body">
                        <i class="fas fa-check me-2"></i>Copied to clipboard!
                    </div>
                    <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast"></button>
                </div>
            `;
            document.body.appendChild(toast);
            const bsToast = new bootstrap.Toast(toast);
            bsToast.show();
            
            // Remove toast after it's hidden
            toast.addEventListener('hidden.bs.toast', function() {
                document.body.removeChild(toast);
            });
        }).catch(function(err) {
            console.error('Failed to copy text: ', err);
        });
    }

    // Add copy buttons to code blocks
    document.querySelectorAll('code').forEach(function(codeBlock) {
        if (codeBlock.textContent.length > 20) {
            const copyBtn = document.createElement('button');
            copyBtn.className = 'btn btn-sm btn-outline-secondary ms-2';
            copyBtn.innerHTML = '<i class="fas fa-copy"></i>';
            copyBtn.title = 'Copy to clipboard';
            copyBtn.addEventListener('click', function() {
                if (window.ScamShield && window.ScamShield.copyToClipboard) {
                    window.ScamShield.copyToClipboard(codeBlock.textContent);
                } else {
                    copyToClipboard(codeBlock.textContent);
                }
            });
            codeBlock.parentNode.insertBefore(copyBtn, codeBlock.nextSibling);
        }
    });

    // Risk level color coding
    function updateRiskLevelColors() {
        const riskBadges = document.querySelectorAll('.badge');
        riskBadges.forEach(function(badge) {
            const text = badge.textContent.toLowerCase();
            if (text.includes('low')) {
                badge.classList.remove('bg-warning', 'bg-danger', 'bg-secondary');
                badge.classList.add('bg-success');
            } else if (text.includes('medium')) {
                badge.classList.remove('bg-success', 'bg-danger', 'bg-secondary');
                badge.classList.add('bg-warning');
            } else if (text.includes('high')) {
                badge.classList.remove('bg-success', 'bg-warning', 'bg-secondary');
                badge.classList.add('bg-danger');
            }
        });
    }

    // Call risk level coloring on page load
    updateRiskLevelColors();

    // Auto-refresh for logs (if on logs page)
    if (window.location.pathname.includes('/logs')) {
        setInterval(function() {
            fetch('/logs')
                .then(response => response.json())
                .then(data => {
                    // Update logs display if needed
                    console.log('Logs updated:', data);
                })
                .catch(error => console.error('Error fetching logs:', error));
        }, 30000); // Refresh every 30 seconds
    }

    // Service status check
    function checkServiceStatus() {
        fetch('/api/status')
            .then(response => response.json())
            .then(data => {
                console.log('Service status:', data);
                // Update UI indicators if needed
            })
            .catch(error => console.error('Error checking service status:', error));
    }

    // Check service status on page load
    checkServiceStatus();

    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd + Enter to submit forms
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            const activeForm = document.querySelector('form:focus-within');
            if (activeForm) {
                activeForm.requestSubmit();
            }
        }
        
        // Escape to clear forms
        if (e.key === 'Escape') {
            const activeInput = document.activeElement;
            if (activeInput && activeInput.tagName === 'INPUT') {
                activeInput.value = '';
            }
        }
    });

    // Performance monitoring
    window.addEventListener('load', function() {
        const loadTime = performance.now();
        console.log(`Page loaded in ${loadTime.toFixed(2)}ms`);
    });
});

// Utility functions
function formatTimestamp(timestamp) {
    const date = new Date(timestamp);
    return date.toLocaleString();
}

function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validateUrl(url) {
    try {
        new URL(url);
        return true;
    } catch {
        return false;
    }
}

// Export functions for global use
window.ScamShield = {
    copyToClipboard,
    formatTimestamp,
    sanitizeInput,
    validateEmail,
    validateUrl,
    checkServiceStatus
};
