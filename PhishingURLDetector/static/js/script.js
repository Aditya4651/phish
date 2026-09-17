// Phishing URL Detector Interactive Script

document.addEventListener('DOMContentLoaded', () => {
    const scanForm = document.getElementById('scanForm');
    const urlInput = document.getElementById('urlInput');

    if (scanForm && urlInput) {
        scanForm.addEventListener('submit', (e) => {
            const val = urlInput.value.trim();
            if (!val) {
                e.preventDefault();
                alert('Please enter a URL to analyze.');
                urlInput.focus();
            }
        });
    }
});
