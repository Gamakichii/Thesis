// Get references to DOM elements
const scanButton = document.getElementById('scanButton');
const viewFlaggedButton = document.getElementById('viewFlaggedButton');
const statusDiv = document.getElementById('status');
const reportFnButton = document.getElementById('reportFnButton');
const fnUrlInput = document.getElementById('fnUrl');
const userIdDisplay = document.getElementById('userIdDisplay');

// Function to update the status message in the popup
function updateStatus(message, type = 'info') {
    statusDiv.textContent = message;
    statusDiv.className = `status-message status-${type}`;
}

// Request user ID from background script when popup opens
document.addEventListener('DOMContentLoaded', () => {
    chrome.runtime.sendMessage({ action: "getUserId" }, (response) => {
        if (response && response.userId) {
            userIdDisplay.textContent = response.userId;
        } else {
            userIdDisplay.textContent = "N/A";
        }
    });
});

// Event listener for the "Scan Current Page" button
scanButton.addEventListener('click', () => {
    updateStatus('Scanning page for phishing links...', 'info');
    // Send a message to the background script to initiate scanning
    chrome.runtime.sendMessage({ action: "scanPage" }, (response) => {
        if (response && response.status === 'success') {
            updateStatus(response.message, 'success');
        } else if (response && response.status === 'error') {
            updateStatus(response.message, 'error');
        } else {
            updateStatus('Scan request sent. Check console for details.', 'info');
        }
    });
});

// Event listener for the "View Flagged Links" button
viewFlaggedButton.addEventListener('click', () => {
    updateStatus('Fetching flagged links...', 'info');
    // Send a message to the background script to fetch flagged links from Firestore
    chrome.runtime.sendMessage({ action: "getFlaggedLinks" }, (response) => {
        if (response && response.links && response.links.length > 0) {
            const linkList = response.links.map(link => `<li>${link.url} (Flagged by: ${link.userId})</li>`).join('');
            updateStatus(`Flagged Links:<ul class="text-left mt-2">${linkList}</ul>`, 'info');
        } else if (response && response.status === 'error') {
            updateStatus(`Error fetching flagged links: ${response.message}`, 'error');
        } else {
            updateStatus('No phishing links flagged yet.', 'info');
        }
    });
});

// Event listener for reporting a false negative
if (reportFnButton) {
    reportFnButton.addEventListener('click', () => {
        const url = (fnUrlInput && fnUrlInput.value || '').trim();
        if (!url) {
            updateStatus('Please paste a URL to report.', 'error');
            return;
        }
        updateStatus('Reporting missed phishing link...', 'info');
        chrome.runtime.sendMessage({ action: 'reportFalseNegative', url }, (response) => {
            if (response && response.status === 'reported') {
                updateStatus('Thank you. We recorded your report.', 'success');
                fnUrlInput.value = '';
            } else {
                const msg = response && response.message ? response.message : 'Unknown error';
                updateStatus(`Error reporting: ${msg}`, 'error');
            }
        });
    });
}
