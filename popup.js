// Get references to DOM elements
const scanButton = document.getElementById('scanButton');
const viewFlaggedButton = document.getElementById('viewFlaggedButton');
const statusDiv = document.getElementById('status');
const userIdDisplay = document.getElementById('userIdDisplay');

// Function to update the status message in the popup
function updateStatus(message, type = 'info') {
    statusDiv.textContent = message;
    statusDiv.className = `status-message status-${type}`;
}

// Function to safely update HTML content (for flagged links list)
function updateStatusHTML(htmlContent, type = 'info') {
    statusDiv.innerHTML = htmlContent;
    statusDiv.className = `status-message status-${type}`;
}

// Check if current tab is a Facebook page
async function checkFacebookPage() {
    try {
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (tab && tab.url) {
            const isFacebookPage = /^https?:\/\/([a-z0-9-]+\.)*facebook\.com\//i.test(tab.url);
            if (!isFacebookPage) {
                updateStatus('Please navigate to a Facebook page to use this extension', 'error');
                scanButton.disabled = true;
                return false;
            } else {
                updateStatus('Ready to scan Facebook page for phishing links', 'info');
                scanButton.disabled = false;
                return true;
            }
        }
    } catch (error) {
        console.error('Error checking current tab:', error);
        updateStatus('Could not determine current page', 'error');
        return false;
    }
}

// Request user ID from background script when popup opens
document.addEventListener('DOMContentLoaded', async () => {
    // Check if we're on Facebook first
    await checkFacebookPage();
    
    // Get user ID
    chrome.runtime.sendMessage({ action: "getUserId" }, (response) => {
        if (chrome.runtime.lastError) {
            console.error('Error getting user ID:', chrome.runtime.lastError);
            userIdDisplay.textContent = "Error";
            return;
        }
        
        if (response && response.userId) {
            userIdDisplay.textContent = response.userId;
        } else {
            userIdDisplay.textContent = "N/A";
        }
    });
});

// Event listener for the "Scan Current Page" button
scanButton.addEventListener('click', () => {
    // Disable button to prevent multiple clicks
    scanButton.disabled = true;
    const originalText = scanButton.textContent;
    scanButton.textContent = 'Scanning...';
    
    updateStatus('Scanning page for phishing links...', 'info');
    
    // Send a message to the background script to initiate scanning
    chrome.runtime.sendMessage({ action: "scanPage" }, (response) => {
        // Re-enable button
        scanButton.disabled = false;
        scanButton.textContent = originalText;
        
        if (chrome.runtime.lastError) {
            console.error('Error during scan:', chrome.runtime.lastError);
            updateStatus('Error communicating with extension', 'error');
            return;
        }
        
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
    // Disable button during request
    viewFlaggedButton.disabled = true;
    const originalText = viewFlaggedButton.textContent;
    viewFlaggedButton.textContent = 'Loading...';
    
    updateStatus('Fetching flagged links...', 'info');
    
    // Send a message to the background script to fetch flagged links from Firestore
    chrome.runtime.sendMessage({ action: "getFlaggedLinks" }, (response) => {
        // Re-enable button
        viewFlaggedButton.disabled = false;
        viewFlaggedButton.textContent = originalText;
        
        if (chrome.runtime.lastError) {
            console.error('Error fetching flagged links:', chrome.runtime.lastError);
            updateStatus('Error communicating with extension', 'error');
            return;
        }
        
        if (response && response.links && response.links.length > 0) {
            const linkList = response.links.map(link => {
                const url = link.url || 'Unknown URL';
                const userId = link.userId || 'Unknown';
                const timestamp = link.timestamp ? new Date(link.timestamp.toDate()).toLocaleString() : 'Unknown time';
                return `<li style="margin-bottom: 8px; padding: 4px; background: #f8f9fa; border-radius: 4px;">
                    <strong>URL:</strong> ${url}<br>
                    <small>Flagged by: ${userId}<br>Time: ${timestamp}</small>
                </li>`;
            }).join('');
            updateStatusHTML(`<div><strong>Flagged Links (${response.links.length}):</strong><ul style="text-align: left; margin-top: 8px; padding-left: 0; list-style: none;">${linkList}</ul></div>`, 'info');
        } else if (response && response.status === 'error') {
            updateStatus(`Error fetching flagged links: ${response.message || 'Unknown error'}`, 'error');
        } else {
            updateStatus('No phishing links flagged yet.', 'info');
        }
    });
});
<<<<<<< Updated upstream
=======

// Event listener for reporting a false negative
if (reportFnButton && fnUrlInput) {
    reportFnButton.addEventListener('click', () => {
        const url = fnUrlInput.value.trim();
        
        if (!url) {
            updateStatus('Please paste a URL to report.', 'error');
            fnUrlInput.focus();
            return;
        }
        
        // Basic URL validation
        try {
            new URL(url);
        } catch (e) {
            updateStatus('Please enter a valid URL (include http:// or https://)', 'error');
            fnUrlInput.focus();
            return;
        }
        
        // Disable button during request
        reportFnButton.disabled = true;
        const originalText = reportFnButton.textContent;
        reportFnButton.textContent = 'Reporting...';
        
        updateStatus('Reporting missed phishing link...', 'info');
        
        chrome.runtime.sendMessage({ action: 'reportFalseNegative', url, postId: null }, (response) => {
            // Re-enable button
            reportFnButton.disabled = false;
            reportFnButton.textContent = originalText;
            
            if (chrome.runtime.lastError) {
                console.error('Error reporting false negative:', chrome.runtime.lastError);
                updateStatus('Error communicating with extension', 'error');
                return;
            }
            
            if (response && response.status === 'reported') {
                updateStatus('Thank you. We recorded your report and flagged this link.', 'success');
                fnUrlInput.value = ''; // Clear the input
            } else {
                const msg = response && response.message ? response.message : 'Unknown error occurred';
                updateStatus(`Error reporting: ${msg}`, 'error');
            }
        });
    });
    
    // Allow Enter key to submit false negative report
    fnUrlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            reportFnButton.click();
        }
    });
    
    // Clear error status when user starts typing
    fnUrlInput.addEventListener('input', () => {
        if (statusDiv.classList.contains('status-error') && statusDiv.textContent.includes('URL')) {
            updateStatus('Ready to scan Facebook page for phishing links', 'info');
        }
    });
}

// Add some visual feedback for better UX
document.addEventListener('DOMContentLoaded', () => {
    // Add hover effects via JavaScript if needed
    const buttons = document.querySelectorAll('.button');
    buttons.forEach(button => {
        button.addEventListener('mouseenter', () => {
            if (!button.disabled) {
                button.style.transform = 'translateY(-1px)';
                button.style.boxShadow = '0 4px 8px rgba(0,0,0,0.1)';
            }
        });
        
        button.addEventListener('mouseleave', () => {
            button.style.transform = '';
            button.style.boxShadow = '';
        });
    });
});
>>>>>>> Stashed changes
