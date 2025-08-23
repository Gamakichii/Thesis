// Prevent multiple script injections
if (window.phishingDetectorLoaded) {
    console.log("Content script already loaded, skipping...");
} else {
    window.phishingDetectorLoaded = true;
    console.log("Content script loading...");

    // Set to keep track of processed post IDs to avoid redundant scanning
    const processedPostIds = new Set();

    function extractPostContent(postElement) {
        let text = '';
        let links = [];

<<<<<<< Updated upstream
function extractPostContent(postElement) {
    let text = '';
    let links = [];

    const textElement = postElement.querySelector(
        '[data-testid="post_message"] span, ' +
        '._5pbx.userContent, ' +
        'div[data-ad-preview="message"]'
    );
    if (textElement) {
        text = textElement.textContent;
    }

    // Try to get links from common areas
    const linkElements = postElement.querySelectorAll('a[href]');
    linkElements.forEach(link => {
        const href = link.href;
        
        if (href && !href.includes('facebook.com') && !href.includes('fb.com')) {
            links.push(href);
=======
        const textElement = postElement.querySelector(
            '[data-testid="post_message"] span, ' +
            '._5pbx.userContent, ' +
            'div[data-ad-preview="message"]'
        );
        if (textElement) {
            text = textElement.textContent;
>>>>>>> Stashed changes
        }

<<<<<<< Updated upstream
    return { text, links };
}

// Function to blur a specific post element
function blurPost(postElement, postId) {
    // Check if the post is already blurred to avoid re-blurring
    if (postElement.dataset.phishingBlurred === 'true') {
        return;
    }

    // Create an overlay div
    const overlay = document.createElement('div');
    overlay.style.cssText = `
        position: absolute;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background-color: rgba(0, 0, 0, 0.8);
        color: white;
        display: flex;
        flex-direction: column;
        justify-content: center;
        align-items: center;
        text-align: center;
        z-index: 9999;
        border-radius: 0.5rem;
        font-family: 'Inter', sans-serif;
        padding: 1rem;
        box-sizing: border-box;
    `;
    overlay.innerHTML = `
        <p class="text-lg font-bold mb-2">⚠️ Potential Phishing Link Detected ⚠️</p>
        <p class="text-sm mb-4">This post may contain a malicious link. Proceed with caution.</p>
        <button class="unblur-button bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-4 rounded-full shadow-lg transition-all duration-200 ease-in-out">
            View Post Anyway
        </button>
    `;

    // Apply blur to the post content (excluding the overlay)
    postElement.style.filter = 'blur(8px)';
    postElement.style.pointerEvents = 'none'; // Disable interaction with blurred content

    // Append the overlay to the post element
    postElement.style.position = 'relative'; // Ensure overlay positions correctly
    postElement.appendChild(overlay);

    // Add event listener to the unblur button
    const unblurButton = overlay.querySelector('.unblur-button');
    unblurButton.addEventListener('click', (event) => {
        event.stopPropagation(); // Prevent click from propagating to the blurred element
        postElement.style.filter = 'none'; // Remove blur
        postElement.style.pointerEvents = 'auto'; // Re-enable interaction
        overlay.remove(); // Remove the overlay
        postElement.dataset.phishingBlurred = 'false'; // Mark as unblurred
    });

    postElement.dataset.phishingBlurred = 'true'; // Mark as blurred
    console.log(`Post ${postId} blurred.`);
}

function getFacebookPostElements() {

    const selectors = [
        'div[role="article"]', // Common for many posts
        'div[data-pagelet^="FeedUnit_"]', // Used for feed units
        'div[data-testid="KeyScrollableArea"] div[data-visualcompletion="loading-state"]', // For newer Facebook UI
        'div[data-ft="{&quot;tn&quot;:&quot;*s&quot;}"]', // Older post structure
        'div[aria-label="Post"]', // Another potential selector for posts
        'div.x1yztbdb.x1n2onr6.xh8yej3.x1ja2u2z' // A common class combination for post containers (highly unstable)
    ];
    let posts = [];
    selectors.forEach(selector => {
        document.querySelectorAll(selector).forEach(element => {
            // Ensure unique posts and avoid duplicates if multiple selectors match
            if (!posts.includes(element)) {
                posts.push(element);
            }
        });
    });
    return posts;
}

// Function to scan the current page for posts and send to background script
async function scanAndSendPosts() {
    console.log("Content script: Scanning for posts...");
    const posts = getFacebookPostElements();
    const newPostsData = [];

    posts.forEach((postElement, index) => {
        // Assign a unique ID to each post element for tracking
        const postId = postElement.dataset.phishingPostId || `post-${Date.now()}-${index}`;
        postElement.dataset.phishingPostId = postId;

        // Only process if not already processed
        if (!processedPostIds.has(postId)) {
            const content = extractPostContent(postElement);
            if (content.text || content.links.length > 0) {
                newPostsData.push({
                    id: postId,
                    text: content.text,
                    links: content.links,
                });
                processedPostIds.add(postId); // Mark as processed
            }
        }
    });

    if (newPostsData.length > 0) {
        console.log(`Content script: Found ${newPostsData.length} new posts. Sending to background.`);
        // Send new posts data to the background script for analysis
        chrome.runtime.sendMessage({
            action: "analyzePosts",
            posts: newPostsData
        });
    } else {
        console.log("Content script: No new relevant posts found on this page.");
    }
}

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "blurPost") {
        // Find the post element by its ID and blur it
        const postElement = document.querySelector(`[data-phishing-post-id="${request.postId}"]`);
        if (postElement) {
            blurPost(postElement, request.postId);
            sendResponse({ status: "blurred", postId: request.postId });
        } else {
            console.warn(`Content script: Could not find post with ID ${request.postId} to blur.`);
            sendResponse({ status: "not_found", postId: request.postId });
        }
        return true; // Indicate that sendResponse will be called asynchronously
    } else if (request.action === "scanPageFromBackground") {
        // Trigger scan when requested by background script (e.g., from popup)
        scanAndSendPosts();
        sendResponse({ status: "scan_initiated" });
        return true;
    }
});

// Initial scan when the content script loads (page is idle)
scanAndSendPosts();

const observer = new MutationObserver((mutations) => {
    mutations.forEach((mutation) => {
        if (mutation.addedNodes.length > 0) {
            // A small delay to ensure the content is fully rendered
            // and to avoid excessive scanning on rapid DOM changes
            setTimeout(scanAndSendPosts, 300); // Reduced delay
        }
    });
});

// Observe the document body for changes in its children (where new posts would appear)
observer.observe(document.body, { childList: true, subtree: true });

console.log("Content script loaded and observing.");
=======
        // Try to get links from common areas (anchor tags)
        const linkElements = postElement.querySelectorAll('a[href]');
        linkElements.forEach(link => {
            const href = link.href;
            
            if (href && !href.includes('facebook.com') && !href.includes('fb.com')) {
                links.push(href);
            }
        });

        // Also extract URLs present as plain text in captions
        try {
            const urlRegex = /(?:https?:\/\/|www\.)[^\s<>)"']+/gi;
            const candidates = (text || '').match(urlRegex) || [];
            candidates.forEach(u => {
                let href = u;
                if (href.startsWith('www.')) href = 'https://' + href;
                if (href && !href.includes('facebook.com') && !href.includes('fb.com')) {
                    links.push(href);
                }
            });
        } catch (_) {}

        return { text, links };
    }

    function linkLooksSuspicious(url) {
        try {
            const u = new URL(url);
            const host = (u.hostname || '').toLowerCase();
            const href = url.toLowerCase();
            const suspiciousTlds = ['.xyz','.top','.club','.online','.buzz','.site'];
            const shorteners = ['bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','is.gd','cutt.ly','lnkd.in','buff.ly'];
            if (href.startsWith('http://')) return true;
            if (shorteners.some(s => host === s)) return true;
            if (suspiciousTlds.some(t => host.endsWith(t))) return true;
            if (host.includes('login-') || host.includes('-verify') || host.includes('-update') || host.includes('-security') || host.includes('-account')) return true;
            return false;
        } catch (_) {
            return false;
        }
    }

    // Function to blur a specific post element
    function blurPost(postElement, postId) {
        if (postElement.dataset.phishingBlurred === 'true') return;
        if (!postElement) return;

        // Remove any existing controls first
        const existingControls = postElement.querySelectorAll('.post-nonblur-malicious, .post-unblur-controls');
        existingControls.forEach(control => control.remove());

        // Capture current children to apply blur only to them (not the overlay)
        let childrenToBlur = [];
        const contentWrapper = postElement.querySelector('[role="feed"], div[dir="auto"], div[data-ad-preview], div.x1lliihq');
        if (contentWrapper) {
            childrenToBlur = Array.from(contentWrapper.children);
        } else {
            childrenToBlur = Array.from(postElement.children);
        }

        // Create an overlay div
        const overlay = document.createElement('div');
        overlay.className = 'phishing-blur-overlay';
        overlay.style.cssText = `
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.8);
            color: white;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            z-index: 9999;
            border-radius: 0.5rem;
            font-family: system-ui, -apple-system, sans-serif;
            padding: 1rem;
            box-sizing: border-box;
            pointer-events: auto;
        `;
        overlay.innerHTML = `
            <p style="font-size: 18px; font-weight: bold; margin-bottom: 8px;">⚠️ Potential Phishing Link Detected ⚠️</p>
            <p style="font-size: 14px; margin-bottom: 16px;">This post may contain a malicious link. Proceed with caution.</p>
            <div style="display: flex; gap: 12px;">
                <button class="unblur-button" style="background: #dc2626; color: white; border: none; border-radius: 20px; padding: 8px 16px; font-size: 12px; cursor: pointer; box-shadow: 0 2px 6px rgba(0,0,0,0.2);">
                    View Post Anyway
                </button>
            </div>
        `;

        // Blur only the children, not the container (so the overlay isn't blurred)
        childrenToBlur.forEach((child) => {
            if (child !== overlay && !child.classList.contains('phishing-blur-overlay')) {
                child.style.filter = 'blur(8px)';
                child.style.pointerEvents = 'none';
            }
        });

        // Append the overlay to the post element
        postElement.style.position = postElement.style.position || 'relative';
        postElement.appendChild(overlay);

        // Add event listener to the unblur button
        const unblurButton = overlay.querySelector('.unblur-button');
        unblurButton.addEventListener('click', (event) => {
            event.stopPropagation();
            // Remove blur from children and re-enable interactions
            childrenToBlur.forEach((child) => {
                child.style.filter = '';
                child.style.pointerEvents = '';
            });
            overlay.remove();
            postElement.dataset.phishingBlurred = 'false';
            addPostUnblurControls(postElement, postId);
        });

        postElement.dataset.phishingBlurred = 'true';
        console.log(`Post ${postId} blurred due to phishing detection.`);
    }

    function addPostUnblurControls(postElement, postId) {
        // Remove existing controls if present
        const existing = postElement.querySelector('.post-unblur-controls');
        if (existing) existing.remove();

        const wrapper = document.createElement('div');
        wrapper.className = 'post-unblur-controls';
        wrapper.style.cssText = `
            position: absolute;
            top: 8px;
            right: 8px;
            z-index: 10000;
            display: flex;
            gap: 8px;
        `;

        const safeBtn = document.createElement('button');
        safeBtn.textContent = 'Mark as Safe';
        safeBtn.style.cssText = `
            background: #16a34a; color: #fff; border: none; border-radius: 16px;
            padding: 6px 10px; font-size: 12px; cursor: pointer; box-shadow: 0 2px 6px rgba(0,0,0,0.2);
        `;
        safeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            try {
                const encodedLinks = postElement.dataset.phishingLinks || '[]';
                const links = JSON.parse(encodedLinks);
                chrome.runtime.sendMessage({ action: 'reportFalsePositive', postId, links });
            } catch (_) {
                chrome.runtime.sendMessage({ action: 'reportFalsePositive', postId, links: [] });
            }
            wrapper.remove();
        });

        const malBtn = document.createElement('button');
        malBtn.textContent = 'Mark as Malicious';
        malBtn.style.cssText = `
            background: #dc2626; color: #fff; border: none; border-radius: 16px;
            padding: 6px 10px; font-size: 12px; cursor: pointer; box-shadow: 0 2px 6px rgba(0,0,0,0.2);
        `;
        malBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            try {
                const encodedLinks = postElement.dataset.phishingLinks || '[]';
                const links = JSON.parse(encodedLinks);
                chrome.runtime.sendMessage({ action: 'reportTruePositive', postId, links });
            } catch (_) {
                chrome.runtime.sendMessage({ action: 'reportTruePositive', postId, links: [] });
            }
            wrapper.remove();
            // Re-blur the post automatically
            blurPost(postElement, postId);
        });

        wrapper.appendChild(safeBtn);
        wrapper.appendChild(malBtn);
        postElement.style.position = postElement.style.position || 'relative';
        postElement.appendChild(wrapper);
    }

    function getFacebookPostElements() {
        const selectors = [
            'div[role="article"]', // Common for many posts
            'div[data-pagelet^="FeedUnit_"]', // Used for feed units
            'div[data-testid="KeyScrollableArea"] div[data-visualcompletion="loading-state"]', // For newer Facebook UI
            'div[data-ft="{&quot;tn&quot;:&quot;*s&quot;}"]', // Older post structure
            'div[aria-label="Post"]', // Another potential selector for posts
            'div.x1yztbdb.x1n2onr6.xh8yej3.x1ja2u2z' // A common class combination for post containers (highly unstable)
        ];
        let posts = [];
        selectors.forEach(selector => {
            document.querySelectorAll(selector).forEach(element => {
                // Ensure unique posts and avoid duplicates if multiple selectors match
                if (!posts.includes(element)) {
                    posts.push(element);
                }
            });
        });
        return posts;
    }

    // Function to scan the current page for posts and send to background script
    async function scanAndSendPosts() {
        console.log("Content script: Scanning for posts...");
        const posts = getFacebookPostElements();
        const newPostsData = [];

        posts.forEach((postElement, index) => {
            // Assign a unique ID to each post element for tracking
            const postId = postElement.dataset.phishingPostId || `post-${Date.now()}-${index}`;
            postElement.dataset.phishingPostId = postId;

            // Store links on the element for later reporting and controls
            const content = extractPostContent(postElement);
            postElement.dataset.phishingLinks = JSON.stringify(content.links || []);

            // Only process if not already processed
            if (!processedPostIds.has(postId)) {
                // Only analyze posts that contain external links
                if (content.links.length > 0) {
                    newPostsData.push({
                        id: postId,
                        text: content.text,
                        links: content.links,
                    });
                    processedPostIds.add(postId); // Mark as processed

                    // Graph ingestion: send minimal post + domains info to background
                    try {
                        const domains = Array.from(new Set((content.links || []).map(h => {
                            try { return new URL(h).hostname; } catch { return null; }
                        }).filter(Boolean)));
                        chrome.runtime.sendMessage({
                            action: 'graphIngestPost',
                            postId,
                            author: null,
                            ts: Date.now(),
                            domains,
                            counts: { reactions: null, comments: null, shares: null }
                        });
                    } catch (_) {}

                    // Add non-blur control so user can mark as malicious if we miss it
                    addNonBlurMaliciousControl(postElement, postId);
                }
            }
        });

        if (newPostsData.length > 0) {
            console.log(`Content script: Found ${newPostsData.length} new posts. Sending to background.`);
            // Send new posts data to the background script for analysis
            chrome.runtime.sendMessage({
                action: "analyzePosts",
                posts: newPostsData
            });
        } else {
            console.log("Content script: No new relevant posts found on this page.");
        }
    }

    // Listen for messages from the background script
    chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
        if (request.action === "blurPost") {
            // Find the post element by its ID and blur it
            const postElement = document.querySelector(`[data-phishing-post-id="${request.postId}"]`);
            if (postElement) {
                blurPost(postElement, request.postId);
                sendResponse({ status: "blurred", postId: request.postId });
            } else {
                console.warn(`Content script: Could not find post with ID ${request.postId} to blur.`);
                sendResponse({ status: "not_found", postId: request.postId });
            }
            return true;
        } else if (request.action === 'reblurPost') {
            const postElement = document.querySelector(`[data-phishing-post-id="${request.postId}"]`);
            if (postElement) {
                blurPost(postElement, request.postId);
                sendResponse({ status: 'reblurred', postId: request.postId });
            } else {
                sendResponse({ status: 'not_found', postId: request.postId });
            }
            return true;
        } else if (request.action === "scanPageFromBackground") {
            // Trigger scan when requested by background script (e.g., from popup)
            scanAndSendPosts();
            sendResponse({ status: "scan_initiated" });
            return true;
        }
    });

    // Initial scan when the content script loads
    scanAndSendPosts();

    // Also scan when DOM is ready and when the page becomes visible again
    document.addEventListener('DOMContentLoaded', () => {
        requestScanDebounced(200);
    });
    document.addEventListener('visibilitychange', () => {
        if (document.visibilityState === 'visible') requestScanDebounced(200);
    });

    let scanDebounceHandle = null;
    function requestScanDebounced(delay = 400) {
        if (scanDebounceHandle) clearTimeout(scanDebounceHandle);
        scanDebounceHandle = setTimeout(() => {
            scanDebounceHandle = null;
            scanAndSendPosts();
        }, delay);
    }

    const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            if (mutation.addedNodes && mutation.addedNodes.length > 0) {
                requestScanDebounced(500);
                break;
            }
        }
    });

    // Observe the document body for changes in its children (where new posts would appear)
    observer.observe(document.body, { childList: true, subtree: true });

    console.log("Content script loaded and observing.");

    // Global click listener to capture external link clicks for graph edges
    let graphClickListenerAdded = false;
    if (!graphClickListenerAdded) {
        graphClickListenerAdded = true;
        document.addEventListener('click', (e) => {
            const linkEl = e.target && (e.target.closest ? e.target.closest('a[href]') : null);
            if (!linkEl) return;
            const href = linkEl.getAttribute('href') || '';
            try {
                const absoluteUrl = new URL(href, location.href);
                const hostname = absoluteUrl.hostname || '';
                if (/facebook\.com|fb\.com/i.test(hostname)) return;
                const postContainer = linkEl.closest('[data-phishing-post-id]');
                const postId = postContainer ? postContainer.dataset.phishingPostId : null;
                chrome.runtime.sendMessage({
                    action: 'graphClick',
                    url: absoluteUrl.href,
                    domain: hostname,
                    postId
                });
            } catch (_) {}
        }, true);
    }

    function addNonBlurMaliciousControl(postElement, postId) {
        // If already blurred, skip
        if (postElement.dataset.phishingBlurred === 'true') return;
        // Avoid duplicates
        const existing = postElement.querySelector('.post-nonblur-malicious');
        if (existing) return;

        const btn = document.createElement('div');
        btn.className = 'post-nonblur-malicious';
        btn.style.cssText = `
            position: absolute; top: 8px; right: 8px; z-index: 10000; display: flex; gap: 8px;
        `;

        const mal = document.createElement('button');
        mal.textContent = 'Mark as Malicious';
        mal.style.cssText = `
            background: #dc2626; color: #fff; border: none; border-radius: 16px;
            padding: 6px 10px; font-size: 12px; cursor: pointer; box-shadow: 0 2px 6px rgba(0,0,0,0.2);
        `;
        mal.addEventListener('click', (e) => {
            e.stopPropagation();
            try {
                const encodedLinks = postElement.dataset.phishingLinks || '[]';
                const links = JSON.parse(encodedLinks);
                chrome.runtime.sendMessage({ action: 'reportFalseNegative', postId, links: (links && links[0]) ? links[0] : null, url: (links && links[0]) ? links[0] : null });
            } catch (_) {
                chrome.runtime.sendMessage({ action: 'reportFalseNegative', postId, url: null });
            }
            // Blur the post since user marked it malicious
            btn.remove();
            blurPost(postElement, postId);
        });

        const safe = document.createElement('button');
        safe.textContent = 'Mark as Safe';
        safe.style.cssText = `
            background: #16a34a; color: #fff; border: none; border-radius: 16px;
            padding: 6px 10px; font-size: 12px; cursor: pointer; box-shadow: 0 2px 6px rgba(0,0,0,0.2);
        `;
        safe.addEventListener('click', (e) => {
            e.stopPropagation();
            try {
                const encodedLinks = postElement.dataset.phishingLinks || '[]';
                const links = JSON.parse(encodedLinks);
                chrome.runtime.sendMessage({ action: 'reportTrueNegative', postId, links });
            } catch (_) {
                chrome.runtime.sendMessage({ action: 'reportTrueNegative', postId, links: [] });
            }
            btn.remove();
        });

        btn.appendChild(safe);
        btn.appendChild(mal);
        postElement.style.position = postElement.style.position || 'relative';
        postElement.appendChild(btn);
    }
}
>>>>>>> Stashed changes
