

// Set to keep track of processed post IDs to avoid redundant scanning
const processedPostIds = new Set();

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
        }
    });

    return { text, links };
}

// Function to blur a specific post element
function blurPost(postElement, postId) {
    if (postElement.dataset.phishingBlurred === 'true') {
        return;
    }

    // Capture current children to apply blur only to them (not the overlay)
    const childrenToBlur = Array.from(postElement.children);

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
        pointer-events: auto;
    `;
    overlay.innerHTML = `
        <p class="text-lg font-bold mb-2">⚠️ Potential Phishing Link Detected ⚠️</p>
        <p class="text-sm mb-4">This post may contain a malicious link. Proceed with caution.</p>
        <div class="flex gap-3">
            <button class="unblur-button bg-red-500 hover:bg-red-700 text-white font-semibold py-2 px-4 rounded-full shadow-lg transition-all duration-200 ease-in-out">
                View Post Anyway
            </button>
            <button class="report-safe-button bg-gray-600 hover:bg-gray-700 text-white font-semibold py-2 px-4 rounded-full shadow-lg transition-all duration-200 ease-in-out">
                Report as Safe
            </button>
        </div>
    `;

    // Blur only the children, not the container (so the overlay isn't blurred)
    childrenToBlur.forEach((child) => {
        if (child !== overlay) {
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
        addReblurButton(postElement, postId);
    });

    // Add event listener to the report-as-safe (false positive) button
    const reportSafeButton = overlay.querySelector('.report-safe-button');
    reportSafeButton.addEventListener('click', (event) => {
        event.stopPropagation();
        try {
            const encodedLinks = postElement.dataset.phishingLinks || '[]';
            const links = JSON.parse(encodedLinks);
            chrome.runtime.sendMessage({
                action: 'reportFalsePositive',
                postId,
                links
            });
        } catch (_) {
            chrome.runtime.sendMessage({ action: 'reportFalsePositive', postId, links: [] });
        }
    });

    postElement.dataset.phishingBlurred = 'true';
    console.log(`Post ${postId} blurred.`);
}

function addReblurButton(postElement, postId) {
    // Remove existing reblur button if present
    const existingBtn = postElement.querySelector('.reblur-button');
    if (existingBtn) existingBtn.remove();

    const btn = document.createElement('button');
    btn.className = 'reblur-button';
    btn.textContent = 'Re-blur';
    btn.style.cssText = `
        position: absolute;
        top: 8px;
        right: 8px;
        z-index: 10000;
        background: rgba(66, 103, 178, 0.95);
        color: #fff;
        border: none;
        border-radius: 16px;
        padding: 6px 10px;
        font-size: 12px;
        cursor: pointer;
    `;
    btn.addEventListener('click', (e) => {
        e.stopPropagation();
        // Remove button before re-blur to avoid double overlays
        btn.remove();
        blurPost(postElement, postId);
    });
    postElement.style.position = postElement.style.position || 'relative';
    postElement.appendChild(btn);
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
