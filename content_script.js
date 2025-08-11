// ==============================================================================
//
//  Facebook Phishing Detector - Content Script
//  - Scans the DOM for posts.
//  - Injects UI elements (blur overlays, report buttons).
//  - Communicates with the background script.
//
// ==============================================================================

// A Set to keep track of posts that have already been processed to avoid redundant API calls.
const processedPostIds = new Set();

/**
 * Extracts text and all unique, valid external links from a Facebook post element.
 * @param {HTMLElement} postElement - The DOM element of the Facebook post.
 * @returns {{text: string, links: string[]}} - An object containing the post's text and an array of unique external links.
 */
function extractPostContent(postElement) {
    let text = '';
    const links = new Set(); // Use a Set to automatically handle duplicate links

    // More robust selectors for post text
    const textElement = postElement.querySelector('[data-ad-preview="message"], div[data-ad-id], div[data-testid="post_message"]');
    if (textElement) {
        text = textElement.textContent || '';
    }

    // Find all anchor tags within the post
    const linkElements = postElement.querySelectorAll('a[href]');
    linkElements.forEach(link => {
        const href = link.href;
        // CRITICAL: Filter out internal Facebook links, javascript links, and other non-http links.
        if (href && href.startsWith('http') && !href.includes('facebook.com') && !href.includes('fb.me')) {
            links.add(href);
        }
    });

    return { text, links: [...links] }; // Convert Set back to an array
}

/**
 * Sends a report message to the background script.
 * @param {string} url - The URL being reported.
 *_ @param {'false_positive' | 'false_negative'} reportType - The type of report.
 */
function reportLink(url, reportType, buttonElement) {
    console.log(`Reporting ${reportType}: ${url}`);
    chrome.runtime.sendMessage({
        action: "reportLink",
        url: url,
        type: reportType
    });
    // Provide visual feedback to the user on the button
    buttonElement.textContent = "✔️ Reported";
    buttonElement.style.backgroundColor = "#27ae60"; // Green color for success
    buttonElement.disabled = true;
}

/**
 * Creates and injects the blur overlay with report buttons onto a flagged post.
 * @param {HTMLElement} postElement - The post element to blur.
 * @param {string} postId - The unique ID assigned to this post.
 * @param {string[]} links - The array of links found in the post.
 */
function blurPost(postElement, postId, links) {
    // Avoid re-blurring a post
    if (postElement.dataset.phishingBlurred === 'true') return;

    const overlay = document.createElement('div');
    overlay.className = 'phishing-detector-overlay';
    overlay.style.cssText = `
        position: absolute; top: 0; left: 0; width: 100%; height: 100%;
        background-color: rgba(22, 22, 33, 0.92); color: white;
        display: flex; flex-direction: column; justify-content: center; align-items: center;
        text-align: center; z-index: 100; border-radius: 8px; padding: 1rem;
        font-family: sans-serif; backdrop-filter: blur(4px);
    `;

    overlay.innerHTML = `
        <p style="font-size: 1.1rem; font-weight: bold; margin-bottom: 8px;">⚠️ Potential Phishing Detected</p>
        <p style="font-size: 0.9rem; margin-bottom: 16px;">This content was flagged by the AI model.</p>
        <button class="unblur-button" style="background-color: #3498db; color: white; padding: 8px 16px; border-radius: 20px; border: none; cursor: pointer; margin-bottom: 16px; font-weight: bold;">View Content Anyway</button>
        <p style="font-size: 0.8rem; margin-bottom: 4px;">Was this prediction wrong?</p>
        <button class="report-fp-button" style="background-color: transparent; color: #2ecc71; padding: 6px 12px; border-radius: 20px; border: 1px solid #2ecc71; cursor: pointer;">Report as Safe Link</button>
    `;

    postElement.style.filter = 'blur(8px)';
    postElement.style.position = 'relative'; // Necessary for absolute positioning of overlay
    postElement.appendChild(overlay);
    postElement.dataset.phishingBlurred = 'true';

    // --- Event Listeners for Overlay Buttons ---
    overlay.querySelector('.unblur-button').addEventListener('click', (e) => {
        e.stopPropagation();
        unblurPost(postElement, overlay, links);
    });

    overlay.querySelector('.report-fp-button').addEventListener('click', (e) => {
        e.stopPropagation();
        // Report the first detected link as a false positive
        if (links.length > 0) {
            reportLink(links[0], 'false_positive', e.target);
        }
    });
}

/**
 * Removes the blur and adds new controls for re-blurring and reporting false negatives.
 * @param {HTMLElement} postElement - The post element to unblur.
 * @param {HTMLElement} overlay - The overlay element to remove.
 * @param {string[]} links - The links in the post, needed for reporting.
 */
function unblurPost(postElement, overlay, links) {
    postElement.style.filter = 'none';
    overlay.remove();
    postElement.dataset.phishingBlurred = 'false';

    // Create a new controls container for after unblurring
    const controls = document.createElement('div');
    controls.className = 'phishing-detector-controls';
    controls.style.cssText = `
        position: absolute; top: 8px; right: 8px; z-index: 101;
        display: flex; gap: 8px; background-color: rgba(0,0,0,0.5); padding: 4px; border-radius: 20px;
    `;
    controls.innerHTML = `
        <button class="reblur-button" title="Re-blur this post" style="background-color: #f39c12; color: white; border: none; border-radius: 50%; width: 30px; height: 30px; cursor: pointer; font-size: 16px;">👁️</button>
        <button class="report-fn-button" title="This was phishing and should have been blocked" style="background-color: #e74c3c; color: white; border: none; border-radius: 50%; width: 30px; height: 30px; cursor: pointer; font-size: 16px;">🚩</button>
    `;
    postElement.appendChild(controls);

    // --- Event Listeners for New Controls ---
    controls.querySelector('.reblur-button').addEventListener('click', (e) => {
        e.stopPropagation();
        controls.remove(); // Remove the controls before re-blurring
        blurPost(postElement, postElement.dataset.phishingPostId, links);
    });

    controls.querySelector('.report-fn-button').addEventListener('click', (e) => {
        e.stopPropagation();
        if (links.length > 0) {
            reportLink(links[0], 'false_negative', e.target);
        }
    });
}

/**
 * Scans the page for new posts, extracts content, and sends link-containing posts to the background script.
 */
async function scanAndSendPosts() {
    // A more specific selector to target feed posts
    const posts = document.querySelectorAll('div[data-pagelet^="FeedUnit_"]');
    const newPostsData = [];

    posts.forEach((postElement) => {
        // Use a more stable attribute if available, otherwise create one
        const postId = postElement.dataset.phishingPostId || `post-${Math.random().toString(36).substr(2, 9)}`;
        postElement.dataset.phishingPostId = postId;

        if (!processedPostIds.has(postId)) {
            const content = extractPostContent(postElement);
            // --- CRITICAL CHANGE: Only process posts that actually contain external links ---
            if (content.links.length > 0) {
                newPostsData.push({
                    id: postId,
                    text: content.text,
                    links: content.links,
                });
                processedPostIds.add(postId);
            }
        }
    });

    if (newPostsData.length > 0) {
        chrome.runtime.sendMessage({
            action: "analyzePosts",
            posts: newPostsData
        });
    }
}

// --- Listen for Messages from the Background Script ---
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "blurPost") {
        const postElement = document.querySelector(`[data-phishing-post-id="${request.postId}"]`);
        if (postElement) {
            blurPost(postElement, request.postId, request.links);
            sendResponse({ status: "blurred" });
        }
        return true; // Asynchronous response
    }
    if (request.action === "scanPageFromBackground") {
        scanAndSendPosts();
        sendResponse({ status: "Scan initiated from content script." });
        return true;
    }
});

// Use a MutationObserver to detect when new posts are added to the page (e.g., by scrolling)
const observer = new MutationObserver((mutations) => {
    // A simple check to see if new nodes were added
    for (const mutation of mutations) {
        if (mutation.addedNodes.length) {
            // Use a timeout to debounce the function and avoid running it too frequently
            setTimeout(scanAndSendPosts, 500);
            return;
        }
    }
});

// Start observing the main feed container for changes
const targetNode = document.querySelector('div[role="main"]');
if (targetNode) {
    observer.observe(targetNode, { childList: true, subtree: true });
}

// Run an initial scan when the script is first injected
scanAndSendPosts();

console.log("Phishing Detector content script is active and observing the page.");