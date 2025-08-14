// Firebase imports
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import { getAuth, signInAnonymously, signInWithCustomToken, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { getFirestore, doc, getDoc, addDoc, setDoc, updateDoc, deleteDoc, onSnapshot, collection, query, where, getDocs } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";

// Global Firebase variables (provided by Canvas environment)
  // background.js
  const appId = 'ads-phishing-link'; // e.g., 'prod' or your Firebase project ID
  const firebaseConfig = {
    apiKey: "AIzaSyB9FgbYrbiKZ7Z8LaPZprDtndSjgY7YDq8",
    authDomain: "ads-phishing-link.firebaseapp.com",
    projectId: "ads-phishing-link",
    storageBucket: "ads-phishing-link.firebasestorage.app",
    messagingSenderId: "406180111870",
    appId: "1:406180111870:web:5cc2190210073a0e2d8caf",
    measurementId: "G-79ECP9L5YV"
  };
  const initialAuthToken = null; // keep null; we use anonymous auth
  // Backend API base URL (can be overridden by page-injected global __api_base)
  const API_BASE_URL = "https://dakugumen-api.mangosea-8f507dd6.southeastasia.azurecontainerapps.io"; // your container URL


let app;
let db;
let auth;
let userId = null; // Will store the authenticated user ID

// Initialize Firebase and authenticate
async function initializeFirebase() {
    try {
        if (!app) { // Initialize only once
        app = initializeApp(firebaseConfig);
        db = getFirestore(app);
        auth = getAuth(app);

            // Authenticate user
        if (initialAuthToken) {
            await signInWithCustomToken(auth, initialAuthToken);
                console.log("Firebase: Signed in with custom token.");
        } else {
            await signInAnonymously(auth);
                console.log("Firebase: Signed in anonymously.");
        }

            // Listen for auth state changes to get the user ID
        onAuthStateChanged(auth, (user) => {
            if (user) {
                userId = user.uid;
                    console.log("Firebase: User ID set:", userId);
            } else {
                    userId = crypto.randomUUID(); // Fallback for unauthenticated or anonymous
                    console.log("Firebase: User not authenticated, using random ID:", userId);
            }
        });
        }
    } catch (error) {
        console.error("Firebase initialization or authentication error:", error);
    }
}

// Call Firebase initialization immediately
initializeFirebase();

// --- Firestore Operations ---

// Collection path for flagged links (public data for sharing)
function getFlaggedLinksCollectionRef() {
    if (!db) {
        console.error("Firestore not initialized.");
        return null;
    }
    // Using public collection as per instructions for shared data
    return collection(db, `artifacts/${appId}/public/data/flagged_phishing_links`);
}

// Graph collections
function getGraphNodesCollectionRef() {
    if (!db) return null;
    return collection(db, `artifacts/${appId}/private/graph/nodes`);
}
function getGraphEdgesCollectionRef() {
    if (!db) return null;
    return collection(db, `artifacts/${appId}/private/graph/edges`);
}

async function upsertGraphNode(nodeId, data) {
    const colRef = getGraphNodesCollectionRef();
    if (!colRef) return false;
    try {
        const nodeRef = doc(db, `artifacts/${appId}/private/graph/nodes/${nodeId}`);
        await setDoc(nodeRef, { ...data, updatedAt: new Date() }, { merge: true });
        return true;
    } catch (e) {
        console.error('Firestore: upsert node failed', e);
            return false;
        }
}

async function addGraphEdge(edge) {
    const colRef = getGraphEdgesCollectionRef();
    if (!colRef) return false;
    try {
        await addDoc(colRef, { ...edge, userId, ts: new Date() });
        return true;
    } catch (e) {
        console.error('Firestore: add edge failed', e);
        return false;
    }
}

function postNodeId(postId) { return `post:${postId}`; }
function domainNodeId(domain) { return `domain:${domain}`; }
function userNodeId(uid) { return `user:${uid}`; }

// Add a collection for user reports (private by rules)
function getUserReportsCollectionRef() {
    if (!db) {
        console.error("Firestore not initialized.");
        return null;
    }
    return collection(db, `artifacts/${appId}/private_user_reports`);
}

async function addUserReport(type, payload) {
    const collectionRef = getUserReportsCollectionRef();
    if (!collectionRef) return false;
    try {
        await addDoc(collectionRef, {
            type,
            payload,
            userId: userId || 'anon',
            timestamp: new Date()
        });
        return true;
    } catch (e) {
        console.error('Firestore: Error adding user report:', e);
        return false;
    }
}

// Ensure graph nodes/edges exist for a reported post to avoid training-time mismatches
async function ensureGraphNodeForReport(postId, links = []) {
    try {
        const domains = Array.from(new Set((Array.isArray(links) ? links : []).map((h) => {
            try { return new URL(h).hostname; } catch { return null; }
        }).filter(Boolean)));
        await upsertGraphNode(userNodeId(userId || 'anon'), { type: 'user', userId: userId || 'anon' });
        await upsertGraphNode(postNodeId(postId), { type: 'post', postId });
        for (const d of domains) {
            await upsertGraphNode(domainNodeId(d), { type: 'domain', domain: d });
            await addGraphEdge({ src: postNodeId(postId), dst: domainNodeId(d), edgeType: 'contains' });
        }
        await addGraphEdge({ src: userNodeId(userId || 'anon'), dst: postNodeId(postId), edgeType: 'view' });
    } catch (e) {
        console.warn('ensureGraphNodeForReport failed:', e);
    }
}

// Add a new flagged link to Firestore
async function addFlaggedLink(linkUrl, detectedByUserId) {
    const collectionRef = getFlaggedLinksCollectionRef();
    if (!collectionRef) return false;

    try {
        await addDoc(collectionRef, {
            url: linkUrl,
            timestamp: new Date(),
            userId: detectedByUserId || 'anon' // Store which user flagged it
        });
        console.log(`Firestore: Added flagged link: ${linkUrl}`);
        return true;
    } catch (e) {
        console.error("Firestore: Error adding document: ", e);
        return false;
    }
}

// Get all flagged links from Firestore
async function getAllFlaggedLinks() {
    const collectionRef = getFlaggedLinksCollectionRef();
    if (!collectionRef) return [];

    try {
        const querySnapshot = await getDocs(collectionRef);
        const links = [];
        querySnapshot.forEach((doc) => {
            links.push(doc.data());
        });
        console.log("Firestore: Fetched flagged links:", links);
        return links;
    } catch (e) {
        console.error("Firestore: Error getting documents: ", e);
        return [];
    }
}

// --- Backend ML Model Prediction ---
const PREDICTION_TTL_MS = 10 * 60 * 1000; // 10 minutes
const predictionCache = new Map(); // key: urlLower -> { is_phishing, ts }

function getCachedPrediction(urlLower) {
    const entry = predictionCache.get(urlLower);
    if (!entry) return null;
    if (Date.now() - entry.ts > PREDICTION_TTL_MS) {
        predictionCache.delete(urlLower);
        return null;
    }
    return entry;
}

function setCachedPrediction(urlLower, value) {
    predictionCache.set(urlLower, { ...value, ts: Date.now() });
}

async function getBackendPredictionForLink(url, postId) {
    try {
        const urlLower = String(url || '').toLowerCase();
        const cached = getCachedPrediction(urlLower);
        if (cached) return { is_phishing: !!cached.is_phishing };
        const response = await fetch(`${API_BASE_URL}/predict`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url, post_id: postId })
        });
        if (!response.ok) {
            const errText = await response.text();
            console.error('Backend prediction error:', response.status, errText);
            return { is_phishing: false };
        }
        const data = await response.json();
        setCachedPrediction(urlLower, { is_phishing: !!data.is_phishing });
        return data; // { is_phishing: boolean }
    } catch (e) {
        console.error('Network error calling backend /predict:', e);
        return { is_phishing: false };
    }
}

// Aggregates per-link predictions using batch endpoint
async function getMLPrediction(postText, postLinks, postId) {
    try {
        if (!postLinks || postLinks.length === 0) {
            return { isPhishing: false, flaggedLinks: [] };
        }
        const items = postLinks.map((url) => ({ url, post_id: postId }));
        const response = await fetch(`${API_BASE_URL}/predict_batch`, {
            method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ items })
        });
        if (!response.ok) throw new Error(`batch status ${response.status}`);
        const data = await response.json();
        const flagged = (data.predictions || []).filter(p => p.is_phishing).map(p => p.url);
        // Update cache for each url
        (data.predictions || []).forEach(p => setCachedPrediction(String(p.url || '').toLowerCase(), { is_phishing: !!p.is_phishing }));
        return { isPhishing: flagged.length > 0, flaggedLinks: flagged };
    } catch (e) {
        console.warn('Batch prediction failed, falling back per-link', e);
        const results = await Promise.all(postLinks.map(async (link) => ({ link, res: await getBackendPredictionForLink(link, postId) })));
        const flaggedLinks = results.filter(({ res }) => !!res && res.is_phishing).map(({ link }) => link);
        return { isPhishing: flaggedLinks.length > 0, flaggedLinks };
    }
}

// --- Background Script Logic ---

// Listener for messages from popup.js and content_script.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "scanPage") {
        // Message from popup to scan the current active tab
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
            if (tabs[0]) {
                // Send a message to the content script in the active tab to initiate scanning
                chrome.tabs.sendMessage(tabs[0].id, { action: "scanPageFromBackground" }, (response) => {
                    if (chrome.runtime.lastError) {
                        console.error("Error sending message to content script:", chrome.runtime.lastError.message);
                        sendResponse({ status: "error", message: "Could not inject content script. Make sure you are on a Facebook page." });
                        return;
                    }
                    console.log("Scan initiated on active tab:", tabs[0].url, response);
                    sendResponse({ status: "success", message: "Scan initiated on Facebook page." });
                });
            } else {
                sendResponse({ status: "error", message: "No active tab found." });
            }
        });
        return true; // Indicate that sendResponse will be called asynchronously
    } else if (request.action === "analyzePosts") {
        // Message from content_script.js with extracted post data
        console.log("Background script: Received posts for analysis:", request.posts.length);
        request.posts.forEach(async (post) => {
            const prediction = await getMLPrediction(post.text, post.links, post.id);
            if (prediction.isPhishing) {
                console.warn(`Phishing detected in post ${post.id}! Links: ${post.links.join(', ')}`);
                // Store the flagged link in Firestore
                for (const link of prediction.flaggedLinks) {
                    await addFlaggedLink(link, userId);
                }

                // Send message back to content script to blur the post
             chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    if (tabs[0]) {
                        chrome.tabs.sendMessage(tabs[0].id, { action: "blurPost", postId: post.id });
                    }
                });
            } else {
                // Unblur if previously blurred by a heuristic (now disabled) or prior run
                chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    if (tabs[0]) {
                        chrome.tabs.sendMessage(tabs[0].id, { action: "unblurPost", postId: post.id });
                    }
                });
            }
        });
        sendResponse({ status: "processing" }); // Acknowledge receipt
        return true;
    } else if (request.action === 'reportFalsePositive') {
        // User says: This blurred post/link is safe
        (async () => {
            try {
                const links = Array.isArray(request.links) ? request.links : [];
                if (request.postId) {
                    await ensureGraphNodeForReport(request.postId, links);
                }
                await addUserReport('false_positive', { postId: request.postId, links });
                sendResponse({ status: 'reported' });
            } catch (e) {
                console.error('Error reporting false positive:', e);
                sendResponse({ status: 'error', message: String(e) });
            }
        })();
        return true;
    } else if (request.action === 'reportFalseNegative') {
        // User says: This phishing link was missed
        (async () => {
            try {
                const url = request.url;
                if (!url) {
                    sendResponse({ status: 'error', message: 'Missing url' });
                    return;
                }
                if (request.postId) {
                    await ensureGraphNodeForReport(request.postId, [url]);
                }
                await addUserReport('false_negative', { url });
                sendResponse({ status: 'reported' });
            } catch (e) {
                console.error('Error reporting false negative:', e);
                sendResponse({ status: 'error', message: String(e) });
            }
        })();
        return true;
    } else if (request.action === 'confirmPhishing') {
        // User manually marks a post as malicious (FN capture)
        (async () => {
            try {
                const links = Array.isArray(request.links) ? request.links : [];
                // Report each link as false negative; if none, still log postId
                if (links.length === 0) {
                    await ensureGraphNodeForReport(request.postId, []);
                    await addUserReport('false_negative', { postId: request.postId, source: 'manual' });
                } else {
                    await ensureGraphNodeForReport(request.postId, links);
                    for (const url of links) {
                        await addUserReport('false_negative', { url, postId: request.postId, source: 'manual' });
                    }
                }
                // Optionally also store under flagged links (public)
                for (const link of links) {
                    await addFlaggedLink(link, userId);
                }
                // Ask content script to blur it again just in case
                chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    if (tabs[0]) {
                        chrome.tabs.sendMessage(tabs[0].id, { action: "blurPost", postId: request.postId });
                    }
                });
                sendResponse({ status: 'ok' });
            } catch (e) {
                console.error('confirmPhishing error', e);
                sendResponse({ status: 'error', message: String(e) });
            }
        })();
        return true;
    } else if (request.action === "getFlaggedLinks") {
        // Message from popup to get all flagged links
        (async () => {
            const links = await getAllFlaggedLinks();
            sendResponse({ status: "success", links: links });
        })();
        return true; // Indicate that sendResponse will be called asynchronously
    } else if (request.action === "getUserId") {
        // Message from popup to get the current user ID
        sendResponse({ userId: userId });
        return true; // Indicate that sendResponse will be called asynchronously
    } else if (request.action === 'graphIngestPost') {
        (async () => {
            try {
                const { postId, author, ts, domains = [], counts = {} } = request;
                await upsertGraphNode(userNodeId(userId), { type: 'user', userId });
                await upsertGraphNode(postNodeId(postId), { type: 'post', postId, author: author || null, ts: ts || Date.now(), domains, counts });
                for (const d of domains) {
                    await upsertGraphNode(domainNodeId(d), { type: 'domain', domain: d });
                    await addGraphEdge({ src: postNodeId(postId), dst: domainNodeId(d), edgeType: 'contains' });
                }
                await addGraphEdge({ src: userNodeId(userId), dst: postNodeId(postId), edgeType: 'view' });
                sendResponse({ status: 'ok' });
            } catch (e) {
                console.error('graphIngestPost error', e);
                sendResponse({ status: 'error', message: String(e) });
            }
        })();
        return true;
    } else if (request.action === 'graphClick') {
        (async () => {
            try {
                const { domain, postId = null } = request;
                if (!domain) { sendResponse({ status: 'error', message: 'missing domain' }); return; }
                await upsertGraphNode(userNodeId(userId), { type: 'user', userId });
                await upsertGraphNode(domainNodeId(domain), { type: 'domain', domain });
                await addGraphEdge({ src: userNodeId(userId), dst: domainNodeId(domain), edgeType: 'click', postId });
                sendResponse({ status: 'ok' });
            } catch (e) {
                console.error('graphClick error', e);
                sendResponse({ status: 'error', message: String(e) });
            }
        })();
        return true;
    }
});

console.log("Background service worker loaded.");

function isFacebookUrl(url) {
    return /https?:\/\/([a-z0-9-]+\.)*facebook\.com\//i.test(url || "");
}

function ensureContentScriptAndScan(tabId) {
    // Try to ping the content script; if not present, inject then retry
    try {
        chrome.tabs.sendMessage(tabId, { action: "scanPageFromBackground" }, () => {
            if (chrome.runtime.lastError) {
                // Fallback: inject content script then retry once
                chrome.scripting.executeScript({ target: { tabId }, files: ["content_script.js"] }, () => {
                    setTimeout(() => {
                        chrome.tabs.sendMessage(tabId, { action: "scanPageFromBackground" }, () => {});
                    }, 200);
                });
            }
        });
    } catch (e) {
        console.warn('ensureContentScriptAndScan error', e);
    }
}

// Auto-scan: trigger scans on tab activation, tab updates, and SPA navigations
function triggerScanOnActiveFacebookTab() {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        const tab = tabs && tabs[0];
        if (!tab || !tab.url) return;
        if (!isFacebookUrl(tab.url)) return;
        ensureContentScriptAndScan(tab.id);
        // Also trigger a couple follow-up scans to catch lazy-loaded posts
        setTimeout(() => {
            ensureContentScriptAndScan(tab.id);
        }, 600);
        setTimeout(() => {
            ensureContentScriptAndScan(tab.id);
        }, 1600);
    });
}

chrome.tabs.onActivated.addListener(() => {
    triggerScanOnActiveFacebookTab();
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab && tab.url && isFacebookUrl(tab.url)) {
        ensureContentScriptAndScan(tabId);
        setTimeout(() => { ensureContentScriptAndScan(tabId); }, 600);
        setTimeout(() => { ensureContentScriptAndScan(tabId); }, 1600);
    }
});

if (chrome.webNavigation && chrome.webNavigation.onHistoryStateUpdated) {
    chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
        if (details && details.url && isFacebookUrl(details.url)) {
            ensureContentScriptAndScan(details.tabId);
            setTimeout(() => { ensureContentScriptAndScan(details.tabId); }, 600);
            setTimeout(() => { ensureContentScriptAndScan(details.tabId); }, 1600);
        }
    });
}