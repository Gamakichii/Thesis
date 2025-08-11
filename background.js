// Firebase imports
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import { getAuth, signInAnonymously, signInWithCustomToken, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { getFirestore, doc, getDoc, addDoc, setDoc, updateDoc, deleteDoc, onSnapshot, collection, query, where, getDocs } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";

// Global Firebase variables (provided by Canvas environment)
const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
const firebaseConfig = JSON.parse(typeof __firebase_config !== 'undefined' ? __firebase_config : '{}');
const initialAuthToken = typeof __initial_auth_token !== 'undefined' ? __initial_auth_token : null;

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
    if (!db || !userId) {
        console.error("Firestore not initialized or userId not available.");
        return null;
    }
    // Using public collection as per instructions for shared data
    return collection(db, `artifacts/${appId}/public/data/flagged_phishing_links`);
}

// Add a collection for user reports (private by rules)
function getUserReportsCollectionRef() {
    if (!db || !userId) {
        console.error("Firestore not initialized or userId not available.");
        return null;
    }
    return collection(db, `artifacts/${appId}/private/user_reports`);
}

async function addUserReport(type, payload) {
    const collectionRef = getUserReportsCollectionRef();
    if (!collectionRef) return false;
    try {
        await addDoc(collectionRef, {
            type,
            payload,
            userId,
            timestamp: new Date()
        });
        return true;
    } catch (e) {
        console.error('Firestore: Error adding user report:', e);
        return false;
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
            userId: detectedByUserId // Store which user flagged it
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

async function getBackendPredictionForLink(url, postId) {
    try {
        const response = await fetch('http://127.0.0.1:5000/predict', {
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
        return data; // { is_phishing: boolean }
    } catch (e) {
        console.error('Network error calling backend /predict:', e);
        return { is_phishing: false };
    }
}

// Aggregates per-link predictions into a per-post decision
async function getMLPrediction(postText, postLinks, postId) {
    if (!postLinks || postLinks.length === 0) {
        return { isPhishing: false, flaggedLinks: [] };
    }
    const results = await Promise.all(
        postLinks.map(async (link) => ({ link, res: await getBackendPredictionForLink(link, postId) }))
    );
    const flaggedLinks = results.filter(({ res }) => !!res && res.is_phishing).map(({ link }) => link);
    return { isPhishing: flaggedLinks.length > 0, flaggedLinks };
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
                // console.log(`Post ${post.id} seems legitimate.`);
            }
        });
        sendResponse({ status: "processing" }); // Acknowledge receipt
        return true;
    } else if (request.action === 'reportFalsePositive') {
        // User says: This blurred post/link is safe
        (async () => {
            try {
                const links = Array.isArray(request.links) ? request.links : [];
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
                await addUserReport('false_negative', { url });
                sendResponse({ status: 'reported' });
            } catch (e) {
                console.error('Error reporting false negative:', e);
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
    }
});

console.log("Background service worker loaded.");