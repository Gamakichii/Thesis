// ==============================================================================
//
//  Facebook Phishing Detector - Background Service Worker
//
// ==============================================================================

// --- Firebase Imports ---
import { initializeApp } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-app.js";
import { getAuth, signInAnonymously, signInWithCustomToken, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-auth.js";
import { getFirestore, collection, addDoc, getDocs } from "https://www.gstatic.com/firebasejs/11.6.1/firebase-firestore.js";

// --- Global Variables ---
const appId = typeof __app_id !== 'undefined' ? __app_id : 'default-app-id';
const firebaseConfig = JSON.parse(typeof __firebase_config !== 'undefined' ? __firebase_config : '{}');
const initialAuthToken = typeof __initial_auth_token !== 'undefined' ? __initial_auth_token : null;

// The endpoint where your Flask backend API is running
const API_ENDPOINT = "http://127.0.0.1:5000/predict";

let app;
let db;
let auth;
let userId = null;

// ==============================================================================
//  INITIALIZATION
// ==============================================================================

async function initializeFirebase() {
    try {
        if (app) return; // Initialize only once
        app = initializeApp(firebaseConfig);
        db = getFirestore(app);
        auth = getAuth(app);

        if (initialAuthToken) {
            await signInWithCustomToken(auth, initialAuthToken);
        } else {
            await signInAnonymously(auth);
        }

        onAuthStateChanged(auth, (user) => {
            if (user) {
                userId = user.uid;
                console.log("Firebase Authentication successful. User ID:", userId);
            } else {
                userId = crypto.randomUUID();
                console.warn("Firebase anonymous auth failed. Using random ID:", userId);
            }
        });
    } catch (error) {
        console.error("Firebase initialization failed:", error);
    }
}

initializeFirebase();

// ==============================================================================
//  BACKEND API AND DATABASE FUNCTIONS
// ==============================================================================

/**
 * Calls the backend server to get a prediction from the hybrid AI model.
 * @param {string} url - The URL to analyze.
 * @param {string} postId - The unique ID of the post element.
 * @returns {Promise<boolean>} - A promise that resolves to true if phishing, false otherwise.
 */
async function getHybridPrediction(url, postId) {
    try {
        const response = await fetch(API_ENDPOINT, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: url,
                // The backend needs a post ID to look up in the graph. We simulate
                // mapping the element's ID to a node ID in our graph.
                post_id: parseInt(postId.split('-').pop()) % 2000 + 500
            }),
        });
        if (!response.ok) {
            console.error(`API Error: ${response.status}`);
            return false;
        }
        const data = await response.json();
        return data.is_phishing;
    } catch (error) {
        console.error("API call failed:", error);
        return false; // Fail safe: default to not phishing on network errors
    }
}

/**
 * Saves a user's report about a link to the Firestore database.
 * @param {string} url - The URL being reported.
 * @param {string} reportType - 'false_positive' or 'false_negative'.
 * @param {string} reportingUserId - The ID of the user submitting the report.
 */
async function saveReportedLink(url, reportType, reportingUserId) {
    if (!db) {
        console.error("Firestore not initialized. Cannot save report.");
        return;
    }
    try {
        const reportsCollectionRef = collection(db, `artifacts/${appId}/public/data/reported_links`);
        await addDoc(reportsCollectionRef, {
            url: url,
            report_type: reportType,
            reported_by: reportingUserId,
            timestamp: new Date()
        });
        console.log(`Firestore: Report for ${url} as ${reportType} saved successfully.`);
    } catch (e) {
        console.error("Firestore: Error saving report:", e);
    }
}

/**
 * Fetches previously flagged links from the database for the popup.
 * @returns {Promise<Array>} - A promise that resolves to an array of flagged link objects.
 */
async function getAllFlaggedLinks() {
    if (!db) return [];
    try {
        const flaggedLinksCollectionRef = collection(db, `artifacts/${appId}/public/data/flagged_phishing_links`);
        const querySnapshot = await getDocs(flaggedLinksCollectionRef);
        const links = [];
        querySnapshot.forEach((doc) => links.push(doc.data()));
        return links;
    } catch (e) {
        console.error("Firestore: Error getting flagged links:", e);
        return [];
    }
}

// ==============================================================================
//  MAIN MESSAGE LISTENER
// ==============================================================================

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // Ensure this listener returns true for asynchronous operations
    let isAsync = false;

    switch (request.action) {
        case "analyzePosts":
            isAsync = true;
            console.log(`Received ${request.posts.length} posts with links to analyze.`);
            request.posts.forEach(async (post) => {
                for (const link of post.links) {
                    const isPhishing = await getHybridPrediction(link, post.id);
                    if (isPhishing) {
                        console.warn(`HYBRID MODEL DETECTED PHISHING in post ${post.id}`);
                        // Tell the content script to blur the post
                        chrome.tabs.sendMessage(sender.tab.id, {
                            action: "blurPost",
                            postId: post.id,
                            links: post.links // Pass links for reporting functionality
                        });
                        // Once one link is flagged, we can stop checking this post
                        return;
                    }
                }
            });
            sendResponse({ status: "Analysis requests sent to backend." });
            break;

        case "reportLink":
            isAsync = true;
            if (userId) {
                saveReportedLink(request.url, request.type, userId);
                sendResponse({ status: "Report received by background." });
            } else {
                sendResponse({ status: "Error: User not authenticated." });
            }
            break;

        case "getUserId":
            sendResponse({ userId: userId });
            break;

        case "getFlaggedLinks":
            isAsync = true;
            getAllFlaggedLinks().then(links => {
                sendResponse({ links: links });
            });
            break;
            
        case "scanPage": // From popup
             isAsync = true;
             chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                if (tabs[0] && tabs[0].id) {
                    chrome.tabs.sendMessage(tabs[0].id, { action: "scanPageFromBackground" }, (response) => {
                         if (chrome.runtime.lastError) {
                            console.error("Error sending scan request:", chrome.runtime.lastError.message);
                            sendResponse({ status: "error", message: "Could not connect to the page." });
                         } else {
                            sendResponse({ status: "success", message: "Page scan initiated." });
                         }
                    });
                } else {
                    sendResponse({ status: "error", message: "No active tab found." });
                }
            });
            break;
    }

    return isAsync;
});

console.log("Phishing Detector background service worker loaded and ready.");