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

// --- Simulated ML Model Prediction ---

// This function simulates the ML model's prediction.
async function getMLPrediction(postText, postLinks) {
    console.log("Simulating ML prediction for:", { postText, postLinks });

    // More aggressive phishing keywords for testing purposes
    const phishingKeywords = [
        "scam", "phish", "free money", "urgent update", "verify account", "click here",
        "congratulations", "winner", "claim now", "limited time", "security alert",
        "account suspended", "password reset", "invoice", "delivery failed",
        "unusual activity", "verify your identity", "financial aid", "tax refund",
        "cash app", "paypal", "bank account", "login required", "authentication",
        "suspicious login", "your package is waiting", "update your information"
    ];
    const textContainsPhishing = phishingKeywords.some(keyword =>
        postText.toLowerCase().includes(keyword)
    );

    // More aggressive URL patterns for testing purposes
    const suspiciousUrlPatterns = [
        "scam", "phish", "bit.ly", "tinyurl.com", "goo.gl", // Common shorteners
        "login-", "-verify", "-update", "-security", "-account", // Common phishing URL components
        ".xyz", ".top", ".club", ".online", ".buzz", ".site", // Common suspicious TLDs
        "paypal.com.fake.site.com", // Example of sub-domain trickery
        "http://" // Non-HTTPS links are often suspicious for sensitive actions
    ];

    const linkContainsPhishing = postLinks.some(link => {
        const lowerCaseLink = link.toLowerCase();
        return suspiciousUrlPatterns.some(pattern => lowerCaseLink.includes(pattern));
    });

    const isPhishing = textContainsPhishing || linkContainsPhishing;

    return {
        isPhishing: isPhishing,
        confidence: isPhishing ? 0.95 : 0.05 // High confidence if detected, low otherwise
    };
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
            const prediction = await getMLPrediction(post.text, post.links);
            if (prediction.isPhishing) {
                console.warn(`Phishing detected in post ${post.id}! Links: ${post.links.join(', ')}`);
                // Store the flagged link in Firestore
                if (post.links.length > 0) {
                    for (const link of post.links) {
                        await addFlaggedLink(link, userId); // Use the authenticated userId
                    }
                } else {
                    // If no specific link, store the post text as a "link" for simplicity
                    await addFlaggedLink(`Post Text: "${post.text.substring(0, 50)}..."`, userId);
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