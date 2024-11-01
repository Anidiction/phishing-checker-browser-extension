import { compareTwoStrings } from './libs/stringSimilarity.js';

const VIRUS_TOTAL_API_KEY = '7445627c19e8356df7ebafbced41008919dc10e86941dcac25c8b93a6495d0a5'; // Replace with your VirusTotal API key
let knownDomains = [];

// Load known domains from the JSON file
async function loadKnownDomains() {
    const response = await fetch(chrome.runtime.getURL('assets/known_domains.json'));
    knownDomains = await response.json();
}

// Normalize URL (strip protocol and www)
function normalizeUrl(url) {
    return url.replace(/^(https?:\/\/)?(www\.)?/, '').replace(/\/.*$/, '');
}

// Detect homoglyph characters
function findHomoglyphs(url) {
    const homoglyphs = {
        'a': ['?', '?', '?', '??'],
        'b': ['?', '?', '?', '??'],
        'c': ['?', '?', '??'],
        'e': ['?', '??'],
        'g': ['g', '?', '??'],
        'i': ['?', '??'],
        'o': ['?', '0', '?', '??'],
        'p': ['?', '??'],
        's': ['?', '?', '??'],
        't': ['?', '??'],
        'x': ['?', '??'],
        // Add more mappings as needed
    };

    const found = new Set();
    const normalizedUrl = normalizeUrl(url).toLowerCase();

    for (const [key, values] of Object.entries(homoglyphs)) {
        for (const value of values) {
            if (normalizedUrl.includes(value)) {
                found.add(key);
            }
        }
    }

    return [...found];
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'checkUrl') {
        const url = request.encodedUrl;

        // Check for homoglyphs first
        const homoglyphCharacters = findHomoglyphs(url);
        if (homoglyphCharacters.length > 0) {
            // Send response with the homoglyphs found
            sendResponse({ homoglyphs: homoglyphCharacters.join(', ') });
            return; // Return early to prevent further processing
        }

        // Check URL with VirusTotal
        checkUrlWithVirusTotal(url, sendResponse);
        return true; // Keep the message channel open until sendResponse is called
    }
});

// Check URL with VirusTotal
async function checkUrlWithVirusTotal(url, sendResponse) {
    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${encodeURIComponent(url)}`, {
            method: 'GET',
            headers: { 'x-apikey': VIRUS_TOTAL_API_KEY }
        });

        if (!response.ok) {
            throw new Error('Network response was not ok ' + response.statusText);
        }

        const data = await response.json();
        sendResponse({ vtData: data });

    } catch (error) {
        console.error('Error fetching data from VirusTotal:', error);
        sendResponse({ error: 'An error occurred while checking the URL.' });
    }
}
