const VIRUS_TOTAL_API_KEY = 'PLACE_API_HERE'; // Replace with your VirusTotal API key
const KNOWN_DOMAINS = ['google.com', 'facebook.com', 'amazon.com']; // Add more known legitimate domains

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'checkUrl') {
        const url = request.encodedUrl;

        if (isCousinDomain(url)) {
            sendResponse({ error: 'Cousin domain detected. The URL is too similar to known safe domains.' });
            return true;
        }

        if (detectHomoglyphAttack(url)) {
            sendResponse({ error: 'Homoglyph attack detected. The URL contains suspicious characters.' });
            return true;
        }

        checkUrlWithVirusTotal(url, sendResponse);
        return true; // Keep the message channel open until sendResponse is called
    }
});

async function checkUrlWithVirusTotal(url, sendResponse) {
    try {
        const response = await fetch(`https://www.virustotal.com/api/v3/urls/${url}`, {
            method: 'GET',
            headers: { 'x-apikey': VIRUS_TOTAL_API_KEY }
        });

        if (!response.ok) {
            throw new Error('Network response was not ok ' + response.statusText);
        }
        
        const data = await response.json();
        sendResponse(data);
    } catch (error) {
        console.error('Error fetching data from VirusTotal:', error);
        sendResponse({ error: 'An error occurred while checking the URL.' });
    }
}
