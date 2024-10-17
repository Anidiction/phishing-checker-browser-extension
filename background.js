chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'checkUrl') {
        fetch(`https://www.virustotal.com/api/v3/urls/${request.encodedUrl}`, {
            method: 'GET',
            headers: {
                'x-apikey': '7445627c19e8356df7ebafbced41008919dc10e86941dcac25c8b93a6495d0a5'  // Replace with your VirusTotal API key
            }
        })
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok ' + response.statusText);
            }
            return response.json();
        })
        .then(data => {
            sendResponse(data);
        })
        .catch(error => {
            console.error('Error fetching data from VirusTotal:', error);
            sendResponse({ error: 'An error occurred while checking the URL.' });
        });

        // Keep the message channel open until sendResponse is called
        return true;
    }
});
