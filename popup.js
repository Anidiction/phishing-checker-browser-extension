const API_KEY = '7445627c19e8356df7ebafbced41008919dc10e86941dcac25c8b93a6495d0a5'; // Replace with your VirusTotal API key

// Add event listener for "Check URL" button click
document.getElementById('checkButton').addEventListener('click', checkUrl);

// Add event listener for pressing "Enter" in the URL input
document.getElementById('urlInput').addEventListener('keypress', (event) => {
    if (event.key === 'Enter') {
        checkUrl();
    }
});

async function checkUrl() {
    const urlInput = document.getElementById('urlInput').value.trim();
    const loadingDiv = document.getElementById('loading');
    const resultDiv = document.getElementById('result');
    const summaryDiv = document.getElementById('summary');
    const chartDiv = document.getElementById('chart');
    const warningDiv = document.getElementById('cousinWarning'); // New warning div

    if (!urlInput) return;

    resetDisplay(resultDiv, summaryDiv, chartDiv, loadingDiv, warningDiv);

    try {
        // Check for homoglyphs
        const response = await chrome.runtime.sendMessage({ type: 'checkUrl', encodedUrl: urlInput });

        // Display homoglyph warning if detected
        if (response.homoglyphs) {
            resultDiv.innerHTML = `This URL contains homoglyphs: <span style="color: red;">${response.homoglyphs}</span>`;
            resultDiv.style.color = "red"; // Change text color for warning
            resultDiv.style.display = 'block'; // Show the result div
            return; // Exit if homoglyphs are found
        }

        // Check URL with VirusTotal
        const scanData = await scanUrl(urlInput);
        const analysisData = await getAnalysis(scanData.data.id);

        // Check if analysisData is valid before displaying results
        if (analysisData && analysisData.data && analysisData.data.attributes) {
            displayResults(urlInput, analysisData, resultDiv, summaryDiv, chartDiv);
        } else {
            resultDiv.textContent = 'Error: Analysis data is not available.';
            resultDiv.style.display = 'block';
        }
    } catch (error) {
        resultDiv.textContent = `Error: ${error.message}`;
        resultDiv.style.display = 'block';
    } finally {
        loadingDiv.style.display = 'none';
    }
}

function resetDisplay(resultDiv, summaryDiv, chartDiv, loadingDiv) {
    resultDiv.style.display = 'none';
    summaryDiv.style.display = 'none';
    chartDiv.style.display = 'none';
    loadingDiv.style.display = 'block';
}

async function scanUrl(url) {
    const response = await fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
            'accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded',
            'x-apikey': API_KEY
        },
        body: `url=${encodeURIComponent(url)}`
    });
    if (!response.ok) throw new Error('Failed to scan URL');
    return await response.json();
}

async function getAnalysis(analysisId) {
    const analysisUrl = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;
    while (true) {
        const response = await fetch(analysisUrl, {
            method: 'GET',
            headers: {
                'accept': 'application/json',
                'x-apikey': API_KEY
            }
        });
        const data = await response.json();
        if (data.data && data.data.attributes.status === 'completed') return data;
        await new Promise(resolve => setTimeout(resolve, 2000));
    }
}

function displayResults(url, analysisData, resultDiv, summaryDiv, chartDiv) {
    const { malicious, suspicious, harmless, undetected } = analysisData.data.attributes.stats;
    const totalVendors = malicious + suspicious + harmless + undetected;
    const redirectContainer = document.getElementById('redirectContainer');
    const redirectButton = document.getElementById('redirectButton');

    console.log('Analysis Data:', analysisData);

    // Set summary message based on the analysis results
    if (malicious > 0 || suspicious > 0) {
        summaryDiv.innerHTML = `<span style="color: red;">${malicious}/${totalVendors} security vendors flagged this URL as malicious.</span>`;
        summaryDiv.style.display = 'block';
        redirectContainer.style.display = 'none'; // Hide redirect button if malicious
    } else {
        summaryDiv.innerHTML = `<span style="color: green;">No security vendors flagged this URL as malicious.</span>`;
        summaryDiv.style.display = 'block';
        redirectContainer.style.display = 'block'; // Show redirect button if safe
        redirectButton.onclick = () => {
            chrome.tabs.create({ url: `${url}` }); // Open URL in a new tab
        };
    }

    resultDiv.style.color = "black"; // Reset text color
    resultDiv.innerHTML = `
        URL: ${url}<br/>
        Malicious: <span class="${malicious > 0 ? 'highlight' : ''}">${malicious}</span><br/>
        Suspicious: ${suspicious}
    `;
    resultDiv.style.display = 'block';

    drawCircleGraph(malicious, suspicious);
    chartDiv.style.display = 'block';
}

// Track the chart instance globally
let chartInstance;

function drawCircleGraph(malicious, suspicious) {
    const ctx = document.getElementById('chartCanvas').getContext('2d');

    // Check if a chart instance already exists and destroy it if so
    if (chartInstance) {
        chartInstance.destroy();
    }

    const colors = getChartColors(malicious, suspicious);
    const data = [malicious, suspicious];

    // Create a new chart instance
    chartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Malicious', 'Suspicious'],
            datasets: [{
                label: 'Detection Statistics',
                data,
                backgroundColor: colors
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            legend: { position: 'bottom' }
        }
    });
}

function getChartColors(malicious, suspicious, harmless, undetected) {
    if (malicious > 0) return ['#F44336', '#FF9800']; // Red if malicious is present
    if (suspicious > 0 && malicious == 0) return ['#FF9800', '#FF9800']; // Orange if only suspicious is present
    return ['#4CAF50', '#4CAF50']; // Green if neither malicious nor suspicious
}