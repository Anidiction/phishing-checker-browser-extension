const API_KEY = 'PLACE_API_HERE'; // Replace with your actual VirusTotal API key

document.getElementById('checkButton').addEventListener('click', async () => {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();
    const resultDiv = document.getElementById('result');
    const loadingDiv = document.getElementById('loading');
    const summaryDiv = document.getElementById('summary');
    const chartDiv = document.getElementById('chart');

    if (!url) return;

    resetDisplay(resultDiv, summaryDiv, chartDiv, loadingDiv);

    try {
        const scanResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
            method: 'POST',
            headers: {
                'accept': 'application/json',
                'content-type': 'application/x-www-form-urlencoded',
                'x-apikey': API_KEY
            },
            body: `url=${encodeURIComponent(url)}`
        });

        if (!scanResponse.ok) {
            throw new Error((await scanResponse.json()).error.message || 'Failed to scan URL');
        }

        const scanData = await scanResponse.json();
        const analysisId = scanData.data.id;
        const analysisData = await waitForAnalysis(analysisId);

        displayResults(url, analysisData, resultDiv, summaryDiv, chartDiv);
    } catch (error) {
        resultDiv.textContent = `Error: ${error.message}`;
        resultDiv.style.display = 'block';
    } finally {
        loadingDiv.style.display = 'none'; // Hide loading message after processing
    }
});

function resetDisplay(resultDiv, summaryDiv, chartDiv, loadingDiv) {
    resultDiv.style.display = 'none';
    summaryDiv.style.display = 'none';
    chartDiv.style.display = 'none';
    loadingDiv.style.display = 'block'; // Show loading message
}

async function waitForAnalysis(analysisId) {
    const analysisUrl = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;
    let analysisData;

    while (true) {
        const analysisResponse = await fetch(analysisUrl, {
            method: 'GET',
            headers: {
                'accept': 'application/json',
                'x-apikey': API_KEY
            }
        });
        analysisData = await analysisResponse.json();

        if (analysisData.data.attributes.status === 'completed') {
            return analysisData;
        }
        await new Promise(resolve => setTimeout(resolve, 2000));
    }
}

function displayResults(url, analysisData, resultDiv, summaryDiv, chartDiv) {
    const attributes = analysisData.data.attributes;
    const stats = attributes.stats;

    const totalVendors = stats.harmless + stats.malicious + stats.suspicious + stats.undetected;
    const summaryText = `${stats.malicious}/${totalVendors} security vendors flagged this URL as malicious.`;
    summaryDiv.textContent = summaryText;
    summaryDiv.style.display = 'block';

    resultDiv.innerHTML = `
        URL: ${url}<br/>
        Harmless: ${stats.harmless}<br/>
        Malicious: <span class="${stats.malicious > 0 ? 'highlight' : ''}">${stats.malicious}</span><br/>
        Suspicious: ${stats.suspicious}<br/>
        Undetected: ${stats.undetected}
    `;
    resultDiv.style.display = 'block';

    drawCircleGraph(stats);
    chartDiv.style.display = 'block';
}

function drawCircleGraph(stats) {
    const ctx = document.getElementById('chartCanvas').getContext('2d');
    const data = [stats.harmless, stats.malicious, stats.suspicious, stats.undetected];
    const labels = ['Harmless', 'Malicious', 'Suspicious', 'Undetected'];
    const colors = ['#4CAF50', '#F44336', '#FFC107', '#9E9E9E'];

    new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels,
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
