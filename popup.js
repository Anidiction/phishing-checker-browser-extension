document.getElementById('checkButton').addEventListener('click', async () => {
    const urlInput = document.getElementById('urlInput');
    const url = urlInput.value.trim();
    const resultDiv = document.getElementById('result');
    const loadingDiv = document.getElementById('loading');
    const summaryDiv = document.getElementById('summary');
    const chartDiv = document.getElementById('chart');

    if (url) {
        resultDiv.style.display = 'none';
        summaryDiv.style.display = 'none';
        chartDiv.style.display = 'none';
        loadingDiv.style.display = 'block'; // Show loading message

        try {
            const apiKey = '7445627c19e8356df7ebafbced41008919dc10e86941dcac25c8b93a6495d0a5';  // Replace with your actual VirusTotal API key
            const encodedUrl = encodeURIComponent(url);
            const options = {
                method: 'POST',
                headers: {
                    'accept': 'application/json',
                    'content-type': 'application/x-www-form-urlencoded',
                    'x-apikey': apiKey
                },
                body: `url=${encodedUrl}`  // URL-encoded form data
            };

            const scanResponse = await fetch('https://www.virustotal.com/api/v3/urls', options);
            const scanData = await scanResponse.json();

            if (scanResponse.ok) {
                const analysisId = scanData.data.id;
                const analysisUrl = `https://www.virustotal.com/api/v3/analyses/${analysisId}`;
                let analysisData;

                while (true) {
                    const analysisResponse = await fetch(analysisUrl, {
                        method: 'GET',
                        headers: {
                            'accept': 'application/json',
                            'x-apikey': apiKey
                        }
                    });
                    analysisData = await analysisResponse.json();

                    if (analysisData.data.attributes.status === 'completed') {
                        break;
                    }
                    await new Promise(resolve => setTimeout(resolve, 2000));
                }

                if (analysisData.data) {
                    const attributes = analysisData.data.attributes;
                    const stats = attributes.stats;

                    // Show summary
                    const totalVendors = stats.harmless + stats.malicious + stats.suspicious + stats.undetected;
                    const summaryText = `${stats.malicious}/${totalVendors} security vendors flagged this URL as malicious.`;
                    summaryDiv.textContent = summaryText;
                    summaryDiv.style.display = 'block';

                    // Highlight malicious count
                    let resultText = `
                        URL: ${url}<br/>
                        Harmless: ${stats.harmless}<br/>
                        Malicious: <span class="${stats.malicious > 0 ? 'highlight' : ''}">${stats.malicious}</span><br/>
                        Suspicious: ${stats.suspicious}<br/>
                        Undetected: ${stats.undetected}
                    `;

                    resultDiv.innerHTML = resultText;
                    resultDiv.style.display = 'block';

                    // Show circle graph
                    drawCircleGraph(stats);
                    chartDiv.style.display = 'block';
                } else {
                    throw new Error('Failed to retrieve analysis results');
                }
            } else {
                throw new Error(scanData.error.message || 'Failed to scan URL');
            }
        } catch (error) {
            resultDiv.textContent = `Error: ${error.message}`;
            resultDiv.className = 'result error';
            resultDiv.style.display = 'block';
        } finally {
            loadingDiv.style.display = 'none'; // Hide loading message when done
        }
    } else {
        alert('Please enter a URL to check.');
    }
});

// Function to draw the circle graph
function drawCircleGraph(stats) {
    const canvas = document.getElementById('chartCanvas');
    const ctx = canvas.getContext('2d');

    const total = stats.harmless + stats.malicious + stats.suspicious + stats.undetected;

    const segments = [
        { label: 'Harmless', value: stats.harmless, color: '#4CAF50' },
        { label: 'Malicious', value: stats.malicious, color: '#F44336' },
        { label: 'Suspicious', value: stats.suspicious, color: '#FF9800' },
        { label: 'Undetected', value: stats.undetected, color: '#9E9E9E' }
    ];

    let startAngle = 0;

    segments.forEach(segment => {
        const sliceAngle = (segment.value / total) * 2 * Math.PI;
        ctx.beginPath();
        ctx.moveTo(150, 75); // Circle center
        ctx.arc(150, 75, 75, startAngle, startAngle + sliceAngle);
        ctx.closePath();
        ctx.fillStyle = segment.color;
        ctx.fill();
        startAngle += sliceAngle;
    });

    // Adding labels
    ctx.font = '16px Arial';
    ctx.fillStyle = '#000';
    let legendY = 160;
    segments.forEach(segment => {
        ctx.fillStyle = segment.color;
        ctx.fillRect(20, legendY - 10, 10, 10);
        ctx.fillStyle = '#000';
        ctx.fillText(`${segment.label}: ${segment.value}`, 40, legendY);
        legendY += 20;
    });
}
