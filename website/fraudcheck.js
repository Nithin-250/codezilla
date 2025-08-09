document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('fraudTransactionForm');
    const API_BASE =
        window.location.hostname === 'localhost'
          ? 'http://localhost:3001'
          : 'https://codezilla-1-1jc8.onrender.com';

    form.addEventListener('submit', async function(event) {
        event.preventDefault();

        const data = new FormData(form);
        const payload = Object.fromEntries(data.entries());

        try {
            const response = await fetch(API_BASE + '/fraudcheck', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);

            const result = await response.json();
            document.getElementById('fraudResult').innerHTML = `
                <div class="${result.isFraud ? 'fraud-alert-danger' : 'fraud-alert-safe'} p-4 rounded-lg">
                    ${result.message}
                </div>
            `;
        } catch (error) {
            console.error('Error:', error);
            alert('Unable to connect to backend');
        }
    });
});
