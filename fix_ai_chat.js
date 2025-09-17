// Fix AI chat loop
async function sendMessage() {
    const input = document.getElementById('messageInput');
    const message = input.value.trim();
    if (!message) return;
    
    input.value = '';
    addMessage(message, 'user');
    
    try {
        const response = await fetch('/api/chat', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({message})
        });
        const data = await response.json();
        addMessage(data.response, 'ai');
    } catch (error) {
        addMessage('Error connecting to AI', 'ai');
    }
}

function addMessage(text, sender) {
    const messages = document.getElementById('messages');
    const div = document.createElement('div');
    div.className = sender;
    div.textContent = text;
    messages.appendChild(div);
    messages.scrollTop = messages.scrollHeight;
}