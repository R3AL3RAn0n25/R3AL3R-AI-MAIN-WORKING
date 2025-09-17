class MatrixRain {
    constructor() {
        this.canvas = document.getElementById('matrix-canvas');
        this.ctx = this.canvas.getContext('2d');
        this.chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%^&*()';
        this.drops = [];
        this.init();
    }
    init() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
        const columns = this.canvas.width / 20;
        for (let i = 0; i < columns; i++) { this.drops[i] = 1; }
        this.animate();
    }
    animate() {
        this.ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        this.ctx.fillStyle = '#0f0';
        this.ctx.font = '15px monospace';
        for (let i = 0; i < this.drops.length; i++) {
            const text = this.chars[Math.floor(Math.random() * this.chars.length)];
            this.ctx.fillText(text, i * 20, this.drops[i] * 20);
            if (this.drops[i] * 20 > this.canvas.height && Math.random() > 0.975) {
                this.drops[i] = 0;
            }
            this.drops[i] += 0.8;
        }
        setTimeout(() => requestAnimationFrame(() => this.animate()), 30);
    }
}

class VoiceManager {
    constructor() {
        this.recognition = null;
        this.synthesis = window.speechSynthesis;
        this.isListening = false;
        this.voiceEnabled = false;
        this.initSpeechRecognition();
    }
    initSpeechRecognition() {
        if ('webkitSpeechRecognition' in window || 'SpeechRecognition' in window) {
            const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
            this.recognition = new SpeechRecognition();
            this.recognition.continuous = false;
            this.recognition.interimResults = false;
            this.recognition.lang = 'en-US';

            this.recognition.onresult = (event) => {
                const transcript = event.results[0][0].transcript;
                if (app.elements.messageInput) {
                    app.elements.messageInput.value = transcript;
                    this.stopListening();
                    app.sendMessage();
                }
            };
            this.recognition.onerror = (event) => {
                console.error('Speech recognition error:', event.error);
                app.addMessage("System", `Speech Error: ${event.error}`);
                this.stopListening();
            };
            this.recognition.onend = () => { this.stopListening(); };
        }
    }
    startListening() {
        if (this.recognition && !this.isListening) {
            this.isListening = true;
            this.recognition.start();
            this.updateMicButton(true);
            app.addMessage("System", "🎤 Listening...");
        }
    }
    stopListening() {
        if (this.recognition && this.isListening) {
            this.isListening = false;
            this.recognition.stop();
            this.updateMicButton(false);
        }
    }
    updateMicButton(listening) {
        const micButton = document.getElementById('mic-button');
        if (micButton) {
            micButton.textContent = listening ? '🔴 Stop' : '🎤 Voice';
            micButton.style.background = listening ? '#f00' : 'var(--button-bg)';
        }
    }
    speak(text) {
        if (this.voiceEnabled && this.synthesis) {
            this.synthesis.cancel();
            const utterance = new SpeechSynthesisUtterance(text);
            utterance.rate = 0.9;
            utterance.pitch = 0.8;
            utterance.volume = 0.8;
            const voices = this.synthesis.getVoices();
            const selectedVoice = voices.find(voice => voice.name.includes('Google') || voice.name.includes('Microsoft') || voice.name.includes('Alex'));
            if (selectedVoice) { utterance.voice = selectedVoice; }
            this.synthesis.speak(utterance);
        }
    }
    toggleVoice() {
        this.voiceEnabled = !this.voiceEnabled;
        const voiceButton = document.getElementById('voice-toggle');
        if (voiceButton) {
            voiceButton.textContent = this.voiceEnabled ? '🔊 Voice ON' : '🔇 Voice OFF';
            voiceButton.style.background = this.voiceEnabled ? '#080' : '#500';
        }
        app.addMessage("System", `Voice ${this.voiceEnabled ? 'enabled' : 'disabled'}`);
    }
}

const app = {
    API_URL: "/api",
    token: null,
    elements: {},
    voiceManager: null,

    init() {
        this.elements = {
            container: document.getElementById("app-container"),
            loginView: document.getElementById("login-view"),
            registerView: document.getElementById("register-view"),
            mainView: document.getElementById("main-view"),
            usernameInput: document.getElementById("username"),
            passwordInput: document.getElementById("password"),
            output: document.getElementById("output"),
            chatMessages: document.getElementById("chat-messages"),
            messageInput: document.getElementById("message-input")
        };
        
        this.voiceManager = new VoiceManager();
        this.setupEventListeners();
        
        this.token = localStorage.getItem("authToken");
        if (this.token) {
            this.showMainView();
        } else {
            this.showLoginView();
        }
    },

    setupEventListeners() {
        if (this.elements.messageInput) {
            this.elements.messageInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter') this.sendMessage();
            });
        }
    },

    showLoginView() {
        this.elements.container.classList.remove("fading-out");
        this.elements.loginView.classList.remove("hidden");
        this.elements.mainView.classList.add("hidden");
        if (this.elements.registerView) this.elements.registerView.classList.add("hidden");
    },

    showRegisterView() {
        this.elements.loginView.classList.add("hidden");
        if (this.elements.registerView) this.elements.registerView.classList.remove("hidden");
    },

    showMainView() {
        this.elements.container.classList.remove("fading-out");
        this.elements.loginView.classList.add("hidden");
        this.elements.mainView.classList.remove("hidden");
        if (this.elements.registerView) this.elements.registerView.classList.add("hidden");
        this.setOutput("R3ÆLƎR TƎCH™ Authorization complete. Welcome to R3ÆLƎR AI.");
        this.addMessage("System", "R3ÆLƎR TƎCH™ Authorization complete. Welcome to R3ÆLƎR AI.");
    },

    setOutput(content, isError = false) {
        if (this.elements.output) {
            this.elements.output.style.color = isError ? "#f00" : "#0f0";
            const output = typeof content === "string" ? content : JSON.stringify(content, null, 2);
            this.elements.output.textContent = isError ? `// ERROR: ${output}` : output;
        }
    },

    addMessage(sender, message) {
        if (this.elements.chatMessages) {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message';
            messageDiv.innerHTML = `<span class="sender">[${sender}]:</span> ${message}`;
            this.elements.chatMessages.appendChild(messageDiv);
            this.elements.chatMessages.scrollTop = this.elements.chatMessages.scrollHeight;
        }
    },

    async apiRequest(endpoint, options = {}) {
        try {
            const headers = {
                "Content-Type": "application/json",
                ...options.headers
            };
            
            if (this.token) {
                headers.Authorization = `Bearer ${this.token}`;
            }
            
            const response = await fetch(`${this.API_URL}${endpoint}`, {
                ...options,
                headers
            });
            
            const data = await response.json();
            
            if (!response.ok) {
                throw new Error(data.message || "API request failed");
            }
            
            return data;
        } catch (error) {
            this.setOutput(error.message, true);
            return null;
        }
    },

    async login() {
        const username = this.elements.usernameInput.value;
        const password = this.elements.passwordInput.value;
        
        const data = await this.apiRequest("/auth/login", {
            method: "POST",
            body: JSON.stringify({ username, password })
        });
        
        if (data && data.token) {
            this.token = data.token;
            localStorage.setItem("authToken", this.token);
            this.elements.container.classList.add("fading-out");
            setTimeout(() => this.showMainView(), 1000);
        }
    },

    async register() {
        const fullName = document.getElementById("full-name").value;
        const dateOfBirth = document.getElementById("date-of-birth").value;
        const email = document.getElementById("email").value;
        const username = document.getElementById("reg-username").value;
        const password = document.getElementById("reg-password").value;
        
        if (!fullName || !dateOfBirth || !email || !username || !password) {
            this.setOutput("Please fill in all fields", true);
            return;
        }
        
        const data = await this.apiRequest("/auth/register", {
            method: "POST",
            body: JSON.stringify({
                full_name: fullName,
                date_of_birth: dateOfBirth,
                email: email,
                username: username,
                password: password
            })
        });
        
        if (data && data.success) {
            this.setOutput(`Registration successful! Your username is: @${username}@R3ÆLƎRAI.com`);
            setTimeout(() => this.showLoginView(), 2000);
        }
    },

    async sendMessage() {
        const message = this.elements.messageInput.value.trim();
        if (!message) return;

        this.addMessage("You", message);
        this.elements.messageInput.value = '';

        const data = await this.apiRequest('/chat', {
            method: 'POST',
            body: JSON.stringify({
                message: message,
                voice_enabled: this.voiceManager.voiceEnabled
            })
        });

        if (data && data.response) {
            this.addMessage("AI", data.response);
            if (this.voiceManager.voiceEnabled) {
                this.voiceManager.speak(data.response);
            }
        }
    },

    logout() {
        this.token = null;
        localStorage.removeItem("authToken");
        this.showLoginView();
    }
};

document.addEventListener('DOMContentLoaded', () => {
    new MatrixRain();
    app.init();
    
    speechSynthesis.onvoiceschanged = () => {
        if (app.voiceManager && app.voiceManager.synthesis) {
            app.voiceManager.synthesis.getVoices();
        }
    };
});

window.app = app;