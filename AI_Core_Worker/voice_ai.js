// Voice AI with animated face
class VoiceAI {
    constructor() {
        if (!window.SpeechRecognition && !window.webkitSpeechRecognition) {
            throw new Error('Speech recognition not supported in this browser');
        }
        if (!window.speechSynthesis) {
            throw new Error('Speech synthesis not supported in this browser');
        }
        
        this.recognition = new (window.SpeechRecognition || window.webkitSpeechRecognition)();
        this.synthesis = window.speechSynthesis;
        this.isListening = false;
        this.isSpeaking = false;
        
        this.recognition.continuous = false;
        this.recognition.interimResults = false;
        this.recognition.lang = 'en-US';
        
        this.recognition.onresult = (event) => {
            const transcript = event.results[0][0].transcript;
            this.sendToAI(transcript);
        };
        
        this.recognition.onend = () => {
            this.isListening = false;
            this.updateFaceState();
        };
    }
    
    startListening() {
        if (!this.isListening && !this.isSpeaking) {
            this.isListening = true;
            this.recognition.start();
            this.updateFaceState();
        }
    }
    
    async sendToAI(message) {
        try {
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({message})
            });
            const data = await response.json();
            this.speak(data.response);
        } catch (error) {
            this.speak('Sorry, I had trouble processing that.');
        }
    }
    
    speak(text) {
        this.isSpeaking = true;
        this.updateFaceState();
        
        const utterance = new SpeechSynthesisUtterance(text);
        utterance.rate = 0.9;
        utterance.pitch = 1.1;
        
        utterance.onend = () => {
            this.isSpeaking = false;
            this.updateFaceState();
        };
        
        this.synthesis.speak(utterance);
    }
    
    updateFaceState() {
        if (app.matrixFace) {
            app.matrixFace.isListening = this.isListening;
            app.matrixFace.isSpeaking = this.isSpeaking;
        }
    }
}

// Updated MatrixFace with voice states
class MatrixFace {
    constructor() {
        this.canvas = document.createElement('canvas');
        this.ctx = this.canvas.getContext('2d');
        this.canvas.style.cssText = 'position:fixed;top:0;left:0;z-index:1000;pointer-events:none;';
        document.body.appendChild(this.canvas);
        
        this.resize();
        this.mouseX = window.innerWidth / 2;
        this.mouseY = window.innerHeight / 2;
        this.faceVisible = false;
        this.isListening = false;
        this.isSpeaking = false;
        this.mouthAnimation = 0;
        
        window.addEventListener('resize', () => this.resize());
        document.addEventListener('mousemove', (e) => {
            this.mouseX = e.clientX;
            this.mouseY = e.clientY;
        });
        
        // Click to activate voice
        this.canvas.style.pointerEvents = 'auto';
        this.canvas.addEventListener('click', () => {
            if (app.voiceAI) {
                app.voiceAI.startListening();
            }
        });
    }
    
    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
    }
    
    showFace() {
        this.faceVisible = true;
        this.animate();
    }
    
    animate() {
        if (!this.faceVisible) return;
        
        this.ctx.fillStyle = 'rgba(0,0,0,0.05)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        
        // Matrix rain
        this.ctx.fillStyle = this.isListening ? '#ffff00' : '#00ff00';
        this.ctx.font = '12px monospace';
        for (let i = 0; i < 30; i++) {
            this.ctx.fillText(Math.random() > 0.5 ? '1' : '0', 
                Math.random() * this.canvas.width, 
                Math.random() * this.canvas.height);
        }
        
        const cx = this.canvas.width / 2;
        const cy = this.canvas.height / 2;
        
        // Face outline - changes color based on state
        this.ctx.strokeStyle = this.isListening ? '#ffff00' : this.isSpeaking ? '#ff0000' : '#00ff00';
        this.ctx.lineWidth = 3;
        this.ctx.beginPath();
        this.ctx.arc(cx, cy, 80, 0, Math.PI * 2);
        this.ctx.stroke();
        
        // Eyes
        const dx = this.mouseX - cx;
        const dy = this.mouseY - cy;
        const dist = Math.sqrt(dx*dx + dy*dy);
        const lookX = (dx/dist) * Math.min(8, dist/20);
        const lookY = (dy/dist) * Math.min(8, dist/20);
        
        this.ctx.fillStyle = this.ctx.strokeStyle;
        this.ctx.beginPath();
        this.ctx.arc(cx - 25 + lookX, cy - 15 + lookY, 6, 0, Math.PI * 2);
        this.ctx.fill();
        
        this.ctx.beginPath();
        this.ctx.arc(cx + 25 + lookX, cy - 15 + lookY, 6, 0, Math.PI * 2);
        this.ctx.fill();
        
        // Animated mouth when speaking
        if (this.isSpeaking) {
            this.mouthAnimation += 0.3;
            const mouthHeight = Math.abs(Math.sin(this.mouthAnimation)) * 10 + 5;
            this.ctx.beginPath();
            this.ctx.ellipse(cx, cy + 25, 15, mouthHeight, 0, 0, Math.PI * 2);
            this.ctx.fill();
        } else {
            // Static mouth
            this.ctx.beginPath();
            this.ctx.arc(cx, cy + 25, 8, 0, Math.PI);
            this.ctx.stroke();
        }
        
        // Instructions
        if (!this.isListening && !this.isSpeaking) {
            this.ctx.fillStyle = '#00ff00';
            this.ctx.font = '16px monospace';
            this.ctx.textAlign = 'center';
            this.ctx.fillText('Click face to speak', cx, cy + 120);
        } else if (this.isListening) {
            this.ctx.fillStyle = '#ffff00';
            this.ctx.font = '16px monospace';
            this.ctx.textAlign = 'center';
            this.ctx.fillText('Listening...', cx, cy + 120);
        }
        
        requestAnimationFrame(() => this.animate());
    }
}

// Updated app object
const app = {
    token: null,
    matrixFace: null,
    voiceAI: null,
    
    init() {
        this.token = localStorage.getItem('authToken');
        if (this.token) {
            this.showVoiceView();
        } else {
            this.showLoginView();
        }
        this.setupEventListeners();
    },
    
    setupEventListeners() {
        document.getElementById('loginForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.login();
        });
    },
    
    async login() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password})
            });
            
            const data = await response.json();
            if (data.success) {
                this.token = data.token;
                localStorage.setItem('authToken', this.token);
                this.showVoiceView();
                this.initVoiceAI();
            }
        } catch (error) {
            console.error('Login error:', error);
        }
    },
    
    showLoginView() {
        document.getElementById('loginView').style.display = 'block';
        document.getElementById('chatView').style.display = 'none';
    },
    
    showVoiceView() {
        document.getElementById('loginView').style.display = 'none';
        document.getElementById('chatView').style.display = 'none';
        document.body.style.background = '#000';
    },
    
    initVoiceAI() {
        this.voiceAI = new VoiceAI();
        this.matrixFace = new MatrixFace();
        setTimeout(() => this.matrixFace.showFace(), 1000);
    }
};

document.addEventListener('DOMContentLoaded', () => app.init());