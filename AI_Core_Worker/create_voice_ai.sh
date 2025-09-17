#!/bin/bash
cat > /home/ubuntu/r3aler-ai/application/Frontend/static/js/app.js << 'EOF'
class VoiceAI {
    constructor() {
        if (!('webkitSpeechRecognition' in window) && !('SpeechRecognition' in window)) {
            throw new Error('Speech recognition not supported');
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
        
        this.recognition.onerror = (event) => {
            this.isListening = false;
            this.updateFaceState();
            console.error('Speech recognition error:', event.error);
        };
    }
    
    startListening() {
        if (!this.isListening && !this.isSpeaking) {
            this.isListening = true;
            try {
                this.recognition.start();
            } catch (error) {
                this.isListening = false;
                console.error('Speech recognition start error:', error);
            }
            this.updateFaceState();
        }
    }
    
    async sendToAI(message) {
        try {
            const headers = {
                'Content-Type': 'application/json'
            };
            
            if (app.token) {
                headers['Authorization'] = `Bearer ${app.token}`;
            }
            
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: headers,
                body: JSON.stringify({message})
            });
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}`);
            }
            
            const data = await response.json();
            if (data.response) {
                this.speak(data.response);
            } else {
                this.speak('I received an empty response.');
            }
        } catch (error) {
            console.error('AI request error:', error);
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

class MatrixFace {
    constructor() {
        this.canvas = document.createElement('canvas');
        this.ctx = this.canvas.getContext('2d');
        this.canvas.style.cssText = 'position:fixed;top:0;left:0;z-index:1000;pointer-events:auto;cursor:pointer;';
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
        
        this.ctx.fillStyle = 'rgba(0,0,0,0.1)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        
        this.ctx.fillStyle = this.isListening ? '#ffff00' : '#00ff00';
        this.ctx.font = '12px monospace';
        for (let i = 0; i < 50; i++) {
            this.ctx.fillText(Math.random() > 0.5 ? '1' : '0', 
                Math.random() * this.canvas.width, 
                Math.random() * this.canvas.height);
        }
        
        const cx = this.canvas.width / 2;
        const cy = this.canvas.height / 2;
        
        this.ctx.strokeStyle = this.isListening ? '#ffff00' : this.isSpeaking ? '#ff0000' : '#00ff00';
        this.ctx.lineWidth = 4;
        this.ctx.beginPath();
        this.ctx.arc(cx, cy, 100, 0, Math.PI * 2);
        this.ctx.stroke();
        
        const dx = this.mouseX - cx;
        const dy = this.mouseY - cy;
        const dist = Math.sqrt(dx*dx + dy*dy);
        const lookX = dist > 0 ? (dx/dist) * Math.min(12, dist/15) : 0;
        const lookY = dist > 0 ? (dy/dist) * Math.min(12, dist/15) : 0;
        
        this.ctx.fillStyle = this.ctx.strokeStyle;
        this.ctx.beginPath();
        this.ctx.arc(cx - 30 + lookX, cy - 20 + lookY, 8, 0, Math.PI * 2);
        this.ctx.fill();
        
        this.ctx.beginPath();
        this.ctx.arc(cx + 30 + lookX, cy - 20 + lookY, 8, 0, Math.PI * 2);
        this.ctx.fill();
        
        if (this.isSpeaking) {
            this.mouthAnimation += 0.4;
            const mouthHeight = Math.abs(Math.sin(this.mouthAnimation)) * 15 + 8;
            this.ctx.beginPath();
            this.ctx.ellipse(cx, cy + 30, 20, mouthHeight, 0, 0, Math.PI * 2);
            this.ctx.fill();
        } else {
            this.ctx.beginPath();
            this.ctx.arc(cx, cy + 30, 12, 0, Math.PI);
            this.ctx.stroke();
        }
        
        this.ctx.textAlign = 'center';
        if (!this.isListening && !this.isSpeaking) {
            this.ctx.fillStyle = '#00ff00';
            this.ctx.font = '18px monospace';
            this.ctx.fillText('CLICK TO SPEAK', cx, cy + 150);
        } else if (this.isListening) {
            this.ctx.fillStyle = '#ffff00';
            this.ctx.font = '18px monospace';
            this.ctx.fillText('LISTENING...', cx, cy + 150);
        } else if (this.isSpeaking) {
            this.ctx.fillStyle = '#ff0000';
            this.ctx.font = '18px monospace';
            this.ctx.fillText('SPEAKING...', cx, cy + 150);
        }
        
        requestAnimationFrame(() => this.animate());
    }
}

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
        try {
            this.voiceAI = new VoiceAI();
            this.matrixFace = new MatrixFace();
            setTimeout(() => this.matrixFace.showFace(), 1000);
        } catch (error) {
            console.error('Voice AI initialization failed:', error);
            alert('Voice recognition is not supported in this browser.');
        }
    }
};

document.addEventListener('DOMContentLoaded', () => app.init());
EOF