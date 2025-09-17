// Matrix Rain Background
class MatrixRain {
    constructor() {
        this.canvas = document.createElement('canvas');
        this.ctx = this.canvas.getContext('2d');
        this.canvas.style.cssText = 'position:fixed;top:0;left:0;z-index:-1;';
        document.body.appendChild(this.canvas);
        
        this.resize();
        this.drops = [];
        this.initDrops();
        this.animate();
        
        window.addEventListener('resize', () => this.resize());
    }
    
    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
        this.initDrops();
    }
    
    initDrops() {
        this.drops = [];
        const columns = Math.floor(this.canvas.width / 20);
        for (let i = 0; i < columns; i++) {
            this.drops[i] = Math.random() * this.canvas.height;
        }
    }
    
    animate() {
        this.ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        
        this.ctx.fillStyle = '#00ff00';
        this.ctx.font = '15px monospace';
        
        for (let i = 0; i < this.drops.length; i++) {
            const text = Math.random() > 0.5 ? '1' : '0';
            this.ctx.fillText(text, i * 20, this.drops[i]);
            
            if (this.drops[i] > this.canvas.height && Math.random() > 0.975) {
                this.drops[i] = 0;
            }
            this.drops[i] += 20;
        }
        
        requestAnimationFrame(() => this.animate());
    }
    
    transitionToFace() {
        // Animate rain particles moving to center to form face
        this.canvas.style.zIndex = '999';
        setTimeout(() => {
            this.canvas.style.display = 'none';
        }, 2000);
    }
}

// AI Face Assistant
class AIFace {
    constructor() {
        this.canvas = document.createElement('canvas');
        this.ctx = this.canvas.getContext('2d');
        this.canvas.style.cssText = 'position:fixed;top:0;left:0;z-index:1000;pointer-events:auto;cursor:pointer;';
        document.body.appendChild(this.canvas);
        
        this.resize();
        this.mouseX = window.innerWidth / 2;
        this.mouseY = window.innerHeight / 2;
        this.isListening = false;
        this.isSpeaking = false;
        this.mouthAnimation = 0;
        this.formingAnimation = 0;
        this.isForming = true;
        
        this.setupEventListeners();
        this.animate();
    }
    
    setupEventListeners() {
        window.addEventListener('resize', () => this.resize());
        document.addEventListener('mousemove', (e) => {
            this.mouseX = e.clientX;
            this.mouseY = e.clientY;
        });
        
        this.canvas.addEventListener('click', () => {
            if (!this.isForming && app.voiceAI) {
                app.voiceAI.startListening();
            }
        });
    }
    
    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
    }
    
    animate() {
        this.ctx.fillStyle = 'rgba(0,0,0,0.1)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        
        const cx = this.canvas.width / 2;
        const cy = this.canvas.height / 2;
        
        if (this.isForming) {
            this.formingAnimation += 0.02;
            
            // Particles converging to form face
            this.ctx.fillStyle = '#00ff00';
            this.ctx.font = '12px monospace';
            
            for (let i = 0; i < 100; i++) {
                const angle = (i / 100) * Math.PI * 2;
                const radius = 200 - (this.formingAnimation * 150);
                const x = cx + Math.cos(angle) * Math.max(0, radius);
                const y = cy + Math.sin(angle) * Math.max(0, radius);
                
                if (radius > 0) {
                    this.ctx.fillText(Math.random() > 0.5 ? '1' : '0', x, y);
                }
            }
            
            if (this.formingAnimation >= 1) {
                this.isForming = false;
            }
        } else {
            // Stable AI face
            this.ctx.strokeStyle = this.isListening ? '#ffff00' : this.isSpeaking ? '#ff0000' : '#00ff00';
            this.ctx.lineWidth = 4;
            this.ctx.beginPath();
            this.ctx.arc(cx, cy, 100, 0, Math.PI * 2);
            this.ctx.stroke();
            
            // Eyes following cursor
            const dx = this.mouseX - cx;
            const dy = this.mouseY - cy;
            const dist = Math.sqrt(dx*dx + dy*dy);
            const lookX = (dx/dist) * Math.min(12, dist/15);
            const lookY = (dy/dist) * Math.min(12, dist/15);
            
            this.ctx.fillStyle = this.ctx.strokeStyle;
            this.ctx.beginPath();
            this.ctx.arc(cx - 30 + lookX, cy - 20 + lookY, 8, 0, Math.PI * 2);
            this.ctx.fill();
            
            this.ctx.beginPath();
            this.ctx.arc(cx + 30 + lookX, cy - 20 + lookY, 8, 0, Math.PI * 2);
            this.ctx.fill();
            
            // Animated mouth
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
            
            // Status text
            this.ctx.textAlign = 'center';
            this.ctx.font = '18px monospace';
            if (!this.isListening && !this.isSpeaking) {
                this.ctx.fillStyle = '#00ff00';
                this.ctx.fillText('R3AL3R AI ASSISTANT', cx, cy + 150);
                this.ctx.font = '14px monospace';
                this.ctx.fillText('Click to speak', cx, cy + 170);
            } else if (this.isListening) {
                this.ctx.fillStyle = '#ffff00';
                this.ctx.fillText('LISTENING...', cx, cy + 150);
            } else if (this.isSpeaking) {
                this.ctx.fillStyle = '#ff0000';
                this.ctx.fillText('RESPONDING...', cx, cy + 150);
            }
        }
        
        requestAnimationFrame(() => this.animate());
    }
}

// Voice AI Controller
class VoiceAI {
    constructor() {
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
            const response = await fetch(`${window.location.protocol === 'https:' ? 'https:' : 'https:'}//${window.location.host}/api/chat`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({message})
            });
            const data = await response.json();
            this.speak(data.response);
        } catch (error) {
            this.speak('I apologize, but I encountered an error processing your request.');
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
        if (app.aiFace) {
            app.aiFace.isListening = this.isListening;
            app.aiFace.isSpeaking = this.isSpeaking;
        }
    }
}

// Main App Controller
const app = {
    token: null,
    matrixRain: null,
    aiFace: null,
    voiceAI: null,
    
    init() {
        this.token = localStorage.getItem('authToken');
        this.matrixRain = new MatrixRain();
        
        if (this.token) {
            this.showAIInterface();
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
        
        document.getElementById('registerForm')?.addEventListener('submit', (e) => {
            e.preventDefault();
            this.register();
        });
    },
    
    async login() {
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        try {
            const response = await fetch(`${window.location.protocol === 'https:' ? 'https:' : 'https:'}//${window.location.host}/api/auth/login`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({username, password})
            });
            
            const data = await response.json();
            if (data.success) {
                this.token = data.token;
                localStorage.setItem('authToken', this.token);
                this.transitionToAI();
            }
        } catch (error) {
            console.error('Login error:', error);
        }
    },
    
    async register() {
        const formData = {
            full_name: document.getElementById('fullName').value,
            date_of_birth: document.getElementById('dob').value,
            email: document.getElementById('email').value,
            username: document.getElementById('regUsername').value,
            password: document.getElementById('regPassword').value
        };
        
        try {
            const response = await fetch(`${window.location.protocol === 'https:' ? 'https:' : 'https:'}//${window.location.host}/api/auth/register`, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify(formData)
            });
            
            const data = await response.json();
            if (data.success) {
                alert('Registration successful! Please login.');
                this.showLoginView();
            }
        } catch (error) {
            console.error('Registration error:', error);
        }
    },
    
    showLoginView() {
        document.getElementById('loginView').style.display = 'block';
        document.getElementById('registerView').style.display = 'none';
    },
    
    showRegisterView() {
        document.getElementById('loginView').style.display = 'none';
        document.getElementById('registerView').style.display = 'block';
    },
    
    transitionToAI() {
        // Hide login forms
        document.getElementById('loginView').style.display = 'none';
        document.getElementById('registerView').style.display = 'none';
        
        // Transition matrix rain to form AI face
        this.matrixRain.transitionToFace();
        
        // Initialize AI interface after transition
        setTimeout(() => {
            this.showAIInterface();
        }, 1000);
    },
    
    showAIInterface() {
        document.body.style.background = '#000';
        this.voiceAI = new VoiceAI();
        this.aiFace = new AIFace();
    }
};

// Initialize app when DOM is ready
document.addEventListener('DOMContentLoaded', () => app.init());