// Complete R3AL3R AI Interface - Matrix Rain to AI Face Transition
class MatrixRainSystem {
    constructor() {
        this.canvas = document.getElementById('matrix-canvas');
        if (!this.canvas) {
            console.warn('Matrix canvas element not found, creating fallback');
            this.canvas = document.createElement('canvas');
            this.canvas.id = 'matrix-canvas';
            document.body.appendChild(this.canvas);
        }
        this.ctx = this.canvas.getContext('2d');
        if (!this.ctx) {
            throw new Error('Canvas 2D context not supported');
        }
        this.isTransitioning = false;
        this.transitionProgress = 0;
        
        this.resize();
        this.initializeDrops();
        this.startAnimation();
        
        window.addEventListener('resize', () => this.resize());
    }
    
    resize() {
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
        this.initializeDrops();
    }
    
    initializeDrops() {
        this.drops = [];
        this.columns = Math.floor(this.canvas.width / 20);
        for (let i = 0; i < this.columns; i++) {
            this.drops[i] = Math.random() * this.canvas.height;
        }
    }
    
    startAnimation() {
        const animate = () => {
            this.render();
            requestAnimationFrame(animate);
        };
        animate();
    }
    
    render() {
        // Clear with fade effect
        this.ctx.fillStyle = 'rgba(0, 0, 0, 0.05)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        
        // Matrix characters
        this.ctx.fillStyle = '#00ff00';
        this.ctx.font = '15px monospace';
        
        for (let i = 0; i < this.drops.length; i++) {
            const char = Math.random() > 0.5 ? '1' : '0';
            this.ctx.fillText(char, i * 20, this.drops[i]);
            
            if (this.drops[i] > this.canvas.height && Math.random() > 0.975) {
                this.drops[i] = 0;
            }
            this.drops[i] += 20;
        }
        
        // Handle transition animation
        if (this.isTransitioning) {
            this.renderTransition();
        }
    }
    
    renderTransition() {
        this.transitionProgress += 0.02;
        const centerX = this.canvas.width / 2;
        const centerY = this.canvas.height / 2;
        
        // Converge particles to center
        this.ctx.fillStyle = `rgba(0, 255, 0, ${1 - this.transitionProgress})`;
        
        for (let i = 0; i < 50; i++) {
            const angle = (i / 50) * Math.PI * 2;
            const radius = 200 * (1 - this.transitionProgress);
            const x = centerX + Math.cos(angle) * radius;
            const y = centerY + Math.sin(angle) * radius;
            
            if (radius > 0) {
                this.ctx.fillText(Math.random() > 0.5 ? '1' : '0', x, y);
            }
        }
        
        if (this.transitionProgress >= 1) {
            this.completeTransition();
        }
    }
    
    startTransition() {
        this.isTransitioning = true;
        this.transitionProgress = 0;
        this.canvas.style.zIndex = '999';
    }
    
    completeTransition() {
        this.canvas.style.display = 'none';
        app.initializeAIInterface();
    }
}

class AIFaceSystem {
    constructor() {
        this.createCanvas();
        this.initializeProperties();
        this.setupEventListeners();
        this.startAnimation();
    }
    
    createCanvas() {
        this.canvas = document.createElement('canvas');
        this.ctx = this.canvas.getContext('2d');
        this.canvas.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100vw;
            height: 100vh;
            z-index: 1000;
            pointer-events: auto;
            cursor: pointer;
        `;
        document.body.appendChild(this.canvas);
        this.canvas.width = window.innerWidth;
        this.canvas.height = window.innerHeight;
    }
    
    initializeProperties() {
        this.mouseX = window.innerWidth / 2;
        this.mouseY = window.innerHeight / 2;
        this.isListening = false;
        this.isSpeaking = false;
        this.mouthAnimation = 0;
        this.formationProgress = 0;
        this.isForming = true;
    }
    
    setupEventListeners() {
        window.addEventListener('resize', () => {
            this.canvas.width = window.innerWidth;
            this.canvas.height = window.innerHeight;
        });
        
        document.addEventListener('mousemove', (e) => {
            this.mouseX = e.clientX;
            this.mouseY = e.clientY;
        });
        
        this.canvas.addEventListener('click', () => {
            if (!this.isForming && app.voiceSystem) {
                app.voiceSystem.startListening();
            }
        });
    }
    
    startAnimation() {
        const animate = () => {
            this.render();
            requestAnimationFrame(animate);
        };
        animate();
    }
    
    render() {
        // Clear with subtle fade
        this.ctx.fillStyle = 'rgba(0, 0, 0, 0.1)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        
        const centerX = this.canvas.width / 2;
        const centerY = this.canvas.height / 2;
        
        if (this.isForming) {
            this.renderFormation(centerX, centerY);
        } else {
            this.renderStableFace(centerX, centerY);
        }
    }
    
    renderFormation(centerX, centerY) {
        this.formationProgress += 0.03;
        
        // Particles forming the face
        this.ctx.fillStyle = '#00ff00';
        this.ctx.font = '12px monospace';
        
        for (let i = 0; i < 80; i++) {
            const angle = (i / 80) * Math.PI * 2;
            const targetRadius = 100;
            const currentRadius = targetRadius + (150 * (1 - this.formationProgress));
            
            const x = centerX + Math.cos(angle) * currentRadius;
            const y = centerY + Math.sin(angle) * currentRadius;
            
            this.ctx.fillText(Math.random() > 0.5 ? '1' : '0', x, y);
        }
        
        if (this.formationProgress >= 1) {
            this.isForming = false;
        }
    }
    
    renderStableFace(centerX, centerY) {
        // Face outline with state-based color
        const faceColor = this.isListening ? '#ffff00' : 
                         this.isSpeaking ? '#ff0000' : '#00ff00';
        
        this.ctx.strokeStyle = faceColor;
        this.ctx.lineWidth = 4;
        this.ctx.beginPath();
        this.ctx.arc(centerX, centerY, 100, 0, Math.PI * 2);
        this.ctx.stroke();
        
        // Eyes that follow cursor
        this.renderEyes(centerX, centerY, faceColor);
        
        // Mouth with animation
        this.renderMouth(centerX, centerY, faceColor);
        
        // Status display
        this.renderStatus(centerX, centerY, faceColor);
    }
    
    renderEyes(centerX, centerY, color) {
        const dx = this.mouseX - centerX;
        const dy = this.mouseY - centerY;
        const distance = Math.sqrt(dx * dx + dy * dy);
        const maxLook = 15;
        
        const lookX = (dx / distance) * Math.min(maxLook, distance / 20);
        const lookY = (dy / distance) * Math.min(maxLook, distance / 20);
        
        this.ctx.fillStyle = color;
        
        // Left eye
        this.ctx.beginPath();
        this.ctx.arc(centerX - 35 + lookX, centerY - 25 + lookY, 10, 0, Math.PI * 2);
        this.ctx.fill();
        
        // Right eye
        this.ctx.beginPath();
        this.ctx.arc(centerX + 35 + lookX, centerY - 25 + lookY, 10, 0, Math.PI * 2);
        this.ctx.fill();
    }
    
    renderMouth(centerX, centerY, color) {
        if (this.isSpeaking) {
            // Animated speaking mouth
            this.mouthAnimation += 0.5;
            const mouthHeight = Math.abs(Math.sin(this.mouthAnimation)) * 20 + 10;
            
            this.ctx.fillStyle = color;
            this.ctx.beginPath();
            this.ctx.ellipse(centerX, centerY + 35, 25, mouthHeight, 0, 0, Math.PI * 2);
            this.ctx.fill();
        } else {
            // Static mouth
            this.ctx.strokeStyle = color;
            this.ctx.lineWidth = 3;
            this.ctx.beginPath();
            this.ctx.arc(centerX, centerY + 35, 15, 0, Math.PI);
            this.ctx.stroke();
        }
    }
    
    renderStatus(centerX, centerY, color) {
        this.ctx.fillStyle = color;
        this.ctx.textAlign = 'center';
        this.ctx.font = 'bold 20px monospace';
        
        if (!this.isListening && !this.isSpeaking) {
            this.ctx.fillText('R3AL3R AI ASSISTANT', centerX, centerY + 160);
            this.ctx.font = '16px monospace';
            this.ctx.fillText('Click my face to speak', centerX, centerY + 185);
        } else if (this.isListening) {
            this.ctx.fillText('LISTENING...', centerX, centerY + 160);
        } else if (this.isSpeaking) {
            this.ctx.fillText('RESPONDING...', centerX, centerY + 160);
        }
    }
    
    updateState(listening, speaking) {
        this.isListening = listening;
        this.isSpeaking = speaking;
    }
}

class VoiceSystem {
    constructor() {
        this.initializeSpeechRecognition();
        this.initializeSpeechSynthesis();
        this.isListening = false;
        this.isSpeaking = false;
    }
    
    initializeSpeechRecognition() {
        const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
        
        if (!SpeechRecognition) {
            console.error('Speech recognition not supported');
            return;
        }
        
        this.recognition = new SpeechRecognition();
        this.recognition.continuous = false;
        this.recognition.interimResults = false;
        this.recognition.lang = 'en-US';
        
        this.recognition.onstart = () => {
            this.isListening = true;
            this.updateFaceState();
        };
        
        this.recognition.onresult = (event) => {
            const transcript = event.results[0][0].transcript;
            this.processUserInput(transcript);
        };
        
        this.recognition.onend = () => {
            this.isListening = false;
            this.updateFaceState();
        };
        
        this.recognition.onerror = (event) => {
            console.error('Speech recognition error:', event.error);
            this.isListening = false;
            this.updateFaceState();
        };
    }
    
    initializeSpeechSynthesis() {
        this.synthesis = window.speechSynthesis;
        
        if (!this.synthesis) {
            console.error('Speech synthesis not supported');
        }
    }
    
    startListening() {
        if (this.isListening || this.isSpeaking) return;
        
        try {
            this.recognition.start();
        } catch (error) {
            console.error('Failed to start recognition:', error);
        }
    }
    
    async processUserInput(message) {
        try {
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': getCSRFToken()
                },
                body: JSON.stringify({ message })
            });
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            this.speakResponse(data.response || 'I apologize, but I received an empty response.');
            
        } catch (error) {
            console.error('Error processing user input:', error);
            this.speakResponse('I apologize, but I encountered an error processing your request. Please try again.');
        }
    }
    
    speakResponse(text) {
        if (!this.synthesis) return;
        
        this.isSpeaking = true;
        this.updateFaceState();
        
        const sanitizedText = this.sanitizeText(text);
        const utterance = new SpeechSynthesisUtterance(sanitizedText);
        utterance.rate = 0.9;
        utterance.pitch = 1.1;
        utterance.volume = 0.8;
        
        utterance.onstart = () => {
            this.isSpeaking = true;
            this.updateFaceState();
        };
        
        utterance.onend = () => {
            this.isSpeaking = false;
            this.updateFaceState();
        };
        
        utterance.onerror = (event) => {
            console.error('Speech synthesis error:', event.error);
            this.isSpeaking = false;
            this.updateFaceState();
        };
        
        this.synthesis.speak(utterance);
    }
    
    sanitizeText(text) {
        return text.replace(/<[^>]*>/g, '').replace(/[<>"'&]/g, '');
    }
    
    updateFaceState() {
        if (app.aiFace) {
            app.aiFace.updateState(this.isListening, this.isSpeaking);
        }
    }
}

// CSRF Token Management
function getCSRFToken() {
    const token = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || 
                  document.cookie.split('; ').find(row => row.startsWith('csrf_token='))?.split('=')[1];
    return token;
}

// Main Application Controller
const app = {
    matrixRain: null,
    aiFace: null,
    voiceSystem: null,
    token: null,
    
    initialize() {
        this.token = localStorage.getItem('authToken');
        this.matrixRain = new MatrixRainSystem();
        
        // If already logged in, skip to AI interface
        if (this.token) {
            setTimeout(() => this.transitionToAI(), 1000);
        }
    },
    
    async login() {
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();
        
        if (!username || !password) {
            alert('Please enter both username and password');
            return;
        }
        
        try {
            const response = await fetch('/api/auth/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': getCSRFToken()
                },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (data.success) {
                this.token = data.token;
                localStorage.setItem('authToken', this.token);
                this.transitionToAI();
            } else {
                alert('Login failed: ' + (data.error || 'Invalid credentials'));
            }
            
        } catch (error) {
            console.error('Login error:', error);
            alert('Login failed: Network error');
        }
    },
    
    async register() {
        const formData = {
            full_name: document.getElementById('full-name').value.trim(),
            date_of_birth: document.getElementById('date-of-birth').value,
            email: document.getElementById('email').value.trim(),
            username: document.getElementById('reg-username').value.trim(),
            password: document.getElementById('reg-password').value.trim()
        };
        
        // Validate required fields
        if (!formData.full_name || !formData.date_of_birth || !formData.email || 
            !formData.username || !formData.password) {
            alert('Please fill in all fields');
            return;
        }
        
        try {
            const response = await fetch('/api/auth/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': getCSRFToken()
                },
                body: JSON.stringify(formData)
            });
            
            const data = await response.json();
            
            if (data.success) {
                alert('Registration successful! Please login with your credentials.');
                this.showLoginView();
            } else {
                alert('Registration failed: ' + (data.error || 'Unknown error'));
            }
            
        } catch (error) {
            console.error('Registration error:', error);
            alert('Registration failed: Network error');
        }
    },
    
    showLoginView() {
        document.getElementById('login-view').classList.remove('hidden');
        document.getElementById('register-view').classList.add('hidden');
    },
    
    showRegisterView() {
        document.getElementById('login-view').classList.add('hidden');
        document.getElementById('register-view').classList.remove('hidden');
    },
    
    transitionToAI() {
        // Hide login interface
        document.getElementById('app-container').style.display = 'none';
        
        // Start matrix rain transition
        this.matrixRain.startTransition();
    },
    
    initializeAIInterface() {
        // Set full black background
        document.body.style.background = '#000';
        document.body.style.overflow = 'hidden';
        
        // Initialize AI systems
        this.voiceSystem = new VoiceSystem();
        this.aiFace = new AIFaceSystem();
    },
    
    logout() {
        localStorage.removeItem('authToken');
        location.reload();
    }
};

// Initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    app.initialize();
});

// Handle Enter key for login
document.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        const loginView = document.getElementById('login-view');
        const registerView = document.getElementById('register-view');
        
        if (loginView && !loginView.classList.contains('hidden')) {
            app.login();
        } else if (registerView && !registerView.classList.contains('hidden')) {
            app.register();
        }
    }
});

// Export for global access
window.app = app;