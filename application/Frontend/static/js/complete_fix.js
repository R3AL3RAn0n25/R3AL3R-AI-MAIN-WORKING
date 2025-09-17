// Complete working chat and matrix face
const app = {
    token: null,
    matrixFace: null,
    
    init() {
        this.token = localStorage.getItem('authToken');
        if (this.token) {
            this.showChatView();
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
        
        document.getElementById('messageInput')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                this.sendMessage();
            }
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
                this.showChatView();
                this.initMatrixFace();
            }
        } catch (error) {
            console.error('Login error:', error);
        }
    },
    
    async sendMessage() {
        const input = document.getElementById('messageInput');
        const message = input.value.trim();
        if (!message) return;
        
        input.value = '';
        this.addMessage(message, 'user');
        
        try {
            const response = await fetch('/api/chat', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({message})
            });
            const data = await response.json();
            this.addMessage(data.response, 'ai');
        } catch (error) {
            this.addMessage('Error connecting to AI', 'ai');
        }
    },
    
    addMessage(text, sender) {
        const messages = document.getElementById('messages');
        const div = document.createElement('div');
        div.className = `message ${sender}`;
        div.textContent = text;
        messages.appendChild(div);
        messages.scrollTop = messages.scrollHeight;
    },
    
    showLoginView() {
        document.getElementById('loginView').style.display = 'block';
        document.getElementById('chatView').style.display = 'none';
    },
    
    showChatView() {
        document.getElementById('loginView').style.display = 'none';
        document.getElementById('chatView').style.display = 'block';
    },
    
    initMatrixFace() {
        if (!this.matrixFace) {
            this.matrixFace = new MatrixFace();
            setTimeout(() => this.matrixFace.showFace(), 1000);
        }
    }
};

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
        
        window.addEventListener('resize', () => this.resize());
        document.addEventListener('mousemove', (e) => {
            this.mouseX = e.clientX;
            this.mouseY = e.clientY;
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
        this.ctx.fillStyle = '#00ff00';
        this.ctx.font = '12px monospace';
        for (let i = 0; i < 30; i++) {
            this.ctx.fillText(Math.random() > 0.5 ? '1' : '0', 
                Math.random() * this.canvas.width, 
                Math.random() * this.canvas.height);
        }
        
        // AI Face
        const cx = this.canvas.width / 2;
        const cy = this.canvas.height / 2;
        
        this.ctx.strokeStyle = '#00ff00';
        this.ctx.lineWidth = 2;
        this.ctx.beginPath();
        this.ctx.arc(cx, cy, 80, 0, Math.PI * 2);
        this.ctx.stroke();
        
        // Eyes following cursor
        const dx = this.mouseX - cx;
        const dy = this.mouseY - cy;
        const dist = Math.sqrt(dx*dx + dy*dy);
        const lookX = (dx/dist) * Math.min(8, dist/20);
        const lookY = (dy/dist) * Math.min(8, dist/20);
        
        this.ctx.fillStyle = '#00ff00';
        this.ctx.beginPath();
        this.ctx.arc(cx - 25 + lookX, cy - 15 + lookY, 6, 0, Math.PI * 2);
        this.ctx.fill();
        
        this.ctx.beginPath();
        this.ctx.arc(cx + 25 + lookX, cy - 15 + lookY, 6, 0, Math.PI * 2);
        this.ctx.fill();
        
        requestAnimationFrame(() => this.animate());
    }
}

document.addEventListener('DOMContentLoaded', () => app.init());