// Matrix AI Face Animation
class MatrixFace {
    constructor() {
        this.canvas = document.createElement('canvas');
        this.ctx = this.canvas.getContext('2d');
        this.canvas.style.position = 'fixed';
        this.canvas.style.top = '0';
        this.canvas.style.left = '0';
        this.canvas.style.zIndex = '1000';
        this.canvas.style.pointerEvents = 'none';
        document.body.appendChild(this.canvas);
        
        this.resize();
        this.mouseX = 0;
        this.mouseY = 0;
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
        
        this.ctx.fillStyle = 'rgba(0, 0, 0, 0.1)';
        this.ctx.fillRect(0, 0, this.canvas.width, this.canvas.height);
        
        // Draw matrix rain
        this.ctx.fillStyle = '#00ff00';
        this.ctx.font = '12px monospace';
        for (let i = 0; i < 50; i++) {
            const x = Math.random() * this.canvas.width;
            const y = Math.random() * this.canvas.height;
            this.ctx.fillText(String.fromCharCode(0x30A0 + Math.random() * 96), x, y);
        }
        
        // Draw AI face
        const centerX = this.canvas.width / 2;
        const centerY = this.canvas.height / 2;
        
        // Face outline
        this.ctx.strokeStyle = '#00ff00';
        this.ctx.lineWidth = 2;
        this.ctx.beginPath();
        this.ctx.arc(centerX, centerY, 100, 0, Math.PI * 2);
        this.ctx.stroke();
        
        // Eyes that follow cursor
        const eyeOffset = 20;
        const eyeRadius = 8;
        
        // Calculate eye direction
        const dx = this.mouseX - centerX;
        const dy = this.mouseY - centerY;
        const distance = Math.sqrt(dx * dx + dy * dy);
        const maxLook = 10;
        const lookX = distance > 0 ? (dx / distance) * Math.min(maxLook, distance / 10) : 0;
        const lookY = distance > 0 ? (dy / distance) * Math.min(maxLook, distance / 10) : 0;
        
        // Left eye
        this.ctx.fillStyle = '#00ff00';
        this.ctx.beginPath();
        this.ctx.arc(centerX - eyeOffset + lookX, centerY - 20 + lookY, eyeRadius, 0, Math.PI * 2);
        this.ctx.fill();
        
        // Right eye
        this.ctx.beginPath();
        this.ctx.arc(centerX + eyeOffset + lookX, centerY - 20 + lookY, eyeRadius, 0, Math.PI * 2);
        this.ctx.fill();
        
        requestAnimationFrame(() => this.animate());
    }
}

// Initialize on login success
function onLoginSuccess() {
    try {
        const matrixFace = new MatrixFace();
        setTimeout(() => matrixFace.showFace(), 1000);
    } catch (error) {
        console.error('Failed to initialize matrix face:', error);
    }
}