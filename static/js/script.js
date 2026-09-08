/**
 * Sentinel Cyber Defense Console — Interactive Threat Telemetry Network
 * Renders an interactive, high-performance cybersecurity node graph and 
 * data packet telemetry background.
 */

(function () {
    'use strict';

    document.addEventListener('DOMContentLoaded', () => {
        initCyberTelemetryCanvas();
    });

    function initCyberTelemetryCanvas() {
        const canvas = document.getElementById('cyber-canvas');
        if (!canvas) return;

        const ctx = canvas.getContext('2d');
        if (!ctx) return;

        let width = (canvas.width = window.innerWidth);
        let height = (canvas.height = window.innerHeight);

        let animationFrameId = null;
        let isRunning = true;

        // Mouse tracking for interactive threat radar link
        const mouse = {
            x: -1000,
            y: -1000,
            radius: 160,
            active: false
        };

        window.addEventListener('mousemove', (e) => {
            mouse.x = e.clientX;
            mouse.y = e.clientY;
            mouse.active = true;
        }, { passive: true });

        window.addEventListener('mouseleave', () => {
            mouse.x = -1000;
            mouse.y = -1000;
            mouse.active = false;
        });

        // Resize handler with debounce
        let resizeTimeout;
        window.addEventListener('resize', () => {
            clearTimeout(resizeTimeout);
            resizeTimeout = setTimeout(() => {
                width = canvas.width = window.innerWidth;
                height = canvas.height = window.innerHeight;
                initNodes();
            }, 150);
        }, { passive: true });

        // Node definitions
        const NODE_COUNT = width < 768 ? 24 : 52;
        const CONNECTION_DIST = width < 768 ? 95 : 135;
        const PACKET_CHANCE = 0.015;

        const COLOR_PALETTE = [
            { r: 6, g: 182, b: 212 },   // Cyan (Primary Cyber)
            { r: 59, g: 130, b: 246 },  // Cobalt Blue
            { r: 99, g: 102, b: 241 },  // Indigo
            { r: 16, g: 185, b: 129 },  // Emerald (Safe Node)
            { r: 244, g: 63, b: 94 }    // Rose (Threat Beacon)
        ];

        let nodes = [];
        let packets = [];

        class CyberNode {
            constructor() {
                this.reset();
            }

            reset() {
                this.x = Math.random() * width;
                this.y = Math.random() * height;
                this.vx = (Math.random() - 0.5) * 0.45;
                this.vy = (Math.random() - 0.5) * 0.45;
                this.radius = Math.random() * 1.8 + 1.2;
                this.baseAlpha = Math.random() * 0.4 + 0.3;
                this.pulseSpeed = Math.random() * 0.03 + 0.01;
                this.pulsePhase = Math.random() * Math.PI * 2;
                
                // Color selection (majority cyan/indigo, occasional threat beacon)
                const isThreat = Math.random() < 0.12;
                this.color = isThreat ? COLOR_PALETTE[4] : COLOR_PALETTE[Math.floor(Math.random() * 4)];
                this.isThreat = isThreat;
            }

            update() {
                this.x += this.vx;
                this.y += this.vy;

                // Bounce at edges smoothly
                if (this.x < 0 || this.x > width) this.vx *= -1;
                if (this.y < 0 || this.y > height) this.vy *= -1;

                this.pulsePhase += this.pulseSpeed;

                // Subtle mouse gravity
                if (mouse.active) {
                    const dx = mouse.x - this.x;
                    const dy = mouse.y - this.y;
                    const dist = Math.sqrt(dx * dx + dy * dy);
                    if (dist < mouse.radius && dist > 10) {
                        const force = (1 - dist / mouse.radius) * 0.25;
                        this.x += (dx / dist) * force;
                        this.y += (dy / dist) * force;
                    }
                }
            }

            draw() {
                const pulse = Math.sin(this.pulsePhase) * 0.25;
                const currentAlpha = Math.max(0.1, Math.min(1, this.baseAlpha + pulse));
                const currentRadius = Math.max(1, this.radius + (this.isThreat ? pulse * 1.5 : pulse * 0.5));

                ctx.beginPath();
                ctx.arc(this.x, this.y, currentRadius, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, ${currentAlpha})`;
                ctx.fill();

                // Glow ring around threat beacons
                if (this.isThreat) {
                    ctx.beginPath();
                    ctx.arc(this.x, this.y, currentRadius * 3, 0, Math.PI * 2);
                    ctx.strokeStyle = `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, ${currentAlpha * 0.25})`;
                    ctx.lineWidth = 1;
                    ctx.stroke();
                }
            }
        }

        class DataPacket {
            constructor(nodeA, nodeB) {
                this.nodeA = nodeA;
                this.nodeB = nodeB;
                this.progress = 0;
                this.speed = Math.random() * 0.015 + 0.008;
                this.color = Math.random() < 0.2 ? 'rgba(244, 63, 94, 0.9)' : 'rgba(6, 182, 212, 0.9)';
            }

            update() {
                this.progress += this.speed;
                return this.progress < 1;
            }

            draw() {
                const px = this.nodeA.x + (this.nodeB.x - this.nodeA.x) * this.progress;
                const py = this.nodeA.y + (this.nodeB.y - this.nodeA.y) * this.progress;

                ctx.beginPath();
                ctx.arc(px, py, 2, 0, Math.PI * 2);
                ctx.fillStyle = this.color;
                ctx.shadowColor = this.color;
                ctx.shadowBlur = 6;
                ctx.fill();
                ctx.shadowBlur = 0;
            }
        }

        function initNodes() {
            nodes = [];
            packets = [];
            for (let i = 0; i < NODE_COUNT; i++) {
                nodes.push(new CyberNode());
            }
        }

        function render() {
            if (!isRunning) return;

            ctx.clearRect(0, 0, width, height);

            // 1. Update and draw nodes
            for (let i = 0; i < nodes.length; i++) {
                nodes[i].update();
                nodes[i].draw();
            }

            // 2. Draw connections between nearby nodes
            for (let i = 0; i < nodes.length; i++) {
                for (let j = i + 1; j < nodes.length; j++) {
                    const dx = nodes[i].x - nodes[j].x;
                    const dy = nodes[i].y - nodes[j].y;
                    const dist = Math.sqrt(dx * dx + dy * dy);

                    if (dist < CONNECTION_DIST) {
                        const alpha = (1 - dist / CONNECTION_DIST) * 0.22;
                        ctx.beginPath();
                        ctx.moveTo(nodes[i].x, nodes[i].y);
                        ctx.lineTo(nodes[j].x, nodes[j].y);

                        // Gradient line between node colors
                        ctx.strokeStyle = `rgba(6, 182, 212, ${alpha})`;
                        ctx.lineWidth = 0.85;
                        ctx.stroke();

                        // Occasionally spawn a moving data packet along active connection
                        if (Math.random() < PACKET_CHANCE && packets.length < 8) {
                            packets.push(new DataPacket(nodes[i], nodes[j]));
                        }
                    }
                }

                // Interactive connection to mouse
                if (mouse.active) {
                    const mdx = nodes[i].x - mouse.x;
                    const mdy = nodes[i].y - mouse.y;
                    const mdist = Math.sqrt(mdx * mdx + mdy * mdy);

                    if (mdist < mouse.radius) {
                        const mAlpha = (1 - mdist / mouse.radius) * 0.45;
                        ctx.beginPath();
                        ctx.moveTo(nodes[i].x, nodes[i].y);
                        ctx.lineTo(mouse.x, mouse.y);
                        ctx.strokeStyle = `rgba(56, 189, 248, ${mAlpha})`;
                        ctx.lineWidth = 1;
                        ctx.stroke();
                    }
                }
            }

            // 3. Update and draw data packets
            for (let p = packets.length - 1; p >= 0; p--) {
                const packet = packets[p];
                if (packet.update()) {
                    packet.draw();
                } else {
                    packets.splice(p, 1);
                }
            }

            animationFrameId = requestAnimationFrame(render);
        }

        // Pause animation when tab is inactive to preserve CPU / battery
        document.addEventListener('visibilitychange', () => {
            if (document.hidden) {
                isRunning = false;
                if (animationFrameId) cancelAnimationFrame(animationFrameId);
            } else {
                if (!isRunning) {
                    isRunning = true;
                    render();
                }
            }
        });

        initNodes();
        render();
    }
})();
