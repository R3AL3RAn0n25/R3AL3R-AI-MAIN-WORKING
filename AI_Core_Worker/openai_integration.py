"""
R3ÆLƎR AI - OpenAI API Integration
Provides real AI responses using OpenAI's GPT models
"""
import openai
import logging
from typing import Dict, List, Optional
import json

class OpenAIIntegration:
    """OpenAI API integration for R3ÆLƎR AI"""
    
    def __init__(self, api_key: str, model: str = "gpt-3.5-turbo"):
        self.client = openai.OpenAI(api_key=api_key)
        self.model = model
        self.max_tokens = 1000
        self.temperature = 0.7
        
    def generate_response(self, system_prompt: str, user_message: str, 
                         conversation_history: List[Dict] = None) -> str:
        """Generate AI response using OpenAI API"""
        try:
            messages = [{"role": "system", "content": system_prompt}]
            
            # Add conversation history
            if conversation_history:
                for msg in conversation_history[-5:]:  # Last 5 messages for context
                    messages.append({"role": "user", "content": msg.get("user", "")})
                    messages.append({"role": "assistant", "content": msg.get("ai", "")})
            
            # Add current user message
            messages.append({"role": "user", "content": user_message})
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=messages,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                presence_penalty=0.1,
                frequency_penalty=0.1
            )
            
            return response.choices[0].message.content.strip()
            
        except Exception as e:
            logging.error(f"OpenAI API error: {e}")
            return f"I encountered an issue processing that request. Could you try rephrasing your question?"
    
    def generate_code(self, language: str, task: str, requirements: str = "") -> Dict:
        """Generate code using OpenAI with R3ÆLƎR security focus"""
        system_prompt = """You are R3ÆLƎR AI, an elite software architect and security analyst.
        Generate secure, scalable, and maintainable code following these principles:
        1. Security First: Consider OWASP Top 10, input sanitization, secure libraries
        2. Clean Code: Well-documented, meaningful variable names, proper structure
        3. Performance: Efficient algorithms and data structures
        4. Explain your approach and any security considerations"""
        
        user_prompt = f"Language: {language}\nTask: {task}\nRequirements: {requirements}"
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=1500,
                temperature=0.3  # Lower temperature for code generation
            )
            
            content = response.choices[0].message.content.strip()
            
            return {
                "code": content,
                "language": language,
                "security_focused": True,
                "explanation": "Generated with R3ÆLƎR security principles"
            }
            
        except Exception as e:
            logging.error(f"Code generation error: {e}")
            return {
                "error": str(e),
                "fallback": "I encountered an issue generating code. Please check your request and try again."
            }
    
    def analyze_forensics(self, file_info: str, analysis_type: str) -> Dict:
        """Forensic analysis using OpenAI with R3ÆLƎR expertise"""
        system_prompt = """You are R3ÆLƎR AI, a world-class digital forensics expert.
        Provide precise, factual analysis based on forensic principles:
        1. Reference authoritative sources (Bitcoin Wiki, BIPs, Berkeley DB docs)
        2. Always recommend working on evidence copies
        3. Provide step-by-step forensic methodology
        4. Explain technical reasoning for each step
        5. Emphasize legal compliance and proper authorization"""
        
        user_prompt = f"File Context: {file_info}\nAnalysis Type: {analysis_type}"
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                max_tokens=1200,
                temperature=0.2  # Very low temperature for forensic accuracy
            )
            
            return {
                "forensic_analysis": response.choices[0].message.content.strip(),
                "methodology": "R3ÆLƎR forensic principles applied",
                "legal_notice": "Analysis for authorized forensic/recovery purposes only"
            }
            
        except Exception as e:
            logging.error(f"Forensic analysis error: {e}")
            return {
                "error": str(e),
                "recommendation": "Please verify your analysis request and ensure proper authorization"
            }
    
    def set_model_parameters(self, model: str = None, temperature: float = None, 
                           max_tokens: int = None):
        """Update model parameters"""
        if model:
            self.model = model
        if temperature is not None:
            self.temperature = max(0.0, min(2.0, temperature))
        if max_tokens:
            self.max_tokens = max_tokens
            
        logging.info(f"Updated OpenAI parameters: model={self.model}, temp={self.temperature}, tokens={self.max_tokens}")