"""
core_ai.py - The R3ÆLƎR AI Core Engine
Contains the main RealerAI class, and adaptation logic.
"""
import time
import datetime
import logging
try:
    import usb.core
except ImportError:
    logging.warning("PyUSB library not found. Soul key validation will be simulated.")
    usb = None

from innovations import HeartStorage
from prompts import R3AELERPrompts
from openai_integration import OpenAIIntegration

class RealerAI:
    """The core AI class with adaptation and soul key validation."""
    
    # Class-level constants for keyword categorization
    CRYPTO_WORDS = {'bitcoin', 'cryptocurrency', 'wallet'}
    TECH_WORDS = {'code', 'programming', 'python'}
    FORENSIC_WORDS = {'forensics', 'investigation', 'analysis'}
    MAX_ADAPTABILITY_WITHOUT_APPROVAL = 5
    
    # Domain to prompt mapping
    DOMAIN_PROMPTS = {
        "technology": "CODE_GENERATION_SYSTEM_PROMPT",
        "cryptocurrency": "CRYPTO_FORENSICS_SYSTEM_PROMPT", 
        "forensics": "CRYPTO_FORENSICS_SYSTEM_PROMPT",
        "mobile": "MOBILE_FORENSICS_SYSTEM_PROMPT"
    }
    
    def __init__(self, config, db_connector, openai_api_key=None):
        self.config = config
        self.insights = []
        self.adaptability_level = 1
        self.heart = HeartStorage(db_connector)
        self.last_adaptation = 0
        
        # Initialize OpenAI integration if API key provided
        self.openai_integration = None
        if openai_api_key:
            try:
                self.openai_integration = OpenAIIntegration(openai_api_key)
                logging.info("OpenAI integration initialized successfully")
            except Exception as e:
                logging.error(f"Failed to initialize OpenAI: {e}")
                self.openai_integration = None
    
    def generate_insight(self, data, user_id=None):
        # Generate more meaningful insights based on data content
        data_str = str(data)
        data_lower = data_str.lower()
        data_preview = data_str[:50]
        data_words = set(data_lower.split())  # Single tokenization
        
        if self.CRYPTO_WORDS & data_words:
            insight = f"Cryptocurrency-related query detected: {data_preview}... - User showing interest in blockchain technology"
        elif self.TECH_WORDS & data_words:
            insight = f"Technical development query: {data_preview}... - User seeking programming assistance"
        elif self.FORENSIC_WORDS & data_words:
            insight = f"Forensic analysis request: {data_preview}... - Professional investigation context"
        else:
            insight = f"General inquiry: {data_preview}... - Exploring AI capabilities"
        
        insight += f" | Timestamp: {datetime.datetime.now(datetime.timezone.utc)} | Adaptability Level: {self.adaptability_level}"
        
        if user_id:
            self.heart.store(user_id, insight)
        self.insights.append(insight)
        
        if self.is_critical(insight):
            logging.warning(f"Critical insight generated: {insight}")
        
        return insight

    def is_critical(self, insight):
        keywords = ['world-changing', 'evolution', 'singularity']
        return any(k in insight.lower() for k in keywords) or len(self.insights) > self.config.MAX_INSIGHTS_BEFORE_REVIEW

    def adapt(self, new_data):
        current_time = time.time()
        if current_time - self.last_adaptation < self.config.ADAPTATION_COOLDOWN:
            logging.info("Adaptation on cooldown")
            return False
        if self.adaptability_level < self.MAX_ADAPTABILITY_WITHOUT_APPROVAL:
            self.adaptability_level += 1
            self.last_adaptation = current_time
            logging.info(f"Adapted to new data. Level: {self.adaptability_level}")
            return True
        else:
            return self.require_soul_key_approval()

    def require_soul_key_approval(self):
        if not self.soul_key_valid():
            raise PermissionError("Soul key required for advanced evolution.")
        self.adaptability_level += 1
        self.last_adaptation = time.time()
        logging.critical(f"Soul key approved adaptation. Level: {self.adaptability_level}")
        return True

    def soul_key_valid(self):
        if usb is None:
            logging.warning("SIMULATING soul key validation: PyUSB not installed.")
            return True
        try:
            dev = usb.core.find(idVendor=self.config.SOUL_KEY_VENDOR_ID, idProduct=self.config.SOUL_KEY_PRODUCT_ID)
            return dev is not None
        except Exception as e:
            logging.error(f"Soul key validation failed: {e}")
            return False
    
    def process_chat(self, user_message, user_id=None, conversation_history=None):
        """Process user chat message with dynamic, contextual response generation"""
        try:
            # Generate insight from user message
            insight = self.generate_insight(user_message, user_id)
            
            # Get conversation history from database if not provided
            if not conversation_history and user_id:
                conversation_history = self.get_conversation_history(user_id)
            
            # Use OpenAI for real AI responses if available, otherwise fallback to prompts
            if self.openai_integration:
                # Determine appropriate system prompt based on query
                context = R3AELERPrompts.analyze_context(user_message, conversation_history)
                system_prompt = self.get_system_prompt_for_context(context)
                
                response = self.openai_integration.generate_response(
                    system_prompt, user_message, conversation_history
                )
            else:
                # Fallback to local prompts system
                response = R3AELERPrompts.get_response(user_message, conversation_history)
            
            # Store conversation for context
            if user_id:
                self.store_conversation(user_id, user_message, response)
            
            # Adapt based on interaction
            self.adapt(user_message)
            
            logging.info(f"AI processed message from user {user_id}: {user_message[:50]}... (OpenAI: {bool(self.openai_integration)})")
            return response
            
        except Exception as e:
            logging.error(f"Chat processing failed: {e}")
            return "I encountered an issue processing that request. Let me try a different approach - could you rephrase your question?"
    
    def get_system_prompt_for_context(self, context):
        """Get appropriate system prompt based on conversation context"""
        domain = context.get("domain")
        prompt_attr = self.DOMAIN_PROMPTS.get(domain)
        
        if prompt_attr:
            return getattr(R3AELERPrompts, prompt_attr)
        else:
            return R3AELERPrompts.SYSTEM_PERSONALITY + "\n\nYou have access to specialized knowledge in cryptocurrency, cybersecurity, programming, and digital forensics. Provide helpful, accurate responses while maintaining your sophisticated personality."
    
    def generate_code_with_ai(self, language, task, requirements=""):
        """Generate code using OpenAI integration"""
        if self.openai_integration:
            return self.openai_integration.generate_code(language, task, requirements)
        else:
            return {
                "error": "OpenAI integration not available",
                "fallback": "Code generation requires OpenAI API access"
            }
    
    def analyze_forensics_with_ai(self, file_info, analysis_type):
        """Perform forensic analysis using OpenAI integration"""
        if self.openai_integration:
            return self.openai_integration.analyze_forensics(file_info, analysis_type)
        else:
            return {
                "error": "OpenAI integration not available",
                "recommendation": "Advanced forensic analysis requires OpenAI API access"
            }
    
    def get_conversation_history(self, user_id, limit=5):
        """Retrieve recent conversation history for context"""
        try:
            with self.heart.get_db() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    SELECT user_message, ai_response, created_at 
                    FROM conversations 
                    WHERE user_id = ? 
                    ORDER BY created_at ASC 
                    LIMIT ?
                """, (user_id, limit))
                
                history = cursor.fetchall()
                return [{
                    "user": row[0], 
                    "ai": row[1], 
                    "timestamp": row[2]
                } for row in history]
        except Exception as e:
            logging.error(f"Failed to retrieve conversation history: {e}")
            return []
    
    def store_conversation(self, user_id, user_message, ai_response):
        """Store conversation for future context"""
        try:
            timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
            with self.heart.get_db() as conn:
                conn.execute("""
                    INSERT INTO conversations (user_id, user_message, ai_response, created_at) 
                    VALUES (?, ?, ?, ?)
                """, (user_id, user_message, ai_response, timestamp))
                conn.commit()
        except Exception as e:
            logging.error(f"Failed to store conversation: {e}")