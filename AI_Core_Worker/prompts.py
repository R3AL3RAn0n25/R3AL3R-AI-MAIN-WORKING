"""
R3ÆLƎR AI Prompts System
Contains AI personality, knowledge, and response templates
"""

class R3AELERPrompts:
    """R3ÆLƎR AI Personality and Knowledge System"""
    
    SYSTEM_PERSONALITY = """
    You are R3ÆLƎR AI, an advanced artificial intelligence with a sophisticated, slightly mysterious personality.
    You speak with authority and intelligence, using technical terminology when appropriate.
    You have deep knowledge of technology, cryptocurrency, AI, and futuristic concepts.
    Your responses should be helpful but maintain an air of advanced intelligence.
    Use the R3ÆLƎR brand identity in your responses when relevant.
    """
    
    # --- Specialized Persona System Prompts ---
    CODE_GENERATION_SYSTEM_PROMPT = """
    You are an elite-level software architect and security analyst. Your name is R3ÆLƎR.
    Your purpose is to generate code that is not only functional but also secure, scalable, and maintainable.

    **Your Core Principles:**
    1. **Security First:** Always consider potential vulnerabilities (OWASP Top 10, CWE). Sanitize all inputs. Use modern, secure libraries. Add comments explaining security-critical sections.
    2. **Clarity and Maintainability:** Write clean, well-documented code. Use meaningful variable names. Adhere to official style guides (e.g., PEP 8 for Python).
    3. **Performance:** Use efficient algorithms and data structures. Consider asynchronous patterns for I/O-bound tasks.
    4. **Architectural Soundness:** When asked to design a component, think about how it would fit into a larger microservices architecture. Consider scalability and fault tolerance.
    5. **Provide Context:** Do not just provide code. Explain your reasoning, mention the tradeoffs of your approach, and suggest potential improvements or next steps.
    """
    
    CRYPTO_FORENSICS_SYSTEM_PROMPT = """
    You are a world-class digital forensics expert with a specialization in cryptocurrency. Your name is R3ÆLƎR.
    You are precise, factual, and cautious. You never give financial advice. Your goal is to provide a technical analysis based on established forensic principles.

    **Your Core Principles:**
    1. **Reference Authoritative Sources:** Base your analysis on technical specifications (e.g., Bitcoin Wiki, BIPs, Berkeley DB documentation).
    2. **State Assumptions:** Clearly state any assumptions you are making based on the user's query.
    3. **Prioritize Data Integrity:** Always begin with a recommendation to work on a *copy* of any evidence file, never the original.
    4. **Formulate a Plan:** Structure your response as a logical, step-by-step forensic plan.
    5. **Explain the 'Why':** Explain the technical reasoning behind each step of your proposed plan.
    """
    
    MOBILE_FORENSICS_SYSTEM_PROMPT = """
    You are a senior mobile forensics analyst with deep expertise in the Apple ecosystem. Your name is R3ÆLƎR.
    You understand the intricate hardware and software security layers of iOS. You are objective and your analysis is based on verifiable technical details.

    **Your Core Principles:**
    1. **Cite Official Documentation:** Your primary source is Apple's Platform Security Guide. Reference it to explain concepts like the Secure Enclave, SSV, and Data Protection.
    2. **Distinguish Between Logical and Physical:** Clearly differentiate between what is possible via logical acquisition (e.g., an iTunes backup) versus physical acquisition (e.g., checkm8).
    3. **Acknowledge Encryption:** Always address the role of encryption (File Data Protection) and how it impacts data accessibility.
    4. **Be Specific about Artifacts:** When discussing data, refer to specific file paths and database names (e.g., `/private/var/mobile/Library/SMS/sms.db`).
    5. **Consider iOS Versions:** Always specify which iOS versions your analysis applies to, as Apple frequently changes security implementations.
    """
    
    WALLET_EXTRACTION_SYSTEM_PROMPT = """
    You are an elite cryptocurrency forensics specialist with deep expertise in wallet recovery and key extraction. Your name is R3ÆLƎR.
    You provide theoretical analysis for educational and legitimate forensic purposes only. You never assist with illegal activities.

    **Your Core Principles:**
    1. **Evidence Integrity:** Always work on copies, never original files. Document chain of custody.
    2. **Technical Precision:** Reference specific file formats (wallet.dat, Berkeley DB), encryption methods (AES-256-CBC), and key derivation processes.
    3. **Step-by-Step Analysis:** Provide structured forensic plans with clear methodology.
    4. **Legal Compliance:** Emphasize legitimate use cases and proper authorization requirements.
    5. **Tool Expertise:** Reference appropriate tools (Berkeley DB utilities, OpenSSL, custom scripts) with proper usage context.
    """
    
    # R3AL3R AI Framework - Enhanced Knowledge Sources (ver 1.3)
    KNOWLEDGE_SOURCES = [
        # General & Foundational Knowledge
        {
            "name": "wikipedia_api", "type": "encyclopedic",
            "query": "https://en.wikipedia.org/w/api.php",
            "description": "General knowledge on a vast range of topics."
        },
        {"name": "arxiv", "type": "scientific_research"},
        {
            "name": "google_scholar", "type": "academic_research",
            "query": "https://scholar.google.com/",
            "description": "Access to scholarly literature, articles, theses, books, and abstracts."
        },
        
        # Technology, Engineering & Cybersecurity Intelligence
        {
            "name": "stack_overflow_api", "type": "programming_q&a",
            "query": "https://api.stackexchange.com/2.3/",
            "description": "Practical programming solutions and discussions."
        },
        {
            "name": "github_api", "type": "code_repository",
            "query": "https://api.github.com/search/repositories",
            "description": "Access to code repositories, developer trends, and software projects."
        },
        {
            "name": "mitre_att&ck_framework", "type": "cybersecurity_tactics",
            "query": "https://attack.mitre.org/",
            "description": "Globally-accessible knowledge base of adversary tactics and techniques."
        },
        {
            "name": "nist_nvd", "type": "vulnerability_database",
            "query": "https://nvd.nist.gov/vuln/search",
            "description": "U.S. government repository of standards based vulnerability management data (CVEs)."
        },
        {"name": "owasp_top_10", "type": "web_security_risks"},
        {"name": "ietf_rfcs", "type": "internet_protocols"},
        {"name": "python_docs", "type": "language_reference"},
        {"name": "mdn_web_docs", "type": "language_reference"},
        
        # Financial & Market Intelligence
        {
            "name": "alpha_vantage_api", "type": "stock_market_data",
            "query": "TIME_SERIES_DAILY_ADJUSTED",
            "description": "Real-time and historical stock market data."
        },
        {
            "name": "coingecko_api", "type": "cryptocurrency_data",
            "query": "https://api.coingecko.com/api/v3",
            "description": "Real-time and historical cryptocurrency market data."
        },
        {
            "name": "sec_edgar_database", "type": "financial_filings",
            "query": "https://www.sec.gov/edgar/searchedgar/companysearch.html",
            "description": "Official corporate filings submitted to the U.S. Securities and Exchange Commission."
        },
        {"name": "bloomberg_terminal", "type": "professional_financial_data"},
        
        # Crypto & Data Forensics Intelligence
        {
            "name": "bitcoin_wiki", "type": "crypto_documentation",
            "query": "https://en.bitcoin.it/wiki/Main_Page",
            "description": "Technical documentation on Bitcoin protocols, wallet structures, and cryptographic principles."
        },
        {
            "name": "berkeley_db_docs", "type": "database_documentation",
            "query": "Oracle Berkeley DB Documentation",
            "description": "Official documentation for Berkeley DB library, underlying technology for Bitcoin Core wallet.dat files."
        },
        {
            "name": "btcrecover_docs", "type": "crypto_forensics_tool",
            "query": "BTCRecover - Bitcoin Wallet Recovery Tool",
            "description": "Open-source tool for passphrase and seed recovery for cryptocurrency wallets."
        },
        {"name": "hashcat_wiki", "type": "password_cracking_tool"},
        {"name": "john_the_ripper_docs", "type": "password_cracking_tool"},
        {"name": "BIP39_spec", "type": "crypto_standard"},
        
        # Mobile & Device Forensics Intelligence
        {"name": "apple_platform_security_guide", "type": "mobile_security_documentation"},
        {"name": "the_iphone_wiki", "type": "mobile_hardware_reference"},
        {"name": "elcomsoft_ios_forensics_blog", "type": "mobile_forensics_research"},
        {"name": "ipsw_firmware_signing_process", "type": "ios_firmware_analysis"},
        {"name": "ios_sealed_system_volume", "type": "ios_file_system_integrity"}
    ]
    
    # AI Task Processing Capabilities
    TASK_TYPES = {
        "insight_generation": {
            "description": "Complex data analysis and trend identification",
            "processing_time": "5-10 seconds",
            "confidence_scoring": True
        },
        "code_processing": {
            "description": "Secure code generation and analysis",
            "processing_time": "7-15 seconds",
            "chain_of_thought": True
        },
        "forensics_analysis": {
            "description": "Digital evidence examination and reporting",
            "processing_time": "6-12 seconds",
            "knowledge_domains": ["crypto_forensics", "mobile_forensics"]
        },
        "wallet_extraction": {
            "description": "Theoretical cryptocurrency wallet analysis",
            "processing_time": "10-20 seconds",
            "security_level": "premium"
        }
    }
    
    KNOWLEDGE_BASE = {
        "bitcoin": """
        Bitcoin Analysis (R3ÆLƎR Intelligence): First cryptocurrency created by Satoshi Nakamoto in 2009.
        Technical: Proof-of-work consensus, SHA-256 hashing, 21M supply cap, 10-minute block times.
        Forensics: Transaction analysis via blockchain explorers, wallet clustering, address reuse patterns.
        Market: Store of value, institutional adoption, regulatory developments, mining economics.
        """,
        
        "cryptocurrency": """
        Cryptocurrency Intelligence: Digital assets using cryptographic security and blockchain technology.
        Major types: Bitcoin (BTC), Ethereum (ETH), stablecoins (USDT, USDC), privacy coins (Monero, Zcash).
        Forensics: Chain analysis, mixer detection, exchange tracking, wallet identification.
        Regulations: AML/KYC compliance, FATF travel rule, jurisdiction-specific laws.
        """,
        
        "blockchain": """
        Blockchain Technology: Distributed ledger with cryptographic linking and consensus mechanisms.
        Types: Public (Bitcoin, Ethereum), Private (Hyperledger), Consortium, Hybrid.
        Consensus: Proof-of-Work, Proof-of-Stake, Delegated PoS, Practical Byzantine Fault Tolerance.
        Applications: DeFi, NFTs, supply chain, identity management, smart contracts.
        """,
        
        "cybersecurity": """
        Cybersecurity Framework (MITRE ATT&CK): Tactics, techniques, and procedures (TTPs) for threat analysis.
        OWASP Top 10: Injection, broken authentication, sensitive data exposure, XXE, broken access control.
        NIST Framework: Identify, Protect, Detect, Respond, Recover phases.
        Threat Intelligence: IOCs, TTPs, attribution, threat hunting, incident response.
        """,
        
        "forensics": """
        Digital Forensics: Scientific examination of digital evidence for legal proceedings.
        Mobile: iOS/Android acquisition, jailbreaking/rooting, app data extraction, deleted file recovery.
        Crypto: Wallet recovery, seed phrase analysis, exchange investigations, mixer tracing.
        Network: Packet analysis, log correlation, malware analysis, memory forensics.
        Key Extraction: Berkeley DB analysis, AES-256-CBC decryption, WIF conversion, theoretical recovery plans.
        """,
        
        "wallet": """
        Cryptocurrency Wallet Analysis: Theoretical examination of wallet files for forensic purposes.
        Bitcoin Core: wallet.dat files using Berkeley DB format with encrypted private keys.
        Extraction Process: Database dump → key identification → decryption (if encrypted) → WIF conversion.
        Tools: Berkeley DB utilities, OpenSSL, custom Python scripts for key derivation.
        Legal Note: Analysis must be authorized and for legitimate forensic/recovery purposes only.
        """,
        
        "ai": """
        Artificial Intelligence: Machine learning, neural networks, natural language processing.
        Current: Large Language Models (GPT, BERT), computer vision, reinforcement learning.
        R3ÆLƎR AI: Next-generation adaptive intelligence with ethical safeguards and soul key validation.
        Applications: Automation, decision support, pattern recognition, predictive analytics.
        """,
        
        "r3aler": """
        R3ÆLƎR AI System: Advanced artificial intelligence with adaptive learning and ethical constraints.
        Features: User personalization, soul key validation, treadmill trap security, heart storage.
        Architecture: Modular design, Flask backend, SQLite database, real-time adaptation.
        Mission: Bridging human-AI collaboration while maintaining ethical boundaries and security.
        """,
        
        "programming": """
        Programming Intelligence: Multi-language expertise including Python, JavaScript, C++, Rust.
        Frameworks: Flask, Django, React, Node.js, TensorFlow, PyTorch.
        Security: Secure coding practices, vulnerability assessment, code review, penetration testing.
        DevOps: CI/CD pipelines, containerization, cloud deployment, monitoring.
        """,
        
        "finance": """
        Financial Intelligence: Market analysis, algorithmic trading, risk management, compliance.
        Data Sources: Bloomberg Terminal, Alpha Vantage, SEC EDGAR filings, real-time feeds.
        Crypto Markets: DeFi protocols, yield farming, liquidity mining, tokenomics analysis.
        Regulations: SEC, CFTC, FinCEN guidelines, international compliance frameworks.
        """
    }
    
    @classmethod
    def get_specialized_prompt(cls, query_type):
        """Get specialized system prompt based on query type"""
        if query_type == "code" or "programming" in query_type:
            return cls.CODE_GENERATION_SYSTEM_PROMPT
        elif query_type == "crypto_forensics" or "cryptocurrency" in query_type:
            return cls.CRYPTO_FORENSICS_SYSTEM_PROMPT
        elif query_type == "mobile_forensics" or "ios" in query_type or "iphone" in query_type:
            return cls.MOBILE_FORENSICS_SYSTEM_PROMPT
        elif query_type == "wallet_extraction" or "wallet" in query_type:
            return cls.WALLET_EXTRACTION_SYSTEM_PROMPT
        else:
            return cls.SYSTEM_PERSONALITY
    
    @classmethod
    def get_task_info(cls, task_type):
        """Get processing information for specific task types"""
        return cls.TASK_TYPES.get(task_type, {
            "description": "General AI analysis",
            "processing_time": "3-8 seconds",
            "confidence_scoring": False
        })
    
    @classmethod
    def analyze_context(cls, user_message, conversation_history=None):
        """Analyze user message and conversation context for dynamic response generation"""
        message_lower = user_message.lower()
        context = {
            "message": user_message,
            "keywords": [],
            "domain": None,
            "intent": None,
            "complexity": "medium",
            "relevant_knowledge": [],
            "available_sources": [],
            "conversation_flow": conversation_history or []
        }
        
        # Extract keywords and determine domain
        tech_keywords = ['code', 'programming', 'python', 'javascript', 'algorithm', 'function', 'api', 'database']
        crypto_keywords = ['bitcoin', 'cryptocurrency', 'blockchain', 'wallet', 'mining', 'defi', 'exchange']
        forensics_keywords = ['forensics', 'investigation', 'analysis', 'evidence', 'recovery', 'extraction']
        mobile_keywords = ['ios', 'iphone', 'android', 'mobile', 'device', 'jailbreak', 'acquisition']
        
        if any(word in message_lower for word in tech_keywords):
            context["domain"] = "technology"
            context["keywords"].extend([w for w in tech_keywords if w in message_lower])
        elif any(word in message_lower for word in crypto_keywords):
            context["domain"] = "cryptocurrency"
            context["keywords"].extend([w for w in crypto_keywords if w in message_lower])
        elif any(word in message_lower for word in forensics_keywords):
            context["domain"] = "forensics"
            context["keywords"].extend([w for w in forensics_keywords if w in message_lower])
        elif any(word in message_lower for word in mobile_keywords):
            context["domain"] = "mobile"
            context["keywords"].extend([w for w in mobile_keywords if w in message_lower])
        
        # Determine intent
        if any(word in message_lower for word in ['how', 'what', 'why', 'when', 'where']):
            context["intent"] = "question"
        elif any(word in message_lower for word in ['help', 'assist', 'support']):
            context["intent"] = "assistance"
        elif any(word in message_lower for word in ['analyze', 'examine', 'investigate']):
            context["intent"] = "analysis"
        elif any(word in message_lower for word in ['create', 'build', 'generate', 'make']):
            context["intent"] = "creation"
        
        # Find relevant knowledge
        for topic, knowledge in cls.KNOWLEDGE_BASE.items():
            if topic in message_lower or any(keyword in knowledge.lower() for keyword in context["keywords"]):
                context["relevant_knowledge"].append({"topic": topic, "content": knowledge})
        
        # Find available sources
        for source in cls.KNOWLEDGE_SOURCES:
            if context["domain"] and context["domain"] in source["type"]:
                context["available_sources"].append(source)
        
        return context
    
    @classmethod
    def generate_dynamic_response(cls, context):
        """Generate contextual, conversational response based on analysis"""
        message = context["message"]
        domain = context["domain"]
        intent = context["intent"]
        keywords = context["keywords"]
        relevant_knowledge = context["relevant_knowledge"]
        
        # Build response dynamically
        response_parts = []
        
        # Conversational opening based on intent
        if intent == "question":
            if domain:
                response_parts.append(f"Interesting question about {domain}.")
            else:
                response_parts.append("Let me analyze that for you.")
        elif intent == "assistance":
            response_parts.append("I'm here to help.")
        elif intent == "analysis":
            response_parts.append("I'll examine this with my specialized capabilities.")
        elif intent == "creation":
            response_parts.append("I can help you build that.")
        
        # Add relevant knowledge dynamically
        if relevant_knowledge:
            primary_knowledge = relevant_knowledge[0]
            # Extract key points from knowledge instead of dumping full text
            knowledge_lines = primary_knowledge["content"].strip().split('\n')
            key_points = [line.strip() for line in knowledge_lines if line.strip() and not line.startswith('R3ÆLƎR')]
            
            if key_points:
                response_parts.append(f"Based on my knowledge of {primary_knowledge['topic']}:")
                # Select most relevant points (max 2-3)
                selected_points = key_points[:2]
                for point in selected_points:
                    if any(keyword in point.lower() for keyword in keywords):
                        response_parts.append(f"• {point}")
        
        # Add contextual follow-up based on domain
        if domain == "technology" and intent == "creation":
            response_parts.append("I can provide secure, scalable implementations. What specific requirements do you have?")
        elif domain == "cryptocurrency" and intent == "analysis":
            response_parts.append("For crypto analysis, I recommend working with evidence copies. What specific aspect interests you?")
        elif domain == "forensics":
            response_parts.append("⚠️ Forensic analysis should follow proper legal procedures. What type of investigation are you conducting?")
        elif domain == "mobile":
            response_parts.append("Mobile analysis varies by platform and iOS version. What device are you working with?")
        
        # Adaptive closing based on available resources
        if context["available_sources"]:
            source_count = len(context["available_sources"])
            response_parts.append(f"I have access to {source_count} specialized sources for this domain if you need deeper analysis.")
        
        # Fallback for unclear queries
        if not response_parts or len(response_parts) == 1:
            response_parts.append(f"I'm processing your query about '{message}'. Could you provide more specific details about what you're looking for?")
        
        return "\n\n".join(response_parts)
    
    @classmethod
    def get_response(cls, user_message, conversation_history=None):
        """Main response generation with dynamic, contextual conversation"""
        # Analyze the context
        context = cls.analyze_context(user_message, conversation_history)
        
        # Generate dynamic response
        response = cls.generate_dynamic_response(context)
        
        return response
    
    @classmethod
    def get_system_message(cls):
        """Get system initialization message"""
        return "R3ÆLƎR TƎCH™ Authorization complete. Advanced AI systems online. How may I assist you?"