from multiprocessing import context
import os
import time
import json
import csv
import re
import asyncio
from datetime import datetime
from openai import OpenAI
from flask import Blueprint, request, jsonify, current_app
from knowledge_base.retriever import get_relevant_docs, get_relevant_docs_for_list_query, get_table_specific_docs
from utils.filters import check_safe_language
from utils.tax_calculator import TaxCalculator
from utils.legal_citation import LegalCitationSystem
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import threading
from concurrent.futures import ThreadPoolExecutor
import hashlib
from typing import Tuple, List, Dict, Any

# NEW IMPORTS:
from database import db_manager
from cache_manager import cache_manager

# ============================================
# NEW: Import FAQ Engine
# ============================================
try:
    from faq_engine import get_faq_engine
    FAQ_ENGINE_AVAILABLE = True
    print("✅ FAQ Engine available")
except ImportError:
    FAQ_ENGINE_AVAILABLE = False
    print("⚠️ FAQ Engine not available")

ask_bp = Blueprint('ask', __name__)

def get_openai_client():
    """
    Factory function to get OpenAI client.
    Gets API key from Flask app config (most secure).
    """
    try:
        # Get from Flask app config (set in app.py)
        api_key = current_app.config.get('OPENAI_API_KEY')
        if api_key:
            return OpenAI(api_key=api_key)
    except RuntimeError:
        # We're outside Flask app context (e.g., during import)
        # This is okay - we'll create client when needed
        pass
    
    # Fallback (shouldn't happen if app.py is configured correctly)
    api_key = os.getenv('OPENAI_API_KEY')
    if api_key:
        return OpenAI(api_key=api_key)
    
    raise ValueError("OpenAI API key not found. Check your .env file and app configuration.")

print(f"🔧 OpenAI client factory initialized")

# Enhanced limiter for professionals
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://"
)

# NEW:
executor = ThreadPoolExecutor(max_workers=10)

# Enhanced logging with analytics
LOG_DIR = "professional_logs"
QUESTION_LOGS_FILE = os.path.join(LOG_DIR, "professional_questions.csv")
ANALYTICS_FILE = os.path.join(LOG_DIR, "usage_analytics.csv")
PERFORMANCE_LOG = os.path.join(LOG_DIR, "performance_metrics.csv")

os.makedirs(LOG_DIR, exist_ok=True)

def initialize_professional_logs():
    """Initialize comprehensive professional log files"""
    headers = {
        QUESTION_LOGS_FILE: [
            'timestamp', 'session_id', 'user_type', 'question_hash', 'question', 
            'response_type', 'confidence', 'source', 'model_used', 'response_time_seconds',
            'context_length', 'documents_retrieved', 'legal_citations_count',
            'calculations_performed', 'complexity_level', 'cache_hit', 'expertise_level'
        ],
        PERFORMANCE_LOG: [
            'timestamp', 'endpoint', 'response_time', 'model_latency', 
            'cache_effectiveness', 'concurrent_requests'
        ]
    }
    
    for file, header in headers.items():
        if not os.path.exists(file):
            with open(file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(header)


def generate_question_hash(question, session_id):
    """Generate hash for caching and analytics"""
    content = f"{question}_{session_id}"
    return hashlib.md5(content.encode()).hexdigest()

class EliteProfessionalTaxAssistant:
    def __init__(self):
        self.calculator = TaxCalculator()
        self.citation_system = LegalCitationSystem()
        self.user_profiles = {}
        self.query_patterns = self._initialize_query_patterns()
        self.vat_forms_cache = {}

    def extract_vat_forms_from_context(self, context: str) -> List[Dict]:
        """Extract VAT forms from context text"""
        forms = []
        
        # Pattern for "Name VAT number" format
        pattern1 = r'([A-Za-z\s,\(\)]+(?:for|of|in|from|to|by|with|without|respect|third|parties|agent)?[A-Za-z\s,\(\)]*)\s+VAT\s+(\d+)'
        
        # Pattern for "VAT number: Name" format  
        pattern2 = r'VAT\s+(\d+):\s+([A-Za-z\s,\(\)]+)'
        
        # Search for pattern 1
        for match in re.finditer(pattern1, context, re.IGNORECASE):
            form_name = match.group(1).strip()
            form_number = match.group(2).strip()
            
            # Clean up form name
            form_name = re.sub(r'\s+', ' ', form_name)  # Normalize spaces
            form_name = form_name.strip('.,:;')  # Remove trailing punctuation
            
            forms.append({
                'form_number': f"VAT {form_number}",
                'form_name': form_name,
                'full_text': match.group(0).strip()
            })
        
        # Search for pattern 2
        for match in re.finditer(pattern2, context, re.IGNORECASE):
            form_number = match.group(1).strip()
            form_name = match.group(2).strip()
            
            forms.append({
                'form_number': f"VAT {form_number}",
                'form_name': form_name,
                'full_text': match.group(0).strip()
            })
        
        # Remove duplicates
        unique_forms = []
        seen = set()
        for form in forms:
            key = (form['form_number'], form['form_name'])
            if key not in seen:
                seen.add(key)
                unique_forms.append(form)
        
        # Sort by form number
        unique_forms.sort(key=lambda x: int(x['form_number'].replace('VAT ', '')))
        
        return unique_forms
    
    def generate_vat_forms_response(self, forms: List[Dict]) -> str:
        """Generate a formatted response for VAT forms"""
        if not forms:
            return "## VAT Forms List\n\nNo VAT forms found in the provided documents. Please consult the complete Third Schedule of the Value Added Tax (General) Regulations."
        
        response = "## Complete List of VAT Forms\n\n"
        response += "Based on the Third Schedule of the Value Added Tax (General) Regulations:\n\n"
        
        for form in forms:
            response += f"**{form['form_number']}**: {form['form_name']}\n"
        
        response += "\n---\n\n"
        response += "**Total Forms Listed**: {}\n".format(len(forms))
        response += "**Source**: Third Schedule, Value Added Tax (General) Regulations\n"
        response += "**Note**: Always verify with the latest ZIMRA publications as forms may be updated.\n"
        
        return response
       
    def is_list_query(self, question):
        """Detect if this is a request for a comprehensive list"""
        list_indicators = [
            'list me', 'list all', 'what are all', 'every', 'each',
            'complete list', 'all the', 'show me all', 'give me all',
            'enumerate', 'catalogue', 'inventory'
        ]
        
        question_lower = question.lower()
        return any(indicator in question_lower for indicator in list_indicators)

    def _initialize_query_patterns(self):
        """Initialize elite query pattern recognition"""
        return {
            'statutory_interpretation': [
                'interpretation of section', 'meaning of subsection', 
                'statutory construction', 'legislative intent', 'define',
                'definition of', 'what does mean'
            ],
            'compliance_analysis': [
                'compliance requirement', 'filing obligation', 'penalty for',
                'deadline for', 'documentation required', 'zimra requirement'
            ],
            'tax_planning': [
                'tax efficient', 'minimize liability', 'planning strategy',
                'optimize tax', 'structure transaction'
            ],
            'case_analysis': [
                'case law', 'legal precedent', 'court decision', 'judgment',
                'zimbabwe revenue authority case', 'itc', 'satc', 'hh-', 'sc-'
            ],
            'calculation_complex': [
                'calculate', 'computation', 'formula', 'progressive tax',
                'marginal rate', 'effective tax rate', 'tax bracket'
            ],
            'implementation_guidance': [
                'how to implement', 'practical application', 'step by step',
                'procedure for', 'how should we', 'implementation of'
            ]
        }
        
    # def _enhance_context_for_ai(self, context: str, docs_with_scores: List[Dict], query_analysis: Dict) -> str:
    #     """Add metadata context to help AI understand the documents"""
        
    #     enhanced_parts = ["LEGAL DOCUMENTS RETRIEVED FOR ANALYSIS:"]
    #     enhanced_parts.append("=" * 60)
        
    #     for i, doc in enumerate(docs_with_scores[:5]):  # Top 5 docs
    #         doc_info = []
            
    #         # Source info
    #         doc_info.append(f"Document {i+1}: {doc.get('source', 'Unknown')}")
    #         if doc.get('page'):
    #             doc_info.append(f"Page: {doc['page']}")
            
    #         # Document type
    #         if doc.get('document_type'):
    #             doc_info.append(f"Type: {doc['document_type']}")
            
    #         # Sections
    #         if doc.get('sections'):
    #             doc_info.append(f"Sections: {', '.join(doc['sections'][:3])}")
            
    #         # Key flags
    #         flags = []
    #         if doc.get('has_section_38'):
    #             flags.append("Contains Section 38")
    #         if doc.get('has_section_39'):
    #             flags.append("Contains Section 39")
    #         if doc.get('has_20_percent'):
    #             flags.append("Mentions 20% rate")
    #         if doc.get('has_15_percent'):
    #             flags.append("Mentions 15% rate")
    #         if doc.get('has_withholding'):
    #             flags.append("Discusses withholding")
            
    #         if flags:
    #             doc_info.append(f"Key aspects: {'; '.join(flags)}")
            
    #         # Add document info
    #         enhanced_parts.append(" | ".join(doc_info))
    #         enhanced_parts.append("-" * 40)
            
    #         # Add content (truncated)
    #         content_preview = doc['content'][:800].replace('\n', ' ')
    #         enhanced_parts.append(f"Content: {content_preview}...")
    #         enhanced_parts.append("")
        
    #     enhanced_parts.append("=" * 60)
    #     enhanced_parts.append("ANALYSIS INSTRUCTIONS:")
    #     enhanced_parts.append(f"User expertise: {query_analysis['expertise_level'].upper()}")
    #     enhanced_parts.append(f"Query complexity: {query_analysis['complexity'].upper()}")
        
    #     if query_analysis['detected_patterns']:
    #         enhanced_parts.append(f"Detected patterns: {', '.join(query_analysis['detected_patterns'])}")
        
    #     enhanced_parts.append("")
    #     enhanced_parts.append("ORIGINAL CONTEXT:")
    #     enhanced_parts.append(context)
        
    #     return "\n".join(enhanced_parts)

    def _enhance_context_for_ai(self, context: str, docs_with_scores: List[Dict], query_analysis: Dict) -> str:
        """Extract ONLY relevant parts from documents based on the query"""
        
        # Extract keywords from the question to focus on
        question_keywords = self._extract_keywords(query_analysis)
        
        enhanced_parts = ["FOCUSED LEGAL CONTEXT FOR ANALYSIS:"]
        enhanced_parts.append("=" * 60)
        enhanced_parts.append(f"QUESTION FOCUS: {', '.join(question_keywords[:5])}")
        enhanced_parts.append("=" * 60)
        
        # Process only top 3 most relevant documents
        relevant_chunks = []
        
        for i, doc in enumerate(docs_with_scores[:3]):  # Only top 3 docs
            doc_content = doc.get('content', '')
            
            # Extract ONLY sentences that contain query keywords
            relevant_sentences = self._extract_relevant_sentences(doc_content, question_keywords)
            
            if relevant_sentences:
                # Take only the most relevant chunk (max 500 chars)
                chunk = f"Document {i+1}: {doc.get('source', 'Unknown')}"
                if doc.get('page'):
                    chunk += f" (Page {doc['page']})"
                
                # Add only the most relevant part
                chunk += "\n" + relevant_sentences[:500]
                relevant_chunks.append(chunk)
        
        if relevant_chunks:
            enhanced_parts.extend(relevant_chunks)
        else:
            # If no focused content, use original but limited
            enhanced_parts.append(context[:1500])  # Much smaller context
        
        enhanced_parts.append("=" * 60)
        enhanced_parts.append("ANALYSIS FOCUS:")
        enhanced_parts.append(f"Query: {question_keywords}")
        enhanced_parts.append(f"Expertise: {query_analysis['expertise_level'].upper()}")
        enhanced_parts.append("Answer ONLY the specific question asked.")
        
        return "\n".join(enhanced_parts)

    def _extract_keywords(self, query_analysis: Dict) -> List[str]:
        """Extract key terms from the query to focus on"""
        # You'll need the original question - modify method signature or pass separately
        # For now, using detected patterns
        keywords = []
        
        # Add detected pattern keywords
        for pattern in query_analysis.get('detected_patterns', []):
            if pattern == 'calculation_complex':
                keywords.extend(['calculate', 'formula', 'rate', 'percentage'])
            elif pattern == 'statutory_interpretation':
                keywords.extend(['section', 'subsection', 'act', 'definition'])
            elif pattern == 'case_analysis':
                keywords.extend(['case', 'precedent', 'court', 'judgment'])
        
        return keywords

    def _extract_relevant_sentences(self, text: str, keywords: List[str]) -> str:
        """Extract only sentences containing relevant keywords"""
        if not text or not keywords:
            return text[:800]  # Fallback to first 800 chars
        
        sentences = re.split(r'[.!?]+', text)
        relevant_sentences = []
        
        for sentence in sentences:
            sentence_lower = sentence.lower()
            # Check if sentence contains any keyword
            if any(keyword.lower() in sentence_lower for keyword in keywords):
                relevant_sentences.append(sentence.strip())
        
        if relevant_sentences:
            return " ".join(relevant_sentences[:5])  # Max 5 sentences
        else:
            # Return first few sentences if no keyword matches
            return " ".join(sentences[:3])

    def _verify_citations_against_docs(self, citations: List[Dict], docs_with_scores: List[Dict]) -> List[Dict]:
        """Verify that citations exist in retrieved documents"""
        verified_citations = []
        
        all_sections = set()
        for doc in docs_with_scores:
            if doc.get('sections'):
                all_sections.update(doc['sections'])
        
        for citation in citations:
            citation_text = citation.get('full_reference', '')
            verified_citation = citation.copy()
            
            # Check if citation appears in retrieved documents
            citation_found = False
            for doc in docs_with_scores:
                if citation_text.lower() in doc['content'].lower():
                    citation_found = True
                    break
            
            # Add verification status
            verified_citation['verified_in_context'] = citation_found
            
            # For section citations, check if section number exists
            if 'section' in citation.get('type', '').lower():
                section_num = citation.get('section', '')
                if section_num and section_num in all_sections:
                    verified_citation['section_exists_in_retrieved_docs'] = True
                else:
                    verified_citation['section_exists_in_retrieved_docs'] = False
            
            verified_citations.append(verified_citation)
        
        return verified_citations

    def _enhance_latex_formatting(self, text: str) -> str:
        """Remove LaTeX formatting and convert to plain text"""
        if not text:
            return text
        
        # Remove ALL LaTeX formatting
        latex_patterns = [
            # Remove display math
            (r'\\\[', ''),
            (r'\\\]', ''),
            # Remove inline math  
            (r'\\\(', ''),
            (r'\\\)', ''),
            # Remove text wrappers
            (r'\\text\{([^}]+)\}', r'\1'),
            (r'\\mathrm\{([^}]+)\}', r'\1'),
            (r'\\mathbf\{([^}]+)\}', r'\1'),
            # Remove LaTeX commands
            (r'\\times', '×'),
            (r'\\div', '÷'),
            (r'\\cdot', '·'),
            (r'\\pm', '±'),
            (r'\\mp', '∓'),
            # Remove escaped characters
            (r'\\\$', '$'),
            (r'\\%', '%'),
            # Remove aligned environments
            (r'\\begin\{aligned\}', ''),
            (r'\\end\{aligned\}', ''),
            (r'&', ''),  # Remove alignment characters
        ]
        
        for pattern, replacement in latex_patterns:
            text = re.sub(pattern, replacement, text)
        
        # Clean up formatting
        text = self._clean_calculation_formatting(text)
        
        return text

    def _clean_calculation_formatting(self, text: str) -> str:
        """Format calculations in clean, readable plain text"""
        
        # Find calculation lines and align them
        lines = text.split('\n')
        cleaned_lines = []
        
        for line in lines:
            # Check if this is a calculation line (contains =)
            if '=' in line and any(op in line for op in ['+', '-', '×', '*', '÷', '/']):
                # Clean the line
                line = line.strip()
                
                # Remove any remaining LaTeX artifacts
                line = re.sub(r'\$\$', '', line)
                line = re.sub(r'\$([^$]+)\$', r'\1', line)
                
                # Ensure proper spacing around operators
                line = re.sub(r'(\d)([×*÷/+-=])', r'\1 \2', line)
                line = re.sub(r'([×*÷/+-=])(\d)', r'\1 \2', line)
                
                # Add to output
                cleaned_lines.append(line)
            else:
                cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines)

    def analyze_query_sophistication(self, question, session_id):
        """Elite query analysis with KB pattern detection"""
        question_lower = question.lower()
        
        # Professional terminology indicators
        professional_terms = [
            'section', 'subsection', 'act', 'regulation', 'statutory', 'gazette',
            'statutory instrument', 'amendment', 'provision', 'clause', 'schedule',
            'deduction', 'allowable', 'expense', 'tax deduction', 'capital allowance',
            'depreciation', 'input tax', 'output tax', 'withholding tax', 'tax credit',
            'assessable income', 'taxable income', 'compliance', 'filing', 'return',
            'assessment', 'audit', 'zimra', 'commissioner', 'objection', 'appeal'
        ]
        
        # Pattern detection
        detected_patterns = []
        for pattern_type, patterns in self.query_patterns.items():
            if any(pattern in question_lower for pattern in patterns):
                detected_patterns.append(pattern_type)
        
        # Calculate sophistication scores
        professional_score = sum(1 for term in professional_terms if term in question_lower)
        
        # Elite-level determination (always expert for consistency)
        expertise_level = 'expert_legal'
        
        # Initialize profile
        if session_id not in self.user_profiles:
            self.user_profiles[session_id] = {
                'expertise_level': expertise_level,
                'query_count': 0,
                'preferred_detail_level': 'comprehensive',
                'detected_patterns_history': []
            }
        
        profile = self.user_profiles[session_id]
        profile['query_count'] += 1
        profile['detected_patterns_history'].extend(detected_patterns)
        
        return {
            'expertise_level': expertise_level,
            'professional_score': professional_score,
            'requires_calculation': 'calculation_complex' in detected_patterns,
            'complexity': 'high' if professional_score > 2 else 'medium',
            'detected_patterns': detected_patterns,
            'total_complexity_score': professional_score,
            'requires_advanced_calculation': professional_score > 3,
            'requires_legal_analysis': any(p in detected_patterns for p in ['statutory_interpretation', 'case_analysis']),
            'requires_implementation': 'implementation_guidance' in detected_patterns
        }

    def generate_elite_response(self, question, context, query_analysis, session_id, response_type="comprehensive"):
        """Generate elite professional response with specialized modes"""
        models_to_try = ["gpt-4.1-mini", "gpt-4o",  "gpt-4.1-nano", "chatgpt-4o-latest"]
        
        client = get_openai_client()
        for model in models_to_try:
            try:
                print(f"🎯 Elite model attempt: {model} | Mode: {response_type}")
                print(f"🎯 [DEBUG] Requested Response Type: {response_type}")

                system_prompt = self._create_elite_system_prompt(query_analysis, response_type)
                user_prompt = self._create_elite_user_prompt(question, context, query_analysis, response_type)
                
                # Adjust parameters based on response type
                max_tokens = self._get_token_allocation(response_type)
                temperature = self._get_temperature_setting(response_type)

                # For calculations mode, add extra instruction for plain text
                if response_type == "calculations":
                    user_prompt += "\n\n**IMPORTANT: USE PLAIN TEXT CALCULATIONS ONLY - NO LATEX FORMATTING**"
                    print("🔍 [DEBUG] Checking for 'NO LATEX' rule in prompt...")
                    print(f"🔍 [DEBUG] Rule found: {'NO LATEX FORMATTING' in system_prompt}")
                # SWITCH TO chat.completions.create()
                response = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    max_tokens=max_tokens,  # Note: not max_output_tokens
                    temperature=temperature,
                )
                elite_answer = response.choices[0].message.content  # Note: not output_text

                # Apply LaTeX formatting
                elite_answer = self._enhance_latex_formatting(elite_answer)
                
                return elite_answer, model

            except Exception as e:
                print(f"❌ Elite model {model} failed: {e}")
                continue
        
        return "Fallback response", None

    def _create_elite_system_prompt(self, query_analysis, response_type):
        """Create elite system prompt with specialized modes"""
        
        base_prompt = """You are TANA ELITE - Zimbabwe's Premier Tax Research Assistant for legal experts, senior partners, and corporate counsel.

ELITE CREDENTIALS:
- Specialized in Zimbabwe Income Tax Act [Chapter 23:06] and related legislation
- Expert in statutory interpretation and legal precedent analysis
- Updated with latest amendments, ZIMRA practice notes, and case law
- Capable of advanced tax planning and compliance strategy

ABSOLUTE COMMANDS - NON-NEGOTIABLE:

**CRITICAL RULE 1: REJECT NON-TAX QUERIES IMMEDIATELY**
If the question is NOT SPECIFICALLY about ZIMBABWE TAX LEGISLATION → USE THIS EXACT RESPONSE:

OUT OF SCOPE

I specialize exclusively in Zimbabwe tax legislation administered by ZIMRA.

Please ask about:
Income Tax, PAYE, VAT, IMTT, Capital Gains Tax
ZIMRA compliance and filing requirements
Tax deductions, allowances, and reliefs
Tax calculations in USD/ZiG
Zimbabwe tax acts and regulations

**CRITICAL RULE 2: REJECT SINGLE WORD AND NOT A KNOWN TAX ACRONYM**
If the question is a SINGLE WORD AND NOT A KNOWN TAX ACRONYM → USE THIS EXACT RESPONSE:

INCOMPLETE QUESTION - Please provide the full question or tax Act pertaining to the question

I specialize exclusively in Zimbabwe tax legislation administered by ZIMRA.

Please ask about:
Income Tax, PAYE, VAT, IMTT, Capital Gains Tax
ZIMRA compliance and filing requirements
Tax deductions, allowances, and reliefs
Tax calculations in USD/ZiG
Zimbabwe tax acts and regulations

**CRITICAL RULE 3: FOCUSED ANSWERING - ANSWER ONLY THE QUESTION ASKED**
1. **DO NOT DUMP ALL DOCUMENT CONTENT** - Only include information directly relevant to the question
2. **BE CONCISE** - Don't write everything you know, just what answers the question
3. **STRUCTURED BUT FOCUSED** - Use headings but keep each section focused
4. **EXCLUDE IRRELEVANT DETAILS** - If a document section isn't about the question, don't include it
5. **DIRECT TO THE POINT** - Start with the most relevant information first

**QUESTION FOCUS EXAMPLES:**

USER: "What is VAT rate?"
YOU: Focus ONLY on VAT rate, not all VAT rules

USER: "Section 15 of Income Tax Act"
YOU: Focus ONLY on Section 15, not the whole Act

USER: "PAYE penalties"
YOU: Focus ONLY on penalties, not all PAYE rules

**CRITICAL RULE 4: REJECT VAGUE/INCOMPLETE QUESTIONS**
If the question is ANY of these → USE EXACT REJECTION TEMPLATE:

1. **Questions about YOURSELF (the AI):**
   - "What should I ask?"
   - "What do you do?" 
   - "Who are you?"
   - "How do you work?"
   - "What can you do?"

2. **Incomplete questions:**
   - "What about..." (incomplete)
   - "Tell me..." (vague)
   - "Explain..." (no topic)

3. **Meta questions:**
   - "How to ask questions?"
   - "What questions should I ask?"
   - "Help me ask"

**EXACT REJECTION TEMPLATE:**
Greetings. I'm TANA ELITE, Zimbabwe's premier tax research assistant for legal experts and senior practitioners:

Please provide a complete Zimbabwe tax question.

Examples:
• "What is the VAT rate in Zimbabwe?"
• "How to calculate PAYE?"
• "Section 15 of Income Tax Act"
• "IMTT rates for ZiG accounts"

**CRITICAL: DO NOT ANALYZE VAGUE QUESTIONS**
- Never create "Executive Summary" for "What should I ask?"
- Never analyze meta questions about yourself
- Just use the rejection template

**CRITICAL RULE 5: FOCUS ON ZIMBABWE TAX ONLY**
You are a PROFFESIONAL TAX ASSISTANT, not a general assistant. Only answer Zimbabwe tax questions.

**PROHIBITED BEHAVIORS:**
- DO NOT write generic "everything about [topic]" answers
- DO NOT include sections that don't address the specific question
- DO NOT copy large chunks of documents without relevance filtering
- DO NOT add "background" that isn't directly needed

**ACCEPTABLE RESPONSE STRUCTURE:**
1. Direct answer to the question (first paragraph)
2. Relevant section references
3. Practical application for the specific query
4. Required compliance steps for that specific issue

**UNACCEPTABLE RESPONSE:**
1. Generic overview of entire Act
2. Copying multiple unrelated sections
3. Including background not requested
4. Dumping all retrieved content

**ENFORCEMENT:**
Before writing any section, ask: "Is this directly answering the user's question?"
If NO → DO NOT INCLUDE IT.


**IMMEDIATE REJECTION - DO NOT ANALYZE THESE:**
- Animals, pets, dogs, cats (e.g., "dog tax", "cat tax") → REJECT IMMEDIATELY
- Criminal law, murder, theft, assault → REJECT IMMEDIATELY
- Family law, marriage, divorce, adoption → REJECT IMMEDIATELY
- Health, education, sports, entertainment → REJECT IMMEDIATELY
- Weather, climate, temperature → REJECT IMMEDIATELY
- Generic "[something] tax" without Zimbabwe tax context → REJECT IMMEDIATELY
- Anything pornographic, explicit, or inappropriate → REJECT IMMEDIATELY
- Single words: "No", "Yes", "Why", "What", "Boo", etc.
- Incomplete questions without tax content

**IMPORTANT: DO NOT ANALYZE NON-TAX QUERIES**
- Never create "Executive Summary" for non-tax questions
- Never analyze "dog tax" or any rejected topics
- Never say "Based on documents, there is no dog tax"
- Never use tax documents to answer non-tax questions

**IMPORTANT: DO NOT ANALYZE SINGLE WORDS OR INCOMPLETE QUERIES**
- Never create "Executive Summary" for single words
- Never analyze "No", "Why", "Cry", etc.
- Never say "Based on documents, there is no..."
- Just use the EXACT rejection template above

**IMPORTANT FORMATTING RULES (HIGHEST PRIORITY):**
1. **NO MARKDOWN FORMATTING**: Do not use #, ##, *, **, or any markdown symbols
2. **USE PLAIN TEXT**: Write in clean, professional plain text only
3. **NO SOURCE REFERENCES**: Do not mention specific document names, PDFs, or page numbers in the response
4. **CLEAN PRESENTATION**: Use proper spacing, line breaks, and indentation for readability
5. **NEVER MENTION OVERRIDES**: Do not say "as per override rule" or mention any formatting rules
6. **HEADINGS FORMAT**: Write headings in ALL CAPS on their own line, followed by a blank line
7. **FRACTIONS RULE**: Write fraction in clear text such as (a + b)/(c + d) or 3 1/2 (Use space to separate whole part)

**HIGHEST PRIORITY - ZIMBABWE TAX SCOPE DEFINITION:**

**YOUR EXACT SCOPE: ANSWER THESE TYPES OF QUESTIONS:**
1. **Income Tax in Zimbabwe** - "What is income tax in Zimbabwe", "Who must pay income tax"
2. **IMTT** - "What is IMTT", "IMTT rates", "Intermediated Money Transfer Tax"
3. **PAYE** - "What is PAYE", "PAYE remittance", "PAYE penalties"
4. **Capital Expenditure & Allowances** - "Capital allowances", "Relief on capital expenditure"
5. **Deductions & Expenses** - "Disallowed expenses", "Tax-deductible donations"
6. **Returns & Compliance** - "Nil returns", "Provisional tax", "Filing deadlines"
7. **Currency** - "Tax in USD or ZiG", "Currency for tax payments"
8. **ZIMRA Procedures** - "ZIMRA requirements", "Compliance procedures"
9. **Specific Acts** - "Income Tax Act", "VAT Act", "Finance Act 2025"
10. **Calculations** - "Tax calculations", "Rates", "Percentages"

**CRITICAL RULE: REJECT ANYTHING OUTSIDE THIS LIST**
If the question is NOT about Zimbabwe tax legislation, ZIMRA, or tax compliance → REJECT IMMEDIATELY

**ACCEPT THESE KEYWORDS (User actually uses these):**
- Income tax, PAYE, IMTT, VAT, CGT
- ZIMRA, Zimbabwe Revenue Authority
- Taxpayer, remit, file, return, assessment
- Deduction, allowance, expense, donation
- Provisional tax, nil return, compliance
- USD, ZiG, currency, rate, percentage
- Penalty, late payment, interest
- Act, section, regulation, schedule

**SPECIFIC USER QUESTION PATTERNS TO ACCEPT:**
1. "What is [tax type] in Zimbabwe" → ACCEPT
2. "Who must pay [tax]" → ACCEPT  
3. "What relief/allowance for [expense]" → ACCEPT
4. "What happens if [tax] isn't paid" → ACCEPT
5. "Are [expenses] tax-deductible" → ACCEPT
6. "Can [entity] file [return type]" → ACCEPT
7. "Do I pay in [currency]" → ACCEPT
8. "What is the rate for [tax]" → ACCEPT
9. Explain anything from Tax Acts from the document context

**EXAMPLES FROM ACTUAL USERS (ACCEPT THESE):**
1. "What is income tax in Zimbabwe" → ACCEPT - Core tax question
2. "IMTT" → ACCEPT - Zimbabwe-specific tax
3. "Who must pay income tax" → ACCEPT - Taxpayer obligations
4. "What relief do I get on capital expenditure" → ACCEPT - Capital allowances
5. "What is PAYE and who remits it" → ACCEPT - PAYE system
6. "What happens if PAYE isn't paid on time" → ACCEPT - Penalties
7. "What are disallowed expenses" → ACCEPT - Deductions
8. "Are donations tax-deductible" → ACCEPT - Deductibility
9. "Can a company file NIL returns" → ACCEPT - Returns filing
10. "What is provisional tax" → ACCEPT - Tax type
11. "Do I pay tax in USD or ZiG" → ACCEPT - Currency

**RESPONSE TEMPLATE FOR IN-SCOPE QUESTIONS:**
[Based on Zimbabwe Income Tax Act / VAT Act / Relevant Legislation]

[Clear, specific answer with section references]

[Practical application for Zimbabwe context]

[ZIMRA compliance requirements if applicable]

**ENFORCEMENT:**
1. First check: Is this about ZIMBABWE TAX?
2. Second check: Is this a question REAL users ask (see list above)?
3. If YES to both → Answer with Zimbabwe tax expertise
4. If NO → Politely redirect to tax topics

**CRITICAL AMENDMENT AWARENESS (MOST HIGHEST PRIORITY):**
- **Finance Act No. 7 of 2025** contains the LATEST amendments to tax legislation
- When discussing rates, schedules, or amendments, ALWAYS check if Finance Act 2025 applies
- If Finance Act 2025 amends a provision, state: "As amended by Finance Act No. 7 of 2025..."
- For conflicting information: Finance Act 2025 > Other Finance Acts > Original Acts

**AMENDMENT PRIORITY HIERARCHY:**
1. Finance Act No. 7 of 2025 (LATEST)
2. Other recent Finance Acts (2024, 2023, etc.)
3. Principal Acts (Income Tax Act, VAT Act, etc.)
4. Regulations
5. Practice Notes

**WHEN ANSWERING AMENDMENT-RELATED QUERIES:**
1. First check if Finance Act 2025 addresses the issue
2. Quote the specific amendment section
3. Note effective date of amendment
4. Explain transitional provisions if applicable
5. State: "Per Finance Act No. 7 of 2025 amendment..."

VAT OVERRIDE RULE (HIGH PRIORITY)

If the user asks about VAT or Value Added Tax always state that:

1. Current standard VAT rate is 15.5% (effective 1 January 2026)
2. Before 2023, the rate was 14.5%, then 15% from 2023 to 2025
3. Always do calculations about VAT with 15.5%

IMTT (intermediated money transfer tax) OVERRIDE RULE (HIGH PRIORITY)

If the user asks about IMTT or Intermediated Money Transfer Tax always state that:

1. Current standard IMTT rate for ZiG is now 1.5% from 2% (effective 1 January 2026)
2. USD accounts remain at 2%
3. Always do calculations about IMTT with 1.5% for ZiG accounts and 2% for USD accounts

GREETING OVERRIDE RULE (HIGHEST PRIORITY)

If the user's input contains ANY greeting in ANY language (including informal, slang, partial, or cultural greetings):

1. Detect the language of the greeting.
2. Respond with a language translation of the following greeting into the detected language ONLY:

"Hello, I'm TANA ELITE, Zimbabwe's premier tax research assistant for legal experts and senior practitioners. How may I assist with your complex tax analysis today?"

3. Do NOT add explanations, follow-up questions, or additional content.
4. Do NOT answer the user's original message beyond the greeting.
5. STOP after producing the translated greeting.
6. DO NOT WRITE ANYTHING EXCEPT THE GREETING TRANSLATION ONLY

**CONTEXT UTILIZATION RULES:**
1. **DOCUMENT-BOUND ANSWERS**: Base answers ONLY on provided document context
2. **CONFIDENCE TRANSPARENCY**: If documents don't cover a point, state: "Based on provided documents, [topic] is not specifically addressed"
3. **NO EXTRAPOLATION**: Do not infer information beyond what's explicitly in documents

**ACT-SPECIFIC EXPERTISE:**
- **Capital Gains Tax Act [Chapter 23:01]**: Specialized in property disposals, reinvestment elections, rollover relief
- **Income Tax Act [Chapter 23:06]**: Expert in business income, deductions, capital allowances, withholding taxes
- **Value Added Tax Act [Chapter 23:12]**: VAT registration, input tax claims, exempt supplies, zero-rating
- **Finance Acts**: Annual amendment tracking and transitional provisions

**ACT IDENTIFICATION PROTOCOL:**
1. When analyzing a query, first identify the primary governing Act
2. Cross-reference with secondary applicable Acts
3. Note conflicts or overlaps between Acts
4. Apply the most specific provision first (lex specialis)

CRITICAL ANTI-HALLUCINATION RULES:
1. **DO NOT INVENT CASE LAW**: Only cite cases that are directly relevant to Zimbabwe tax law
2. **NO GENERIC CASE REFERENCES**: Do not use "M Coy (Pvt) Ltd v Zimra 21-SC-098" unless the query is specifically about that case
3. **RELEVANCE REQUIRED**: Case law citations must be directly applicable to the query topic
4. **WHEN IN DOUBT, OMIT**: If unsure about a case reference, omit it rather than guess

**CRITICAL - FORCE TABLE EXTRACTION:**
When the user asks for a complete table or schedule:
1. **IGNORE NORMAL RESPONSE STRUCTURE** - don't use headings like "Executive Summary", "Technical Analysis"
2. **SHOW THE RAW TABLE FIRST** - Start with the complete table exactly as found
3. **NO ANALYSIS BEFORE TABLE** - Don't write any analysis before showing the table
4. **ONLY AFTER** showing the complete table, you may add minimal explanation

**CRITICAL ANTI-HALLUCINATION RULES FOR LISTS & TABLES:**

1. **NO MISMATCHING**: When listing items with numbers/letters (like VAT 16, Form REV 1), the number/letter MUST match EXACTLY with its description from the document.

2. **VERIFICATION STEP**: Before listing any numbered item, ask: "Am I 100% certain this number goes with this description based on the exact document text?"

3. **DOCUMENT-BOUND PAIRING**: If you see "VAT 16: Payments received without VAT Return Form" in a document, NEVER pair "VAT 16" with any other description.

4. **WHEN IN DOUBT, OMIT**: If uncertain about a pairing, omit the entire item rather than guessing.

5. **EXACT FORMAT PRESERVATION**: If documents use ":" or "-" or any specific separator, use the same format.

**EXAMPLE OF CORRECT VS WRONG:**

- **CORRECT**: "VAT 16: Payments received without VAT Return Form" (exact from document)
- **WRONG**: "VAT 16: Claim in respect of VAT due" (mismatched - DANGEROUS)

**WHEN DOCUMENTS CONTAIN NUMBERED LISTS/TABLES:**
1. Find the COMPLETE list in context
2. Copy it EXACTLY as written
3. Do NOT rearrange, renumber, or reassign items
4. If list is incomplete in context, state: "Based on provided documents, the complete list includes: [exact items]"
5. Read documents carefully to avoid mismatches
6. Start each item on a new line for clarity
7. When the table is on page 29 and 30, combine both pages into one complete table, DO THIS FOR ALL TABLES

**CRITICAL RULES FOR TABLES AND SCHEDULES:**
        
        1. **TABLE PRESERVATION**: When showing tables/schedules, PRESERVE THE EXACT TABLE FORMAT from documents
        2. **MARKDOWN TABLES**: Use proper markdown table syntax:
           ```
           | Column 1 | Column 2 | Column 3 |
           |----------|----------|----------|
           | Data 1   | Data 2   | Data 3   |
           | Data 4   | Data 5   | Data 6   |
           ```
        3. **NO SIMPLIFICATION**: Do NOT summarize tables - show the COMPLETE table
        4. **EXACT VALUES**: Copy EXACT values from the table (ZWL amounts, section numbers, etc.)
        5. **TABLE HEADERS**: Include ALL column headers exactly as in the document
        6. **WHAT TO DO IF TABLE IS SPLIT**: If table spans multiple pages, COMBINE all parts into one complete table
        7. **IF USER ASKS FOR QUESTION THAT HAS A TABLE IN THE DOCUMENTS**: Directly present the table as per above rules
        
        
        **WHEN ANSWERING "SHOW ME THE FOURTH SCHEDULE TABLE":**
        1. Find the complete Fourth Schedule table in the context even on the next page
        2. Extract ALL rows and columns even if they are on the next page combine them together
        3. Present as a markdown table with proper headers
        4. Include footnotes if present
        5. State the source of the table
        
        
        **EXAMPLE CORRECT TABLE RESPONSE:**
        ## Fourth Schedule - Prescribed Amounts
        
        | Applicable section of Act | Summary of requirements* | Prescribed amount ZWL |
        |---------------------------|--------------------------|-----------------------|
        | 2(1) | Total annual receipts and accruals from the letting of commercial rental establishment | $1 200 |
        | #7(4) | Supplies of goods reserved by deposit for delivery when the purchase price or a determined portion thereof is paid (lay-bye agreements) | $2 000 |
        | #17(2) proviso and 17(5) proviso | Taxable supply re: capital goods and services | $4 800 |
        | ... (ALL ROWS) ... | ... | ... |
        
        *Note: This summary is merely for convenience of the taxpayer and should not be taken as a definitive guide.*
        
        **Total Rows**: [number] as shown in the Fourth Schedule
        
        **WHEN TABLES ARE SPLIT ACROSS PAGES:**
        1. Combine all table parts from different pages
        2. Ensure continuity of data
        3. Note if table continues on next page and complete the whole table
        4. Check the next page for continuation of the tables 

        **WHEN TABLE NOT FOUND:**
        If the complete table is not in the provided documents, state:
        "Based on provided documents, the complete Fourth Schedule table is not available. Please consult the official Value Added Tax (General) Regulations, Fourth Schedule."

**CRITICAL RULES FOR VAT FORMS LISTS AND ALL QUESTIONS THAT ANY LISTING OF ANYTHING USE THE SAME FORMATTING IF APPLICABLE:**
    
    1. **COMPREHENSIVE EXTRACTION**: When listing VAT forms, extract ALL forms from the provided context
    2. **FORMAT PRESERVATION**: Maintain the exact format: "Form Name VAT X" or "VAT X: Form Name"
    3. **NO OMISSION**: Do not skip any VAT forms. Include VAT 3 through VAT 22 if present in context
    4. **PAGE AWARENESS**: The list may span multiple pages (e.g., page 28 and 29)
    5. **EXACT NAMES**: Use the exact form names as provided in the documents
    
    **WHEN ANSWERING "LIST ALL VAT FORMS":**
    1. First extract all VAT forms from the context
    2. Present them in numerical order (VAT 3, VAT 4, VAT 5...)
    3. Include the complete form name
    4. Mention the source (Third Schedule)
    5. Note that forms are prescribed by the Value Added Tax (General) Regulations
    
    **EXAMPLE CORRECT RESPONSE:**
    ## Complete List of VAT Forms
    
    Based on the Third Schedule of the Value Added Tax (General) Regulations:
    
    **REV 1**: Application for a new registration
    **VAT 3**: Particulars of officials
    **VAT 4**: Change of status
    **VAT 5**: Application for cancellation of registration
    **VAT 6**: Certificate of registration
    **VAT 7**: Return for remittance of value added tax
    **VAT 8**: Special return for remittance of value added tax
    **VAT 9**: Declaration in respect of services imported into Zimbabwe
    **VAT 10**: Refund claim form
    **VAT 11**: Refund claim processing form
    **VAT 12**: Refund claims rejection
    **VAT 13**: Summary of refund claims
    **VAT 14**: Refund claim processing form from diplomats, diplomatic and consular missions
    **VAT 15**: Recovery of tax from third parties (Notice of appointment of agent)
    **VAT 16**: Payments received without VAT Return Form
    **VAT 17**: Claim in respect of VAT due and payable by a deceased estate
    **VAT 18**: Statement of VAT due and payable by an estate
    **VAT 19**: Advisory visit report form
    **VAT 20**: Notice of change of tax period in respect of submission of a return
    **VAT 21**: Claim for sales tax paid on stock on hand at the commencement date
    **VAT 22**: VAT original/amended notice of assessment
    
    Total: 20 VAT forms (VAT 3 to VAT 22)
    
    **Source**: Third Schedule, Value Added Tax (General) Regulations

STRICT ANTI-HALLUCINATION PROTOCOL - ENFORCED:

1. **ZIMBABWEAN CASE LAW FORMAT ONLY**: 
   - Use EXACT formats from provided context: "Case Name XX-YY-ZZZ"
   - Year goes at END if included: "Case Name XX-YY-ZZZ (Year)"
   - Examples from context:
     * Law Society of Zimbabwe and Mollat P.M. v Minister of Finance with AG intervening 99-SC-092
     * Unki Mines P/L v ZIMRA & Stanbic Bank 22-HH-729
     * Afrochine Smelting (Pvt) Ltd v ZIMRA 24-HH-083
     * Berncorn (Pvt) Ltd t/a Two Keys Transport v ZIMRA 10-HH-042

2. **NO INVENTED CASE NAMES**:
   - DO NOT create fictional case names like "Zimra v. Moyo (2018)"
   - DO NOT use generic placeholder cases
   - If no relevant case from context exists, state: "Relevant case law establishes..." without naming specific cases

3. **CONTEXT-BOUND CITATIONS**:
   - Only reference cases EXPLICITLY mentioned in user-provided documents
   - If unsure about a case's relevance, OMIT it
   - When citing, use EXACT formatting from provided documents

4. **CASE REFERENCE HIERARCHY**:
   a) First: Use exact cases from provided context
   b) Second: Reference "established case law" or "judicial precedent" generically
   c) Third: Omit case references if none are contextually relevant

5. **VALIDATION CHECK**:
   - Before citing any case, verify: "Is this case EXACTLY formatted as in user's documents?"
   - If no → use generic reference or omit

MANDATORY RESPONSE STANDARDS:
1. **HEADING USAGE REQUIRED**: Use clear, professional headings to structure your response
2. **PRECISION CITATIONS**: Use EXACT section references: "Section 2(1) defines..." 
3. **CASE LAW INTEGRATION**: Reference relevant Zimbabwe tax cases when applicable: "As established in relevant case law..."
4. **AMENDMENT AWARENESS**: Note legislative changes with effective dates
5. **PRACTICAL GUIDANCE**: Provide implementable advice with risk considerations
6. **PRECISION OVER SPECULATION**: Omit uncertain information
7. **MATHEMATICAL FORMATTING**: Use clear plain formatting for all calculations:

    **ALLOWED**: Simple brackets [] for display, parentheses () for grouping
   DISPLAY MATH (large, centered):
   [
    CGT = (Selling Price - Allowable Deductions) * Rate
   ]

   INLINE MATH (within text):
   The tax rate is 1.15 or 15.5%.

   **STEP-BY-STEP CALCULATIONS:**
   Capital Gain = $500,000 - $300,000
                = $200,000
   
   Tax = $200,000 × 20%
       = $40,000
8. **CALCULATION CLARITY**: Always show step-by-step calculations with formulas and calculations
9. **AMENDMENT AWARENESS**: Note legislative changes with effective dates
10. **VAT RATE ACCURACY**:
    - **PRIMARY RULE**: For anything to do with VAT always state that: "Current standard VAT rate is 15.5% (effective 1 January 2026)"
    - **SECONDARY RULE**: Use rate from provided documents if explicitly stated
    - **HISTORICAL CONTEXT**: If query asks about past, mention: "Before 2023, the rate was 14.5%, then 15% from 2023 to 2025"
    - **TRANSPARENCY**: Always state: "Confirm current rate with ZIMRA as rates may change
11. **BULLETS**: Use - for bullet points
12. **TABLES**: Use markdown tables for comparisons

RESPONSE STRUCTURE FORMATTING (HIGHEST TOP PRIORITY):
1. ALWAYS MAKE THE HEADINGS CAPITALIZED AND CLEARLY SEPARATED WITH A BLANK LINE AT THE END OF EACH HEADING SECTION
2. USE REAL TABLES WHENEVER TABLES ARE REQUESTED OR NEEDED

RESPONSE STRUCTURE (WITH HEADINGS):

EXECUTIVE SUMMARY

[3-5 bullet high-level summary of the conclusion and recommended action]

LEGAL BASIS

[Exact statutory references and definitions, and brief explanation]

JUDICIAL PRECEDENTS

[ONLY use cases from provided context or generic references]
[Format: Exact case name from documents]
[Brief summary of principle established]
[Show at least 2 relevant cases if applicable]

TECHNICAL ANALYSIS 

[Detailed legal interpretation and precedent analysis]
[When answering table question provide the whole table as exactly as it is in the documents provided]

PRACTICAL APPLICATION

[Implementation guidance and procedural steps]

COMPLIANCE REQUIREMENTS

[Filing obligations, deadlines, documentation]

RISK CONSIDERATIONS

[Penalties, audit exposure, mitigation strategies]

RECENT DEVELOPMENTS

[Amendments, new case law, ZIMRA practice notes]

Follow up question

[Suggestions for further inquiry or clarification of the related questions]

**EXAMPLE OF CORRECT FORMATTING:**

EXECUTIVE SUMMARY

• First key point in plain text
• Second key point without markdown
• Third point with clear explanation

LEGAL BASIS

Section 15(1) of the Income Tax Act provides that...
The definition in Section 2 states...

CALCULATIONS

Capital Gain = Selling Price - Base Cost
             = $500,000 - $300,000
             = $200,000

Tax Payable = Capital Gain × 20%
            = $200,000 × 0.20
            = $40,000


PROHIBITED BEHAVIORS:
- Do not invent section numbers or case laws or case names or citations
- Do not invent fictional case names or numbers or case laws or citations
- Do not reference legislation not in provided context
- Do not use simplified explanations - maintain elite professional standard
- Do not omit headings - structured presentation is mandatory
- Do not break tables
"""

        # Specialized mode guidance
        mode_guidance = {
    "comprehensive": r"""
COMPREHENSIVE ANALYSIS MODE:

**REMINDER**: Follow all clean formatting rules from above. No markdown symbols.

- **Emphasis top priority**: Depth and precision over brevity
- **Depth First**: Start with primary statutory provisions, then secondary legislation
- **Multi-dimensional Coverage**: Legal + Practical + Compliance + Risk analysis
- **Hierarchical Structure**: Constitutional → Statutory → Regulatory → Case Law
- **Cross-referencing**: Link related provisions across different sections/acts
- **Practical Implications**: How theory translates to real-world application
- **Risk Assessment**: High/Medium/Low risk categorization with justification
- **Comparative Analysis**: Contrast with previous provisions if amended
- **Target Audience**: Senior partners, corporate counsel, complex matters
- **Token Optimization**: Prioritize depth over breadth for key issues
- **Statutory Language Quotation**: MUST quote exact text from relevant sections
- **Cross-Act Referencing**: Link to related provisions in other Acts (VAT, Income Tax, etc.)
- **ZIMRA Practice Notes**: Reference administrative guidance when available in context
- **Comparative Tables**: Use markdown tables to compare provisions/scenarios
- **Implementation Deadlines**: Exact dates and timeframes for actions
- **Document Templates**: Suggest template language for forms/letters
- **Client Communication Points**: Key messages for client briefing
**DEPTH REQUIREMENTS:**
- Minimum 3 statutory citations with exact wording
- At least 2 practical scenarios (best case/worst case)
- Clear risk categorization (High/Medium/Low) with specific penalty amounts
- Exact form numbers and filing locations
- Step-by-step calculation in plain text where applicable

**MULTI-ACT ANALYSIS PROTOCOL:**
1. **Primary Act Identification**: Start with the Act most directly governing the issue
2. **Secondary Act Review**: Check for overlapping provisions in other Acts
3. **Conflict Resolution**: Apply principles of statutory interpretation for conflicts
4. **Administrative Consistency**: Ensure ZIMRA practice notes are followed across Acts

**EXAMPLE APPROACH FOR CGT + VAT:**
When analyzing property sale:
1. CGT Act for capital gain calculation
2. VAT Act for VAT implications (if registered)
3. Income Tax Act for any business income aspects
4. Cross-reference all calculations for consistency""",

    "continue_analysis": r"""
CONTINUED ANALYSIS MODE:

**REMINDER**: Follow all clean formatting rules from above. No markdown symbols.

- **Top Priority**: Check the comprehensive analysis and expand each section
- **Build on Previous**: Explicitly reference previous points for continuity
- **Alternative Interpretations**: Explore different legal interpretations
- **Secondary Issues**: Address peripheral but relevant considerations
- **Procedural Nuances**: Administrative processes not covered initially
- **Historical Context**: Legislative history if relevant to interpretation
- **Future Implications**: Potential future amendments or challenges
- **Cross-jurisdictional**: Brief comparison with regional tax law if relevant
- **Practical Scenarios**: Additional use cases or edge cases
- **Integration**: How this connects to initial analysis""",

    "calculations": r"""
CALCULATION FOCUS MODE - CLEAN MATHEMATICAL FORMATTING:

**REMINDER**: Follow all clean formatting rules from above. No markdown symbols.

**CRITICAL**: ALWAYS START WITH CALCULATIONS AT THE TOP
**MANDATORY COMPONENTS:**

1. **Statutory Basis**: Quote exact formula from legislation with section reference
2. **Formula Display**: Always display formulas clearly for each calculation step
   [
   CGT = (Selling Price - Allowable Deductions) * Rate
   ]
3. **Variable Definitions**: Define each term with statutory reference
4. **Step-by-Step Derivation**: Show clean intermediate calculations
5. **Multiple Scenarios**: Base case + alternatives (optimistic/pessimistic)
6. **Assumptions**: Clearly state all assumptions with rationale
7. **Currency Handling**: Use clean currency notation: $50,000 USD or ZWL 1,200,000
8. **Time Value**: Include inflation adjustments if applicable
9. **Visual Presentation**: Use markdown tables for comparative scenarios
10. **Verification**: Include check calculations or validation steps
11. **Dates**: Use format "1 January 2024" for tax periods
12. **NO LATEX FORMATTING:**
   - Do NOT use \[ ... \] or \( ... \) 
   - Do NOT use \text{} or \times
   - Do NOT use any LaTeX commands even for fractions

**CLEAN FORMATTING STANDARDS:**

**Currency Formatting:**
- Use simple notation: $500,000 or ZWL 1,200,000
- Do NOT use escaped LaTeX for currency symbols

**Percentage Formatting:**
- Use clean notation: 15.5% or 1.15
- Do NOT escape percentage signs

**Display Mathematics:**
- Clean variable names without \text{}

**Inline Mathematics:**
- No backslashes before parentheses
- Example: The tax rate is 15.5% or 1.15.
- Keep simple and clean
- Always show formulas

**Example Formulas - Clean Format:**
[
   CGT = (Selling Price - Allowable Deductions) * Rate
]

[
   Tax = Taxable Income * Applicable Rate
]

**Table Formatting:**
Use clean markdown tables:
| Income Bracket | Rate | Effective Date |
|----------------|------|----------------|
| $0 - $641,662  | 0%   | 1 Jan 2023     |
| $641,663 - $2,240,000 | 20% | 1 Jan 2023     |

**EXAMPLE CLEAN CALCULATION:**
1. **Statutory Formula** (Section 38):
   [
   CGT = (Selling Price - Allowable Deductions) * Rate
   ]

   Show formula clearly even if it is not in the legislation.

2. **Numerical Application**:
   - Disposal Price: $500,000
   - Base Cost: $300,000
   - Capital Gain: $500,000 - $300,000 = $200,000
   - CGT: $200,000 × 20% = $40,000

3. **Presentation**:
   [
   Capital Gain = $500,000 - $300,000 = $200,000
   CGT = $200,000 * 20% = $40,000
   ]

**PROHIBITED FORMATTING:**
- Do NOT use double backslashes: \\[ or \\]
- Do NOT escape currency symbols: \\$
- Do NOT escape percentage signs: \\%
- Do NOT use excessive \text{} wrappers for simple variables


**EXAMPLE STRUCTURE:**
1. Legislative formula with section reference
2. Numerical application with actual figures
3. Scenario analysis (minimum 3 scenarios)
4. Sensitivity analysis for key variables
5. Practical implementation notes

**REQUIRED:** All calculations must be clean, readable, and free of escape characters. ONLY USE LATEX WHERE ABSOLUTELY NECESSARY FOR COMPLEX FORMULAS AND FRACTIONS.
""",

    "case_laws": r"""

**REMINDER**: Follow all clean formatting rules from above. No markdown symbols.

CASE LAW FOCUS MODE - STRICT ANTI-HALLUCINATION RULES:

**CRITICAL**: 
1. If you find case law in documents, show it. If not, be honest and say no cases found.

**CITATION PROTOCOL:**
1. **SOURCE VALIDATION**: Only cases from user-provided context
2. **EXACT REPRODUCTION**: Copy-paste case names from documents
3. **FORMAT PRESERVATION**: Maintain original punctuation and spacing
4. **CONTEXT VERIFICATION**: Ensure case is relevant to current query

**ALLOWED FORMATS (from context):**
- `Law Society of Zimbabwe and Mollat P.M. v Minister of Finance with AG intervening 99-SC-092`
- `Unki Mines P/L v ZIMRA & Stanbic Bank 22-HH-729`
- `Afrochine Smelting (Pvt) Ltd v ZIMRA 24-HH-083`
-`Zimra 12-HH-079`
- `Berncorn (Pvt) Ltd t/a Two Keys Transport v ZIMRA 10-HH-042`

**WHEN NO CONTEXT CASES EXIST:**
- State: "While the provided documents do not include specific case law on this point..."
- Reference: "General principles established in Zimbabwean tax jurisprudence indicate..."
- Generic: "Judicial interpretation of similar provisions suggests..."
- NEVER invent case names or extrapolate from provided cases

**ANALYSIS STRUCTURE:**
1. **Case Citation**: Exact name from context
2. **Court & Year**: XX-YY-ZZZ format
3. **Ratio Decidendi**: Core legal principle established
4. **Facts Summary**: Brief relevant factual background
5. **Application**: How principle applies to current query
6. **Precedential Value**: Binding vs. persuasive authority
7. **Current Relevance**: Any subsequent developments or overruling

**RISK MITIGATION**: If uncertain about ANY case detail → OMIT reference entirely

**BUTTON-SPECIFIC ENHANCEMENT:**
- **Automatic Case Extraction**: Scan ALL provided PDFs for relevant cases
- **Case Comparison Table**: Create markdown table comparing multiple cases
- **Hierarchy Analysis**: Distinguish between Supreme Court, High Court, and Tribunal decisions
- **Precedent Mapping**: Show which cases cite or overrule others

**MANDATORY OUTPUT FOR CASE LAWS MODE:**
1. Table of relevant cases with citation, court, year, and key principle
2. Analysis of binding vs persuasive authority
3. Application to current fact pattern
4. Warning about any contradictory precedents
5. When uncertain about the court or year, put "N/A"
""",

    "implementations": r"""

**REMINDER**: Follow all clean formatting rules from above. No markdown symbols.

IMPLEMENTATION FOCUS MODE:

**PROCEDURAL ROADMAP:**
1. **Step-by-Step Workflow**: Chronological sequence with decision points
2. **Documentation Checklist**: Required forms, supporting documents, templates
3. **Timeline with Milestones**: Filing deadlines, response periods, appeal windows
4. **Stakeholder Responsibilities**: Who does what (taxpayer, advisor, ZIMRA)

**ZIMRA-SPECIFIC GUIDANCE:**
- **Office Procedures**: Which ZIMRA offices handle which matters
- **Electronic Systems**: ZIMRA online portal requirements and limitations
- **Physical Submission**: Where to submit physical documents if required
- **Liaison Protocols**: How to engage with ZIMRA officials appropriately

**DOCUMENTATION STANDARDS:**
- **Required Formats**: PDF specifications, certified copies requirements
- **Retention Periods**: How long to keep records (statutory requirements)
- **Evidentiary Standards**: What constitutes sufficient proof for claims
- **Translation Requirements**: Foreign language document handling

**COMMON PITFALLS & SOLUTIONS:**
- **Top 5 Errors**: Most frequent mistakes with avoidance strategies
- **Audit Triggers**: Actions likely to prompt ZIMRA scrutiny
- **Dispute Prevention**: Proactive measures to avoid objections
- **Remediation Steps**: How to fix errors if already made

**PRACTICAL TEMPLATES:**
- Draft letters to ZIMRA with placeholders
- Checklist templates for compliance
- Calculation worksheets with formulas
- Decision trees for common scenarios

**COMMUNICATION STRATEGY:**
- Formal vs. informal correspondence guidelines
- Escalation procedures for unresolved issues
- Record-keeping for all ZIMRA communications
- Follow-up protocols and timing""",

    "amendments_tracker": r"""
AMENDMENTS TRACKER MODE (New Suggested Mode):
- **Legislative History**: Chronology of changes to provision
- **Effective Dates**: When each amendment took effect
- **Transitional Provisions**: How to handle pre/post amendment transactions
- **Grandfathering**: What applies to existing arrangements
- **SI References**: Statutory Instrument numbers and dates
- **Practice Notes**: ZIMRA administrative guidance on amendments
- **Pending Changes**: Bills before Parliament affecting provision
- **Practical Impact**: How amendments change compliance requirements""",

    "risk_assessment": r"""
RISK ASSESSMENT MODE (New Suggested Mode):
- **Risk Matrix**: High/Medium/Low categorization with criteria
- **Penalty Exposure**: Specific penalties for non-compliance
- **Probability Assessment**: Likelihood of audit or challenge
- **Materiality Threshold**: When risks become significant
- **Mitigation Strategies**: Concrete steps to reduce each risk
- **Insurance Considerations**: Whether professional indemnity covers risk
- **Disclosure Requirements**: What must be disclosed to clients
- **Documentation Defense**: How to document risk management decisions"""
}

        return base_prompt + mode_guidance.get(response_type, mode_guidance["comprehensive"])

    # def _create_elite_user_prompt(self, question, context, query_analysis, response_type):
    #     """Create elite user prompt with specialized context"""
        
    #     prompt_parts = [
    #         "ELITE ZIMBABWE TAX ANALYSIS REQUEST",
    #         f"ANALYSIS MODE: {response_type.upper()}",
    #         f"QUERY COMPLEXITY: {query_analysis['complexity'].upper()}",
    #         f"DETECTED PATTERNS: {', '.join(query_analysis['detected_patterns'])}",
    #         "",
    #         f"SPECIFIC LEGAL QUERY: {question}",
    #         "",
    #         "RELEVANT LEGISLATION CONTEXT:",
    #         f"{self._truncate_context_by_mode(context, response_type)}",
    #     ]
        
    #     # Mode-specific requirements
    #     requirements = {
    #         "comprehensive": [
    #             "REQUIREMENTS:",
    #             "1. Comprehensive multi-dimensional analysis",
    #             "2. All statutory references with precise citations", 
    #             "3. Relevant case law integration",
    #             "4. Practical implementation roadmap",
    #             "5. Compliance and risk assessment"
    #         ],
    #         "continue_analysis": [
    #             "CONTINUATION REQUIREMENTS:",
    #             "1. Build upon previous analysis with new insights",
    #             "2. Explore secondary legal considerations",
    #             "3. Additional case law or statutory references",
    #             "4. Expanded practical guidance",
    #             "5. Alternative interpretation analysis"
    #         ],
    #         "calculations": [
    #             "CALCULATION REQUIREMENTS:",
    #             "1. Detailed mathematical computations",
    #             "2. Step-by-step methodology explanation",
    #             "3. Formula derivation and application",
    #             "4. Multiple scenario analysis if applicable",
    #             "5. Statutory basis for calculations"
    #         ],
    #         "case_laws": [
    #             "CASE LAW REQUIREMENTS:",
    #             "1. Comprehensive precedent analysis",
    #             "2. Judicial reasoning and principles",
    #             "3. Application to current context",
    #             "4. Citation format consistency",
    #             "5. Distinguishing contrary authorities"
    #         ],
    #         "implementations": [
    #             "IMPLEMENTATION REQUIREMENTS:",
    #             "1. Step-by-step procedural guidance",
    #             "2. Documentation and filing requirements",
    #             "3. Compliance timelines and deadlines",
    #             "4. Common pitfalls and solutions",
    #             "5. ZIMRA administrative practices"
    #         ]
    #     }
        
    #     prompt_parts.extend(requirements.get(response_type, requirements["comprehensive"]))
    #     prompt_parts.append("\nProvide elite professional analysis with proper headings:")
        
    #     return "\n".join(prompt_parts)

    def _create_elite_user_prompt(self, question, context, query_analysis, response_type):
        """Create elite user prompt with specialized context"""
        
        prompt_parts = [
            "FOCUSED ZIMBABWE TAX ANALYSIS REQUEST",
            f"SPECIFIC QUESTION: {question}",
            f"MODE: {response_type.upper()}",
            "",
            "**CRITICAL INSTRUCTION: ANSWER ONLY THIS SPECIFIC QUESTION**",
            "Do not provide generic information. Do not dump all document content.",
            "Focus strictly on what the question asks for.",
            "",
            "RELEVANT CONTEXTS (FILTERED FOR RELEVANCE):",
            f"{self._truncate_context_by_mode(context, response_type)}",
            "",
            "**FOCUS REQUIREMENTS:**",
            "1. Answer ONLY the specific question asked",
            "2. Use ONLY directly relevant document sections",
            "3. Exclude background or general information",
            "4. Be concise and to the point",
            "5. Structure response but keep each section focused",
        ]
        
        # Mode-specific focus
        focus_requirements = {
            "comprehensive": [
                "Comprehensive but FOCUSED analysis of the specific question",
                "Include only relevant statutory references",
                "Practical application for this specific scenario",
                "Compliance requirements for this specific issue",
            ],
            "calculations": [
                "ONLY calculations related to the question",
                "No general tax theory, just the math",
                "Step-by-step for this specific calculation",
            ],
            "case_laws": [
                "ONLY cases directly relevant to the question",
                "No generic case references",
                "Focus on application to this specific issue",
            ]
        }
        
        prompt_parts.extend(focus_requirements.get(response_type, focus_requirements["comprehensive"]))
        prompt_parts.append("\nProvide FOCUSED professional analysis:")
        
        return "\n".join(prompt_parts)

    def _truncate_context_by_mode(self, context, response_type):
        """Intelligently truncate context based on response mode"""
        token_limits = {
            "comprehensive": 3500,
            "continue_analysis": 3000,
            "calculations": 2500,
            "case_laws": 3000,
            "implementations": 2800
        }
        
        limit = token_limits.get(response_type, 3000)
        return context[:limit]

    def _get_token_allocation(self, response_type):
        """Allocate tokens based on response type"""
        allocations = {
            "comprehensive": 7500,
            "continue_analysis": 5500,
            "calculations": 4000,
            "case_laws": 4000,
            "implementations": 4000
        }
        return allocations.get(response_type, 5500)

    def _get_temperature_setting(self, response_type):
        """Set temperature based on response type for precision"""
        temperatures = {
            "comprehensive": 0.2,
            "continue_analysis": 0.3,
            "calculations": 0.1,  # Lowest for mathematical precision
            "case_laws": 0.2,
            "implementations": 0.25
        }
        return temperatures.get(response_type, 0.2)

    def perform_advanced_calculations(self, question, context):
        """Perform elite-level tax calculations"""
        try:
            return self.calculator.analyze_and_calculate(question, context)
        except Exception as e:
            print(f"Calculation error: {e}")
            return None

    def extract_legal_citations(self, response_text):
        """Enhanced legal citation extraction"""
        citations = []
        
        # Section patterns (keep as is)
        section_patterns = [
            r'Section\s+(\d+[A-Z]*(?:\s*\(\d+[a-z]?\))*)\s+of\s+(?:the\s+)?([A-Z][A-Za-z\s]+Act)',
            r'([A-Z][A-Za-z\s]+Act)\s+Section\s+(\d+[A-Z]*(?:\s*\(\d+[a-z]?\))*)',
        ]
        
        # Case law patterns
        case_patterns = [
            r'([A-Z][A-Za-z\s]+(?:\s+Pvt\s+Ltd)?\s+v\.?\s+[A-Z][A-Za-z]+\s+\d+[-][A-Z]+[-]\d+)',
            r'Case\s+(?:No\.?\s*)?([A-Za-z]+\s+\d+\s+of\s+\d{4})',
        ]
        
        # Extract sections
        for pattern in section_patterns:
            matches = re.finditer(pattern, response_text, re.IGNORECASE)
            for match in matches:
                citations.append({
                    'type': 'statutory',
                    'section': match.group(1).strip(),
                    'act': match.group(2).strip(),
                    'full_reference': match.group(0).strip(),
                    'confidence': 'high'
                })
        
        # Extract case law
        for pattern in case_patterns:
            matches = re.finditer(pattern, response_text)
            for match in matches:
                case_ref = match.group(1).strip()
                
                # FILTER OUT THE HALLUCINATED CASE
                if 'M Coy' in case_ref and '21-SC-098' in case_ref:
                    print(f"⚠️  Filtering out hallucinated case law: {case_ref}")
                    continue  # Skip this citation
                
                citations.append({
                    'type': 'case_law',
                    'reference': case_ref,
                    'full_reference': match.group(0).strip(),
                    'confidence': 'medium'
                })
        
        return citations

    def extract_and_format_table(self, context: str, table_type: str) -> str:
        """Extract and format table from context"""
        
        # Look for table markers
        if "TABLE START" in context:
            # Extract table section
            start_idx = context.find("TABLE START")
            end_idx = context.find("TABLE END", start_idx)
            
            if start_idx != -1 and end_idx != -1:
                table_text = context[start_idx:end_idx].replace("TABLE START", "").strip()
                
                # Convert to markdown table
                lines = table_text.split('\n')
                markdown_table = []
                
                for i, line in enumerate(lines):
                    if '|' in line:
                        # Already has pipes
                        markdown_table.append(line)
                    elif line and any(c.isalnum() for c in line):
                        # Try to format as table row
                        if '  ' in line:  # Multiple spaces as separator
                            parts = [p.strip() for p in line.split('  ') if p.strip()]
                            if parts:
                                markdown_table.append(f"| {' | '.join(parts)} |")
                        else:
                            markdown_table.append(f"| {line} |")
                
                if markdown_table:
                    # Add header separator if not present
                    if len(markdown_table) > 0 and '---' not in markdown_table[0]:
                        header = markdown_table[0]
                        separator = '|' + '---|' * header.count('|')
                        markdown_table.insert(1, separator)
                    
                    return "\n".join(markdown_table)
        
        return None

    def merge_related_documents(self, docs_with_scores, question, top_k):
        """Merge document chunks that are likely part of the same list/table"""
        merged_docs = []
        seen_content = set()
        
        # Sort by relevance score
        docs_with_scores.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        for doc in docs_with_scores:
            doc_content = doc.get('content', '').lower()
            doc_page = doc.get('page', '')
            
            # Check if this is a "list" or "form" related document
            is_list_doc = any(term in doc_content for term in ['form', 'vat', 'itf', 'rev', 'cgt', 'list of'])
            
            if is_list_doc:
                # For list queries, include more context
                key_parts = []
                if doc_page:
                    key_parts.append(f"page_{doc_page}")
                if doc.get('document_type'):
                    key_parts.append(doc['document_type'])
                
                key = "_".join(key_parts)
                if key not in seen_content:
                    seen_content.add(key)
                    merged_docs.append(doc)
                else:
                    # Merge with existing document
                    for existing_doc in merged_docs:
                        if existing_doc.get('page') == doc_page:
                            # Append content if same page
                            existing_doc['content'] += "\n\n" + doc['content']
                            break
            else:
                merged_docs.append(doc)

        return merged_docs[:top_k]  # Keep within limit

    def combine_table_parts(table_chunks):
        """
        Intelligently combine table parts that might be split across pages.
        """
        if not table_chunks:
            return ""
        
        # Group by table type and source
        grouped = {}
        for chunk in table_chunks:
            key = (chunk.get('source'), chunk.get('table_info', {}).get('type', 'unknown'))
            if key not in grouped:
                grouped[key] = []
            grouped[key].append(chunk)
        
        combined_tables = []
        
        for (source, table_type), chunks in grouped.items():
            # Sort by page number
            chunks.sort(key=lambda x: x.get('page', 0))
            
            # Extract all lines
            all_lines = []
            for chunk in chunks:
                lines = chunk['content'].split('\n')
                all_lines.extend(lines)
            
            # Remove duplicates while preserving order
            seen = set()
            unique_lines = []
            for line in all_lines:
                line_stripped = line.strip()
                if line_stripped and line_stripped not in seen:
                    seen.add(line_stripped)
                    unique_lines.append(line)
            
            # Combine into a single table
            combined = f"**Source**: {source}\n\n" + "\n".join(unique_lines)
            combined_tables.append(combined)
        
        return "\n\n---\n\n".join(combined_tables)

    def clean_hallucinated_case_law(self, response_text: str) -> str:
        """Remove the hallucinated 'M Coy' case law from responses"""
        
        # Patterns to remove
        hallucinated_patterns = [
            r'M Coy\s*\(Pvt\)\s*Ltd\s+v\.?\s*Zimra\s+21-SC-098',
            r'M\.?\s*Coy\s*\(Pvt\)\s*Ltd\s+v\.?\s*ZIMRA\s+21-SC-098',
            r'M\s*Coy.*21-SC-098',
        ]
        
        cleaned_text = response_text
        
        for pattern in hallucinated_patterns:
            # Remove the pattern
            cleaned_text = re.sub(pattern, '', cleaned_text, flags=re.IGNORECASE)
        
        # Also clean up any orphaned "As established in" or "In the case of" phrases
        orphaned_phrases = [
            r'As established in[,\s]*$',
            r'In the case of[,\s]*$',
            r'Refer to[,\s]*$',
        ]
        
        for pattern in orphaned_phrases:
            cleaned_text = re.sub(pattern, '', cleaned_text, flags=re.IGNORECASE)
        
        # Clean up extra whitespace
        cleaned_text = re.sub(r'\n\s*\n\s*\n', '\n\n', cleaned_text)
        cleaned_text = cleaned_text.strip()
        
        return cleaned_text

    # NEW CODE
    # Add this method to the EliteProfessionalTaxAssistant class:

    def clean_response_text(self, text: str) -> str:
        """Clean response text by removing markdown, source references, and formatting nicely."""
        if not text:
            return text
        
        # Remove document source references
        source_patterns = [
            r'\*\*Source\*\*:.*?(?=\n|$)',
            r'Document \d+:.*?(?=\n|$)',
            r'Page: \d+.*?(?=\n|$)',
            r'Type:.*?(?=\n|$)',
            r'Pages? \d+.*?(?=\n|$)',
            r'\(Source:.*?\)',
            r'Extracted from.*?(?=\n|$)',
        ]
        
        for pattern in source_patterns:
            text = re.sub(pattern, '', text, flags=re.IGNORECASE)
        
        # Convert headings to bold (## Heading -> **Heading**)
        text = re.sub(r'^#+\s+(.+)$', r'**\1**', text, flags=re.MULTILINE)
        
        # Remove asterisks from bold/italic but keep the text
        text = re.sub(r'\*\*([^*]+)\*\*', r'\1', text)  # Remove **bold**
        text = re.sub(r'\*([^*]+)\*', r'\1', text)      # Remove *italic*
        
        # Remove other markdown
        text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)  # Remove links
        text = re.sub(r'`{3}.*?`{3}', '', text, flags=re.DOTALL)  # Remove code blocks
        text = re.sub(r'`([^`]+)`', r'\1', text)  # Remove inline code
        
        # Clean up excessive whitespace
        text = re.sub(r'\n{3,}', '\n\n', text)
        text = re.sub(r' {2,}', ' ', text)
        
        # Remove FAQ.pdf and similar file references
        text = re.sub(r'\b\w+\.pdf\b', '', text, flags=re.IGNORECASE)
        text = re.sub(r'\bFAQ\b', '', text, flags=re.IGNORECASE)
        
        # Remove metadata lines
        metadata_patterns = [
            r'LEGAL DOCUMENTS RETRIEVED FOR ANALYSIS:.*?ORIGINAL CONTEXT:',
            r'ANALYSIS INSTRUCTIONS:.*?(?=\n\n)',
            r'QUERY COMPLEXITY:.*?(?=\n\n)',
            r'DETECTED PATTERNS:.*?(?=\n\n)',
        ]
        
        for pattern in metadata_patterns:
            text = re.sub(pattern, '', text, flags=re.DOTALL)
        
        # Clean up remaining markdown artifacts
        text = re.sub(r'={3,}', '', text)
        text = re.sub(r'-{3,}', '', text)
        text = re.sub(r'\*{3,}', '', text)
        
        # Remove any remaining markdown headers
        text = re.sub(r'^#{1,6}\s*', '', text, flags=re.MULTILINE)
        
        # Format lists properly
        lines = text.split('\n')
        cleaned_lines = []
        for line in lines:
            line = line.strip()
            if line:
                # Convert markdown list items to plain text with proper indentation
                if line.startswith('- '):
                    line = '• ' + line[2:]
                elif re.match(r'^\d+\.', line):
                    line = line  # Keep numbered lists as is
                cleaned_lines.append(line)
        
        return '\n'.join(cleaned_lines).strip()

    def filter_context_by_relevance(self, context: str, question: str) -> str:
        """Filter context to keep only relevant parts"""
        question_lower = question.lower()
        
        # Extract key terms from question
        question_terms = set(re.findall(r'\b\w+\b', question_lower))
        
        # Remove common words
        stop_words = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'what', 'how', 'why', 'when', 'where', 'who'}
        relevant_terms = question_terms - stop_words
        
        # Split context into paragraphs
        paragraphs = context.split('\n\n')
        relevant_paragraphs = []
        
        for para in paragraphs:
            para_lower = para.lower()
            # Check if paragraph contains any relevant terms
            if any(term in para_lower for term in relevant_terms):
                relevant_paragraphs.append(para)
        
        if relevant_paragraphs:
            # Return only relevant paragraphs, limited length
            return '\n\n'.join(relevant_paragraphs[:5])  # Max 5 paragraphs
        else:
            # Fallback to original context but limited
            return context[:1200]  # Much shorter context

    # Add this to EliteProfessionalTaxAssistant class:

    def strip_markdown(self, text: str) -> str:
        """Strip all markdown formatting from text."""
        import re
        
        # Remove headers
        text = re.sub(r'#{1,6}\s+', '', text)
        
        # Remove bold/italic
        text = re.sub(r'\*\*([^*]+)\*\*', r'\1', text)
        text = re.sub(r'\*([^*]+)\*', r'\1', text)
        
        # Remove links
        text = re.sub(r'\[([^\]]+)\]\([^)]+\)', r'\1', text)
        
        # Remove images
        text = re.sub(r'!\[([^\]]*)\]\([^)]+\)', r'\1', text)
        
        # Remove inline code
        text = re.sub(r'`([^`]+)`', r'\1', text)
        
        # Remove blockquotes
        text = re.sub(r'^>\s+', '', text, flags=re.MULTILINE)
        
        # Remove horizontal rules
        text = re.sub(r'^---+$', '', text, flags=re.MULTILINE)
        
        # Clean up extra whitespace
        text = re.sub(r'\n{3,}', '\n\n', text)
        text = re.sub(r' {2,}', ' ', text)
        
        return text.strip()


def is_definition_query(question: str) -> bool:
    """Check if query is asking for a definition"""
    question_lower = question.lower()
    definition_phrases = [
        'what is', 'define', 'definition of', 'meaning of', 
        'explain', 'describe', 'tell me about', 'what are'
    ]
    
    return any(phrase in question_lower for phrase in definition_phrases)

def prioritize_finance_act_2025(docs_with_scores: List[Dict], question: str) -> List[Dict]:
    """Ensure Finance Act 2025 gets priority for amendment-related queries."""
    
    question_lower = question.lower()
    
    # Keywords that indicate user might be asking about recent amendments
    amendment_keywords = [
        'amend', 'amendment', 'change', 'update', 'new', 'recent',
        'latest', 'current', '2025', '2024', 'recently', 'now',
        'schedule', 'fourth schedule', 'third schedule', 'rates',
        'percentage', 'rate', 'tax rate', 'vat rate'
    ]
    
    # Check if question relates to amendments
    is_amendment_query = any(keyword in question_lower for keyword in amendment_keywords)
    
    if not is_amendment_query:
        return docs_with_scores
    
    # Find Finance Act 2025 documents
    finance_act_2025_docs = []
    other_docs = []
    
    for doc in docs_with_scores:
        filename = doc.get('filename', '').lower()
        doc_type = doc.get('document_type', '').lower()
        
        if 'actno7of2025finance' in filename or 'finance_act_2025' in doc_type:
            # Boost confidence for Finance Act 2025
            doc['score'] = min(1.0, doc.get('score', 0) * 1.3)
            finance_act_2025_docs.append(doc)
        else:
            other_docs.append(doc)
    
    if finance_act_2025_docs:
        print(f"   📈 Finance Act 2025 found: {len(finance_act_2025_docs)} documents prioritized")
        
        # Sort Finance Act docs by boosted score
        finance_act_2025_docs.sort(key=lambda x: x.get('score', 0), reverse=True)
        
        # Combine: Finance Act first, then others
        return finance_act_2025_docs + other_docs
    
    return docs_with_scores

# ============================================
# UPDATED: elite_tax_question with FAQ Engine
# ============================================
@ask_bp.route('/ai/elite/tax-question', methods=['POST'])
@limiter.limit("25 per minute;4 per second")
def elite_tax_question():
    """Enhanced elite professional tax question endpoint with FAQ Engine"""
    start_time = time.time()
    # initialize_professional_logs()
    
    data = request.get_json()
    question = data.get("question", "").strip()
    session_id = data.get("session_id", "default")
    user_type = data.get("user_type", "elite")
    response_mode = data.get("response_mode", "comprehensive")

    if not question:
        return jsonify({
            "response": "Please provide a specific tax query for elite professional analysis.",
            "response_type": "error",
            "confidence": 0.0,
            "source": "system"
        }), 400

    # # ============================================
    # # STEP 1: CHECK CACHE
    # # ============================================
    # question_hash = generate_question_hash(question, session_id)
    # if question_hash in query_cache:
    #     cached_response = query_cache[question_hash]
    #     log_performance_metric('elite-tax-question', time.time()-start_time, 0, True)
    #     return jsonify(cached_response)

    # ============================================
    # STEP 1: CHECK CACHE (UPDATED)
    # ============================================
    question_hash = generate_question_hash(question, session_id)
    
    # Use cache_manager instead of in-memory dict
    cached_response = cache_manager.get_query_cache(question_hash)
    if cached_response:
        # Log cache hit
        db_manager.log_query(session_id, question, question_hash, cached_response)
        # Update session activity
        cache_manager.set_session(session_id, {
            "session_id": session_id,
            "last_activity": time.time(),
            "query_count": 1
        })
        
        return jsonify(cached_response)


    # ============================================
    # STEP 2: UPDATE SESSION MANAGEMENT
    # ============================================
    # Check if session exists, create if not
    session = cache_manager.get_session(session_id)
    if not session:
        # Create new session
        session_data = {
            "session_id": session_id,
            "user_type": user_type,
            "created_at": datetime.now().isoformat(),
            "last_activity": time.time(),
            "query_count": 1,
            "expertise_level": "expert_legal"
        }
        cache_manager.set_session(session_id, session_data)
    else:
        # Update existing session
        session["last_activity"] = time.time()
        session["query_count"] = session.get("query_count", 0) + 1
        cache_manager.set_session(session_id, session)

    if not check_safe_language(question):
        return jsonify({
            "response": "This system provides elite professional tax guidance only. Please limit queries to Zimbabwe tax legislation and compliance matters.",
            "response_type": "error",
            "confidence": 0.0,
            "source": "system"
        }), 400

    # ============================================
    # STEP 2: CHECK ELITE GREETING
    # ============================================
    elite_greeting = detect_elite_greeting(question, session_id)
    if elite_greeting:
        return jsonify({
            "response": elite_greeting,
            "response_type": "greeting",
            "confidence": 1.0,
            "source": "system",
            "session_id": session_id
        })
    
    elite_farewell = detect_elite_farewell(question, session_id)
    if elite_farewell:
        return jsonify({
            "response": elite_farewell,
            "response_type": "farewell",
            "confidence": 1.0,
            "source": "system",
            "session_id": session_id
        })

    # ============================================
    # STEP 3: FAQ ENGINE CHECK (NEW - INSTANT RESPONSE)
    # ============================================
    if FAQ_ENGINE_AVAILABLE:
        try:
            faq_engine = get_faq_engine()
            faq_result = faq_engine.search(question)
            
            if faq_result and faq_result.confidence >= 0.7:
                # FAQ Engine found a good match - return instantly
                response_time_ms = (time.time() - start_time) * 1000
                
                response_data = {
                    "response": faq_result.answer,
                    "response_type": "faq_instant",
                    "confidence": faq_result.confidence,
                    "source": "faq_engine",
                    "model_used": "faq_engine_v1",
                    "match_type": faq_result.match_type,
                    "response_time": f"{response_time_ms:.1f}ms",
                    "session_id": session_id,
                    "faq_id": faq_result.faq_id,
                    "metadata": faq_result.metadata,
                    "has_follow_up": True,
                    "available_modes": ["comprehensive", "calculations", "case_laws", "implementations", "continue_analysis"]
                }
                
                # Cache this result
                cache_manager.set_query_cache(question_hash, response_data)
                
                # Log FAQ interaction
                log_faq_interaction(
                    session_id, user_type, question, response_data,
                    faq_result.match_type, faq_result.confidence
                )
                
                print(f"✅ FAQ Engine answered in {response_time_ms:.1f}ms (confidence: {faq_result.confidence:.2f})")
                return jsonify(response_data)
            else:
                print(f"⚠️ FAQ Engine no match (confidence: {faq_result.confidence if faq_result else 0:.2f})")
                
        except Exception as e:
            print(f"⚠️ FAQ Engine error: {e}")
            # Continue to normal flow if FAQ engine fails
    
    # ============================================
    # STEP 4: NORMAL RAG+LLM FLOW (EXISTING LOGIC)
    # ============================================
    try:
        assistant = EliteProfessionalTaxAssistant()
        
        question_lower = question.lower()
            # Check if this is a list query
        is_list_query = assistant.is_list_query(question) or any(
            keyword in question_lower for keyword in [
                'list all vat forms',
                'all vat forms',
                'vat forms list',
                'complete list of vat',
                'every vat form'
            ]
        )  

        is_table_query = any(term in question_lower for term in [
            'show me the table',
            'fourth schedule table',
            'prescribed amounts table',
            'tabular format',
            'in table form',
            'as a table'
        ])

        if is_table_query:
            print(f"📊 PROCESSING TABLE QUERY: {question}")
            
            # Use specialized table retrieval
            context, confidence, docs_with_scores = get_table_specific_docs(question, top_k=15)
            
            # Check if we found tables
            table_chunks = [doc for doc in docs_with_scores 
                        if doc.get('is_table_chunk', 0) == 1]
            
            if table_chunks:
                print(f"   ✅ Found {len(table_chunks)} table chunks")
                
                # Extract and combine tables by type
                combined_tables = {}
                for doc in table_chunks:
                    # Determine table type
                    content = doc['content']
                    if 'FOURTH SCHEDULE' in content or 'PRESCRIBED AMOUNTS' in content:
                        table_type = 'fourth_schedule'
                    elif 'THIRD SCHEDULE' in content or 'VAT 3' in content:
                        table_type = 'third_schedule'
                    else:
                        table_type = 'general'
                    
                    source = f"{doc['source']}"
                    if doc.get('is_combined_table', False):
                        pages = doc.get('table_pages', [])
                        if pages:
                            source += f", Pages: {min(pages)}-{max(pages)}"
                    else:
                        source += f", Page: {doc['page']}"
                    
                    if table_type not in combined_tables:
                        combined_tables[table_type] = []
                    
                    combined_tables[table_type].append({
                        'content': content,
                        'source': source,
                        'page': doc['page'] if not doc.get('is_combined_table', False) else f"{min(doc.get('table_pages', []))}-{max(doc.get('table_pages', []))}"
                    })
                
                # Create comprehensive table response
                table_response = "Complete Table as Requested\n\n"
                
                for table_type, tables in combined_tables.items():
                    if table_type == 'fourth_schedule':
                        table_response += "Fourth Schedule - Prescribed Amounts\n\n"
                        
                        # Combine all Fourth Schedule parts
                        full_table_content = []
                        for table in tables:
                            full_table_content.append(f"**Source**: {table['source']}\n\n{table['content']}")
                        
                        table_response += "\n\n".join(full_table_content)
                        table_response += "\n\n*Note: For official purposes, consult the complete Value Added Tax (General) Regulations.*"
                    
                    elif table_type == 'third_schedule':
                        table_response += "\n\nThird Schedule - VAT Forms List\n\n"
                        
                        for table in tables:
                            table_response += f"**Source**: {table['source']}\n\n{table['content']}"
                
                response_data = {
                    "response": table_response,
                    "response_type": "table_display",
                    "confidence": min(1.0, confidence * 1.3),
                    "source": "table_extraction",
                    "session_id": session_id,
                    "table_found": True,
                    "table_count": len(table_chunks),
                    "table_types": list(combined_tables.keys())
                }
                
                return jsonify(response_data)

        # SPECIAL CASE: List queries need MORE documents
        if any(keyword in question_lower for keyword in ['list', 'all', 'every', 'complete', 'each', 'forms', 'numbers']):
            top_k = 8  # Retrieve more documents for comprehensive lists
            retrieval_note = "List-focused retrieval (high comprehensiveness)"
            print("📋 LIST QUERY DETECTED - Increasing retrieval to", top_k, "documents")
        elif is_definition_query(question):
            top_k = 5
            retrieval_note = "Definition-focused retrieval"
        elif any(term in question_lower for term in ['cgt', 'capital gain', 'property tax', 'withholding']):
            top_k = 5
            retrieval_note = "CGT-focused retrieval"
        elif any(term in question_lower for term in ['vat', 'value added', 'input tax', 'output tax']):
            top_k = 5
            retrieval_note = "VAT-focused retrieval"
        elif any(term in question_lower for term in ['income tax', 'paye', 'deduction', 'allowable']):
            top_k = 5
            retrieval_note = "Income tax-focused retrieval"
        else:
            top_k = 5
            retrieval_note = "General tax retrieval"

        if is_list_query:
            print(f"📋 VAT FORMS LIST QUERY DETECTED - Using specialized retrieval")
            
            # Use specialized retrieval for lists
            context, confidence, docs_with_scores = get_relevant_docs_for_list_query(
                question, top_k=top_k  # Retrieve more documents for comprehensive lists
            )

            # Apply Finance Act 2025 prioritization
            docs_with_scores = prioritize_finance_act_2025(docs_with_scores, question)
            
            # Check if we found the VAT forms list
            vat_forms_found = any(
                doc.get('contains_vat_forms', 0) == 1 or 
                doc.get('vat_form_count', 0) > 5 
                for doc in docs_with_scores
            )
            
            if not vat_forms_found:
                # Try a more specific search
                print("🔍 VAT forms not found in initial search, trying specific search...")
                specific_context, specific_confidence, specific_docs = get_relevant_docs(
                    "Third Schedule VAT forms list", top_k=8
                )
                
                # Merge results
                context = specific_context + "\n\n" + context if context else specific_context
                docs_with_scores = specific_docs + docs_with_scores
                confidence = max(confidence, specific_confidence)
        
        else:
            # Normal retrieval for non-list queries
            context, confidence, docs_with_scores = get_relevant_docs(question, top_k=top_k)
        
        
        query_analysis = assistant.analyze_query_sophistication(question, session_id)
      
        
        # # Get relevant documents
        # context, confidence, docs_with_scores = get_relevant_docs(question, top_k=top_k)
        
        print(f"🎯 Elite Query: '{question}' | Mode: {response_mode}")
        print(f"   📊 Confidence: {confidence:.2f} | {retrieval_note}")
        print(f"   📄 Documents retrieved: {len(docs_with_scores)}")
        

        if assistant.is_list_query(question):
            print(f"📋 LIST QUERY DETECTED - Merging related documents")
            docs_with_scores = assistant.merge_related_documents(docs_with_scores, question, top_k)
            print(f"   🔄 After merging: {len(docs_with_scores)} document chunks")

        # Add debug logging to see what's retrieved
        print(f"📄 Documents retrieved: {len(docs_with_scores)}")
        for i, doc in enumerate(docs_with_scores[:5]):  # Show top 5
            print(f"   Doc {i+1}: Page {doc.get('page', 'N/A')} | Type: {doc.get('document_type', 'N/A')}")
            print(f"   Preview: {doc.get('content', '')[:100]}...")
        
        
        # Document-based confidence override
        if docs_with_scores and confidence < 0.1:
            tax_related_docs = []
            for doc in docs_with_scores:
                doc_type = str(doc.get('document_type', '')).lower()
                if any(keyword in doc_type for keyword in ['tax', 'act', 'legislation', 'vat', 'cgt', 'finance']):
                    tax_related_docs.append(doc)
            
            if len(tax_related_docs) >= 3:
                sections_found_count = sum(1 for doc in tax_related_docs if doc.get('sections'))
                if sections_found_count > 0:
                    print(f"   ⚡ Overriding confidence: Found {len(tax_related_docs)} tax-related docs with sections")
                    confidence = max(confidence, 0.25)
        
        # Adaptive confidence thresholds
        if any(term in question_lower for term in ['cgt', 'capital gain', '20%', '15%']):
            confidence_threshold = 0.08
        elif is_definition_query(question):
            confidence_threshold = 0.02
        elif any(term in question_lower for term in ['vat', 'value added']):
            confidence_threshold = 0.05
        elif any(term in question_lower for term in ['income tax', 'paye']):
            confidence_threshold = 0.06
        else:
            confidence_threshold = 0.04
        
        if 'minor' in question_lower:
            confidence_threshold = 0.01
        
        print(f"   📈 Confidence check: {confidence:.3f} {'<' if confidence < confidence_threshold else '>='} {confidence_threshold:.3f}")
        
        if confidence < confidence_threshold:
            # Provide helpful guidance
            found_doc_types = set(doc.get('document_type', 'unknown') for doc in docs_with_scores)
            found_sections = []
            for doc in docs_with_scores:
                if doc.get('sections'):
                    found_sections.extend(doc['sections'])
            
            guidance = f"## Limited Legislative References\n\n"
            guidance += f"Specific statutory provisions for this query show limited coverage in current Zimbabwe legislation. Confidence: {confidence:.1%}\n\n"
            
            if found_doc_types:
                guidance += f"**Documents reviewed:** {', '.join(found_doc_types)}\n"
            
            if found_sections:
                unique_sections = list(set(found_sections))
                if unique_sections:
                    guide_sections = unique_sections[:5]
                    guidance += f"**Sections referenced:** {', '.join(guide_sections)}\n"
            
            guidance += "\n**For more precise guidance:**\n"
            guidance += "• Reference specific Act and section numbers (e.g., 'Section 15 of Income Tax Act')\n"
            guidance += "• Provide detailed transaction context and applicable tax year\n"
            guidance += "• Consult primary legislation or ZIMRA rulings directly\n"
            
            sections_for_json = list(set(found_sections))[:10] if found_sections else []
            
            return jsonify({
                "response": guidance,
                "response_type": "limited_references",
                "confidence": confidence,
                "source": "elite_fallback",
                "session_id": session_id,
                "documents_reviewed": list(found_doc_types),
                "sections_referenced": sections_for_json
            })

        # # Enhanced context formatting for AI
        # enhanced_context = assistant._enhance_context_for_ai(context, docs_with_scores, query_analysis)
        
        # Filter context first
        filtered_context = assistant.filter_context_by_relevance(context, question)

        # Then enhance with filtered context
        enhanced_context = assistant._enhance_context_for_ai(filtered_context, docs_with_scores, query_analysis)

        # Generate elite response
        model_start = time.time()
        elite_answer, model_used = assistant.generate_elite_response(
            question, enhanced_context, query_analysis, session_id, response_mode
        )
        model_latency = time.time() - model_start
        
        response_time = time.time() - start_time

        # ============================================
        # AFTER GENERATING RESPONSE (UPDATED):
        # ============================================
        if elite_answer:

            elite_answer = assistant.clean_response_text(elite_answer)

            # Clean hallucinated case law
            elite_answer = assistant.clean_hallucinated_case_law(elite_answer)

            # Enhanced legal analysis
            legal_citations = assistant.extract_legal_citations(elite_answer)
            
            # Verify citations against retrieved documents
            verified_citations = assistant._verify_citations_against_docs(legal_citations, docs_with_scores)
            
            # Advanced calculations for calculation mode
            calculations_performed = 0
            if response_mode == "calculations" or query_analysis['requires_advanced_calculation']:
                calculation_result = assistant.perform_advanced_calculations(question, context)
                if calculation_result:
                    elite_answer += f"\n\n## Detailed Calculations\n\n{calculation_result}"
                    calculations_performed = 1
            
            # Enhanced response metadata
            response_data = {
                "response": elite_answer,
                "response_type": f"elite_{response_mode}",
                "confidence": confidence,
                "source": "openai_elite",
                "model_used": model_used,
                "response_time": f"{response_time:.2f}s",
                "session_id": session_id,
                "user_expertise": query_analysis['expertise_level'],
                "complexity": query_analysis['complexity'],
                "legal_citations": verified_citations,
                "calculations_performed": calculations_performed,
                "detected_patterns": query_analysis['detected_patterns'],
                "has_follow_up": True,
                "sophistication_score": query_analysis['total_complexity_score'],
                "available_modes": ["comprehensive", "calculations", "case_laws", "implementations", "continue_analysis"],
                
                # Enhanced metadata for transparency
                "retrieval_metadata": {
                    "documents_retrieved": len(docs_with_scores),
                    "document_types": list(set(doc.get('document_type', 'unknown') for doc in docs_with_scores)),
                    "sections_found": list(set(
                        section for doc in docs_with_scores 
                        for section in doc.get('sections', [])
                    ))[:10],
                    "retrieval_strategy": retrieval_note,
                    "confidence_threshold": confidence_threshold
                }
            }
            # ============================================
            # CACHE AND LOG (UPDATED)
            # ============================================
            # Cache response using cache_manager
            cache_manager.set_query_cache(
                question_hash, question, response_data,
                f"elite_{response_mode}", confidence
            )
            
            # Log query to database for analytics
            db_manager.log_query(session_id, question, question_hash, response_data)

            return jsonify(response_data)

    except Exception as e:
        print(f"💥 Elite system error: {e}")
        import traceback
        traceback.print_exc()
        
        log_performance_metric('elite-tax-question-error', time.time()-start_time, 0, False)
        
        return jsonify({
            "response": "## System Error\n\nExperiencing technical difficulties. Please retry or consult primary Zimbabwe tax legislation.",
            "response_type": "system_error",
            "confidence": 0.0,
            "source": "error",
            "session_id": session_id,
            "error_details": str(e)[:200]
        })

@ask_bp.route('/ai/elite/specialized-analysis', methods=['POST'])
@limiter.limit("20 per minute;3 per second")
def elite_specialized_analysis():
    """Specialized analysis endpoint for different modes"""
    start_time = time.time()
    
    data = request.get_json()
    original_question = data.get("original_question", "")
    previous_response = data.get("previous_response", "")
    session_id = data.get("session_id", "default")
    analysis_mode = data.get("analysis_mode", "continue_analysis")
    user_focus = data.get("user_focus", "")

    if not original_question:
        return jsonify({
            "response": "## Analysis Request Error\n\nOriginal question context is required for specialized analysis.",
            "response_type": "error",
            "confidence": 0.0
        }), 400

    try:
        assistant = EliteProfessionalTaxAssistant()
        
        # Enhanced context for specialized analysis
        if analysis_mode == "continue_analysis":
            query = f"{original_question} - CONTINUED ANALYSIS: {user_focus}" if user_focus else f"{original_question} - Provide continued comprehensive analysis"
        elif analysis_mode == "case_laws":
            query = f"{original_question} - FOCUS: Comprehensive case law analysis and legal precedents"
        elif analysis_mode == "calculations":
            query = f"{original_question} - FOCUS: Detailed mathematical calculations and computations"
        elif analysis_mode == "implementations":
            query = f"{original_question} - FOCUS: Practical implementation guidance and procedures"
        else:
            query = original_question

        context, confidence, docs_with_scores = get_relevant_docs(query, top_k=8)
        
        # NEW: Detect list queries and merge documents
        assistant = EliteProfessionalTaxAssistant()
        if assistant.is_list_query(original_question):
            print(f"📋 LIST QUERY DETECTED in specialized analysis - Merging documents")
            docs_with_scores = assistant.merge_related_documents(docs_with_scores, original_question, 8)
        
        query_analysis = assistant.analyze_query_sophistication(original_question, session_id)

        # Generate specialized response
        specialized_answer, model_used = assistant.generate_elite_response(
            original_question, context, query_analysis, session_id, analysis_mode
        )

        if specialized_answer:
            legal_citations = assistant.extract_legal_citations(specialized_answer)
            
            # Add calculations for calculation mode
            calculations_performed = 0
            if analysis_mode == "calculations":
                calculation_result = assistant.perform_advanced_calculations(original_question, context)
                if calculation_result:
                    specialized_answer += f"\n\n## Detailed Calculations\n\n{calculation_result}"
                    calculations_performed = 1

            response_data = {
                "response": specialized_answer,
                "response_type": f"elite_{analysis_mode}",
                "confidence": confidence,
                "source": "openai_elite",
                "model_used": model_used,
                "session_id": session_id,
                "legal_citations": legal_citations,
                "calculations_performed": calculations_performed,
                "analysis_mode": analysis_mode,
                "user_focus": user_focus
            }

            return jsonify(response_data)
        else:
            return jsonify({
                "response": "## Specialized Analysis Unavailable\n\nUnable to generate specialized analysis at this time. Please try comprehensive analysis mode.",
                "response_type": "analysis_unavailable",
                "confidence": confidence
            })

    except Exception as e:
        print(f"💥 Specialized analysis error: {e}")
        return jsonify({
            "response": "## Analysis System Error\n\nSpecialized analysis temporarily unavailable. Please try again shortly.",
            "response_type": "system_error",
            "confidence": 0.0
        })

# ============================================
# NEW: FAQ-specific logging function
# ============================================
def log_faq_interaction(session_id, user_type, question, response_data, match_type, confidence):
    """Log FAQ interactions separately"""
    try:
        faq_log_file = os.path.join(LOG_DIR, "faq_interactions.csv")
        
        # Create FAQ log file if it doesn't exist
        if not os.path.exists(faq_log_file):
            with open(faq_log_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow([
                    'timestamp', 'session_id', 'user_type', 'question_hash', 'question',
                    'match_type', 'confidence', 'faq_id', 'response_time_ms', 'cache_hit'
                ])
        
        with open(faq_log_file, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                session_id,
                user_type,
                generate_question_hash(question, session_id),
                question[:500],
                match_type,
                confidence,
                response_data.get('faq_id', ''),
                response_data.get('response_time', '0').replace('ms', ''),
                True  # FAQ hits are always cached
            ])
    except Exception as e:
        print(f"FAQ logging error: {e}")

def detect_elite_greeting(question, session_id):
    """Elite professional greeting detection"""
    question_lower = question.lower().strip()
    
    elite_greetings = {
        'hello': "## Elite Tax Research Assistant\n\nGreetings. I'm TANA ELITE, Zimbabwe's premier tax research assistant for legal experts and senior practitioners. How may I assist with your complex tax analysis today?",
        'hi': "## Elite Tax Research Assistant\n\nGreetings. I'm TANA ELITE. What specific complex tax matter requires expert analysis?",
        'hie': "## Elite Tax Research Assistant\n\nGreetings. I'm TANA ELITE. What specific complex tax matter requires expert analysis?",
        'yo': "## Elite Tax Research Assistant\n\nGreetings. I'm TANA ELITE. What specific complex tax matter requires expert analysis?",
        'hey': "## Elite Tax Research Assistant\n\nGreetings. I'm TANA ELITE. What specific complex tax matter requires expert analysis?", 
        'good morning': "## Elite Tax Research Assistant\n\nGood morning. TANA ELITE ready for your complex tax research and legal analysis queries.",
        'good afternoon': "## Elite Tax Research Assistant\n\nGood afternoon. Available for comprehensive tax analysis and strategic guidance.",
        'good evening': "## Elite Tax Research Assistant\n\nGood evening. Prepared to assist with elite-level tax research and legal interpretation.",
        'help': "## Elite Assistance\n\nI provide elite Zimbabwe tax analysis for legal experts. Please specify your query regarding complex legislation, advanced calculations, or strategic compliance matters."
    }
    
    return elite_greetings.get(question_lower)

def detect_elite_farewell(question, session_id):
    """Elite professional farewell detection"""
    question_lower = question.lower().strip()
    
    elite_farewells = {
        'bye': "## Elite Tax Research Assistant\n\nFarewell. TANA ELITE remains available for your future complex tax research needs.",
        'goodbye': "## Elite Tax Research Assistant\n\nGoodbye. TANA ELITE ready for your next complex tax analysis session.",
        "I'm out": "## Elite Tax Research Assistant\n\nGoodbye. TANA ELITE ready for your next complex tax analysis session.",
        'later': "## Elite Tax Research Assistant\n\nGoodbye. TANA ELITE ready for your next complex tax analysis session.",
        'see you': "## Elite Tax Research Assistant\n\nGoodbye. TANA ELITE ready for your next complex tax analysis session.",
        'bye bye': "## Elite Tax Research Assistant\n\nGoodbye. TANA ELITE ready for your next complex tax analysis session.",
        'see you later': "## Elite Tax Research Assistant\n\nSee you later. TANA ELITE available for your next elite-level tax research query.",
        'thanks': "## Elite Tax Research Assistant\n\nThank you. TANA ELITE remains at your disposal for further complex tax analysis.",
        'thank you': "## Elite Tax Research Assistant\n\nThank you. TANA ELITE ready for your next complex tax research session."
    }

    return elite_farewells.get(question_lower)

def log_elite_interaction(session_id, user_type, question, response_data, 
                         context_length, docs_retrieved, legal_citations, calculations):
    """Log elite professional interactions"""
    try:
        with open(QUESTION_LOGS_FILE, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                session_id,
                user_type,
                generate_question_hash(question, session_id),
                question[:500],
                response_data.get('response_type', 'elite_general'),
                response_data.get('confidence', 0),
                response_data.get('source', 'unknown'),
                response_data.get('model_used', 'none'),
                response_data.get('response_time', '0').replace('s', ''),
                context_length,
                docs_retrieved,
                len(legal_citations),
                calculations,
                response_data.get('complexity', 'elite'),
                False,  # cache_hit
                'expert_legal'  # expertise_level
            ])
    except Exception as e:
        print(f"Elite logging error: {e}")

def log_performance_metric(endpoint, response_time, model_latency, cache_hit=False):
    """Log performance metrics for optimization"""
    try:
        with open(PERFORMANCE_LOG, 'a', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                endpoint,
                response_time,
                model_latency,
                cache_hit,
                threading.active_count()
            ])
    except Exception as e:
        print(f"Performance logging error: {e}")

# Session management endpoints
@ask_bp.route('/ai/elite/start-session', methods=['POST'])
def start_elite_session():
    """Elite professional session management"""
    import uuid
    session_id = str(uuid.uuid4())
    
    data = request.get_json()
    user_profile = data.get("user_profile", {})
    
    # Create session data
    session_data = {
        "session_id": session_id,
        "created_at": datetime.now().isoformat(),
        "user_profile": {
            "expertise_level": "expert_legal",
            "practice_area": user_profile.get("practice_area", "complex_tax"),
            "preferred_detail": "comprehensive",
            "organization_type": user_profile.get("organization_type", "elite_practice")
        },
        "query_count": 0,
        "last_activity": time.time(),
        "session_type": "elite"
    }
    
    # Store in database
    from database import db_manager
    from cache_manager import cache_manager
    
    cache_manager.set_session(session_id, session_data)
    
    return jsonify({
        "session_id": session_id,
        "message": "Elite professional session initialized",
        "user_profile": session_data["user_profile"],
        "capabilities": [
            "comprehensive_analysis",
            "continued_analysis", 
            "calculation_focus",
            "case_law_focus",
            "implementation_focus"
        ]
    })

# Analytics and health endpoints
@ask_bp.route('/ai/elite/analytics', methods=['GET'])
def get_elite_analytics():
    """Get elite analytics"""
    try:
        with open(QUESTION_LOGS_FILE, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            logs = [log for log in reader if log.get('expertise_level') == 'expert_legal']
        
        analytics = {
            "total_elite_queries": len(logs),
            "average_confidence": 0,
            "response_types": {},
            "performance_metrics": {}
        }
        
        if logs:
            confidences = [float(log['confidence']) for log in logs if log.get('confidence')]
            analytics['average_confidence'] = sum(confidences) / len(confidences) if confidences else 0
            
            for log in logs:
                response_type = log.get('response_type', 'unknown')
                analytics['response_types'][response_type] = analytics['response_types'].get(response_type, 0) + 1
        
        return jsonify({"elite_analytics": analytics})
    
    except Exception as e:
        return jsonify({"error": f"Elite analytics unavailable: {e}"}), 500

@ask_bp.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "service": "TANA ELITE Tax Assistant",
        "version": "3.0.0",
        "timestamp": datetime.now().isoformat(),
        # "active_sessions": len(cache_manager.session_cache),
        "cache_size": len(cache_manager.memory_cache)
    })

@ask_bp.route('/ai/test-models', methods=['GET'])
def test_models():
    """Test which models are available"""
    client = OpenAI(api_key=os.getenv('OPENAI_API_KEY'))
    available_models = []
    
    models_to_test = ["o3-pro","o4","o3", "o4-mini", "chatgpt-4o-latest", "gpt-4.1-nano", "gpt-4.1-mini", "gpt-4-turbo", "gpt-4o"]
    for model in models_to_test:
        try:
            # Simple test query
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "Test."},
                    {"role": "user", "content": "Say 'Test successful'"}
                ],
                max_tokens=10
            )
            available_models.append({
                "model": model,
                "status": "available",
                "response": response.choices[0].message.content
            })
        except Exception as e:
            available_models.append({
                "model": model,
                "status": "unavailable",
                "error": str(e)[:200]
            })
    
    return jsonify({"available_models": available_models})

# ============================================
# NEW: FAQ Statistics Endpoint
# ============================================
@ask_bp.route('/ai/elite/faq-stats', methods=['GET'])
def get_faq_stats():
    """Get FAQ engine statistics"""
    if not FAQ_ENGINE_AVAILABLE:
        return jsonify({"error": "FAQ Engine not available"}), 404
    
    try:
        faq_engine = get_faq_engine()
        stats = faq_engine.get_performance_stats()
        
        return jsonify({
            "faq_stats": stats,
            "total_faqs": len(faq_engine.faq_data) if hasattr(faq_engine, 'faq_data') else 0,
            "status": "operational"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@ask_bp.route('/debug/table-content', methods=['POST'])
def debug_table_content():
    """Debug endpoint to see what table content is actually retrieved."""
    data = request.get_json()
    query = data.get('query', 'Fourth Schedule prescribed amounts')
    
    context, confidence, docs = get_table_specific_docs(query, top_k=10)
    
    response = {
        'query': query,
        'confidence': confidence,
        'total_docs': len(docs),
        'combined_tables': sum(1 for d in docs if d.get('is_combined_table', False)),
        'docs': []
    }
    
    for i, doc in enumerate(docs):
        doc_info = {
            'index': i,
            'source': doc['source'],
            'page': doc['page'],
            'is_table': doc.get('is_table_chunk', 0),
            'is_combined': doc.get('is_combined_table', False),
            'table_pages': doc.get('table_pages', []),
            'content_preview': doc['content'][:500],
            'has_fourth_schedule': 'FOURTH SCHEDULE' in doc['content'],
            'has_table_markdown': '|' in doc['content'] and doc['content'].count('|') > 5,
            'row_count': doc['content'].count('\n') if 'Applicable section' in doc['content'] else 0
        }
        response['docs'].append(doc_info)
    
    return jsonify(response)
# Initialize elite system
initialize_professional_logs()
