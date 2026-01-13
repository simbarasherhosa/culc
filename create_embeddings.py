import os
import sys
import re
import json
import time
from typing import List, Dict, Any, Tuple
from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_chroma import Chroma
import hashlib

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# from config import PDF_DIR, EMBEDDINGS_DIR, USE_OPENAI_EMBEDDINGS, OPENAI_API_KEY, OPENAI_EMBEDDING_MODEL, COLLECTION_NAME
from config import PDF_DIR, EMBEDDINGS_DIR, USE_OPENAI_EMBEDDINGS, OPENAI_API_KEY, OPENAI_EMBEDDING_MODEL, COLLECTION_NAME, LLAMA_CLOUD_API_KEY

# ============================================
# DYNAMIC EMBEDDING MODEL SELECTION
# ============================================
def get_embedding_model():
    """Select embedding model based on configuration"""
    if USE_OPENAI_EMBEDDINGS and OPENAI_API_KEY:
        print("🔷 Using OpenAI embeddings")
        print(f"   Model: {OPENAI_EMBEDDING_MODEL}")
        
        from langchain_openai import OpenAIEmbeddings
        os.environ["OPENAI_API_KEY"] = OPENAI_API_KEY
        
        return OpenAIEmbeddings(
            model=OPENAI_EMBEDDING_MODEL,
            # Optional: Reduce dimensions for storage efficiency
            # dimensions=1024,  # text-embedding-3-large supports dimension reduction
            api_key=OPENAI_API_KEY
        )
    else:
        print("🔷 Using local HuggingFace embeddings")
        
        from langchain_huggingface import HuggingFaceEmbeddings
        
        # Use BGE model for better legal text understanding
        return HuggingFaceEmbeddings(
            model_name="all-MiniLM-L6-v2",  # Better than all-mpnet-base-v2 for structure
            model_kwargs={'device': 'cpu'},
            encode_kwargs={
                'normalize_embeddings': True,
                'show_progress_bar': False
            }
        )

# ============================================
# ENHANCED PDF LOADERS
# ============================================
def load_pdf_with_tables(pdf_path: str) -> List[Any]:
    """
    Load PDF with table preservation using multiple methods.
    Returns list of documents with preserved table structure.
    """
    from langchain_core.documents import Document
    
    all_docs = []
    filename = os.path.basename(pdf_path)
    
    print(f"   📊 Loading with enhanced table extraction...")
    
    try:
        # ============================================
        # OPTION 1: LlamaParse (BEST for tables)
        # ============================================
        if LLAMA_CLOUD_API_KEY:
            print("   🔷 Trying LlamaParse...")
            try:
                from llama_parse import LlamaParse
                from langchain_community.document_loaders import LlamaParseLoader
                
                parser = LlamaParse(
                    api_key=LLAMA_CLOUD_API_KEY,
                    result_type="markdown",  # Preserves tables as markdown!
                    verbose=True,
                    language="en",
                    parsing_instruction="""Extract ALL text, tables, and schedules exactly as they appear. 
                    Preserve table structures with markdown formatting. Include all headers, footnotes, and page numbers.
                    For tax legislation: preserve section numbers, schedules, and prescribed amounts."""
                )
                
                loader = LlamaParseLoader(pdf_path, parser=parser)
                llama_docs = loader.load()
                
                for i, doc in enumerate(llama_docs):
                    doc.metadata.update({
                        'source': filename,
                        'page': i + 1,
                        'extraction_method': 'llamaparse',
                        'has_tables': 1 if '|' in doc.page_content else 0
                    })
                    all_docs.append(doc)
                
                print(f"   ✅ LlamaParse loaded {len(llama_docs)} pages")
                return all_docs
                
            except Exception as e:
                print(f"   ⚠️ LlamaParse failed: {e}")
        
        # ============================================
        # OPTION 2: PyMuPDF + PDFPlumber Hybrid
        # ============================================
        print("   🔷 Using PyMuPDF + PDFPlumber hybrid...")
        import fitz  # PyMuPDF
        import pdfplumber
        
        # Load with PyMuPDF for text
        doc = fitz.open(pdf_path)
        
        for page_num in range(len(doc)):
            page_text = ""
            
            # Extract text with PyMuPDF (better for regular text)
            page = doc[page_num]
            page_text += page.get_text()
            
            # Try to extract tables with PDFPlumber
            try:
                with pdfplumber.open(pdf_path) as pdf:
                    plumber_page = pdf.pages[page_num]
                    
                    # Extract tables
                    tables = plumber_page.extract_tables()
                    for table_num, table in enumerate(tables):
                        if table:
                            # Convert table to markdown
                            table_md = table_to_markdown(table)
                            page_text += f"\n\nTABLE {table_num + 1}:\n{table_md}"
                    
                    # Extract text with layout
                    plumber_text = plumber_page.extract_text()
                    if plumber_text and len(plumber_text) > len(page_text):
                        page_text = plumber_text
            except:
                pass
            
            if page_text.strip():
                # Clean and add metadata
                cleaned_text, sections = clean_legal_text(page_text)
                
                doc_info = Document(
                    page_content=cleaned_text,
                    metadata={
                        'source': filename,
                        'page': page_num + 1,
                        'extraction_method': 'pymupdf_pdfplumber',
                        'has_tables': 1 if 'TABLE' in cleaned_text else 0,
                        'original_sections': ','.join(sections[:10]),
                        'sections_count': len(sections),
                    }
                )
                all_docs.append(doc_info)
        
        print(f"   ✅ Hybrid loader loaded {len(all_docs)} pages")
        return all_docs
        
    except Exception as e:
        print(f"   ❌ Enhanced loading failed: {e}")
        
        # Fallback to PyPDFLoader
        print("   🔷 Falling back to PyPDFLoader...")
        from langchain_community.document_loaders import PyPDFLoader
        loader = PyPDFLoader(pdf_path)
        fallback_docs = loader.load()
        
        for i, doc in enumerate(fallback_docs):
            doc.metadata.update({
                'source': filename,
                'page': i + 1,
                'extraction_method': 'pypdf_fallback',
                'has_tables': 0
            })
            all_docs.append(doc)
        
        return all_docs

def table_to_markdown(table: List[List[str]]) -> str:
    """Convert extracted table to markdown format."""
    if not table or len(table) < 2:
        return ""
    
    markdown_lines = []
    
    # Add headers
    headers = table[0]
    markdown_lines.append("| " + " | ".join(str(cell).strip() for cell in headers) + " |")
    markdown_lines.append("|" + "|".join(["---"] * len(headers)) + "|")
    
    # Add rows
    for row in table[1:]:
        if row:
            markdown_lines.append("| " + " | ".join(str(cell).strip() for cell in row) + " |")
    
    return "\n".join(markdown_lines)

# ============================================
# TABLE-AWARE TEXT SPLITTER
# ============================================
def create_table_aware_chunks(docs: List[Any]) -> List[Any]:
    """Create chunks that don't break tables."""
    from langchain_core.documents import Document
    
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=2500,  # Larger for tables
        chunk_overlap=500,  # More overlap
        separators=[
            "\n\nTABLE \d+:\n",  # Table boundaries
            "\n\nFOURTH SCHEDULE\n",
            "\n\nTHIRD SCHEDULE\n", 
            "\n\nSCHEDULE\n",
            "\n\nPART ",
            "\n\nSection \d+:",
            "\n\n",
            "\n",
            ". ", " ", ""
        ],
        length_function=len,
        keep_separator=True
    )
    
    all_chunks = []
    
    for doc_index, doc in enumerate(docs):
        content = doc.page_content
        base_metadata = doc.metadata.copy()
        
        # Check if this contains schedules/tables
        content_lower = content.lower()
        has_schedule = any(schedule in content_lower for schedule in 
                          ['fourth schedule', 'third schedule', 'first schedule', 'second schedule'])
        has_table = base_metadata.get('has_tables', 0) == 1 or '|' in content
        
        if has_schedule or has_table:
            # Don't split schedule/table content aggressively
            print(f"   📊 Preserving schedule/table content from {base_metadata.get('source')} page {base_metadata.get('page')}")
            
            # Mark as special chunk
            base_metadata['is_schedule_chunk'] = 1
            base_metadata['schedule_type'] = detect_schedule_type(content)
            
            # Keep as larger chunk
            if len(content) > 5000:  # If very large, do gentle split
                gentle_splitter = RecursiveCharacterTextSplitter(
                    chunk_size=5000,
                    chunk_overlap=1000,
                    separators=["\n\nSCHEDULE\n", "\n\n", "\n"],
                    keep_separator=True
                )
                chunks = gentle_splitter.split_text(content)
            else:
                chunks = [content]
        else:
            # Normal splitting for regular text
            chunks = splitter.split_text(content)
        
        for chunk_index, chunk in enumerate(chunks):
            if len(chunk.strip()) < 150:
                continue
            
            # Create metadata
            chunk_metadata = create_chroma_compatible_metadata(base_metadata, chunk)
            chunk_metadata['chunk_index'] = chunk_index
            chunk_metadata['total_chunks'] = len(chunks)
            chunk_metadata['doc_index'] = doc_index
            
            # Detect tables in chunk
            if '|' in chunk and chunk.count('|') > 5:
                chunk_metadata['contains_table_markdown'] = 1
                chunk_metadata['table_column_count'] = chunk.split('\n')[0].count('|') if '\n' in chunk else 0
            
            all_chunks.append(Document(
                page_content=chunk,
                metadata=chunk_metadata
            ))
    
    return all_chunks

def detect_schedule_type(content: str) -> str:
    """Detect what type of schedule this is."""
    content_lower = content.lower()
    
    if 'fourth schedule' in content_lower and 'prescribed amount' in content_lower:
        return 'fourth_schedule'
    elif 'third schedule' in content_lower and ('vat form' in content_lower or 'form number' in content_lower):
        return 'third_schedule_vat_forms'
    elif 'first schedule' in content_lower:
        return 'first_schedule'
    elif 'second schedule' in content_lower:
        return 'second_schedule'
    elif 'schedule' in content_lower:
        return 'general_schedule'
    else:
        return 'unknown'

# ============================================
# EXISTING FUNCTIONS (keep them as is)
# ============================================
def extract_section_numbers(text: str) -> List[str]:
    """Extract section numbers from legal text."""
    patterns = [
        r'^\s*(\d+[A-Z]*(?:\(\d+[a-z]?\))?)\s+[A-Z][A-Za-z\s]+(?:\n|$)',
        r'Section\s+(\d+[A-Z]*(?:\(\d+[a-z]?\))?)',
        r'^\s*(\d+[A-Z]*(?:\(\d+[a-z]?\))?)\.\s+',
    ]
    
    all_sections = []
    for pattern in patterns:
        matches = re.findall(pattern, text, re.MULTILINE | re.IGNORECASE)
        all_sections.extend(matches)
    
    valid_sections = []
    for section in set(all_sections):
        section = section.strip()
        if not section:
            continue
        if re.match(r'^\d+[A-Z]*(?:\(\d+[a-z]?\))?$', section):
            valid_sections.append(section)
    
    return sorted(valid_sections, key=lambda x: [int(c) if c.isdigit() else c for c in re.split(r'(\d+)', x)])

def clean_legal_text(text: str) -> Tuple[str, List[str]]:
    """Enhanced cleaning for Zimbabwe legal documents."""
    text = re.sub(r'Page \d+ of \d+', '', text)
    text = re.sub(r'CHAPTER \d+:\d+', '', text)
    text = re.sub(r'\n\s*\n\s*\n+', '\n\n', text)
    
    sections = extract_section_numbers(text)
    
    lines = text.split('\n')
    normalized_lines = []
    
    for line in lines:
        section_match = re.match(r'^\s*(\d+[A-Z]*(?:\(\d+[a-z]?\))?)\s+([A-Z].*)$', line.strip())
        if section_match:
            section_num = section_match.group(1)
            title = section_match.group(2)
            normalized_lines.append(f"Section {section_num}: {title}")
        else:
            normalized_lines.append(line)
    
    text = '\n'.join(normalized_lines)
    text = re.sub(r'\s+', ' ', text)
    text = re.sub(r'\s+\.\s+', '. ', text)
    
    return text.strip(), sections

def create_chroma_compatible_metadata(base_metadata: Dict[str, Any], chunk_content: str) -> Dict[str, Any]:
    """Create ChromaDB-compatible metadata."""
    chunk_sections = extract_section_numbers(chunk_content)
    chunk_cases = re.findall(r'([A-Z][A-Za-z\s]+v\.?\s+[A-Z][A-Za-z]+\s+\d+[-][A-Z]+[-]\d+)', chunk_content)
    
    content_lower = chunk_content.lower()
    has_cgt = any(term in content_lower for term in ['capital gain', '0.20', '0.15', '20%', '15%', 'withholding'])
    has_rates = any(term in content_lower for term in ['rate', 'percentage', '%'])
    has_section_38 = any('38' in section for section in chunk_sections) or 'section 38' in content_lower
    has_section_39 = any('39' in section for section in chunk_sections) or 'section 39' in content_lower
    
    sections_str = ','.join(chunk_sections[:5]) if chunk_sections else ""
    cases_str = ','.join(list(set(chunk_cases))[:3]) if chunk_cases else ""
    
    metadata = {
        'source': str(base_metadata.get('source', 'unknown')),
        'document_type': str(base_metadata.get('document_type', 'legislation')),
        'page': int(base_metadata.get('page', 0)),
        'chunk_index': int(base_metadata.get('chunk_index', 0)),
        'chunk_size': len(chunk_content),
        'chunk_hash': hashlib.md5(chunk_content.encode()).hexdigest()[:8],
        'sections': sections_str,
        'sections_count': len(chunk_sections),
        'main_section': str(chunk_sections[0]) if chunk_sections else "",
        'cases': cases_str,
        'cases_count': len(set(chunk_cases)),
        'has_cgt_content': 1 if has_cgt else 0,
        'has_tax_rates': 1 if has_rates else 0,
        'has_section_38': 1 if has_section_38 else 0,
        'has_section_39': 1 if has_section_39 else 0,
        'has_withholding': 1 if 'withholding' in content_lower else 0,
        'has_february_2019': 1 if any(term in content_lower for term in ['22 february 2019', 'february 2019']) else 0,
        'has_20_percent': 1 if any(rate in content_lower for rate in ['20%', '0.20', '$0.20']) else 0,
        'has_15_percent': 1 if any(rate in content_lower for rate in ['15%', '0.15', '$0.15']) else 0,
        'preview': chunk_content[:100].replace('\n', ' ').replace('\r', '')[:100]
    }
    
    for key, value in base_metadata.items():
        if key not in metadata:
            if isinstance(value, (str, int, float, bool)):
                metadata[key] = value
            elif isinstance(value, list):
                metadata[key] = ','.join(str(item) for item in value[:5])
            elif value is not None:
                metadata[key] = str(value)
    
    return metadata

def create_section_aware_chunks(docs: List[Any]) -> List[Any]:
    """Create chunks that preserve section boundaries."""
    from langchain_core.documents import Document
    
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=2000,
        chunk_overlap=400,
        separators=[
            "\n\n---\n\n",
            "\n\nPART ",
            "\n\nSection \d+:",
            "\n\n\d+\s+[A-Z]",
            "\n\nName of document",
            "\n\n",
            "\n",
            ". ", "! ", "? ",
            "; ", ": ",
            ", ", " ", ""
        ],
        length_function=len,
        keep_separator=True
    )
    
    all_chunks = []
    
    for doc_index, doc in enumerate(docs):
        content = doc.page_content
        base_metadata = doc.metadata.copy()
        
        # Split content
        chunks = splitter.split_text(content)
        
        for chunk_index, chunk in enumerate(chunks):
            if len(chunk.strip()) < 150:
                continue
            
            # Create metadata
            chunk_metadata = create_chroma_compatible_metadata(base_metadata, chunk)
            chunk_metadata['chunk_index'] = chunk_index
            chunk_metadata['total_chunks'] = len(chunks)
            chunk_metadata['doc_index'] = doc_index
            
            all_chunks.append(Document(
                page_content=chunk,
                metadata=chunk_metadata
            ))
    
    return all_chunks

# ============================================
# NEW: TOKEN COUNT FUNCTION FOR COST ESTIMATION
# ============================================
def estimate_openai_cost(chunks: List[Any]) -> Dict[str, Any]:
    """
    Estimate OpenAI embedding cost for given chunks.
    Returns: {'total_tokens': int, 'estimated_cost': float, 'chunks_count': int}
    """
    total_tokens = 0
    token_counts = []
    
    # Rough estimation: 1 token ≈ 4 characters for English text
    for chunk in chunks:
        chunk_text = chunk.page_content if hasattr(chunk, 'page_content') else str(chunk)
        # OpenAI tokenizer: ~4 chars per token
        tokens = len(chunk_text) // 4
        total_tokens += tokens
        token_counts.append(tokens)
    
    # OpenAI pricing: $0.13 per 1M tokens for text-embedding-3-large
    estimated_cost = (total_tokens / 1_000_000) * 0.13
    
    return {
        'total_tokens': total_tokens,
        'estimated_cost': round(estimated_cost, 4),
        'chunks_count': len(chunks),
        'avg_tokens_per_chunk': sum(token_counts) // len(token_counts) if token_counts else 0,
        'max_tokens_in_chunk': max(token_counts) if token_counts else 0,
        'min_tokens_in_chunk': min(token_counts) if token_counts else 0
    }

# ============================================
# MAIN FUNCTION - UPDATED WITH OPENAI
# ============================================
def build_optimized_knowledge_base():
    """Build knowledge base with OpenAI embeddings and table preservation."""

    print("🚀 BUILDING PROFESSIONAL LEGAL KNOWLEDGE BASE WITH TABLE PRESERVATION")
    print("=" * 60)
    

    # Clear old embeddings
    if os.path.exists(EMBEDDINGS_DIR):
        import shutil
        shutil.rmtree(EMBEDDINGS_DIR)
        print("🗑️  Cleared existing embeddings")
    
    print(f"\n📚 Loading documents from: {PDF_DIR}")
    all_docs = []
    
    # Process each PDF
    pdf_files = [f for f in os.listdir(PDF_DIR) if f.endswith(".pdf")]
    print(f"Found {len(pdf_files)} PDF files")
    
    # for filename in sorted(pdf_files):
    #     path = os.path.join(PDF_DIR, filename)
    #     print(f"\n📄 Processing: {filename}")
        
    #     try:
    #         # Use enhanced PDF loader
    #         docs = load_pdf_with_tables(path)
            
    #         # Determine document type
    #         doc_type = 'legislation'
    #         if 'Income Tax Act' in filename:
    #             doc_type = 'income_tax_act'
    #         elif 'Capital Gains Tax Act' in filename:
    #             doc_type = 'capital_gains_tax_act'
    #         elif 'VAT' in filename:
    #             doc_type = 'vat_act'
    #         elif 'Finance Act' in filename:
    #             doc_type = 'finance_act'
            
    #         # Update metadata
    #         for doc in docs:
    #             doc.metadata['document_type'] = doc_type
    #             doc.metadata['filename'] = filename
            
    #         all_docs.extend(docs)

    # In build_optimized_knowledge_base() function
    for filename in sorted(pdf_files):
        path = os.path.join(PDF_DIR, filename)
        print(f"\n📄 Processing: {filename}")
        
        try:
            # Use enhanced PDF loader
            docs = load_pdf_with_tables(path)
            
            # Determine document type AND PRIORITY
            doc_type = 'legislation'
            priority = 1  # Default priority (1=normal, 2=high, 3=highest)
            
            if 'ActNo7of2025Finance' in filename:
                doc_type = 'finance_act_2025'
                priority = 3  # HIGHEST PRIORITY - most recent amendments
            elif 'FinanceActUpdated' in filename:
                doc_type = 'finance_act'
                priority = 2  # High priority
            elif 'Income Tax Act' in filename or 'IncomeTaxActUpdated' in filename:
                doc_type = 'income_tax_act'
                priority = 2  # High priority
            elif 'Capital Gains Tax Act' in filename or 'CapitalGainsTaxActUpdated' in filename:
                doc_type = 'capital_gains_tax_act'
                priority = 2  # High priority
            elif 'VAT' in filename and 'Act' in filename:
                doc_type = 'vat_act'
                priority = 2  # High priority
            elif 'ValuedAddedRegs' in filename:
                doc_type = 'vat_regulations'
                priority = 2  # High priority
            elif 'FAQ' in filename:
                doc_type = 'faq'
                priority = 1  # Normal priority
            
            # Update metadata
            for doc in docs:
                doc.metadata['document_type'] = doc_type
                doc.metadata['filename'] = filename
                doc.metadata['priority'] = priority  # NEW: Add priority fields
            
            all_docs.extend(docs)
            print(f"   ✅ Loaded {len(docs)} pages with table preservation")
            
            # Show table detection stats
            table_count = sum(1 for doc in docs if doc.metadata.get('has_tables', 0) == 1)
            if table_count > 0:
                print(f"   📊 Detected {table_count} pages with tables")
            
        except Exception as e:
            print(f"   ❌ Error: {str(e)[:100]}...")
    
    if not all_docs:
        print("❌ No documents loaded!")
        return
    
    print(f"\n✅ Total document pages: {len(all_docs)}")
    
    # Create chunks with table awareness
    print("\n✂️ Creating table-aware chunks...")
    chunks = create_table_aware_chunks(all_docs)
    print(f"   Created {len(chunks)} chunks")
    
    # Count schedule/table chunks
    schedule_chunks = sum(1 for chunk in chunks if chunk.metadata.get('is_schedule_chunk', 0) == 1)
    table_md_chunks = sum(1 for chunk in chunks if chunk.metadata.get('contains_table_markdown', 0) == 1)
    
    print(f"   📊 Schedule chunks: {schedule_chunks}")
    print(f"   📋 Table markdown chunks: {table_md_chunks}")
    
    # Show some examples
    print("\n📋 Sample table chunks found:")
    for i, chunk in enumerate(chunks[:10]):
        if chunk.metadata.get('contains_table_markdown', 0) == 1:
            schedule_type = chunk.metadata.get('schedule_type', 'unknown')
            print(f"   Chunk {i}: {schedule_type} on page {chunk.metadata.get('page')}")

    if not all_docs:
        print("❌ No documents loaded!")
        return
    
    print(f"\n✅ Total document pages: {len(all_docs)}")
    
    # Create chunks
    print("\n✂️ Creating section-aware chunks...")
    chunks = create_section_aware_chunks(all_docs)
    print(f"   Created {len(chunks)} chunks")
    
    # ============================================
    # COST ESTIMATION (ONLY FOR OPENAI)
    # ============================================
    if USE_OPENAI_EMBEDDINGS and OPENAI_API_KEY:
        cost_estimate = estimate_openai_cost(chunks)
        print(f"\n💰 OPENAI COST ESTIMATION:")
        print(f"   Total chunks: {cost_estimate['chunks_count']}")
        print(f"   Total tokens: {cost_estimate['total_tokens']:,}")
        print(f"   Estimated cost: ${cost_estimate['estimated_cost']:.4f}")
        print(f"   (Approx. ${cost_estimate['estimated_cost']*100:.2f} cents)")
        
        # Ask for confirmation
        confirm = input("\n⚠️  Confirm OpenAI embedding? (y/n): ").lower().strip()
        if confirm != 'y':
            print("❌ Embedding cancelled by user")
            return
    
    # ============================================
    # LOAD EMBEDDING MODEL
    # ============================================
    print("\n🔍 Loading embedding model...")
    embeddings = get_embedding_model()
    
    # ============================================
    # BUILD VECTOR STORE
    # ============================================
    print("\n🏗️  Building vector store...")
    
    try:
        # ⚠️ WARNING: THIS IS WHERE OPENAI COSTS OCCUR (ONE TIME!)
        vectordb = Chroma.from_documents(
            documents=chunks,
            embedding=embeddings,
            persist_directory=EMBEDDINGS_DIR,
            collection_name=COLLECTION_NAME
        )
        print("   ✅ Vector store created successfully")
        print(f"   📁 Saved to: {EMBEDDINGS_DIR}")
        
    except Exception as e:
        print(f"   ❌ Error creating vector store: {e}")
        import traceback
        traceback.print_exc()
        return
    
    # ============================================
    # COMPREHENSIVE TESTING
    # ============================================
    print("\n🧪 RUNNING CRITICAL TESTS")
    print("=" * 60)
    
    test_queries = [
        ("capital gains tax rate property", "CGT rates"),
        ("VAT registration requirements", "VAT info"),
        ("Section 38 20% rate", "Section 38"),
        ("withholding tax 15%", "Section 39"),
    ]
    
    for query, expected in test_queries:
        print(f"\n🔍 Test: '{query}'")
        
        try:
            results = vectordb.similarity_search(query, k=2)
            if results:
                meta = results[0].metadata
                print(f"   ✅ Found: {meta.get('source', 'unknown')}")
                print(f"   Sections: {meta.get('sections', 'none')}")
                print(f"   Page: {meta.get('page', 0)}")
            else:
                print("   ❌ No results")
        except Exception as e:
            print(f"   ❌ Error: {e}")
    
    # ============================================
    # FINAL REPORT
    # ============================================
    print("\n" + "=" * 60)
    print("📊 DEPLOYMENT SUMMARY")
    print("=" * 60)
    
    stats = {
        'total_chunks': len(chunks),
        'embedding_model': 'OpenAI' if USE_OPENAI_EMBEDDINGS else 'HuggingFace',
        'collection_name': COLLECTION_NAME,
        'storage_path': EMBEDDINGS_DIR,
        'created_at': str(time.ctime())
    }
    
    if USE_OPENAI_EMBEDDINGS and OPENAI_API_KEY:
        stats.update(cost_estimate)
    
    for key, value in stats.items():
        print(f"   ✅ {key}: {value}")
    
    # Save configuration
    config_file = os.path.join(EMBEDDINGS_DIR, "deployment_config.json")
    with open(config_file, 'w') as f:
        json.dump(stats, f, indent=2)
    
    print(f"\n📄 Config saved to: {config_file}")
    
    print("\n🎉 KNOWLEDGE BASE READY FOR PRODUCTION!")
    print("   ✅ Embeddings saved locally (no further OpenAI costs)")
    print("   ✅ Ready to use with Flask app")
    
    # Quick verification
    print("\n🔬 VERIFICATION QUERY:")
    verification_query = "What is VAT registration?"
    results = vectordb.similarity_search(verification_query, k=1)
    
    if results:
        print("   ✅ Retriever is working")
        print(f"   📄 Source: {results[0].metadata.get('source')}")
    else:
        print("   ⚠️  No results for verification query")

if __name__ == "__main__":
    build_optimized_knowledge_base()
