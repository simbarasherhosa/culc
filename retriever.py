from langchain_chroma import Chroma
import os
import re
import time
from typing import Tuple, List, Dict, Any
import json
from dotenv import load_dotenv
import hashlib

# ============================================
# CONFIGURATION
# ============================================
try:
    from config import EMBEDDINGS_DIR, USE_OPENAI_EMBEDDINGS, OPENAI_EMBEDDING_MODEL, COLLECTION_NAME
except ImportError:
    EMBEDDINGS_DIR = "./embeddings"
    USE_OPENAI_EMBEDDINGS = True  # Default to OpenAI since that's what was used
    # OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    OPENAI_EMBEDDING_MODEL = "text-embedding-3-large"
    COLLECTION_NAME = "zimbabwe_tax_law_v3"  # Try v2 first

# Load environment variables from .env
load_dotenv()
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
# ============================================
# OPENAI EMBEDDING FUNCTION
# ============================================
def get_embedding_function():
    """Use OpenAI embeddings - same as what was used to create embeddings."""
    
    if not OPENAI_API_KEY:
        print("❌ OPENAI_API_KEY not found in config/.env")
        print("   Please add your OpenAI API key to .env file")
        return None
    
    try:
        from langchain_openai import OpenAIEmbeddings
        
        print(f"🔷 Using OpenAI embeddings: {OPENAI_EMBEDDING_MODEL}")
        
        return OpenAIEmbeddings(
            model=OPENAI_EMBEDDING_MODEL,
            api_key=OPENAI_API_KEY,
            timeout=60  # Give it more time
        )
    except ImportError:
        print("❌ langchain-openai not installed. Install with:")
        print("   pip install langchain-openai")
        return None
    except Exception as e:
        print(f"❌ Error loading OpenAI embeddings: {e}")
        return None

# ============================================
# LOAD DATABASE
# ============================================
print(f"📂 Loading vector database from: {EMBEDDINGS_DIR}")

# Check if embeddings directory exists
if not os.path.exists(EMBEDDINGS_DIR):
    print(f"❌ ERROR: Embeddings directory not found: {EMBEDDINGS_DIR}")
    print("   Run create_embeddings.py first!")
    db = None
    embedding_function = None
else:
    embedding_function = get_embedding_function()
    
    if embedding_function is None:
        print("❌ Could not create embedding function")
        db = None
    else:
        try:
            # Try different collection names (v2, v3, or default)
            collection_names = ["zimbabwe_tax_law_v3", "zimbabwe_tax_law_v3", "zimbabwe_tax_law"]
            
            for collection in collection_names:
                try:
                    print(f"   Trying collection: {collection}")
                    db = Chroma(
                        persist_directory=EMBEDDINGS_DIR,
                        embedding_function=embedding_function,
                        collection_name=collection
                    )
                    # Test with a simple query
                    test_results = db.similarity_search("test", k=1)
                    print(f"✅ Successfully loaded collection: {collection}")
                    COLLECTION_NAME = collection
                    break
                except Exception as e:
                    print(f"   Collection {collection} failed: {str(e)[:100]}")
                    continue
            else:
                # If no collection worked, try without specifying name
                print("   Trying default collection...")
                db = Chroma(
                    persist_directory=EMBEDDINGS_DIR,
                    embedding_function=embedding_function
                )
                print("✅ Loaded default collection")
            
            # Get collection info
            try:
                count = db._collection.count()
                print(f"📊 Documents in collection: {count}")
            except:
                print("📊 Could not get document count")
            
        except Exception as e:
            print(f"❌ Error loading database: {e}")
            db = None

# ============================================
# UTILITY FUNCTIONS
# ============================================
def parse_sections_from_metadata(metadata: Dict) -> List[str]:
    """Parse sections from metadata string."""
    sections_str = metadata.get('sections', '')
    if sections_str and isinstance(sections_str, str):
        return [s.strip() for s in sections_str.split(',') if s.strip()]
    return []

# ============================================
# MAIN RETRIEVAL FUNCTION
# ============================================
def get_relevant_docs(query: str, top_k: int = 5) -> Tuple[str, float, List[Dict]]:
    """
    Retrieve relevant documents for a query.
    Returns: (context_text, confidence_score, documents_with_metadata)
    """
    # if db is None:
    #     print("⚠️ Database not available")
    #     return "", 0.0, []
    
    # try:
    #     print(f"\n🔍 Searching for: '{query}'")
        
    #     # Search the database
    #     results = db.similarity_search_with_score(query, k=top_k)
        
    #     if not results:
    #         print("   ⚠️ No results found")
    #         return "", 0.0, []
        
    #     print(f"   ✅ Found {len(results)} documents")
        
    #     # ============================================
    #     # PROCESS RESULTS
    #     # ============================================
    #     docs_with_metadata = []
    #     for doc, score in results:
    #         # Parse sections
    #         sections_list = parse_sections_from_metadata(doc.metadata)
            
    #         # Check content for key information
    #         content_lower = doc.page_content.lower()
            
    #         doc_info = {
    #             'content': doc.page_content.strip(),
    #             'score': float(score),
    #             'metadata': doc.metadata,
    #             'sections': sections_list,
    #             'source': doc.metadata.get('source', 'unknown'),
    #             'page': doc.metadata.get('page', 0),
    #             'document_type': doc.metadata.get('document_type', 'legislation'),
    #             'has_section_38': 1 if any('38' in s for s in sections_list) or 'section 38' in content_lower else 0,
    #             'has_section_39': 1 if any('39' in s for s in sections_list) or 'section 39' in content_lower else 0,
    #             'has_20_percent': 1 if any(rate in content_lower for rate in ['20%', '0.20', '$0.20']) else 0,
    #             'has_15_percent': 1 if any(rate in content_lower for rate in ['15%', '0.15', '$0.15']) else 0,
    #             'has_withholding': 1 if 'withholding' in content_lower else 0,
    #             'has_capital_gains': 1 if 'capital gain' in content_lower else 0,
    #             'has_vat': 1 if 'vat' in content_lower or 'value added tax' in content_lower else 0,
    #         }
            
    #         docs_with_metadata.append(doc_info)
        
    if db is None:
        print("⚠️ Database not available")
        return "", 0.0, []
    
    try:
        print(f"\n🔍 Searching for: '{query}'")
        
        # Search with more documents initially
        initial_results = db.similarity_search_with_score(query, k=top_k * 3)
        
        if not initial_results:
            print("   ⚠️ No results found")
            return "", 0.0, []
        
        print(f"   ✅ Found {len(initial_results)} initial documents")
        
        # ============================================
        # PRIORITY-BASED RE-RANKING
        # ============================================
        enhanced_results = []
        
        for doc, score in initial_results:
            metadata = doc.metadata
            
            # Extract priority information
            priority = int(metadata.get('priority', 1))
            doc_type = metadata.get('document_type', '')
            filename = metadata.get('filename', '')
            
            # Boost score based on priority
            priority_boost = 0.0
            
            # HIGHEST PRIORITY: Finance Act 2025 (latest amendments)
            if 'ActNo7of2025Finance' in filename or 'finance_act_2025' in doc_type:
                priority_boost = 0.4  # Significant boost
                print(f"   🚀 Priority boost applied: Finance Act 2025")
            
            # HIGH PRIORITY: Recent finance acts and core legislation
            elif 'finance_act' in doc_type or priority == 2:
                priority_boost = 0.2
            
            # TEMPORAL BOOST: Newer documents get slight boost
            doc_year = metadata.get('year', 0)
            if doc_year >= 2023:
                recency_boost = min(0.1, (doc_year - 2020) * 0.02)
                priority_boost += recency_boost
            
            # Apply boost (OpenAI scores: higher = more similar)
            boosted_score = score + priority_boost
            
            enhanced_results.append((doc, boosted_score, metadata))
        
        # Sort by boosted score (highest first)
        enhanced_results.sort(key=lambda x: x[1], reverse=True)
        
        # Take top_k results
        results = enhanced_results[:top_k]
        
        print(f"   📊 After priority re-ranking: {len(results)} documents")
        
        # Rest of the function remains the same...
        docs_with_metadata = []
        for doc, boosted_score, metadata in results:
            # Parse sections
            sections_list = parse_sections_from_metadata(metadata)
            
            # Check content for key information
            content_lower = doc.page_content.lower()
            
            doc_info = {
                'content': doc.page_content.strip(),
                'score': float(boosted_score),
                'original_score': float(score) if 'score' in locals() else float(boosted_score),
                'metadata': metadata,
                'sections': sections_list,
                'source': metadata.get('source', 'unknown'),
                'page': metadata.get('page', 0),
                'document_type': metadata.get('document_type', 'legislation'),
                'priority': metadata.get('priority', 1),
                'filename': metadata.get('filename', ''),
                'year': metadata.get('year', 0),
                'has_section_38': 1 if any('38' in s for s in sections_list) or 'section 38' in content_lower else 0,
                'has_section_39': 1 if any('39' in s for s in sections_list) or 'section 39' in content_lower else 0,
                'has_20_percent': 1 if any(rate in content_lower for rate in ['20%', '0.20', '$0.20']) else 0,
                'has_15_percent': 1 if any(rate in content_lower for rate in ['15%', '0.15', '$0.15']) else 0,
                'has_withholding': 1 if 'withholding' in content_lower else 0,
                'has_capital_gains': 1 if 'capital gain' in content_lower else 0,
                'has_vat': 1 if 'vat' in content_lower or 'value added tax' in content_lower else 0,
            }
            
            docs_with_metadata.append(doc_info)

        # ============================================
        # CALCULATE CONFIDENCE
        # ============================================
        scores = [doc['score'] for doc in docs_with_metadata]
        if scores:
            # OpenAI embeddings use cosine similarity: higher score = more similar
            # Scores are typically between 0 and 1
            avg_confidence = sum(scores) / len(scores)
            
            # Ensure minimum confidence
            avg_confidence = max(0.1, avg_confidence)
            
            # Boost for specific query types
            query_lower = query.lower()
            if any(phrase in query_lower for phrase in ['what is', 'define', 'explain']):
                avg_confidence = min(0.95, avg_confidence * 1.2)
                print(f"   🔍 Definition boost applied")
        else:
            avg_confidence = 0.0
        
        # ============================================
        # BUILD CONTEXT FOR AI
        # ============================================
        context_parts = []
        for doc in docs_with_metadata:
            source_info = f"[Source: {doc['source']}, Page: {doc['page']}]"
            
            # Add section info
            if doc['sections']:
                source_info += f" [Sections: {', '.join(doc['sections'][:3])}]"
            
            # Add relevant flags for AI
            flags = []
            if doc['has_section_38']:
                flags.append("Section 38")
            if doc['has_section_39']:
                flags.append("Section 39")
            if doc['has_20_percent']:
                flags.append("20% rate")
            if doc['has_15_percent']:
                flags.append("15% rate")
            if doc['has_withholding']:
                flags.append("withholding tax")
            
            if flags:
                source_info += f" [Contains: {', '.join(flags)}]"
            
            context_parts.append(f"{source_info}\n{doc['content']}")
        
        context = "\n\n---\n\n".join(context_parts)
        
        print(f"   📊 Confidence: {avg_confidence:.1%}")
        
        return context, round(avg_confidence, 3), docs_with_metadata
        
    except Exception as e:
        print(f"❌ Error in get_relevant_docs: {e}")
        import traceback
        traceback.print_exc()
        return "", 0.0, []

def get_table_specific_docs(query: str, top_k: int = 10) -> Tuple[str, float, List[Dict]]:
    """Specialized retrieval for table/schedule queries."""
    if db is None:
        return "", 0.0, []
    
    try:
        print(f"📊 Table-specific search for: '{query}'")
        
        # Get more documents for tables
        initial_results = db.similarity_search_with_score(query, k=top_k * 2)
        
        if not initial_results:
            return "", 0.0, []
        
        # ============================================
        # KEY FIX: Group by source and find adjacent pages
        # ============================================
        results_by_source = {}
        for doc, score in initial_results:
            source = doc.metadata.get('source', '')
            page = doc.metadata.get('page', 0)
            
            if source not in results_by_source:
                results_by_source[source] = []
            results_by_source[source].append((doc, score, page))
        
        # Sort each source by page number
        for source in results_by_source:
            results_by_source[source].sort(key=lambda x: x[2])
        
        # ============================================
        # Find table spans (tables often span 2-3 pages)
        # ============================================
        all_results = []
        for source, doc_list in results_by_source.items():
            if len(doc_list) < 2:
                all_results.extend(doc_list)
                continue
            
            # Look for table sequences
            i = 0
            while i < len(doc_list):
                doc, score, page = doc_list[i]
                content = doc.page_content
                
                # Check if this looks like part of a table
                if ('FOURTH SCHEDULE' in content or 
                    'PRESCRIBED AMOUNTS' in content or 
                    'Applicable section' in content):
                    
                    print(f"   📋 Found table start at {source} page {page}")
                    
                    # Collect adjacent pages that might be part of same table
                    table_parts = [(doc, score, page)]
                    
                    # Look ahead for continuation
                    j = i + 1
                    while j < len(doc_list) and doc_list[j][2] <= page + 3:  # Check next 3 pages
                        next_doc, next_score, next_page = doc_list[j]
                        next_content = next_doc.page_content
                        
                        # Check if this continues the table
                        if (any(marker in next_content for marker in 
                              ['|', 'Applicable section', 'Prescribed amount', 'Schedule']) and
                            not any(marker in next_content for marker in 
                                  ['FIFTH SCHEDULE', 'SIXTH SCHEDULE'])):  # Not a new schedule
                            table_parts.append((next_doc, next_score, next_page))
                            j += 1
                        else:
                            break
                    
                    # Combine table parts
                    if len(table_parts) > 1:
                        print(f"   🔗 Combining {len(table_parts)} table parts from pages {page} to {table_parts[-1][2]}")
                        
                        # Create combined document
                        combined_content = []
                        for part_doc, part_score, part_page in table_parts:
                            combined_content.append(f"\n[CONTINUED FROM PAGE {part_page}]\n{part_doc.page_content}")
                        
                        # Create new combined document
                        from langchain_core.documents import Document
                        combined_doc = Document(
                            page_content="\n".join(combined_content),
                            metadata={
                                **doc.metadata,
                                'is_combined_table': True,
                                'table_pages': [p[2] for p in table_parts],
                                'original_scores': [p[1] for p in table_parts]
                            }
                        )
                        
                        # Use average score
                        avg_score = sum(p[1] for p in table_parts) / len(table_parts)
                        all_results.append((combined_doc, avg_score))
                        i = j  # Skip processed parts
                    else:
                        all_results.append((doc, score))
                        i += 1
                else:
                    all_results.append((doc, score))
                    i += 1
        
        # Sort by score and limit
        all_results.sort(key=lambda x: x[1])
        results = all_results[:top_k]
        
        if not results:
            return "", 0.0, []
        
        print(f"   ✅ Found {len(results)} documents (including combined tables)")
        
        # ============================================
        # Process results
        # ============================================
        docs_with_metadata = []
        for doc, score in results:
            # Check if this is a combined table
            is_combined = doc.metadata.get('is_combined_table', False)
            
            doc_info = {
                'content': doc.page_content.strip(),
                'score': float(score),
                'metadata': doc.metadata,
                'source': doc.metadata.get('source', 'unknown'),
                'page': doc.metadata.get('page', 0),
                'is_table_chunk': 1 if ('FOURTH SCHEDULE' in doc.page_content or 
                                      'PRESCRIBED AMOUNTS' in doc.page_content or
                                      '|' in doc.page_content and doc.page_content.count('|') > 5) else 0,
                'is_combined_table': is_combined,
                'table_pages': doc.metadata.get('table_pages', []),
            }
            
            docs_with_metadata.append(doc_info)
        
        # ============================================
        # Calculate confidence (boost for combined tables)
        # ============================================
        scores = [doc['score'] for doc in docs_with_metadata]
        if scores:
            normalized_scores = [max(0.0, 1.0 - (score / 2.0)) for score in scores]
            avg_confidence = sum(normalized_scores) / len(normalized_scores)
            
            # Boost for combined tables
            combined_count = sum(1 for doc in docs_with_metadata if doc.get('is_combined_table', False))
            if combined_count > 0:
                avg_confidence = min(0.95, avg_confidence * (1.0 + combined_count * 0.3))
                print(f"   📊 Found {combined_count} combined tables, confidence boosted")
        else:
            avg_confidence = 0.0
        
        # ============================================
        # Build context with clear table markers
        # ============================================
        context_parts = []
        for doc in docs_with_metadata:
            source_info = f"[Source: {doc['source']}"
            
            if doc.get('is_combined_table', False):
                pages = doc.get('table_pages', [])
                if pages:
                    source_info += f", Pages: {min(pages)}-{max(pages)} [COMBINED TABLE]"
            else:
                source_info += f", Page: {doc['page']}"
            
            source_info += "]"
            
            # Add table indicator
            if doc['is_table_chunk']:
                source_info += " [TABLE CONTENT]"
            
            context_parts.append(f"{source_info}\n{doc['content']}")
        
        context = "\n\n---\n\n".join(context_parts)
        
        return context, round(avg_confidence, 3), docs_with_metadata
        
    except Exception as e:
        print(f"❌ Error in table-specific retrieval: {e}")
        import traceback
        traceback.print_exc()
        return "", 0.0, []

def get_relevant_docs_for_list_query(query: str, top_k: int = 5) -> Tuple[str, float, List[Dict]]:
    """Specialized retrieval for list queries (VAT forms, etc.)"""
    if db is None:
        return "", 0.0, []
    
    try:
        # For table/schedule queries, get MORE documents
        query_lower = query.lower()
        if any(term in query_lower for term in ['table', 'schedule', 'fourth schedule', 'prescribed amounts']):
            top_k = max(top_k, 15)  # Get more for comprehensive tables
            print(f"📊 Schedule/table query detected, increasing to {top_k} documents")
        
        results = db.similarity_search_with_score(query, k=top_k)
        
        if not results:
            return "", 0.0, []
        
        print(f"✅ Found {len(results)} documents")
        
        # ============================================
        # ENHANCED CONTEXT FOR TABLES/SCHEDULES
        # ============================================
        docs_with_metadata = []
        for doc, score in results:
            content = doc.page_content.strip()
            
            # For schedule queries, try to get more complete content
            if any(term in query_lower for term in ['fourth schedule', 'prescribed amounts']):
                # Check if this might be the Fourth Schedule
                if ('fourth schedule' in content.lower() or 
                    'prescribed amounts' in content.lower() or
                    'applicable section' in content.lower()):
                    
                    print(f"   📋 Potential Fourth Schedule found on page {doc.metadata.get('page')}")
                    
                    # Try to get adjacent pages too
                    page_num = doc.metadata.get('page', 0)
                    source = doc.metadata.get('source', '')
                    
                    # Search for pages around this one (table might span pages)
                    adjacent_pages = []
                    try:
                        for offset in [-1, 0, 1, 2]:  # Check page before and 2 after
                            adjacent_query = f"page {page_num + offset} {source}"
                            adj_results = db.similarity_search_with_score(adjacent_query, k=2)
                            for adj_doc, adj_score in adj_results:
                                if adj_doc.metadata.get('source') == source:
                                    # Add to content if it contains schedule info
                                    adj_content = adj_doc.page_content.strip()
                                    if any(marker in adj_content.lower() for marker in 
                                           ['schedule', 'table', 'applicable', 'prescribed']):
                                        content += f"\n\n[CONTINUED FROM PAGE {page_num + offset}]\n{adj_content}"
                    except:
                        pass

    
    # try:
        print(f"📋 List query detected: '{query}'")
        
        # First, try to find documents with VAT forms specifically
        vat_forms_query = "VAT forms list Third Schedule VAT 3 VAT 4 VAT 5"
        results = db.similarity_search_with_score(vat_forms_query, k=top_k)
        
        if not results:
            # Fall back to regular search
            results = db.similarity_search_with_score(query, k=top_k)
        
        if not results:
            return "", 0.0, []
        
        print(f"   ✅ Found {len(results)} documents for list query")
        
        # Process results
        docs_with_metadata = []
        for doc, score in results:
            # Parse sections
            sections_list = parse_sections_from_metadata(doc.metadata)
            
            # Check for VAT forms in content
            content_lower = doc.page_content.lower()
            vat_form_count = count_vat_forms_in_text(doc.page_content)
            contains_vat_forms = vat_form_count > 0
            
            doc_info = {
                'content': doc.page_content.strip(),
                'score': float(score),
                'metadata': doc.metadata,
                'sections': sections_list,
                'source': doc.metadata.get('source', 'unknown'),
                'page': doc.metadata.get('page', 0),
                'document_type': doc.metadata.get('document_type', 'legislation'),
                'contains_vat_forms': 1 if contains_vat_forms else 0,
                'vat_form_count': vat_form_count,
                'has_section_38': 1 if any('38' in s for s in sections_list) or 'section 38' in content_lower else 0,
                'has_section_39': 1 if any('39' in s for s in sections_list) or 'section 39' in content_lower else 0,
                'has_20_percent': 1 if any(rate in content_lower for rate in ['20%', '0.20', '$0.20']) else 0,
                'has_15_percent': 1 if any(rate in content_lower for rate in ['15%', '0.15', '$0.15']) else 0,
            }
            
            docs_with_metadata.append(doc_info)
        
        # Sort by VAT form count (highest first)
        docs_with_metadata.sort(key=lambda x: x['vat_form_count'], reverse=True)
        
        # Calculate confidence
        scores = [doc['score'] for doc in docs_with_metadata]
        if scores:
            # For list queries, use a different confidence calculation
            normalized_scores = [max(0.0, 1.0 - (score / 2.0)) for score in scores]
            avg_confidence = sum(normalized_scores) / len(normalized_scores)
            
            # Boost confidence for list queries
            has_vat_forms = any(doc['contains_vat_forms'] for doc in docs_with_metadata)
            if has_vat_forms:
                avg_confidence = min(0.95, avg_confidence * 1.5)
                print(f"   📋 VAT forms found, boosted confidence")
        else:
            avg_confidence = 0.0
        
        # Build context
        context_parts = []
        for doc in docs_with_metadata:
            source_info = f"[Source: {doc['source']}, Page: {doc['page']}]"
            
            if doc['contains_vat_forms']:
                source_info += f" [Contains VAT Forms: {doc['vat_form_count']}]"
            
            if doc['sections']:
                source_info += f" [Sections: {', '.join(doc['sections'][:3])}]"
            
            context_parts.append(f"{source_info}\n{doc['content']}")
        
        context = "\n\n---\n\n".join(context_parts)
        
        return context, round(avg_confidence, 3), docs_with_metadata
        
    except Exception as e:
        print(f"❌ Error in list query retrieval: {e}")
        return "", 0.0, []

# Add this helper function if not already present
def count_vat_forms_in_text(text: str) -> int:
    """Count how many unique VAT form numbers are in text."""
    vat_pattern = r'VAT\s+(\d+)'
    matches = re.findall(vat_pattern, text)
    return len(set(matches))

# Add this to retriever.py or create a new file table_extractor.py
import re

def extract_table_from_context(context: str, table_name: str = "Fourth Schedule") -> str:
    """
    Extract and format table from context text.
    Returns the table in markdown format if found, otherwise empty string.
    """
    print(f"🔍 Extracting {table_name} table from context...")
    
    # Split context into chunks by source/page markers
    chunks = re.split(r'\[Source:.*?Page:.*?\]', context)
    
    table_found = False
    table_lines = []
    in_table = False
    table_start_markers = {
        "Fourth Schedule": ["FOURTH SCHEDULE", "PRESCRIBED AMOUNTS", "Applicable section of Act"],
        "Third Schedule": ["THIRD SCHEDULE", "LIST OF VALUE ADDED TAX FORMS", "Name of document"]
    }
    
    markers = table_start_markers.get(table_name, [])
    
    for chunk in chunks:
        lines = chunk.split('\n')
        
        for i, line in enumerate(lines):
            line = line.strip()
            
            # Check if this line starts the table
            if not in_table and any(marker in line for marker in markers):
                in_table = True
                table_found = True
                print(f"   📊 Found {table_name} start: {line[:50]}...")
            
            # If we're in a table
            if in_table:
                # Check for end of table
                end_markers = ["FIFTH SCHEDULE", "SIXTH SCHEDULE", "SCHEDULE END", "**END OF TABLE**"]
                if any(marker in line for marker in end_markers) or i > 50:  # Limit table size
                    in_table = False
                    break
                
                # Clean and add table lines
                if line:
                    # Remove source markers from within table
                    if not line.startswith('[Source:') and not line.startswith('[CONTINUED'):
                        # Format table rows
                        if '|' in line:
                            table_lines.append(line)
                        elif '  ' in line and len(line.split('  ')) > 1:  # Space-separated table
                            parts = [p.strip() for p in line.split('  ') if p.strip()]
                            if len(parts) >= 2:
                                formatted = " | ".join(parts)
                                table_lines.append(f"| {formatted} |")
                        else:
                            table_lines.append(line)
    
    if not table_found:
        print(f"   ⚠️ {table_name} table not found in context")
        return ""
    
    print(f"   ✅ Extracted {len(table_lines)} lines from {table_name}")
    
    # Format as markdown table
    formatted_table = []
    
    # Find headers (lines with column indicators)
    headers = []
    data_rows = []
    
    for line in table_lines:
        if any(header in line.lower() for header in ['applicable', 'summary', 'amount', 'name', 'form']):
            headers.append(line)
        else:
            data_rows.append(line)
    
    # Create markdown table
    if headers:
        formatted_table.append(headers[0])  # Use first header
        formatted_table.append("|" + "---|" * (headers[0].count('|') - 1))
        formatted_table.extend(data_rows)
    else:
        formatted_table = table_lines
    
    return "\n".join(formatted_table)

# ============================================
# TESTING FUNCTION
# ============================================
def run_tests():
    """Run comprehensive tests."""
    print("\n" + "=" * 60)
    print("🧪 COMPREHENSIVE TESTS")
    print("=" * 60)
    
    if db is None:
        print("❌ Database not available. Cannot run tests.")
        return
    
    test_queries = [
        ("capital gains tax rate", "CGT rates"),
        ("VAT registration requirements", "VAT info"),
        ("Section 38 20% rate", "Section 38"),
        ("withholding tax on property", "Withholding tax"),
        ("What is VAT?", "VAT definition"),
        ("difference between section 38 and 39", "CGT comparison"),
    ]
    
    for query, description in test_queries:
        print(f"\n🔍 Query: '{query}'")
        print(f"   Expected: {description}")
        
        context, confidence, docs = get_relevant_docs(query, top_k=3)
        
        if docs:
            print(f"   ✅ Found {len(docs)} documents")
            print(f"   📊 Confidence: {confidence:.1%}")
            
            # Show top result
            top_doc = docs[0]
            print(f"   📄 Top source: {top_doc['source']} (p{top_doc['page']})")
            
            if top_doc['sections']:
                print(f"   📍 Sections: {', '.join(top_doc['sections'][:3])}")
            
            # Show preview
            preview = top_doc['content'][:120].replace('\n', ' ')
            print(f"   📋 Preview: {preview}...")
        else:
            print("   ❌ No documents found")

# ============================================
# QUICK TEST
# ============================================
def quick_test():
    """Quick test to verify basic functionality."""
    print("\n" + "=" * 60)
    print("🚀 QUICK TEST")
    print("=" * 60)
    
    if db is None:
        print("❌ Database not loaded")
        return
    
    test_query = "What is capital gains tax?"
    print(f"\n🔍 Query: '{test_query}'")
    
    context, confidence, docs = get_relevant_docs(test_query, top_k=2)
    
    if docs:
        print(f"✅ Success! Found {len(docs)} documents")
        print(f"📊 Confidence: {confidence:.1%}")
        
        print("\n📋 Context preview (first 200 chars):")
        print(context[:200] + "...")
    else:
        print("❌ No documents found")

# ============================================
# MAIN EXECUTION
# ============================================
if __name__ == "__main__":
    # First check if everything is loaded
    if db is None:
        print("\n❌ Database initialization failed. Check:")
        print("   1. Is OpenAI API key in .env file?")
        print("   2. Did you run create_embeddings.py?")
        print("   3. Is embeddings/ directory present?")
    else:
        # Run tests
        run_tests()
        quick_test()
        
        # Show usage info
        print("\n" + "=" * 60)
        print("📚 USAGE INSTRUCTIONS")
        print("=" * 60)
        print("✅ Database is ready for use in your Flask app!")
        print("\nUsage example:")
        print("""
from knowledge_base.retriever import get_relevant_docs

# Get relevant documents
context, confidence, docs = get_relevant_docs("your question here", top_k=5)

# Pass context to GPT
response = call_gpt(query, context)

# Return to user
print(f"Answer: {response}")
print(f"Confidence: {confidence:.1%}")
""")