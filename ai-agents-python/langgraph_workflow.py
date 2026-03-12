import json
from typing import TypedDict, Annotated
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage
from langchain_core.output_parsers import JsonOutputParser
from langgraph.graph import StateGraph, START, END
from langgraph.graph.message import add_messages
from pydantic import BaseModel, Field

# Define the state structure
class SecurityState(TypedDict):
    messages: Annotated[list, "Messages in conversation"]
    log_entry: str
    classification: dict = {}
    risk_score: int = 0
    ai_summary: str = ""
    recommended_action: str = ""

# Initialize LLM
llm = ChatOllama(
    model="llama3",
    temperature=0.1,
)

# Node 1: Classifier - Categorizes the security event
def classifier_node(state: SecurityState) -> SecurityState:
    """Classify the security log entry using Llama3"""
    
    prompt = f"""
    Analyze the following security log and classify the threat type.
    
    Log: {state['log_entry']}
    
    Return JSON with:
    - event_type: (SQL_INJECTION, BRUTE_FORCE, UNAUTHORIZED_ACCESS, PORT_SCAN, MALWARE, DATA_EXFILTRATION, NORMAL)
    - severity: (LOW, MEDIUM, HIGH, CRITICAL)
    - confidence: (1-10)
    - description: brief description
    """
    
    try:
        response = llm.invoke([HumanMessage(content=prompt)])
        result = JsonOutputParser().parse(response.content)
        
        state['classification'] = result
        return state
        
    except Exception as e:
        state['classification'] = {
            "event_type": "NORMAL",
            "severity": "LOW",
            "confidence": 1,
            "description": f"Classification error: {str(e)}"
        }
        return state

# Node 2: Scorer - Calculates risk score based on multiple factors
def scorer_node(state: SecurityState) -> SecurityState:
    """Calculate risk score (1-10) based on classification and context"""
    
    classification = state.get('classification', {})
    severity = classification.get('severity', 'LOW')
    confidence = classification.get('confidence', 1)
    
    # Base score from severity
    severity_scores = {'LOW': 2, 'MEDIUM': 4, 'HIGH': 7, 'CRITICAL': 9}
    base_score = severity_scores.get(severity, 2)
    
    # Adjust based on confidence - uncertainty increases risk
    if confidence >= 7:
        # High confidence - trust the severity
        final_score = base_score
    elif confidence >= 4:
        # Medium confidence - slightly reduce score
        final_score = base_score * 0.8
    else:
        # Low confidence - treat as potential unknown threat
        final_score = max(base_score, 5)  # Minimum medium risk for uncertainty
    
    # Ensure score stays within bounds
    final_score = min(10, max(1, final_score))
    
    state['risk_score'] = final_score
    return state

# Node 3: Responder - Generates human-readable summary and action
def responder_node(state: SecurityState) -> SecurityState:
    """Generate AI summary and recommend action based on analysis"""
    
    classification = state.get('classification', {})
    risk_score = state.get('risk_score', 0)
    event_type = classification.get('event_type', 'NORMAL')
    
    prompt = f"""
    Based on this security analysis:
    - Event Type: {event_type}
    - Risk Score: {risk_score}/10
    - Classification: {classification}
    
    Generate:
    1. A human-readable summary of what happened
    2. A recommended security action (MONITOR, INVESTIGATE, BLOCK_IP, ALERT_ADMIN, ESCALATE)
    
    Return JSON with:
    - ai_summary: clear explanation
    - recommended_action: one of the actions above
    """
    
    try:
        response = llm.invoke([HumanMessage(content=prompt)])
        result = JsonOutputParser().parse(response.content)
        
        state['ai_summary'] = result.get('ai_summary', 'Analysis failed')
        state['recommended_action'] = result.get('recommended_action', 'MONITOR')
        return state
        
    except Exception as e:
        state['ai_summary'] = f"Response generation failed: {str(e)}"
        state['recommended_action'] = 'MONITOR'
        return state

# Build the workflow graph
workflow = StateGraph(SecurityState)

# Add nodes
workflow.add_node("classifier", classifier_node)
workflow.add_node("scorer", scorer_node)
workflow.add_node("responder", responder_node)

# Define the flow
workflow.add_edge(START, "classifier")
workflow.add_edge("classifier", "scorer")
workflow.add_edge("scorer", "responder")
workflow.add_edge("responder", END)

# Compile the workflow
app = workflow.compile()

def analyze_security_log(log_entry: str) -> dict:
    """
    Main entry point for security log analysis using LangGraph workflow
    
    Args:
        log_entry (str): Security log to analyze
        
    Returns:
        dict: Complete analysis with classification, scoring, and recommendations
    """
    
    # Initialize state
    initial_state = {
        'messages': [],
        'log_entry': log_entry,
        'classification': {},
        'risk_score': 0,
        'ai_summary': '',
        'recommended_action': ''
    }
    
    # Run the workflow
    result = app.invoke(initial_state)
    
    return {
        'log_entry': log_entry,
        'classification': result.get('classification', {}),
        'risk_score': result.get('risk_score', 0),
        'ai_summary': result.get('ai_summary', ''),
        'recommended_action': result.get('recommended_action', 'MONITOR'),
        'workflow_steps': ['classification', 'scoring', 'response']
    }

# Example usage
if __name__ == "__main__":
    test_logs = [
        "Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
        "User john successfully logged in from 10.0.0.1",
        "Multiple failed login attempts detected from IP 203.0.113.1",
        "SELECT * FROM users WHERE 1=1; DROP TABLE users; --",
        "Normal system startup completed successfully"
    ]
    
    print("🔍 GuardianAI LangGraph Security Analysis")
    print("=" * 50)
    
    for log in test_logs:
        print(f"\n📋 Analyzing: {log}")
        result = analyze_security_log(log)
        
        print(f"🎯 Classification: {result['classification']}")
        print(f"⚡ Risk Score: {result['risk_score']}/10")
        print(f"🤖 AI Summary: {result['ai_summary']}")
        print(f"🛡️ Recommended Action: {result['recommended_action']}")
        print("-" * 50)
