import json
from typing import TypedDict, List
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage
from langchain_core.output_parsers import JsonOutputParser
from langgraph.graph import StateGraph, START, END

# 1. Define the Batch State structure
class BatchSecurityState(TypedDict):
    logs_to_process: List[str]
    results: List[dict]
    status: str

# 2. State key constants
STATE_KEYS = {
    'LOGS_TO_PROCESS': 'logs_to_process',
    'RESULTS': 'results',
    'STATUS': 'status'
}

# 3. Status constants
STATUS_VALUES = {
    'COMPLETED': 'completed',
    'ERROR': 'error',
    'ALL_FILTERED': 'all_filtered'
}

# 2. Initialize Model
llm = ChatOllama(
    model="llama3.2:1b", 
    temperature=0, 
    format="json",
    keep_alive="1h"
)

# 3. Fast Filter (Pure Python)
def fast_filter(logs: List[str]):
    safe_keywords = ["successfully logged in", "normal system startup"]
    needs_ai = []
    skipped = []

    for log in logs:
        if any(k in log.lower() for k in safe_keywords) and "failed" not in log.lower():
            skipped.append({
                "log": log,
                "event_type": "NORMAL",
                "risk_score": 1,
                "recommended_action": "MONITOR",
                "method": "pattern_match"
            })
        else:
            needs_ai.append(log)
    return needs_ai, skipped

# 4. Node: Unified Batch AI Analyzer 
def batch_analyzer_node(state: BatchSecurityState) -> BatchSecurityState:
    needs_ai, results = fast_filter(state['logs_to_process'])
    
    if not needs_ai:
        state.update({"results": results, "status": "all_filtered"})
        return state
    
    logs_input = "\n".join([f"ID {i}: {log}" for i, log in enumerate(needs_ai)])
    
    prompt = f"""
    Analyze these security logs. Return a JSON list.
    Example Format: [{{"log_id": 0, "event_type": "SQL_INJECTION", "risk_score": 10, "recommended_action": "BLOCK_IP"}}]

    Logs to analyze:
    {logs_input}
    
    Return ONLY the JSON list:"""
    
    try:
        response = llm.invoke([HumanMessage(content=prompt)])
        ai_data = JsonOutputParser().parse(response.content)
        
        # Ensure ai_data is always a list ---
        if isinstance(ai_data, dict):
            # If it's a single dict with the results, wrap it in a list
            if "log_id" in ai_data:
                ai_data = [ai_data]
            else:
                # If it's wrapped in a key like {"logs": [...]}, find the list
                for key in ai_data:
                    if isinstance(ai_data[key], list):
                        ai_data = ai_data[key]
                        break

        # Double check we have a list to iterate over
        if isinstance(ai_data, list):
            for item in ai_data:
                if isinstance(item, dict): # Ensure each item is a dictionary
                    try:
                        idx = int(item.get("log_id", 0))
                        if 0 <= idx < len(needs_ai):
                            item["log"] = needs_ai[idx]
                            item["method"] = "llama3_batch"
                            results.append(item)
                    except (ValueError, TypeError):
                        continue
            
        state.update({"results": results, "status": "completed"})
    except Exception as e:
        state.update({STATE_KEYS['STATUS']: f"{STATUS_VALUES['ERROR']}: {str(e)}", STATE_KEYS['RESULTS']: results})
    
    return state

# 5. Build the Graph
workflow = StateGraph(BatchSecurityState)
workflow.add_node("processor", batch_analyzer_node)
workflow.add_edge(START, "processor")
workflow.add_edge("processor", END)
app = workflow.compile()

if __name__ == "__main__":
    test_batch = [
        "User admin successfully logged in from 10.0.0.5",
        "Failed password for user root from 192.168.1.100",
        "SELECT * FROM users; DROP TABLE users; --"
    ]
    
    print(f"🚀 Analyzing {len(test_batch)} logs...")
    output = app.invoke({
    STATE_KEYS['LOGS_TO_PROCESS']: test_batch, 
    STATE_KEYS['RESULTS']: [], 
    STATE_KEYS['STATUS']: ""
})
    
    # Check for errors first
    has_error = output.get(STATE_KEYS['STATUS']) and STATUS_VALUES['ERROR'] in output[STATE_KEYS['STATUS']]
    
    # Get processed logs
    processed_logs = {r['log']: r for r in output[STATE_KEYS['RESULTS']]}
    
    # Show all logs with their results or error
    for log in test_batch:
        print(f"\nLog: {log}")
        if log in processed_logs:
            r = processed_logs[log]
            print(f"Result: {r['event_type']} | Risk: {r['risk_score']}/10 | Action: {r['recommended_action']} | Logic: {r['method']}")
        elif has_error:
            print(f"Result: ❌ Error: {output[STATE_KEYS['STATUS']]}")
        else:
            print(f"Result: Not processed")
    
    print(f"\nStatus: {output.get('status', 'unknown')}")
