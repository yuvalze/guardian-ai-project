import uvicorn
import json
from typing import List, Literal,TypedDict, Dict, Any, Optional
from fastapi import FastAPI
from pydantic import BaseModel, Field
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage
from langgraph.graph import StateGraph, START, END
from langchain_core.messages import SystemMessage, HumanMessage

# --- 1. Structured Output Schema ---
# This forces Llama 3.2 to return valid, typed JSON.
class LogAnalysis(BaseModel):
    log_id: int = Field(description="The index of the log in the provided list")
    
    # Restrict to specific types Java can understand
    event_type: Literal["BRUTE_FORCE", "SQL_INJECTION", "UNAUTHORIZED_ACCESS", "NORMAL", "SUSPICIOUS"] = Field(
        description="The category of the security event"
    )
    
    # Enforce range 1-10
    risk_score: int = Field(description="Severity score", ge=1, le=10)
    
    # Restrict to specific actions
    recommended_action: Literal["BLOCK_IP", "MONITOR", "ALLOW"] = Field(
        description="The action the system should take"
    )
    
    # Add a justification field (highly recommended for security)
    reasoning: str = Field(description="Short explanation of why this was flagged")

class BatchAnalysisResponse(BaseModel):
    analyses: List[LogAnalysis]

# --- 2. State & Constants ---
class BatchSecurityState(TypedDict):
    logs_to_process: List[str]
    results: List[dict]
    status: str

# --- 3. Initialize AI (Llama 3.2:1b) ---
llm = ChatOllama(
    model="llama3.2:1b", 
    temperature=0, 
    format="json", # Crucial for small models
    keep_alive="1h"
).with_structured_output(BatchAnalysisResponse)

# --- 4. Fast Filter (Pre-AI Logic) ---
def fast_filter(logs: List[str]):
    safe_keywords = ["successfully logged in", "normal system startup"]
    needs_ai = []
    skipped = []

    for i, log in enumerate(logs):
        if any(k in log.lower() for k in safe_keywords) and "failed" not in log.lower():
            skipped.append({
                "log": log,
                "event_type": "NORMAL",
                "risk_score": 1,
                "recommended_action": "ALLOW",
                "method": "pattern_match"
            })
        else:
            # We keep the original index so we can map it back later
            needs_ai.append({"id": i, "text": log})
    return needs_ai, skipped

# --- 5. LangGraph Node: AI Analyzer ---
def batch_analyzer_node(state: BatchSecurityState) -> BatchSecurityState:
    # 1. Separate safe logs (Fast Filter) from suspicious logs
    needs_ai, results = fast_filter(state['logs_to_process'])
    
    # If everything was filtered out by the Fast Filter, exit early
    if not needs_ai:
        return {"results": results, "status": "all_filtered", "logs_to_process": state['logs_to_process']}

    # 2. Create the Safety Map (Python's internal memory)
    # This maps the ID to the original log text so we can find it later
    needs_ai_map = {item['id']: item['text'] for item in needs_ai}
    
    # 3. Create the logs_input string (The exam paper for the AI)
    # We use the map to build this to ensure the IDs match perfectly
    logs_input = "\n".join([f"ID {k}: {v}" for k,v in needs_ai_map.items()])

    # 4. Define the Prompts
    system_prompt = SystemMessage(content=(
        "You are an expert Cyber Security Analyst. "
        "Your task is to analyze system logs for threats like SQL Injection, Brute Force, or Unauthorized Access. "
        "You must return a valid JSON object matching the requested schema. "
        "Assign a risk_score from 1 (Low) to 10 (Critical) and recommend an action: BLOCK_IP, MONITOR, or ALLOW."
    ))        
    
    # We explicitly tell the AI which IDs it is allowed to use
    allowed_ids = list(needs_ai_map.keys())
    user_prompt = HumanMessage(content=(
        f"Analyze these logs. ONLY use these IDs {allowed_ids}:\n"
        f"{logs_input}"
    ))

    try:
        # 5. Run the AI Inference
        ai_response = llm.invoke([system_prompt, user_prompt])
        
        # 6. Match AI results back to original text using the Safety Map
        for analysis in ai_response.analyses:
            # We use .get() to prevent crashes if the AI hallucinated an invalid ID
            log_text = needs_ai_map.get(analysis.log_id, "Unknown/Hallucinated ID")
            
            results.append({
                "log": log_text,
                "event_type": analysis.event_type,
                "risk_score": analysis.risk_score,
                "recommended_action": analysis.recommended_action,
                "reasoning": analysis.reasoning,
                "method": "llama3.2_batch"
            })
        
        return {"results": results, "status": "completed", "logs_to_process": state['logs_to_process']}
    
    except Exception as e:
        # If the LLM fails, we return the results from the Fast Filter + the error status
        return {"results": results, "status": f"error: {str(e)}", "logs_to_process": state['logs_to_process']}

# --- 6. Build the Graph ---
workflow = StateGraph(BatchSecurityState)
workflow.add_node("processor", batch_analyzer_node)
workflow.add_edge(START, "processor")
workflow.add_edge("processor", END)
app_graph = workflow.compile()

# --- 7. FastAPI Bridge ---
api = FastAPI(title="GuardianAI Engine")

class LogBatchRequest(BaseModel):
    logs: List[str]

@api.post("/analyze-batch")
async def analyze_batch_endpoint(request: LogBatchRequest):
    # Java calls this endpoint with a list of logs
    initial_state = {
        "logs_to_process": request.logs,
        "results": [],
        "status": ""
    }
    final_output = app_graph.invoke(initial_state)
    return final_output

if __name__ == "__main__":
    uvicorn.run(api, host="0.0.0.0", port=8000)
