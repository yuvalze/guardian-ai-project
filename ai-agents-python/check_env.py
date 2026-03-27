import sys
import pydantic
import langchain_core
import langgraph
import importlib.metadata # Added this to get the version correctly
from langchain_ollama import ChatOllama
from pydantic import BaseModel, Field

class SimpleSchema(BaseModel):
    status: str = Field(description="Must be 'OK'")

def run_diagnostic():
    print("=== GuardianAI Environment Diagnostic ===")
    
    # 1. Check Library Versions
    print(f" Python version: {sys.version.split()[0]}")
    print(f" Pydantic version: {pydantic.__version__}")
    
    # Correct way to get langgraph version
    lg_version = importlib.metadata.version("langgraph")
    print(f" LangGraph version: {lg_version}")
    
    # 2. Check Ollama Connection and Model
    print("\n=== Testing Ollama Connectivity ===")
    try:
        # Initialize the model
        llm = ChatOllama(model="llama3.2:1b", format="json", temperature=0)
        structured_llm = llm.with_structured_output(SimpleSchema)
        
        print(" Sending test request to Llama 3.2:1b...")
        # This confirms the model can return structured JSON
        response = structured_llm.invoke("Return JSON with status='OK'")
        
        if response.status == "OK":
            print("\n[SUCCESS] Ollama is connected and structured output is working!")
        else:
            print(f"\n[WARNING] Ollama responded but the data was wrong: {response}")
            
    except Exception as e:
        print(f"\n[ERROR] Diagnostic failed!")
        print(f"Details: {str(e)}")

if __name__ == "__main__":
    run_diagnostic()