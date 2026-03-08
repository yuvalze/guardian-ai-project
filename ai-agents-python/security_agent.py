import json
from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage
from langchain_core.output_parsers import JsonOutputParser

# Initialize ChatOllama with local llama3 model
llm = ChatOllama(
    model="llama3",
    temperature=0.1,  # Low temperature for consistent security analysis
)

# JSON output parser
parser = JsonOutputParser()

def analyze_log(log: str) -> dict:
    """
    Analyze a security log and return threat assessment.
    
    Args:
        log (str): Security log entry to analyze
        
    Returns:
        dict: JSON object with is_threat (boolean), severity (string), and summary (string)
    """
    
    # Create the prompt for security analysis
    prompt = f"""
    Analyze the following security log entry and determine if it represents a threat.
    
    Log: {log}
    
    Return a JSON object with exactly these fields:
    - is_threat: boolean (true if this is a security threat, false otherwise)
    - severity: string (one of: "low", "medium", "high", "critical")
    - summary: string (short English description of what happened)
    
    Consider common security threats like:
    - Failed login attempts
    - Unauthorized access attempts
    - Suspicious IP addresses
    - Brute force attacks
    - Port scanning
    - Malware detection
    - Data exfiltration attempts
    
    Respond only with valid JSON, no additional text.
    """
    
    try:
        # Send the prompt to the model
        response = llm.invoke([HumanMessage(content=prompt)])
        
        # Parse the JSON response
        result = parser.parse(response.content)
        
        # Validate required fields
        required_fields = ['is_threat', 'severity', 'summary']
        for field in required_fields:
            if field not in result:
                raise ValueError(f"Missing required field: {field}")
        
        # Validate severity value
        valid_severities = ['low', 'medium', 'high', 'critical']
        if result['severity'] not in valid_severities:
            result['severity'] = 'medium'  # Default fallback
        
        return result
        
    except Exception as e:
        # Return a safe default if parsing fails
        return {
            "is_threat": False,
            "severity": "medium",
            "summary": f"Error analyzing log: {str(e)}"
        }

# Example usage and testing
if __name__ == "__main__":
    # Test with a sample log
    test_logs = [
        "Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
        "User john successfully logged in from 10.0.0.1",
        "Multiple failed login attempts detected from IP 203.0.113.1",
        "Normal system startup completed successfully"
    ]
    
    for log in test_logs:
        print(f"Analyzing: {log}")
        result = analyze_log(log)
        print(f"Result: {json.dumps(result, indent=2)}")
        print("-" * 50)
