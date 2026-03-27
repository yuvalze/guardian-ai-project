import unittest
from langgraph_workflow import app_graph

class TestGuardianAI(unittest.TestCase):

    def test_workflow_logic(self):
        print("\n--- Starting GuardianAI Unit Test ---")
        
        # 1. Define input logs (Mixed: Safe and Dangerous)
        test_logs = [
            "Oct 27 10:00:05 normal system startup completed",  # Should be caught by Fast Filter
            "Failed password for root from 192.168.1.100 port 22", # Should be analyzed by AI
            "SELECT * FROM users WHERE id='1' OR '1'='1'"        # Should be analyzed by AI
        ]

        initial_state = {
            "logs_to_process": test_logs,
            "results": [],
            "status": ""
        }

        # 2. Invoke the Graph directly (No FastAPI needed)
        print("Invoking LangGraph workflow...")
        final_output = app_graph.invoke(initial_state)

        # 3. Assertions (Validation)
        self.assertEqual(final_output["status"], "completed")
        self.assertEqual(len(final_output["results"]), 3)

        # Verify Fast Filter worked for the first log
        first_res = final_output["results"][0]
        print(f"\n[Log 1 - Fast Filter] Type: {first_res['event_type']}, Method: {first_res['method']}")
        self.assertEqual(first_res["method"], "pattern_match")
        self.assertEqual(first_res["risk_score"], 1)

        # Verify AI worked for the second/third logs
        ai_res = final_output["results"][1]
        print(f"[Log 2 - AI] Type: {ai_res['event_type']}, Method: {ai_res['method']}, Reasoning: {ai_res.get('reasoning')}")
        self.assertEqual(ai_res["method"], "llama3.2_batch")

        # Accept ANY of the valid event types defined in your Pydantic schema
        valid_types = ["BRUTE_FORCE", "SQL_INJECTION", "UNAUTHORIZED_ACCESS", "NORMAL", "SUSPICIOUS"]
        self.assertIn(ai_res["event_type"], valid_types)
        print("\n--- Unit Test Passed Successfully! ---")

if __name__ == "__main__":
    unittest.main()