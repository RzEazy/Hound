import json
from typing import List, Dict, Any

class MemoryManager:
    def __init__(self, memory_file: str = "hound_memory.json"):
        self.memory_file = memory_file
        self.load_memory()
    
    def load_memory(self):
        """Load memory from file"""
        try:
            with open(self.memory_file, "r") as f:
                self.memory = json.load(f)
            
            # Ensure all required keys exist
            required_keys = ["conversations", "personal_info", "tasks", "queries"]
            for key in required_keys:
                if key not in self.memory:
                    if key == "queries":
                        self.memory[key] = []
                    elif key == "conversations":
                        self.memory[key] = []
                    elif key == "personal_info":
                        self.memory[key] = {}
                    elif key == "tasks":
                        self.memory[key] = []
        except FileNotFoundError:
            # Initialize with default structure
            self.memory = {
                "conversations": [],
                "personal_info": {},
                "tasks": [],
                "queries": []  # For storing osquery history
            }
            self.save_memory()
        except Exception:
            # Fallback if file is corrupted
            self.memory = {
                "conversations": [],
                "personal_info": {},
                "tasks": [],
                "queries": []
            }
            self.save_memory()
    
    def save_memory(self):
        """Save memory to file"""
        try:
            with open(self.memory_file, "w") as f:
                json.dump(self.memory, f, indent=4)
        except Exception as e:
            print(f"Warning: Could not save memory: {e}")
    
    def add_conversation(self, user_input: str, response: str):
        """Add a conversation turn to memory"""
        self.memory["conversations"].append({
            "user": user_input,
            "hound": response
        })
        # Keep only last 50 conversations to prevent memory bloat
        if len(self.memory["conversations"]) > 50:
            self.memory["conversations"] = self.memory["conversations"][-50:]
        self.save_memory()
    
    def add_query(self, query: str, result: str):
        """Add an osquery to memory"""
        self.memory["queries"].append({
            "query": query,
            "result": result
        })
        # Keep only last 20 queries
        if len(self.memory["queries"]) > 20:
            self.memory["queries"] = self.memory["queries"][-20:]
        self.save_memory()
    
    def get_recent_conversations(self, count: int = 5) -> List[Dict[str, str]]:
        """Get recent conversation history"""
        return self.memory["conversations"][-count:] if self.memory["conversations"] else []
    
    def get_recent_queries(self, count: int = 3) -> List[Dict[str, str]]:
        """Get recent osquery history"""
        queries = self.memory.get("queries", [])
        return queries[-count:] if queries else []
    
    def get_memory_context(self) -> Dict[str, Any]:
        """Get all memory context for prompt building"""
        return {
            "conversations": self.get_recent_conversations(),
            "queries": self.get_recent_queries()
        }
