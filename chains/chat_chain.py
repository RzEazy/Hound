import cohere
from typing import Dict, Any, Optional
from .base_chain import BaseChain

# Define template directly to avoid import issues
CHAT_PROMPT_TEMPLATE = """
You are Hound, a helpful AI assistant. Keep your responses concise and friendly.

Previous conversation:
{history}

User: {user_input}
Hound:"""

class ChatChain(BaseChain):
    def __init__(self, co_client: cohere.Client):
        self.co = co_client
    
    def process(self, user_input: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Process chat input and generate a response
        """
        if context is None:
            context = {}
        
        # Build conversation history
        history = ""
        conversations = context.get("conversations", [])
        for conv in conversations:
            history += f"User: {conv['user']}\nHound: {conv['hound']}\n"
        
        # Construct prompt
        prompt = CHAT_PROMPT_TEMPLATE.format(
            history=history,
            user_input=user_input
        )
        
        try:
            response = self.co.chat(
                model="command-a-03-2025",
                message=prompt
            )
            
            return {
                "response": response.text.strip(),
                "metadata": {
                    "chain": "chat",
                    "confidence": "high"
                }
            }
        except Exception as e:
            return {
                "response": "I'm having trouble responding right now. Could you try again?",
                "metadata": {
                    "chain": "chat",
                    "error": str(e)
                }
            }
