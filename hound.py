# This file is deprecated. Use core/lia_main.py instead.
# Keeping for backward compatibility.

import cohere
import json
import subprocess
import platform

class hound:
    def __init__(self, api_key, memory_file="hound_memory.json"):
        self.co = cohere.Client(api_key)
        self.memory_file = memory_file
        self.load_memory()
        self.os_type = platform.system().lower()  # windows / linux / darwin (mac)

    def load_memory(self):
        try:
            with open(self.memory_file, "r") as f:
                self.memory = json.load(f)
        except:
            self.memory = {
                "conversations": [],
                "personal_info": {}
            }
            self.save_memory()

    def save_memory(self):
        with open(self.memory_file, "w") as f:
            json.dump(self.memory, f, indent=4)

    def generate_response(self, user_input):
        """Decides if it's a command or normal convo."""
        
        command = self.nl_to_os_command(user_input)

        if command and self.is_safe(command):
            execution_result = self.run_system_command(command)
            self.save_in_memory(user_input, f"[Executed]: {execution_result}")
            return f"🛠 Executed: `{command}`\n\nOutput:\n{execution_result}"

        ai_response = self.chat_response(user_input)
        self.save_in_memory(user_input, ai_response)
        return ai_response

    def nl_to_os_command(self, user_input):
        """Uses Cohere to convert human text → real computer command."""

        system_prompt = f"""
Convert the user's request into a command depending on the OS.

OS right now: {self.os_type}

RULES:
- If it's NOT a computer action, reply ONLY with: NO_COMMAND
- No explanation, no extra text, only the command.

Examples:
User: make a folder called test
Windows: mkdir test
Linux: mkdir test
macOS: mkdir test

User: open chrome
Windows: start chrome
Linux: google-chrome &
macOS: open -a "Google Chrome"
"""

        response = self.co.chat(
            model="command-a-03-2025",
            message=f"{system_prompt}\nUser: {user_input}"
        ).text.strip()

        if response == "NO_COMMAND":
            return None

        return response

    def chat_response(self, user_input):
        """Just normal AI chat."""
        
        history = self.build_history()
        prompt = f"{history}User: {user_input}\Hound:"
        
        response = self.co.chat(
            model="command-a-03-2025",
            message=prompt
        )

        return response.text.strip()

    def build_history(self):
        """Keeps convo memory short so she doesn't act cooked."""
        
        history = ""
        for conv in self.memory["conversations"]:
            history += f"User: {conv['user']}\nHound: {conv['Hound']}\n"
        return history

    def run_system_command(self, command):
        """Actually runs the command in Windows/Linux/Mac."""
        
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True
            )
            if result.returncode == 0:
                return result.stdout.strip() if result.stdout else "Done."
            return result.stderr.strip()
        except Exception as e:
            return f"⚠ Error: {str(e)}"

    def is_safe(self, command):
        """Stops her from deleting your whole PC like an ex."""
        
        dangerous = [
            "rm -rf", "rm --no-preserve-root", "format", 
            "mkfs", "dd if=", "shutdown", "del /s"
        ]

        return not any(x in command.lower() for x in dangerous)

    def save_in_memory(self, user_input, response):
        self.memory["conversations"].append({
            "user": user_input,
            "Hound": response
        })
        self.save_memory()
