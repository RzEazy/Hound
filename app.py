from core.hound import HoundMain

# Initialize Hound with your Cohere API key
hound = HoundMain(
    api_key="doeM32W2so3ubfYYs673lmiOmUzwN15weKfB68bj",
    memory_file="hound_memory.json"
)

def chat():
    print("Hound - Modular Cyber Assistant")
    print("Ask me anything - I can chat, run commands, or query system security!")
    print("Type 'exit', 'quit', 'bye', or 'goodbye' to exit.\n")

    while True:
        user_input = input("You: ")

        if user_input.lower() in ["exit", "quit", "bye", "goodbye"]:
            print("Hound: Peace!")
            break

        response = hound.process_input(user_input)
        print("Hound:", response)
        print()  # Add spacing for readability

if __name__ == "__main__":
    chat()
