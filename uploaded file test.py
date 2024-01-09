from chatterbot import ChatBot
from chatterbot.trainers import ListTrainer

# Create a new instance of the ChatBot class
bot = ChatBot('TestBot')

# Create a new instance of the ListTrainer class and set it to train your chatbot
trainer = ListTrainer(bot)

# Train your chatbot with a list of conversations
trainer.train([
    "Hello",
    "Hello, how are you?",
    "I'm fine, thanks! How about you?",
    "I'm doing well too, thank you!",
    "what's your name?",
    "I'm salomon!"
])

# Continuous conversation loop
while True:
    # Get user input
    user_input = input("You: ")

    # Break the loop if the user types 'exit'
    if user_input.lower() == 'exit':
        break

    # Get a response from the chatbot
    response = bot.get_response(user_input)

    # Print the response
    print("Bot:", response)

