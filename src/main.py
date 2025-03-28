
#enable this when not using web
from taskfind import tasksfinder
from flask_cors import CORS

# def main():
#     while True:
#         user_query = input("Enter your query (or type 'exit' to quit): ")
#         if user_query.lower() == "exit":
#             print("Exiting...")
#             break
#         for data in tasksfinder(user_query):
#             print(data, end="")

# if __name__ == "__main__":
#     main()


# def main():
#     while True:
#         user_query = input("Enter your query (or type 'exit' to quit): ")
#         if user_query.lower() == "exit":
#             print("Exiting...")
#             break
#         print(tasksfinder(user_query))
       

# if __name__ == "__main__":
#     main()

from flask import Flask, Response, request
from pydantic import BaseModel
import time

app = Flask(__name__)
CORS(app)  # Enable CORS for all route
# Define the UserQuery model using Pydantic
class UserQuery(BaseModel):
    query: str  # User input query string

# Function to generate SSE stream based on user query


# SSE route that accepts user input via POST request
@app.route('/stream', methods=['POST'])
def stream():
    # Parse request JSON
    data = request.get_json()
    user_query = data.get("query", "Default Query")  # Default if query is missing
    print(user_query)
    # Return SSE response
    return Response(tasksfinder(user_query), content_type='text/event-stream')

# Run the Flask app
if __name__ == '__main__':
    app.run(debug=True, threaded=True)

