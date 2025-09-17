import openai
from flask import Flask, request, jsonify

# Add this to your app.py
@app.route('/api/chat', methods=['POST'])
def chat():
    try:
        data = request.json
        message = data.get('message', '')
        
        # Set your OpenAI API key
        openai.api_key = "your-openai-api-key-here"
        
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": message}],
            max_tokens=150
        )
        
        ai_response = response.choices[0].message.content
        return jsonify({'response': ai_response})
        
    except Exception as e:
        return jsonify({'response': f'Error: {str(e)}'})