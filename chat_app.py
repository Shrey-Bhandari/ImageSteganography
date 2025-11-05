import eventlet
eventlet.monkey_patch(os=True, select=True, socket=True, thread=True, time=True)

import os
import base64
import io
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from flask import Flask, render_template, request, send_from_directory, jsonify
from flask_socketio import SocketIO, join_room, leave_room
from PIL import Image
from Crypto.Random import get_random_bytes
from app import encrypt_message, encode_image, decode_image, decrypt_message

# Create a thread pool for image processing
thread_pool = ThreadPoolExecutor(max_workers=4)

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
socketio = SocketIO(app, 
                   async_mode='eventlet',
                   cors_allowed_origins="*",
                   ping_timeout=60)

# Store room information
rooms = {}
# Store user base images
user_images = {}
# Store processed image cache
image_cache = {}
# Store user sessions
user_sessions = {}  # Maps session ID to username
user_rooms = {}    # Maps username to room

def resize_image(img_data):
    """Resize image to optimal size for steganography"""
    img = Image.open(io.BytesIO(base64.b64decode(img_data.split(',')[1])))
    max_size = (400, 300)  # Reduced size for better performance
    img.thumbnail(max_size, Image.Resampling.LANCZOS)
    output = io.BytesIO()
    img.save(output, format='PNG', optimize=True)
    output.seek(0)
    return 'data:image/png;base64,' + base64.b64encode(output.getvalue()).decode()

def process_message_async(message, key, username):
    """Process message asynchronously"""
    future = thread_pool.submit(process_message, message, key, username)
    return future.result()

def process_message(message, key, username):
    """Encrypt message and hide it in an image"""
    try:
        if username not in user_images:
            print(f"Error: No base image found for user {username}")
            print(f"Available users: {list(user_images.keys())}")
            raise ValueError("User has no base image")
            
        # Check cache first
        cache_key = f"{username}:{message}"
        if cache_key in image_cache:
            return image_cache[cache_key]

        # Get user's base image
        base_image_data = user_images[username]
        
        # Create input buffer from base64 image
        if ',' in base_image_data:  # Handle data URL format
            base_image_data = base_image_data.split(',')[1]
        
        try:
            image_data = base64.b64decode(base_image_data)
        except Exception as e:
            print(f"Error decoding base64 image: {e}")
            raise
            
        input_buffer = io.BytesIO(image_data)
        
        try:
            # Test if image is valid
            test_img = Image.open(input_buffer)
            test_img.verify()
            input_buffer.seek(0)  # Reset buffer position after verify
        except Exception as e:
            print(f"Error verifying image format: {e}")
            raise ValueError("Invalid image format")
        
        # Encrypt message
        try:
            nonce, ciphertext, tag = encrypt_message(message, key)
        except Exception as e:
            print(f"Error during encryption: {e}")
            raise
        
        # Encode message in image
        output_buffer = io.BytesIO()
        try:
            encode_image(input_buffer, ciphertext, output_buffer)
        except Exception as e:
            print(f"Error encoding message in image: {e}")
            raise
        
        # Convert to base64 for sending
        output_buffer.seek(0)
        try:
            img_base64 = base64.b64encode(output_buffer.getvalue()).decode()
        except Exception as e:
            print(f"Error converting image to base64: {e}")
            raise
        
        return {
            'image': img_base64,
            'nonce': base64.b64encode(nonce).decode(),
            'tag': base64.b64encode(tag).decode(),
            'length': len(ciphertext)
        }
    except Exception as e:
        print(f"Error in process_message: {str(e)}")
        raise

@app.route('/')
def index():
    return render_template('index.html')

@socketio.on('connect')
def on_connect():
    print("Client connected", request.sid)

@socketio.on('error')
def on_error(error):
    print(f"WebSocket error: {error}")

@socketio.on('join')
def on_join(data):
    # Make join idempotent and send welcome only when the user is newly added
    try:
        username = data['username']
        room = data['room']
        base_image = data['baseImage']

        # If the room exists and the username is already a member, just send updated user list
        if room in rooms and username in rooms[room]['members']:
            socketio.emit('room_update', {
                'members': list(dict.fromkeys(rooms[room]['members']))
            }, room=room)
            return

        # Store session information
        user_sessions[request.sid] = username
        user_rooms[username] = room

        # Resize and store user's base image
        user_images[username] = resize_image(base_image)

        join_room(room)

        if room not in rooms:
            rooms[room] = {
                'key': get_random_bytes(16),
                'members': []
            }

        # Append and keep order, remove accidental duplicates
        rooms[room]['members'].append(username)
        rooms[room]['members'] = list(dict.fromkeys(rooms[room]['members']))

        # Only send the welcome message for a newly joined user
        welcome_msg = f"Welcome {username} to room {room}!"
        encrypted_msg = process_message(welcome_msg, rooms[room]['key'], username)

        socketio.emit('message', {
            'username': 'System',
            'image_url': f"data:image/png;base64,{encrypted_msg['image']}",
            'nonce': encrypted_msg['nonce'],
            'tag': encrypted_msg['tag'],
            'length': encrypted_msg['length']
        }, room=room)

        # Send updated user list to all members in the room
        socketio.emit('room_update', {
            'members': list(dict.fromkeys(rooms[room]['members']))
        }, room=room)
    except Exception as e:
        print(f"Error during join: {str(e)}")
        socketio.emit('error', {'message': 'Failed to join room'}, room=request.sid)

@socketio.on('disconnect')
def on_disconnect():
    print("Client disconnected", request.sid)
    if request.sid in user_sessions:
        username = user_sessions[request.sid]
        if username in user_rooms:
            room = user_rooms[username]
            if room in rooms and username in rooms[room]['members']:
                try:
                    # Remove user from room
                    rooms[room]['members'].remove(username)
                    # Clean up user data
                    del user_sessions[request.sid]
                    del user_rooms[username]
                    if username in user_images:
                        del user_images[username]
                    
                    # Notify remaining users
                    if rooms[room]['members']:  # If there are still members in the room
                        leave_msg = f"{username} has left the room."
                        encrypted_msg = process_message(leave_msg, rooms[room]['key'], rooms[room]['members'][0])
                        socketio.emit('message', {
                            'username': 'System',
                            'image_url': f"data:image/png;base64,{encrypted_msg['image']}",
                            'nonce': encrypted_msg['nonce'],
                            'tag': encrypted_msg['tag'],
                            'length': encrypted_msg['length']
                        }, room=room)
                        socketio.emit('room_update', {
                            'members': list(set(rooms[room]['members']))  # Remove duplicates
                        }, room=room)
                    else:  # If room is empty, clean it up
                        del rooms[room]
                except Exception as e:
                    print(f"Error during disconnect handling: {str(e)}")
                    

@app.route('/decode', methods=['POST'])
def decode_message():
    data = request.json
    if not data or 'room' not in data or data['room'] not in rooms:
        return jsonify({'success': False, 'error': 'Invalid room'})

    try:
        # Convert base64 image to bytes
        image_data = base64.b64decode(data['image'])
        input_buffer = io.BytesIO(image_data)
        
        # Decode the message
        ciphertext = decode_image(input_buffer, int(data['length']))
        
        # Decrypt the message
        nonce = base64.b64decode(data['nonce'])
        tag = base64.b64decode(data['tag'])
        message = decrypt_message(nonce, ciphertext, tag, rooms[data['room']]['key'])
        
        return jsonify({'success': True, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@socketio.on('message')
def on_message(data):
    try:
        room = data['room']
        message = data['message']
        username = data['username']
        
        # Verify the user is actually in the room and session is valid
        if (request.sid in user_sessions and 
            user_sessions[request.sid] == username and 
            room in rooms and 
            username in rooms[room]['members'] and 
            username in user_images):
            
            # Process message with room's key and user's base image
            encrypted_msg = process_message(message, rooms[room]['key'], username)
            
            socketio.emit('message', {
                'username': username,
                'image_url': f"data:image/png;base64,{encrypted_msg['image']}",
                'nonce': encrypted_msg['nonce'],
                'tag': encrypted_msg['tag'],
                'length': encrypted_msg['length']
            }, room=room)
        else:
            socketio.emit('error', {
                'message': 'Not authorized to send messages in this room'
            }, room=request.sid)
    except Exception as e:
        print(f"Error sending message: {str(e)}")
        socketio.emit('error', {
            'message': 'Failed to send message'
        }, room=request.sid)

if __name__ == '__main__':
    # Check if port 5000 is available, if not try 5001
    port = 5000
    try:
        import socket
        test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            test_socket.bind(('0.0.0.0', 5000))
            test_socket.close()
        except socket.error:
            port = 5001
            print(f"Port 5000 is in use, trying port {port}...")
    except Exception as e:
        print(f"Error checking ports: {e}")
        port = 5001

    print("\n" + "="*50)
    print(f"Chat Application Server")
    print("="*50)
    print(f"\nOpen this link in your browser:")
    print(f"\nhttp://localhost:{port}\n")
    print("="*50 + "\n")
    try:
        socketio.run(app, 
                    debug=False,  # Disable debug mode to prevent double messages
                    host='0.0.0.0', 
                    port=port,
                    use_reloader=False,  # Disable reloader to prevent restart
                    log_output=True)
    except Exception as e:
        print(f"Error starting server: {e}")