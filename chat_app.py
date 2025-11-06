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
import hashlib
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

# Minimal Diffie–Hellman parameters (RFC 3526 group 14: 2048-bit MODP)
P_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"
)
DH_P = int(P_HEX, 16)
DH_G = 2

# Debug logging helper
DEBUG = True
def dbg(msg):
    if DEBUG:
        print(f"[DEBUG] {msg}")

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
            dbg(f"AES key(hex)={key.hex()} for {username}")
            nonce, ciphertext, tag = encrypt_message(message, key)
            dbg(f"Encrypted for {username}: nonce={base64.b64encode(nonce).decode()} tag={base64.b64encode(tag).decode()} ct_len={len(ciphertext)}")
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
                'length': len(ciphertext),
                'ciphertext': base64.b64encode(ciphertext).decode()
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
                'key': None,  # will be established via DH
                'members': [],
                'dh': {}
            }

        # Append and keep order, remove accidental duplicates
        rooms[room]['members'].append(username)
        rooms[room]['members'] = list(dict.fromkeys(rooms[room]['members']))

        # If no key yet, start DH with this user; else, send welcome immediately
        if rooms[room]['key'] is None:
            import secrets
            b = secrets.randbelow(DH_P - 2) + 2  # secret in [2, P-1]
            B = pow(DH_G, b, DH_P)
            rooms[room]['dh'] = {'b': b, 'B': B}
            dbg(f"DH start room={room}: p_bits={DH_P.bit_length()} g={DH_G} b(hex)={format(b,'x')[:64]}... B(hex)={format(B, 'x')[:64]}...")
            socketio.emit('dh_params', {
                'p': format(DH_P, 'x'),
                'g': str(DH_G),
                'B': format(B, 'x'),
                'room': room
            }, room=request.sid)
        else:
            dbg(f"Room {room} key already established; skipping DH.")
            welcome_msg = f"Welcome {username} to room {room}!"
            encrypted_msg = process_message(welcome_msg, rooms[room]['key'], username)
            socketio.emit('message', {
                'username': 'System',
                'image_url': f"data:image/png;base64,{encrypted_msg['image']}",
                'nonce': encrypted_msg['nonce'],
                'tag': encrypted_msg['tag'],
                'length': encrypted_msg['length'],
                'ciphertext': encrypted_msg.get('ciphertext')
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
                        if rooms[room].get('key'):
                            encrypted_msg = process_message(leave_msg, rooms[room]['key'], rooms[room]['members'][0])
                            socketio.emit('message', {
                                'username': 'System',
                                'image_url': f"data:image/png;base64,{encrypted_msg['image']}",
                                'nonce': encrypted_msg['nonce'],
                                'tag': encrypted_msg['tag'],
                                'length': encrypted_msg['length'],
                                'ciphertext': encrypted_msg.get('ciphertext')
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
        if rooms[data['room']].get('key') is None:
            return jsonify({'success': False, 'error': 'Room key not established yet'})
        # Convert base64 image to bytes
        image_data = base64.b64decode(data['image'])
        input_buffer = io.BytesIO(image_data)

        # Decode the message
        ciphertext = decode_image(input_buffer, int(data['length']))

        # Decrypt the message
        nonce = base64.b64decode(data['nonce'])
        tag = base64.b64decode(data['tag'])
        dbg(f"Decrypt with key(hex)={rooms[data['room']]['key'].hex()} nonce={base64.b64encode(nonce).decode()} tag={base64.b64encode(tag).decode()} ct_len={len(ciphertext)}")
        message = decrypt_message(nonce, ciphertext, tag, rooms[data['room']]['key'])
        dbg(f"Decoded message in room={data['room']}: {message}")

        return jsonify({'success': True, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@socketio.on('message')
def on_message(data):
    try:
        room = data['room']
        message = data['message']
        username = data['username']
        dbg(f"on_message: room={room} user={username} msg_len={len(message) if isinstance(message, str) else 'n/a'}")
        
        # Verify the user is actually in the room and session is valid
        if (request.sid in user_sessions and 
            user_sessions[request.sid] == username and 
            room in rooms and 
            username in rooms[room]['members'] and 
            username in user_images):
            
            # Process message only if room key is ready
            if rooms[room].get('key') is None:
                socketio.emit('error', {'message': 'Room key not established yet'}, room=request.sid)
                return
            encrypted_msg = process_message(message, rooms[room]['key'], username)
            
            socketio.emit('message', {
                'username': username,
                'image_url': f"data:image/png;base64,{encrypted_msg['image']}",
                'nonce': encrypted_msg['nonce'],
                'tag': encrypted_msg['tag'],
                'length': encrypted_msg['length'],
                'ciphertext': encrypted_msg.get('ciphertext')
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

# --- DH completion: client sends public 'A' and we derive the room key ---
@socketio.on('dh_client_public')
def on_dh_client_public(data):
    try:
        room = data.get('room')
        A_hex = data.get('A')
        if not room or room not in rooms or not A_hex:
            socketio.emit('error', {'message': 'Invalid DH data'}, room=request.sid)
            return
        # If key already set, just ack
        if rooms[room].get('key'):
            socketio.emit('dh_ok', {'room': room}, room=request.sid)
            return
        dh_state = rooms[room].get('dh', {})
        b = dh_state.get('b')
        if b is None:
            socketio.emit('error', {'message': 'DH state missing'}, room=request.sid)
            return
        try:
            A = int(A_hex, 16)
        except Exception:
            socketio.emit('error', {'message': 'Invalid DH public value'}, room=request.sid)
            return
        # Compute shared secret s = A^b mod p
        s = pow(A, b, DH_P)
        s_bytes = s.to_bytes((s.bit_length() + 7) // 8, byteorder='big') or b"\x00"
        key = hashlib.sha256(s_bytes).digest()[:16]
        dbg(f"DH complete room={room}: A(hex)={A_hex} b(hex)={format(b,'x')} shared_s(hex)={s_bytes.hex()} key(hex)={key.hex()}")
        rooms[room]['key'] = key
        rooms[room]['dh'] = {}
        socketio.emit('dh_ok', {'room': room}, room=request.sid)
        # Also emit the derived key for client console (debug only)
        socketio.emit('dh_key', {
            'room': room,
            'key_hex': key.hex(),
            'A': A_hex,
            'B': format(dh_state.get('B', 0), 'x')
        }, room=request.sid)
        # Send welcome message after key establishment
        username = user_sessions.get(request.sid, 'User')
        try:
            welcome_msg = f"Welcome {username} to room {room}!"
            encrypted_msg = process_message(welcome_msg, key, username)
            socketio.emit('message', {
                'username': 'System',
                'image_url': f"data:image/png;base64,{encrypted_msg['image']}",
                'nonce': encrypted_msg['nonce'],
                'tag': encrypted_msg['tag'],
                'length': encrypted_msg['length'],
                'ciphertext': encrypted_msg.get('ciphertext')
            }, room=room)
        except Exception as e:
            print(f"Error sending welcome after DH: {e}")
    except Exception as e:
        print(f"Error in DH completion: {e}")

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