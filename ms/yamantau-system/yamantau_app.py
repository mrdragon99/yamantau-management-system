import customtkinter as ctk
from tkinter import messagebox, ttk
import json
import os
import bcrypt
from datetime import datetime
import time
import threading
import socket
import queue
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('yamantau_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Set customtkinter appearance
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("green")

# Configuration
CONFIG = {
    'chat_host': '127.0.0.1',
    'chat_port': 5555,
    'db_type': 'json',
    'min_password_length': 6
}


class User:
    """User model for authentication"""
    def __init__(self, username, password):
        self.username = username
        self.password = password


class Yamantau:
    """Yamantau member model"""
    def __init__(self, first_name, last_name, username, yamantau_code, birth_date):
        self.first_name = first_name
        self.last_name = last_name
        self.username = username
        self.yamantau_code = yamantau_code
        self.birth_date = birth_date
        self.registration_date = datetime.now().strftime("%Y-%m-%d")


class AuthManager:
    """Manages user authentication and registration"""
    
    def __init__(self, db_type="json"):
        self.db_type = db_type
        if db_type == "json":
            self.users_file = "users.json"
            self.init_json_files()

    def init_json_files(self):
        """Initialize JSON files if they don't exist"""
        if not os.path.exists(self.users_file):
            with open(self.users_file, 'w') as f:
                json.dump([], f)
        else:
            try:
                with open(self.users_file, 'r') as f:
                    json.load(f)
            except json.JSONDecodeError:
                logger.warning(f"Corrupted {self.users_file}, resetting")
                with open(self.users_file, 'w') as f:
                    json.dump([], f)

    def hash_password(self, password):
        """Hash a password using bcrypt"""
        return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    def verify_password(self, password, hashed):
        """Verify a password against its hash"""
        return bcrypt.checkpw(password.encode('utf-8'), hashed)

    def register_user(self, username, password):
        """Register a new user"""
        try:
            hashed_pw = self.hash_password(password)
        except Exception as e:
            logger.error(f"Password hashing error: {e}")
            return False, f"Password hashing error: {str(e)}"
        
        return self._register_user_json(username, hashed_pw)

    def _register_user_json(self, username, hashed_pw):
        """Register user with JSON storage"""
        try:
            if not os.path.exists(self.users_file):
                with open(self.users_file, 'w') as f:
                    json.dump([], f)
            
            try:
                with open(self.users_file, 'r') as f:
                    users = json.load(f)
            except json.JSONDecodeError:
                users = []
            
            for user in users:
                if user.get('username') == username:
                    return False, "Username already exists"
            
            users.append({
                'username': username,
                'password': hashed_pw.decode('utf-8')
            })
            
            with open(self.users_file, 'w') as f:
                json.dump(users, f, indent=2)
                
            logger.info(f"User registered: {username}")
            return True, "User registered successfully"
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return False, f"Registration error: {str(e)}"

    def login_user(self, username, password):
        """Authenticate a user"""
        try:
            if not os.path.exists(self.users_file):
                return False, "No users registered yet"
            
            try:
                with open(self.users_file, 'r') as f:
                    users = json.load(f)
            except json.JSONDecodeError:
                return False, "Database file corrupted"
            
            for user in users:
                if user.get('username') == username:
                    try:
                        if self.verify_password(password, user.get('password', '').encode('utf-8')):
                            logger.info(f"User logged in: {username}")
                            return True, "Login successful"
                        else:
                            return False, "Invalid password"
                    except Exception as e:
                        logger.error(f"Password verification error: {e}")
                        return False, f"Password verification error: {str(e)}"
            
            return False, "User not found"
        except Exception as e:
            logger.error(f"Login error: {e}")
            return False, f"Login error: {str(e)}"


class YamantauManager:
    """Manages Yamantau members"""
    
    def __init__(self, auth_manager, current_user=None):
        self.auth_manager = auth_manager
        self.current_user = current_user
        if auth_manager.db_type == "json":
            self.yamantau_file = f"yamantau_{current_user}.json" if current_user else "yamantau.json"
            self.init_json_file()

    def init_json_file(self):
        """Initialize yamantau JSON file"""
        if not os.path.exists(self.yamantau_file):
            with open(self.yamantau_file, 'w') as f:
                json.dump([], f)
        else:
            try:
                with open(self.yamantau_file, 'r') as f:
                    json.load(f)
            except json.JSONDecodeError:
                logger.warning(f"Corrupted {self.yamantau_file}, resetting")
                with open(self.yamantau_file, 'w') as f:
                    json.dump([], f)

    def add_yamantau(self, first_name, last_name, username, yamantau_code, birth_date):
        """Add a new yamantau"""
        yamantau = Yamantau(first_name, last_name, username, yamantau_code, birth_date)
        return self._add_yamantau_json(yamantau)

    def _add_yamantau_json(self, yamantau):
        """Add yamantau with JSON storage"""
        try:
            try:
                with open(self.yamantau_file, 'r') as f:
                    yamantau_list = json.load(f)
            except json.JSONDecodeError:
                yamantau_list = []
            
            for y in yamantau_list:
                if y.get('username') == yamantau.username:
                    return False, "Username already exists"
                if y.get('yamantau_code') == yamantau.yamantau_code:
                    return False, "Yamantau code already exists"
            
            yamantau_list.append({
                'first_name': yamantau.first_name,
                'last_name': yamantau.last_name,
                'username': yamantau.username,
                'yamantau_code': yamantau.yamantau_code,
                'birth_date': yamantau.birth_date,
                'registration_date': yamantau.registration_date
            })
            
            with open(self.yamantau_file, 'w') as f:
                json.dump(yamantau_list, f, indent=2)
                
            logger.info(f"Yamantau added: {yamantau.username}")
            return True, "Yamantau added successfully"
        except Exception as e:
            logger.error(f"Error adding yamantau: {e}")
            return False, f"Error adding yamantau: {str(e)}"

    def update_yamantau(self, yamantau_id, first_name=None, last_name=None, username=None, 
                       yamantau_code=None, birth_date=None):
        """Update an existing yamantau"""
        try:
            try:
                with open(self.yamantau_file, 'r') as f:
                    yamantau_list = json.load(f)
            except json.JSONDecodeError:
                return False, "Yamantau file corrupted"
            
            if yamantau_id >= len(yamantau_list):
                return False, "Yamantau not found"
            
            if first_name is not None:
                yamantau_list[yamantau_id]['first_name'] = first_name
            if last_name is not None:
                yamantau_list[yamantau_id]['last_name'] = last_name
            if username is not None:
                for i, y in enumerate(yamantau_list):
                    if i != yamantau_id and y.get('username') == username:
                        return False, "Username already exists"
                yamantau_list[yamantau_id]['username'] = username
            if yamantau_code is not None:
                for i, y in enumerate(yamantau_list):
                    if i != yamantau_id and y.get('yamantau_code') == yamantau_code:
                        return False, "Yamantau code already exists"
                yamantau_list[yamantau_id]['yamantau_code'] = yamantau_code
            if birth_date is not None:
                yamantau_list[yamantau_id]['birth_date'] = birth_date
            
            with open(self.yamantau_file, 'w') as f:
                json.dump(yamantau_list, f, indent=2)
                
            logger.info(f"Yamantau updated: ID {yamantau_id}")
            return True, "Yamantau updated successfully"
        except Exception as e:
            logger.error(f"Error updating yamantau: {e}")
            return False, f"Error updating yamantau: {str(e)}"

    def delete_yamantau(self, yamantau_id):
        """Delete a yamantau"""
        try:
            try:
                with open(self.yamantau_file, 'r') as f:
                    yamantau_list = json.load(f)
            except json.JSONDecodeError:
                return False, "Yamantau file corrupted"
            
            if yamantau_id >= len(yamantau_list):
                return False, "Yamantau not found"
            
            yamantau_list.pop(yamantau_id)
            
            with open(self.yamantau_file, 'w') as f:
                json.dump(yamantau_list, f, indent=2)
                
            logger.info(f"Yamantau deleted: ID {yamantau_id}")
            return True, "Yamantau deleted successfully"
        except Exception as e:
            logger.error(f"Error deleting yamantau: {e}")
            return False, f"Error deleting yamantau: {str(e)}"

    def get_all_yamantau(self):
        """Get all yamantau"""
        try:
            if not os.path.exists(self.yamantau_file):
                with open(self.yamantau_file, 'w') as f:
                    json.dump([], f)
            
            try:
                with open(self.yamantau_file, 'r') as f:
                    yamantau_list = json.load(f)
            except json.JSONDecodeError:
                yamantau_list = []
                
            return True, yamantau_list
        except Exception as e:
            logger.error(f"Error reading yamantau: {e}")
            return False, f"Error reading yamantau: {str(e)}"

    def search_yamantau(self, query):
        """Search yamantau with ranking algorithm"""
        success, yamantau_list = self.get_all_yamantau()
        if not success:
            return False, yamantau_list
        
        results = []
        query_lower = query.lower()
        
        for i, yamantau in enumerate(yamantau_list):
            score = 0
            if isinstance(yamantau, dict):
                for key, value in yamantau.items():
                    if isinstance(value, str) and query_lower in value.lower():
                        score += 1
            
            if score > 0:
                results.append((score, i, yamantau))
        
        results.sort(key=lambda x: x[0], reverse=True)
        ranked_yamantau = [yamantau for score, index, yamantau in results]
        return True, ranked_yamantau


class ChatServer:
    """TCP Chat Server"""
    
    def __init__(self, host='127.0.0.1', port=5555):
        self.host = host
        self.port = port
        self.clients = []
        self.clients_lock = threading.Lock()
        self.server_socket = None
        self.running = False

    def broadcast(self, message, sender_socket=None):
        """Broadcast message to all clients"""
        with self.clients_lock:
            disconnected_clients = []
            for client in self.clients:
                try:
                    client.sendall(message.encode('utf-8'))
                except Exception as e:
                    logger.error(f"Error sending to client: {e}")
                    disconnected_clients.append(client)
            
            for client in disconnected_clients:
                self.clients.remove(client)
                try:
                    client.close()
                except:
                    pass

    def handle_client(self, client_socket, addr):
        """Handle a single client connection"""
        logger.info(f"New connection from {addr}")
        
        try:
            while self.running:
                try:
                    data = client_socket.recv(4096)
                    if not data:
                        break
                    
                    try:
                        msg_str = data.decode('utf-8')
                        json.loads(msg_str)
                        self.broadcast(msg_str)
                    except json.JSONDecodeError:
                        logger.warning(f"Invalid JSON from {addr}")
                    except Exception as e:
                        logger.error(f"Error processing message from {addr}: {e}")
                        break
                except ConnectionResetError:
                    break
                except Exception as e:
                    logger.error(f"Client loop error: {e}")
                    break
                    
        except Exception as e:
            logger.error(f"Connection error with {addr}: {e}")
        finally:
            with self.clients_lock:
                if client_socket in self.clients:
                    self.clients.remove(client_socket)
            client_socket.close()
            logger.info(f"Connection closed: {addr}")

    def start(self):
        """Start the TCP chat server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            self.running = True
            logger.info(f"Chat Server started on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, addr = self.server_socket.accept()
                    with self.clients_lock:
                        self.clients.append(client_socket)
                    
                    client_thread = threading.Thread(target=self.handle_client, args=(client_socket, addr))
                    client_thread.daemon = True
                    client_thread.start()
                except OSError:
                    break
                except Exception as e:
                    logger.error(f"Server accept error: {e}")
                    
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()

    def stop(self):
        """Stop the chat server"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        with self.clients_lock:
            for client in self.clients:
                try:
                    client.close()
                except:
                    pass
            self.clients.clear()


class COSZ1App:
    """Main Application"""
    
    def __init__(self):
        self.root = ctk.CTk()
        self.root.title("COS YMS - Yamantau Management System")
        self.root.geometry("1200x800")
        self.root.minsize(1000, 700)
        
        self.auth_manager = AuthManager(CONFIG['db_type'])
        self.yamantau_manager = None
        self.current_user = None
        
        self.chat_username = None
        self.chat_receiver_thread = None
        self.chat_stop_receiver = False
        self.msg_queue = queue.Queue()
        self.client_socket = None
        
        self.chat_server = ChatServer(CONFIG['chat_host'], CONFIG['chat_port'])
        self.server_thread = threading.Thread(target=self.chat_server.start, daemon=True)
        self.server_thread.start()
        
        self.create_login_screen()
        
    def create_login_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()
            
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(expand=True, fill="both", padx=20, pady=20)
        
        center_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        center_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(center_frame, text="COS Z1", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=(0, 5))
        ctk.CTkLabel(center_frame, text="Member Management System", font=ctk.CTkFont(size=16)).pack(pady=(0, 30))
        
        ctk.CTkLabel(center_frame, text="Username:", font=ctk.CTkFont(size=14)).pack(pady=(0, 5))
        self.username_entry = ctk.CTkEntry(center_frame, width=250, height=35, font=ctk.CTkFont(size=14))
        self.username_entry.pack(pady=5)
        
        ctk.CTkLabel(center_frame, text="Password:", font=ctk.CTkFont(size=14)).pack(pady=(15, 5))
        self.password_entry = ctk.CTkEntry(center_frame, width=250, height=35, font=ctk.CTkFont(size=14), show="*")
        self.password_entry.pack(pady=5)
        
        self.error_label = ctk.CTkLabel(center_frame, text="", text_color="red", font=ctk.CTkFont(size=12))
        self.error_label.pack(pady=(10, 5))
        
        buttons_frame = ctk.CTkFrame(center_frame, fg_color="transparent")
        buttons_frame.pack(pady=20)
        
        ctk.CTkButton(buttons_frame, text="Login", width=100, height=35, 
                     command=self.login, font=ctk.CTkFont(size=14)).pack(side="left", padx=(0, 15))
        
        ctk.CTkButton(buttons_frame, text="Register", width=100, height=35,
                     command=self.register, font=ctk.CTkFont(size=14)).pack(side="left", padx=(15, 0))
        
        self.username_entry.focus()
        self.root.bind("<Return>", lambda event: self.login())
        
    def create_main_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()
            
        main_frame = ctk.CTkFrame(self.root)
        main_frame.pack(expand=True, fill="both", padx=20, pady=20)
        
        header_frame = ctk.CTkFrame(main_frame, fg_color="transparent")
        header_frame.pack(fill="x", padx=20, pady=(20, 10))
        
        ctk.CTkLabel(header_frame, text=f"Welcome, {self.current_user or 'User'}!", 
                    font=ctk.CTkFont(size=20, weight="bold")).pack(side="left")
        
        ctk.CTkButton(header_frame, text="Logout", width=80, height=30,
                     command=self.logout, font=ctk.CTkFont(size=12)).pack(side="right")
        
        tabview = ctk.CTkTabview(main_frame)
        tabview.pack(expand=True, fill="both", padx=20, pady=(10, 20))
        
        tabview.add("Dashboard")
        tabview.add("Add Yamantau")
        tabview.add("View/Edit Yamantau")
        tabview.add("Chat")
        
        self.create_dashboard_tab(tabview.tab("Dashboard"))
        self.create_add_yamantau_tab(tabview.tab("Add Yamantau"))
        self.create_view_yamantau_tab(tabview.tab("View/Edit Yamantau"))
        self.create_chat_tab(tabview.tab("Chat"))
        
    def create_dashboard_tab(self, parent):
        ctk.CTkLabel(parent, text="System Dashboard", font=ctk.CTkFont(size=20, weight="bold")).pack(pady=20)
        
        stats_frame = ctk.CTkFrame(parent)
        stats_frame.pack(fill="x", padx=50, pady=10)
        
        yamantau_count = 0
        if self.yamantau_manager:
            success, yamantau_list = self.yamantau_manager.get_all_yamantau()
            yamantau_count = len(yamantau_list) if success else 0
        
        stats_container = ctk.CTkFrame(stats_frame, fg_color="transparent")
        stats_container.pack(expand=True, fill="both", pady=20)
        
        yamantau_frame = ctk.CTkFrame(stats_container)
        yamantau_frame.pack(side="left", padx=20, expand=True, fill="both")
        ctk.CTkLabel(yamantau_frame, text="Total Yamantau", font=ctk.CTkFont(size=16)).pack(pady=(10, 5))
        ctk.CTkLabel(yamantau_frame, text=str(yamantau_count), font=ctk.CTkFont(size=24, weight="bold")).pack(pady=5)
        
        status_frame = ctk.CTkFrame(stats_container)
        status_frame.pack(side="left", padx=20, expand=True, fill="both")
        ctk.CTkLabel(status_frame, text="System Status", font=ctk.CTkFont(size=16)).pack(pady=(10, 5))
        ctk.CTkLabel(status_frame, text="Operational", text_color="green", font=ctk.CTkFont(size=24, weight="bold")).pack(pady=5)
        
        user_frame = ctk.CTkFrame(stats_container)
        user_frame.pack(side="left", padx=20, expand=True, fill="both")
        ctk.CTkLabel(user_frame, text="Current User", font=ctk.CTkFont(size=16)).pack(pady=(10, 5))
        ctk.CTkLabel(user_frame, text=self.current_user or "N/A", font=ctk.CTkFont(size=14)).pack(pady=5)
        
    def create_add_yamantau_tab(self, parent):
        ctk.CTkLabel(parent, text="Add New Yamantau", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        
        form_container = ctk.CTkFrame(parent)
        form_container.pack(expand=True, fill="both", padx=100, pady=10)
        
        form_frame = ctk.CTkFrame(form_container, fg_color="transparent")
        form_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(form_frame, text="First Name:", font=ctk.CTkFont(size=14)).grid(row=0, column=0, sticky="w", pady=10, padx=(20, 10))
        self.first_name_entry = ctk.CTkEntry(form_frame, width=250, height=35, font=ctk.CTkFont(size=14))
        self.first_name_entry.grid(row=0, column=1, pady=10, padx=(10, 20))
        
        ctk.CTkLabel(form_frame, text="Last Name:", font=ctk.CTkFont(size=14)).grid(row=1, column=0, sticky="w", pady=10, padx=(20, 10))
        self.last_name_entry = ctk.CTkEntry(form_frame, width=250, height=35, font=ctk.CTkFont(size=14))
        self.last_name_entry.grid(row=1, column=1, pady=10, padx=(10, 20))
        
        ctk.CTkLabel(form_frame, text="Nickname:", font=ctk.CTkFont(size=14)).grid(row=2, column=0, sticky="w", pady=10, padx=(20, 10))
        self.yamantau_username_entry = ctk.CTkEntry(form_frame, width=250, height=35, font=ctk.CTkFont(size=14))
        self.yamantau_username_entry.grid(row=2, column=1, pady=10, padx=(10, 20))
        
        ctk.CTkLabel(form_frame, text="Yamantau Code:", font=ctk.CTkFont(size=14)).grid(row=3, column=0, sticky="w", pady=10, padx=(20, 10))
        self.yamantau_code_entry = ctk.CTkEntry(form_frame, width=250, height=35, font=ctk.CTkFont(size=14))
        self.yamantau_code_entry.grid(row=3, column=1, pady=10, padx=(10, 20))
        
        ctk.CTkLabel(form_frame, text="Birth Date (YYYY-MM-DD):", font=ctk.CTkFont(size=14)).grid(row=4, column=0, sticky="w", pady=10, padx=(20, 10))
        self.birth_date_entry = ctk.CTkEntry(form_frame, width=250, height=35, font=ctk.CTkFont(size=14))
        self.birth_date_entry.grid(row=4, column=1, pady=10, padx=(10, 20))
        
        self.add_yamantau_error_label = ctk.CTkLabel(form_frame, text="", text_color="red", font=ctk.CTkFont(size=12))
        self.add_yamantau_error_label.grid(row=5, column=0, columnspan=2, pady=5)
        
        ctk.CTkButton(form_frame, text="Add Yamantau", width=150, height=40,
                     command=self.add_yamantau, font=ctk.CTkFont(size=14)).grid(row=6, column=0, columnspan=2, pady=20)
        
        self.first_name_entry.focus()
        
    def create_view_yamantau_tab(self, parent):
        search_frame = ctk.CTkFrame(parent)
        search_frame.pack(fill="x", padx=20, pady=20)
        
        ctk.CTkLabel(search_frame, text="Search:", font=ctk.CTkFont(size=14)).pack(side="left", padx=(10, 10))
        self.search_entry = ctk.CTkEntry(search_frame, width=200, height=35, font=ctk.CTkFont(size=14))
        self.search_entry.pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(search_frame, text="Search", width=80, height=35,
                     command=self.search_yamantau, font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(search_frame, text="Show All", width=80, height=35,
                     command=self.load_yamantau, font=ctk.CTkFont(size=12)).pack(side="left")
        
        self.view_yamantau_error_label = ctk.CTkLabel(search_frame, text="", text_color="red", font=ctk.CTkFont(size=12))
        self.view_yamantau_error_label.pack(side="right", padx=10)
        
        tree_frame = ctk.CTkFrame(parent)
        tree_frame.pack(expand=True, fill="both", padx=20, pady=(0, 20))
        
        self.yamantau_tree = ttk.Treeview(tree_frame, columns=("ID", "First Name", "Last Name", "Nickname", "Code", "Birth Date", "Registration Date"), show="headings")
        
        self.yamantau_tree.heading("ID", text="ID")
        self.yamantau_tree.heading("First Name", text="First Name")
        self.yamantau_tree.heading("Last Name", text="Last Name")
        self.yamantau_tree.heading("Nickname", text="Nickname")
        self.yamantau_tree.heading("Code", text="Yamantau Code")
        self.yamantau_tree.heading("Birth Date", text="Birth Date")
        self.yamantau_tree.heading("Registration Date", text="Registration Date")
        
        self.yamantau_tree.column("ID", width=30)
        self.yamantau_tree.column("First Name", width=100)
        self.yamantau_tree.column("Last Name", width=100)
        self.yamantau_tree.column("Nickname", width=100)
        self.yamantau_tree.column("Code", width=100)
        self.yamantau_tree.column("Birth Date", width=100)
        self.yamantau_tree.column("Registration Date", width=120)
        
        v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.yamantau_tree.yview)
        h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=self.yamantau_tree.xview)
        self.yamantau_tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
        
        self.yamantau_tree.pack(side="left", expand=True, fill="both")
        v_scrollbar.pack(side="right", fill="y")
        h_scrollbar.pack(side="bottom", fill="x")
        
        buttons_frame = ctk.CTkFrame(parent, fg_color="transparent")
        buttons_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        ctk.CTkButton(buttons_frame, text="Refresh", width=100, height=35,
                     command=self.load_yamantau, font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(buttons_frame, text="Edit Selected", width=100, height=35,
                     command=self.edit_yamantau, font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 10))
        
        ctk.CTkButton(buttons_frame, text="Delete Selected", width=120, height=35,
                     command=self.delete_yamantau, font=ctk.CTkFont(size=12)).pack(side="left")
        
        self.load_yamantau()
        
    def edit_yamantau(self):
        if not self.yamantau_manager:
            messagebox.showwarning("Warning", "Please login first")
            return
            
        selected = self.yamantau_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select a yamantau to edit")
            return
            
        item = self.yamantau_tree.item(selected[0])
        values = item["values"]
        self.create_edit_yamantau_window(values)
        
    def create_edit_yamantau_window(self, yamantau_data):
        edit_window = ctk.CTkToplevel(self.root)
        edit_window.title("Edit Yamantau")
        edit_window.geometry("400x450")
        edit_window.transient(self.root)
        edit_window.grab_set()
        
        yamantau_id = yamantau_data[0]
        
        ctk.CTkLabel(edit_window, text="Edit Yamantau", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        
        form_frame = ctk.CTkFrame(edit_window)
        form_frame.pack(expand=True, fill="both", padx=20, pady=10)
        
        ctk.CTkLabel(form_frame, text="First Name:", font=ctk.CTkFont(size=14)).grid(row=0, column=0, sticky="w", pady=10, padx=(20, 10))
        first_name_entry = ctk.CTkEntry(form_frame, width=200, height=35, font=ctk.CTkFont(size=14))
        first_name_entry.grid(row=0, column=1, pady=10, padx=(10, 20))
        first_name_entry.insert(0, yamantau_data[1])
        
        ctk.CTkLabel(form_frame, text="Last Name:", font=ctk.CTkFont(size=14)).grid(row=1, column=0, sticky="w", pady=10, padx=(20, 10))
        last_name_entry = ctk.CTkEntry(form_frame, width=200, height=35, font=ctk.CTkFont(size=14))
        last_name_entry.grid(row=1, column=1, pady=10, padx=(10, 20))
        last_name_entry.insert(0, yamantau_data[2])
        
        ctk.CTkLabel(form_frame, text="Nickname:", font=ctk.CTkFont(size=14)).grid(row=2, column=0, sticky="w", pady=10, padx=(20, 10))
        username_entry = ctk.CTkEntry(form_frame, width=200, height=35, font=ctk.CTkFont(size=14))
        username_entry.grid(row=2, column=1, pady=10, padx=(10, 20))
        username_entry.insert(0, yamantau_data[3])
        
        ctk.CTkLabel(form_frame, text="Yamantau Code:", font=ctk.CTkFont(size=14)).grid(row=3, column=0, sticky="w", pady=10, padx=(20, 10))
        yamantau_code_entry = ctk.CTkEntry(form_frame, width=200, height=35, font=ctk.CTkFont(size=14))
        yamantau_code_entry.grid(row=3, column=1, pady=10, padx=(10, 20))
        yamantau_code_entry.insert(0, yamantau_data[4])
        
        ctk.CTkLabel(form_frame, text="Birth Date:", font=ctk.CTkFont(size=14)).grid(row=4, column=0, sticky="w", pady=10, padx=(20, 10))
        birth_date_entry = ctk.CTkEntry(form_frame, width=200, height=35, font=ctk.CTkFont(size=14))
        birth_date_entry.grid(row=4, column=1, pady=10, padx=(10, 20))
        birth_date_entry.insert(0, yamantau_data[5])
        
        error_label = ctk.CTkLabel(form_frame, text="", text_color="red", font=ctk.CTkFont(size=12))
        error_label.grid(row=5, column=0, columnspan=2, pady=5)
        
        def save_changes():
            if not self.yamantau_manager:
                error_label.configure(text="Session expired")
                return
                
            first_name = first_name_entry.get().strip()
            last_name = last_name_entry.get().strip()
            username = username_entry.get().strip()
            yamantau_code = yamantau_code_entry.get().strip()
            birth_date = birth_date_entry.get().strip()
            
            if not all([first_name, last_name, username, yamantau_code, birth_date]):
                error_label.configure(text="Fill all fields")
                return
                
            try:
                datetime.strptime(birth_date, "%Y-%m-%d")
            except ValueError:
                error_label.configure(text="Invalid date format")
                return
                
            success, message = self.yamantau_manager.update_yamantau(
                yamantau_id, first_name, last_name, username, yamantau_code, birth_date
            )
            
            if success:
                messagebox.showinfo("Success", message)
                edit_window.destroy()
                self.load_yamantau()
            else:
                error_label.configure(text=message)
        
        ctk.CTkButton(form_frame, text="Save Changes", width=120, height=35,
                     command=save_changes, font=ctk.CTkFont(size=14)).grid(row=6, column=0, columnspan=2, pady=20)
        
    def create_chat_tab(self, parent):
        self.chat_username = self.current_user or "Anonymous"
        
        ctk.CTkLabel(parent, text="Chat Room", font=ctk.CTkFont(size=18, weight="bold")).pack(pady=20)
        
        status_frame = ctk.CTkFrame(parent)
        status_frame.pack(fill="x", padx=20, pady=(0, 10))
        
        self.chat_status_label = ctk.CTkLabel(status_frame, text="● Connecting...", 
                                             text_color="yellow", font=ctk.CTkFont(size=12))
        self.chat_status_label.pack(side="left", padx=10, pady=5)
        
        chat_frame = ctk.CTkFrame(parent)
        chat_frame.pack(expand=True, fill="both", padx=20, pady=10)
        
        self.chat_display = ctk.CTkTextbox(chat_frame, width=500, height=300, 
                                          font=ctk.CTkFont(size=12), wrap="word")
        self.chat_display.pack(expand=True, fill="both", padx=10, pady=10)
        self.chat_display.configure(state="disabled")
        
        input_frame = ctk.CTkFrame(parent)
        input_frame.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(input_frame, text="Message:", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=10, pady=(5, 0))
        self.message_entry = ctk.CTkEntry(input_frame, width=400, height=35, 
                                         font=ctk.CTkFont(size=12))
        self.message_entry.pack(side="left", fill="x", expand=True, padx=10, pady=10)
        
        ctk.CTkButton(input_frame, text="Send", width=100, height=35,
                     command=self.send_chat_message, font=ctk.CTkFont(size=12),
                     fg_color="#2e7d32", hover_color="#1b5e20").pack(side="right", padx=10, pady=10)
        
        self.message_entry.bind("<Return>", lambda event: self.send_chat_message())
        
        self.start_chat_receiver()
        self.connect_to_server()
        self.check_msg_queue()
    
    def check_msg_queue(self):
        try:
            while True:
                msg_type, data = self.msg_queue.get_nowait()
                
                if msg_type == "chat":
                    self.display_chat_message(data['username'], data['text'], data['type'])
                elif msg_type == "status":
                    self.update_chat_status(data['text'], data['color'])
                    
                self.msg_queue.task_done()
        except queue.Empty:
            pass
        finally:
            if not self.chat_stop_receiver:
                self.root.after(100, self.check_msg_queue)

    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((CONFIG['chat_host'], CONFIG['chat_port']))
            self.update_chat_status("● Connected", "green")
            logger.info("Connected to chat server")
        except Exception as e:
            self.update_chat_status("● Connection Failed", "red")
            self.display_chat_message("System", f"Could not connect: {str(e)}", "system")
            logger.error(f"Chat connection failed: {e}")

    def send_chat_message(self, is_system=False, text=None):
        if text is None:
            text = self.message_entry.get().strip()
        
        if not text:
            return
            
        if not self.client_socket:
            self.display_chat_message("System", "Not connected", "system")
            return

        try:
            msg = {
                "username": self.chat_username,
                "text": text,
                "timestamp": time.time()
            }
            
            msg_json = json.dumps(msg)
            self.client_socket.sendall(msg_json.encode('utf-8'))
            
            if not is_system:
                self.message_entry.delete(0, "end")
        except Exception as e:
            self.display_chat_message("System", f"Error: {str(e)}", "system")
            self.update_chat_status("● Error", "red")
            self.client_socket = None
            logger.error(f"Send message error: {e}")
    
    def update_chat_status(self, text, color):
        if threading.current_thread() != threading.main_thread():
            self.msg_queue.put(("status", {"text": text, "color": color}))
        else:
            self.chat_status_label.configure(text=text, text_color=color)
    
    def display_chat_message(self, username, text, msg_type="user"):
        if threading.current_thread() != threading.main_thread():
            self.msg_queue.put(("chat", {"username": username, "text": text, "type": msg_type}))
            return

        self.chat_display.configure(state="normal")
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if msg_type == "system":
            self.chat_display.insert("end", f"[{timestamp}] {username}: {text}\n", "system")
            self.chat_display._textbox.tag_config("system", foreground="yellow", font=("Arial", 12, "italic"))
        elif username == self.chat_username:
            self.chat_display.insert("end", f"[{timestamp}] {username} (You): {text}\n", "own")
            self.chat_display._textbox.tag_config("own", foreground="lightgreen", font=("Arial", 12, "bold"))
        else:
            self.chat_display.insert("end", f"[{timestamp}] {username}: {text}\n")
        
        self.chat_display.see("end")
        self.chat_display.configure(state="disabled")
    
    def chat_receiver(self):
        while not self.chat_stop_receiver:
            if self.client_socket:
                try:
                    data = self.client_socket.recv(4096)
                    if not data:
                        self.update_chat_status("● Disconnected", "red")
                        self.client_socket.close()
                        self.client_socket = None
                        continue
                        
                    msg_str = data.decode('utf-8')
                    try:
                        msg = json.loads(msg_str)
                        self.msg_queue.put(("chat", {
                            "username": msg['username'], 
                            "text": msg['text'], 
                            "type": "own" if msg['username'] == self.chat_username else "user"
                        }))
                    except json.JSONDecodeError:
                        pass
                        
                except Exception as e:
                    if not self.chat_stop_receiver:
                        logger.error(f"Receive error: {e}")
                        self.update_chat_status("● Error", "red")
                        time.sleep(1)
            else:
                time.sleep(1)
    
    def start_chat_receiver(self):
        self.chat_stop_receiver = False
        self.chat_receiver_thread = threading.Thread(target=self.chat_receiver, daemon=True)
        self.chat_receiver_thread.start()
    
    def stop_chat_receiver(self):
        self.chat_stop_receiver = True
        if self.client_socket:
            try:
                self.client_socket.close()
            except:
                pass
    
    def login(self):
        try:
            username = self.username_entry.get().strip()
            password = self.password_entry.get()
        except Exception:
            return
        
        self.error_label.configure(text="")
        
        if not username or not password:
            self.error_label.configure(text="Enter username and password")
            return
            
        success, message = self.auth_manager.login_user(username, password)
        
        if success:
            self.current_user = username
            self.yamantau_manager = YamantauManager(self.auth_manager, self.current_user)
            self.create_main_screen()
        else:
            self.error_label.configure(text=message)
            
    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        self.error_label.configure(text="")
        
        if not username or not password:
            self.error_label.configure(text="Enter username and password")
            return
            
        if len(password) < CONFIG['min_password_length']:
            self.error_label.configure(text=f"Password must be at least {CONFIG['min_password_length']} characters")
            return
            
        success, message = self.auth_manager.register_user(username, password)
        
        if success:
            self.error_label.configure(text="Registration successful! You can now login.", text_color="green")
        else:
            self.error_label.configure(text=message, text_color="red")
            
    def logout(self):
        self.stop_chat_receiver()
        self.current_user = None
        self.yamantau_manager = None
        self.create_login_screen()
        
    def add_yamantau(self):
        if not self.yamantau_manager:
            self.add_yamantau_error_label.configure(text="Please login first")
            return
            
        first_name = self.first_name_entry.get().strip()
        last_name = self.last_name_entry.get().strip()
        username = self.yamantau_username_entry.get().strip()
        yamantau_code = self.yamantau_code_entry.get().strip()
        birth_date = self.birth_date_entry.get().strip()
        
        self.add_yamantau_error_label.configure(text="")
        
        if not all([first_name, last_name, username, yamantau_code, birth_date]):
            self.add_yamantau_error_label.configure(text="Fill all fields")
            return
            
        try:
            datetime.strptime(birth_date, "%Y-%m-%d")
        except ValueError:
            self.add_yamantau_error_label.configure(text="Invalid date format (YYYY-MM-DD)")
            return
            
        success, message = self.yamantau_manager.add_yamantau(
            first_name, last_name, username, yamantau_code, birth_date
        )
        
        if success:
            self.add_yamantau_error_label.configure(text="Yamantau added!", text_color="green")
            self.root.after(1500, self.clear_yamantau_form)
            self.load_yamantau()
        else:
            self.add_yamantau_error_label.configure(text=message, text_color="red")
            
    def clear_yamantau_form(self):
        self.first_name_entry.delete(0, "end")
        self.last_name_entry.delete(0, "end")
        self.yamantau_username_entry.delete(0, "end")
        self.yamantau_code_entry.delete(0, "end")
        self.birth_date_entry.delete(0, "end")
        self.add_yamantau_error_label.configure(text="")
        
    def load_yamantau(self):
        if not self.yamantau_manager:
            return
            
        for item in self.yamantau_tree.get_children():
            self.yamantau_tree.delete(item)
            
        success, yamantau_list = self.yamantau_manager.get_all_yamantau()
        
        if success:
            for i, yamantau in enumerate(yamantau_list):
                if isinstance(yamantau, dict):
                    self.yamantau_tree.insert("", "end", values=(
                        i,
                        yamantau.get("first_name", ""),
                        yamantau.get("last_name", ""),
                        yamantau.get("username", ""),
                        yamantau.get("yamantau_code", ""),
                        yamantau.get("birth_date", ""),
                        yamantau.get("registration_date", "")
                    ))
            self.view_yamantau_error_label.configure(text="")
        else:
            self.view_yamantau_error_label.configure(text=f"Failed: {yamantau_list}")
            
    def search_yamantau(self):
        if not self.yamantau_manager:
            return
            
        query = self.search_entry.get().strip()
        if not query:
            self.load_yamantau()
            return
            
        for item in self.yamantau_tree.get_children():
            self.yamantau_tree.delete(item)
            
        success, results = self.yamantau_manager.search_yamantau(query)
        
        if success:
            for i, yamantau in enumerate(results):
                if isinstance(yamantau, dict):
                    self.yamantau_tree.insert("", "end", values=(
                        i,
                        yamantau.get("first_name", ""),
                        yamantau.get("last_name", ""),
                        yamantau.get("username", ""),
                        yamantau.get("yamantau_code", ""),
                        yamantau.get("birth_date", ""),
                        yamantau.get("registration_date", "")
                    ))
            self.view_yamantau_error_label.configure(text="")
        else:
            self.view_yamantau_error_label.configure(text=f"Search failed: {results}")
            
    def delete_yamantau(self):
        if not self.yamantau_manager:
            messagebox.showwarning("Warning", "Please login first")
            return
            
        selected = self.yamantau_tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Select a yamantau to delete")
            return
            
        item = self.yamantau_tree.item(selected[0])
        yamantau_id = item["values"][0]
        
        result = messagebox.askyesno("Confirm", "Delete this yamantau?")
        if result:
            success, message = self.yamantau_manager.delete_yamantau(yamantau_id)
            
            if success:
                messagebox.showinfo("Success", message)
                self.load_yamantau()
            else:
                messagebox.showerror("Error", message)
                
    def run(self):
        try:
            self.root.mainloop()
        finally:
            if hasattr(self, 'chat_server'):
                self.chat_server.stop()


def main():
    app = COSZ1App()
    app.run()


if __name__ == "__main__":
    main()
