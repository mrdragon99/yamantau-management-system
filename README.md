# yamantau-management-system
Yamantau Member Management System with GUI, Authentication and Chat
✨ Features 

     🔐 Secure Authentication with bcrypt password hashing
     👥 Complete Yamantau Member Management (CRUD operations)
     💬 Integrated TCP Chat with multi-client server support
     🎨 Modern Dark Mode UI using CustomTkinter
     📊 Dashboard with Real-time Statistics
     🔍 Advanced Search with intelligent ranking
     📝 Comprehensive Logging of all operations
     🛡️ User Data Isolation - Each user has their own member database
     

🚀 Quick Start 
Prerequisites 

     Python 3.8 or higher
     Git
Installation
# Clone the repository
git clone https://github.com/yourusername/yamantau-management-system.git
cd yamantau-management-system

# Install dependencies
pip install -r requirements.txt

# Run the application
python yamantau_app.py

First Time Setup 

    Launch the application 
    Click "Register" to create a new account 
    Enter username and password (minimum 6 characters) 
    Login with your credentials 

📖 Usage Guide 
Dashboard Member Management 

     Add: Create new member records with full details
     View: Complete member table with sorting options
     Edit: Update existing member information
     Delete: Remove members with confirmation dialog
     Search: Intelligent search across all member fields
     

Chat System 

     Real-time messaging between connected users
     Built-in TCP server architecture
     Message timestamps
     Connection status indicators
     

     View system statistics
     Total Yamantau members count
     System status indicators
     Recent members activity

📊 Data Structure 
User Account 
{
  "username": "string",
  "password_hash": "bcrypt_hash"
}
Yamantau Member
{
  "first_name": "string",
  "last_name": "string",
  "nickname": "string",
  "yamantau_code": "unique_id",
  "birth_date": "YYYY-MM-DD",
  "registration_date": "automatic_timestamp"
}
📁 Generated Files 

     users.json - User authentication database
     yamantau_<username>.json - Per-user member databases
     yamantau_system.log - Application activity logs
     

⚙️ Configuration 

Customize system behavior by modifying the CONFIG dictionary in yamantau_app.py

CONFIG = {
    'chat_host': '127.0.0.1',      # Chat server host
    'chat_port': 5555,              # Chat server port
    'db_type': 'json',              # Database type
    'min_password_length': 6        # Minimum password length
}
🔧 Improvements Over Original 
Key Enhancements 

    Comprehensive Logging System - Full operation tracking 
    Centralized Configuration - CONFIG dictionary for easy management 
    Enhanced Error Handling - Robust error management and recovery 
    Code Optimization - Reduced redundancy and improved performance 
    Bug Fixes:
         Fixed member_manager → yamantau_manager references
         Improved chat thread management
         Enhanced input validation
         Better JSON corruption handling
          

🔒 Security Features 

     Passwords hashed with bcrypt (automatic salt generation)
     Input validation on all forms
     Secure socket connection handling
     User data separation and isolation
     Comprehensive logging for audit trails
     

🛠️ Troubleshooting 
Chat Connection Issues 

     Verify port 5555 is available
     Check firewall settings
     Review yamantau_system.log for error details
     

JSON File Corruption 

     Application automatically recreates corrupted files
     Manual backup of .json files recommended
     
bcrypt Installation Error
pip install --upgrade bcrypt

🗺️ Roadmap 

     SQLite database integration
     Data export/import (CSV, Excel)
     Statistical charts and graphs
     System notifications
     Automatic backup system
     Multi-language support
     Customizable themes
     

📄 License 

This project is licensed under the MIT License - see the LICENSE  file for details. 
👥 Author 

yamantau Team - Central Oblivion Security 
🤝 Contributing 

Contributions are welcome! Please feel free to submit a Pull Request. 
📞 Support 

For issues or questions: 

    Check the application logs in yamantau_system.log 
    Review existing Issues  
    Create a new issue with detailed information 




