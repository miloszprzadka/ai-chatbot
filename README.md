AI Chatbot with Authentication

This project is a full-stack AI-powered chatbot with user authentication, built using Flask (Python) for the backend and HTML, CSS, and JavaScript for the frontend. Users can register, log in, and chat with an AI assistant, with their conversation history stored securely in a PostgreSQL database.

Features

 • User Authentication – Register & login with encrypted passwords (bcrypt)
	
 • JWT Authentication – Secure access with JSON Web Tokens (JWT)
	
 • AI Chatbot – Communicate with an AI assistant
	
 • Message History – Users can view their previous conversations
	
 • Pagination – Efficient chat history loading
	
 • CORS Configuration – Secure API communication
	
 • Deployment-Ready – Deployed on Render (backend) & Vercel (frontend)

Tech Stack

Backend

  - Flask (Python)
  - PostgreSQL (Database)   
  - bcrypt (Password hashing)    
  - Flask-JWT-Extended (Token authentication)    
  - Flask-CORS (Cross-Origin Requests)
    
Frontend
  - HTML, CSS, JavaScript
  - Fetch API for API requests
    
Deployment
  - Backend: Hosted on Render
  - Frontend: Hosted on Vercel
