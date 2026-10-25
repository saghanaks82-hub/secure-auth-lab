# Secure Authentication Lab

## Project Overview
The Secure Authentication Lab is a beginner-friendly cybersecurity project that demonstrates how to build a web application with safer user authentication.

## Features
- Secure password hashing using Werkzeug.
- Server-side input validation.
- Login rate limiting to reduce repeated login attempts.
- Generic authentication error messages.
- HTTP-only and SameSite cookie settings.
- Session expiry configuration.
- CSRF token checks for form submissions.
- Logout functionality and protected dashboard access.
- SQLite database for user information.

## Technologies Used
- Python
- Flask
- SQLite
- Flask-Limiter
- Werkzeug
- HTML

## How to Run
1. Install Python.
2. Install the dependencies:

   `python -m pip install Flask Flask-Limiter`

3. Run the application:

   `python app.py`

4. Open `http://127.0.0.1:5000` in your browser.

## Testing
The project was checked for registration and login functionality, logout behaviour, dashboard access, and login rate limiting.

## Security Notes
This project is intended for local learning and demonstration. Before deployment, configure a strong secret key, use HTTPS, enable secure cookies, and review production security requirements.

## Author
Student Cybersecurity Project
