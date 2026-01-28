# Job Board Platform

A **role-based job board platform** built with **Flask** and **MySQL**.  
This platform allows **candidates** to browse and apply for jobs, and **organizations** to post job openings and manage applications. It is designed with a clean and user-friendly interface using **Bootstrap**.



## Features

- Role-based login (Candidate / Organization)
- Candidates can browse jobs and submit applications
- Organizations can post jobs and review applications
- CV uploads and file management
- Email feedback for applicants
- Responsive UI with Bootstrap
- Secure handling of sensitive files using `.gitignore`



## Installation

1. **Clone the repository**

```bash
git clone https://github.com/AssaniNdaka/job-board.git
cd job-board

2. ## Create a virtual environment

python -m venv venv


3. ## Activate the virtual environment
**Windows

venv\Scripts\activate

** Mac/Linux

source venv/bin/activate

4. ## Install dependencies

pip install -r requirements.txt


5. ## Run the application

python app.py

6. ## Open your browser and go to:

http://127.0.0.1:5000/


7. ## Folder Structure

job-board/
├─ app.py                  # Main Flask application
├─ config.py               # Optional: configuration for database and secrets
├─ requirements.txt        # Python dependencies
├─ .gitignore
├─ README.md
├─ templates/              # HTML templates (login.html, base.html, etc.)
├─ static/                 # CSS, JS, images
└─ uploads/                # User CV uploads


8. ## Author

Assani Ndaka
GitHub: https://github.com/AssaniNdaka

 
