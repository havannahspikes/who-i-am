# Who I Am


Simple Flask profile site: /alpha (auth), /life (public profile + CV upload), /heartbeat (admin).


## Run locally


1. python -m venv venv
2. source venv/bin/activate # or venv\Scripts\activate on Windows
3. pip install -r requirements.txt
4. python app.py


## Deploy to Render


1. Create a GitHub repo and push this project.
2. Create a new Web Service on Render, connect to the repo.
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app`
5. Set `SECRET_KEY` in environment variables.


**Note:** Uploaded CV files are saved to `uploads/`. On some hosts the filesystem may be ephemeral — for persistent storage, use an S3 bucket or link CVs to GitHub/drive.