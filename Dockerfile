# 1. Use a stable, lightweight modern Python base image
FROM python:3.12-slim

# 2. Set up the secure Hugging Face unprivileged user sandbox
RUN useradd -m -u 1000 user
USER user
ENV PATH="/home/user/.local/bin:$PATH"

# 3. Establish the container working directory inside the user home profile
WORKDIR /home/user/app

# 4. Set the Python path to the working directory so imports find your root files
ENV PYTHONPATH=/home/user/app

# 5. Copy your requirements and install them safely
COPY --chown=user ./requirements.txt requirements.txt
RUN pip install --no-cache-dir --upgrade -r requirements.txt

# 6. Copy all your files and subdirectories directly into the container app folder
COPY --chown=user . /home/user/app

# 7. 🔥 THE KEY: Direct Uvicorn to look inside the 'app' folder for 'server.py'
CMD ["uvicorn", "app.server:app", "--host", "0.0.0.0", "--port", "7860"]