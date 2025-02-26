# Use the official Python image from the Docker Hub
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install the dependencies
RUN apt-get update
RUN apt-get install -y curl
RUN pip install --no-cache-dir -r requirements.txt
RUN curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
RUN \. /root/.nvm/nvm.sh && nvm install 22 && npm install --global xo-cli
RUN ln -s /usr/bin/versions/node/v22.14.0/bin/node /usr/bin/node
RUN ln -s /usr/bin/versions/node/v22.14.0/lib/node_modules/xo-cli/index.mjs /usr/bin/xo-cli

# Copy the rest of the application code into the container
COPY . .

# Expose the port the app runs on
EXPOSE 8000

# Command to run the WSGI Gunicorn server
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--timeout", "600", "wsgi:app"]