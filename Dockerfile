# Use a lightweight Python base image
FROM python:3.11-slim

# Set environment variables to prevent python from writing pyc files
# and to flush stdout/stderr immediately
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory inside the container
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the main script
COPY main.py .

# Set the entrypoint so arguments can be passed directly
ENTRYPOINT ["python", "main.py"]

# Default command if no arguments are provided
CMD ["serve"]
