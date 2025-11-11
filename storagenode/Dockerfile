# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app


COPY storage_node.py .

# Expose ports for storage nodes
EXPOSE 5001-5003

# Define the entry point for the container.
# This makes the container run "python <command>"
ENTRYPOINT ["python"]