# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app


COPY metadata_server.py .

# Expose ports for storage nodes
EXPOSE 6000

# Define the entry point for the container.
# This makes the container run "python <command>"
ENTRYPOINT ["python"]