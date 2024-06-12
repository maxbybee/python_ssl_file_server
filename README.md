# Python SSL File Server

This project is a simple SSL file server implemented in Python. It allows for basic authentication and file uploads via an HTML form. The server generates a self-signed SSL certificate for secure communication.

## Features
- HTTPS support with self-signed SSL certificates
- Basic authentication
- File upload via HTML form

## Prerequisites

Before you begin, ensure you have the following installed:
- Python 3.x
- `pip` (Python package installer)

## Installation

1. **Clone the repository:**
    ```sh
    git clone https://github.com/maxbybee/python_ssl_file_server.git
    cd python_ssl_file_server
    ```

2. **Install the required Python packages:**
    ```sh
    pip install cryptography
    ```

## Usage

1. **Run the server:**
    ```sh
    python python_ssl_file_server.py
    ```

2. **Access the server:**
    Open your web browser and navigate to `https://localhost:8080`. The server will display the username and password required for authentication when it starts.

3. **Upload a file:**
    - Use the provided HTML form to select and upload a file.

## Code Overview

### `python_ssl_file_server.py`

This script sets up a simple HTTPS server with basic authentication and file upload capability. 

- **HTTP Server Handler:**
    - `SimpleHTTPRequestHandler`: Handles GET and POST requests, including authentication and file upload logic.

- **Certificate Generation:**
    - `generate_self_signed_cert`: Creates a self-signed SSL certificate if one does not already exist.

- **Credential Generation:**
    - `generate_credentials`: Generates random username and password for basic authentication.

- **Server Setup and Execution:**
    - `run`: Configures and starts the HTTP server with SSL support.

## Example

Upon running the script, the server will output credentials:
```
Username: abc12345
Password: def67890
(example credentials, actual credentials will be different!)

```



Navigate to `https://localhost:8080` and enter these credentials when prompted. You can then use the provided form to upload files securely.

## Shutting Down

To gracefully shut down the server, use `Ctrl+C` in the terminal. The server has a signal handler to close gracefully.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
