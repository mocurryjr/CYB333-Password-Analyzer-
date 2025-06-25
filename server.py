import socket
import sys
import logging
from typing import Optional

# Configure logging for better debugging and monitoring
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SocketServer:
    def __init__(self, host: str = 'localhost', port: int = 5000):
        """
        Initialize the socket server.
        
        Args:
            host (str): Host address to bind the server to
            port (int): Port number to listen on
        """
        self.host = host
        self.port = port
        self.server_socket: Optional[socket.socket] = None
        self.client_socket: Optional[socket.socket] = None
        self.client_address: Optional[tuple] = None

    def start(self) -> None:
        """Start the server and listen for connections."""
        try:
            # Create a TCP/IP socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Allow port reuse to prevent "Address already in use" errors
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind the socket to the address
            self.server_socket.bind((self.host, self.port))
            
            # Listen for incoming connections
            self.server_socket.listen(1)
            logger.info(f"Server listening on {self.host}:{self.port}")
            
            while True:
                try:
                    # Wait for a connection
                    self.client_socket, self.client_address = self.server_socket.accept()
                    logger.info(f"Connected to client at {self.client_address}")
                    
                    # Handle client communication
                    self._handle_client()
                    
                except KeyboardInterrupt:
                    logger.info("Server shutdown requested")
                    break
                except Exception as e:
                    logger.error(f"Error handling client: {e}")
                finally:
                    self._cleanup_client()
                    
        except Exception as e:
            logger.error(f"Server error: {e}")
        finally:
            self._cleanup_server()

    def _handle_client(self) -> None:
        """Handle communication with the connected client."""
        try:
            while True:
                # Receive data from client
                data = self.client_socket.recv(1024)
                if not data:
                    logger.info("Client disconnected")
                    break
                
                # Decode and process the message
                message = data.decode('utf-8')
                logger.info(f"Received from client: {message}")
                
                # Send response back to client
                response = f"Server received: {message}"
                self.client_socket.sendall(response.encode('utf-8'))
                logger.info(f"Sent response to client: {response}")
                
        except ConnectionResetError:
            logger.warning("Client connection was reset")
        except Exception as e:
            logger.error(f"Error in client communication: {e}")

    def _cleanup_client(self) -> None:
        """Clean up client connection."""
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception as e:
                logger.error(f"Error closing client socket: {e}")
            finally:
                self.client_socket = None
                self.client_address = None

    def _cleanup_server(self) -> None:
        """Clean up server socket."""
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception as e:
                logger.error(f"Error closing server socket: {e}")
            finally:
                self.server_socket = None

def main():
    """Main function to run the server."""
    try:
        server = SocketServer()
        server.start()
    except KeyboardInterrupt:
        logger.info("Server shutdown by user")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 