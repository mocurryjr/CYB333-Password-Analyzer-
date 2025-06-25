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

class SocketClient:
    def __init__(self, host: str = 'localhost', port: int = 5000):
        """
        Initialize the socket client.
        
        Args:
            host (str): Server host address
            port (int): Server port number
        """
        self.host = host
        self.port = port
        self.socket: Optional[socket.socket] = None

    def connect(self) -> None:
        """Connect to the server."""
        try:
            # Create a TCP/IP socket
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Connect to the server
            self.socket.connect((self.host, self.port))
            logger.info(f"Connected to server at {self.host}:{self.port}")
            
        except ConnectionRefusedError:
            logger.error("Connection refused. Make sure the server is running.")
            raise
        except Exception as e:
            logger.error(f"Connection error: {e}")
            raise

    def send_message(self, message: str) -> str:
        """
        Send a message to the server and receive the response.
        
        Args:
            message (str): Message to send to the server
            
        Returns:
            str: Server's response
        """
        try:
            # Send the message
            self.socket.sendall(message.encode('utf-8'))
            logger.info(f"Sent to server: {message}")
            
            # Receive the response
            response = self.socket.recv(1024).decode('utf-8')
            logger.info(f"Received from server: {response}")
            
            return response
            
        except Exception as e:
            logger.error(f"Error in communication: {e}")
            raise

    def close(self) -> None:
        """Close the connection."""
        if self.socket:
            try:
                self.socket.close()
                logger.info("Connection closed")
            except Exception as e:
                logger.error(f"Error closing connection: {e}")
            finally:
                self.socket = None

def main():
    """Main function to run the client."""
    client = None
    try:
        # Create and connect client
        client = SocketClient()
        client.connect()
        
        # Interactive message loop
        while True:
            try:
                # Get message from user
                message = input("Enter message (or 'quit' to exit): ")
                
                if message.lower() == 'quit':
                    break
                
                # Send message and get response
                response = client.send_message(message)
                print(f"Server response: {response}")
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"Error: {e}")
                break
                
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        sys.exit(1)
    finally:
        if client:
            client.close()

if __name__ == "__main__":
    main() 