import sys

from PySide6.QtWidgets import QApplication

from client import Client
from server import Server

if __name__ == "__main__":
    app = QApplication(sys.argv)
    server = Server()
    server.show()
    client = Client()
    client.show()
    sys.exit(app.exec())
