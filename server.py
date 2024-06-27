from PySide6.QtCore import QUrl
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QTcpSocket, QHostAddress, QTcpServer, \
    QNetworkReply
from PySide6.QtWebSockets import QWebSocket, QWebSocketServer
from PySide6.QtWidgets import QMainWindow, QVBoxLayout, QTextEdit, QLineEdit, QPushButton, QWidget


class Server(QMainWindow):
    def __init__(self):
        super().__init__()
        self.http_connection: QTcpSocket = None
        self.setWindowTitle("WebSocket Server")
        self.setGeometry(100, 100, 600, 400)

        self.server = None
        self.connection: QWebSocket = None
        self.http_server = None

        layout = QVBoxLayout()

        self.incoming_messages = QTextEdit()
        self.incoming_messages.setReadOnly(True)
        layout.addWidget(self.incoming_messages)

        self.start_button = QPushButton("Start Server")
        self.start_button.clicked.connect(self.start_server)
        layout.addWidget(self.start_button)

        # Set layout
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.server = QWebSocketServer("TestServer", QWebSocketServer.NonSecureMode, None)
        self.server.newConnection.connect(self.on_new_connection)
        self.server.closed.connect(self.on_disconnected)
        self.server.serverError.connect(self.on_disconnected)
        self.server.setMaxPendingConnections(1)

        self.http_server = QTcpServer()
        self.http_server.newConnection.connect(self.on_new_http_connection)
        self.network_manager = QNetworkAccessManager()

    def start_server(self):
        print("Starting server...")
        if self.server:
            self.server.listen(QHostAddress.LocalHost, 8765)
            self.start_button.setText("Server started...")
            self.start_button.setEnabled(False)
        if self.http_server:
            self.http_server.listen(QHostAddress.LocalHost, 8766)
            self.start_button.setText("Server started...")
            self.start_button.setEnabled(False)

    def on_message_received(self, message):
        request = self.connection.readAll()
        print(request)
        self.incoming_messages.append(message)
        self.connection.sendTextMessage(message)

    def on_new_http_connection(self):
        self.incoming_messages.append("New http connection")
        self.http_connection = self.http_server.nextPendingConnection()
        self.http_connection.readyRead.connect(self.on_http_message_received)

    def on_http_message_received(self):
        request = {}
        while self.http_connection.bytesAvailable() > 0:
            data = self.http_connection.readLine().data().decode().strip().split(": ")
            if len(data) == 2:
                key, val = data[0], data[1]
                request[key] = val
            elif len(data) == 1:
                request["Single data"] = data[0]
        for key, val in request.items():
            self.incoming_messages.append(f"{key}: {val}")
        self.send_http_response()

    def send_http_response(self):
        m_str = "Message received"
        response = (f"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {len(m_str)}\r\n\r\n{m_str}"
        )
        self.http_connection.write(response.encode())
        self.http_connection.flush()
        self.http_connection.disconnectFromHost()

    def closeEvent(self, event):
        if self.server:
            self.server.close()
        event.accept()

    def on_new_connection(self):
        print("New connection")
        self.connection = self.server.nextPendingConnection()
        self.connection.textMessageReceived.connect(self.on_message_received)
        self.incoming_messages.append("New connection")

    def on_disconnected(self):
        print("Disconnected")
        self.connection = None
        self.incoming_messages.append("Disconnected")
