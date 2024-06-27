from PySide6.QtCore import QUrl
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QAuthenticator
from PySide6.QtWebSockets import QWebSocket
from PySide6.QtWidgets import QMainWindow, QVBoxLayout, QTextEdit, QLineEdit, QPushButton, QWidget


class Client(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WebSocket Client")
        self.setGeometry(100, 100, 600, 400)

        self.websocket = QWebSocket()
        self.websocket.connected.connect(self.on_connected)
        self.websocket.disconnected.connect(self.on_disconnected)
        self.websocket.textMessageReceived.connect(self.on_message_received)

        self.manager: QNetworkAccessManager = QNetworkAccessManager()

        layout = QVBoxLayout()

        self.incoming_messages = QTextEdit()
        self.incoming_messages.setReadOnly(True)
        layout.addWidget(self.incoming_messages)

        self.message_input = QLineEdit()
        layout.addWidget(self.message_input)

        self.send_button = QPushButton("Send Message")
        self.send_button.setEnabled(False)
        self.send_button.clicked.connect(self.send_message)
        layout.addWidget(self.send_button)

        self.abb_button = QPushButton("Connect to ABB")
        self.abb_button.clicked.connect(self.try_abb_connect)
        layout.addWidget(self.abb_button)

        self.connect_button = QPushButton("Connect WebSocket")
        self.connect_button.clicked.connect(self.connect_websocket)
        layout.addWidget(self.connect_button)


        # Set layout
        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Authentication
        self.authenticator = None
        self.username = "Default User"
        self.password = "robotics"

    def authenticate(self, username: str, password: str):
        self.authenticator: QAuthenticator = QAuthenticator()
        self.authenticator.setOption("Digest", self.authenticator)
        self.authenticator.setUser(username)
        self.authenticator.setPassword(password)
        # here: how to connect authenticator to network manager?
    def on_connected(self):
        self.send_button.setEnabled(True)
        self.connect_button.setText("Connected...")
        self.connect_button.setEnabled(False)

    def on_disconnected(self):
        self.send_button.setEnabled(False)
        self.connect_button.setText("Connect WebSocket")
        self.connect_button.setEnabled(True)

    def send_message(self):
        message = self.message_input.text()
        if message:
            #self.websocket.sendTextMessage(message)
            #self.message_input.clear()
            self.incoming_messages.append(f"Me: {message}")
            request = QNetworkRequest(QUrl("http://localhost:8766"))
            request.setHeader(QNetworkRequest.KnownHeaders.ContentTypeHeader, "text/plain")
            request.setRawHeader(b"Content-Length", str(len(message)).encode())
            request.setRawHeader(b"Message", message.encode())
            reply = self.manager.post(request, message.encode())
            print("Client: " + reply.readAll())
            reply.readyRead.connect(self.on_reply_finished)

    def try_abb_connect(self):
        self.authenticate("Default User", "robotics")
        payload = b"lvalue=1"
        url = QUrl("http://168.168.64.61/rw/iosystem/signals/Virtual1/Board1/di1?action = set")
        request = QNetworkRequest(url)
        request.setHeader(QNetworkRequest.KnownHeaders.ContentTypeHeader, "application/x-www-form-urlencoded")
        resp = self.manager.post(request, payload)
        print("ABB: " + str(resp.error()) + resp.errorString())
        #resp = requests.post("http://localhost/rw/iosystem/signals/Virtual1/Board1 / di1?action = set", auth = HTTPDigestAuth("Default User", "robotics"), data = payload)
    def connect_websocket(self):
        if not self.websocket:
            self.websocket = QWebSocket()
        self.authenticate(self.username, self.password)
        self.websocket.open("ws://localhost:8765")
        #self.websocket.open(QUrl("168.168.64.61"))

    def on_message_received(self, message):
        self.incoming_messages.append("Server: " +message)

    def on_reply_finished(self):
        reply = self.sender()
        print(self.sender().error())
        print(self.sender().errorString())
        while reply.bytesAvailable() > 0:
            print("Response from Server: " + reply.readLine())
        reply.deleteLater()

    def closeEvent(self, event):
        if self.websocket:
            self.websocket.close()
        event.accept()