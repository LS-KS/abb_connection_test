from PySide6.QtWidgets import QMainWindow, QHBoxLayout, QVBoxLayout, QTextEdit, QLineEdit, QPushButton, QWidget, \
    QApplication, QLabel
from PySide6.QtNetwork import QNetworkAccessManager, QNetworkRequest, QAuthenticator, QNetworkReply
from PySide6.QtCore import QUrl, QByteArray
import ipaddress

from MWE_QtWebSocket.server import Server

class ABBConnectionTester(QMainWindow):
    _ip: str = None
    _network_manager: QNetworkAccessManager = None
    _username: str = None
    _password: str = None
    _response: QNetworkReply = None
    _request: QNetworkRequest = None

    def __init__(self):
        super().__init__(None)
        self.network_manager = QNetworkAccessManager()
        self._build_ui()

    @property
    def ip(self) -> str:
        if self._ip is None:
            return ""
        return self._ip

    @ip.setter
    def ip(self, value: str) -> None:
        if self._ip == value:
            return
        try:
            ip_obj = ipaddress.ip_address(value)
            self._ip = str(ip_obj)
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {value}") from e

    @property
    def network_manager(self) -> QNetworkAccessManager:
        return self._network_manager

    @network_manager.setter
    def network_manager(self, value) -> None:
        if self._network_manager == value:
            return
        if not isinstance(value, QNetworkAccessManager):
            raise TypeError("network_manager must be a QNetworkAccessManager")
        self._network_manager = value
        self._network_manager.authenticationRequired.connect(self.provide_authentication)
        #self._network_manager.finished.connect(self.handle_response)

    @property
    def response(self) -> QNetworkReply:
        return self._response

    @response.setter
    def response(self, value):
        raise NotImplementedError("Response cannot be set directly. It's set internally by the network manager.")

    @property
    def request(self) -> QNetworkRequest:
        return self._request

    @request.setter
    def request(self, value):
        raise NotImplementedError("Request cannot be set directly. It's built internally.")


    @property
    def username(self) -> str:
        if self._username is None:
            return ""
        return self._username

    @username.setter
    def username(self, value: str) -> None:
        if self._username == value:
            return
        if not isinstance(value, str):
            raise TypeError("Username must be a string")
        self._username = value

    @property
    def password(self) -> str:
        if self._password is None:
            return ""
        return self._password

    @password.setter
    def password(self, value: str) -> None:
        if self._password == value:
            return
        if not isinstance(value, str):
            raise TypeError("Password must be a string")
        self._password = value

    def build_request(self) -> (QNetworkRequest, QByteArray):
        self._request = QNetworkRequest()
        url = QUrl(self.ui_url_field.text())
        self._request.setUrl(url)
        self._request.setHeader(QNetworkRequest.ContentTypeHeader, "application/x-www-form-urlencoded")
        payload = QByteArray(self.ui_payload_field.text())
        return self._request, payload

    def handle_response(self) -> None:
        self.ui_incoming_messages.append("Response received.")
        if self.response.error() == QNetworkReply.NoError:
            self.ui_incoming_messages.append(f"Success: {self.response.readAll().data().decode()}")
        else:
            self.ui_incoming_messages.append(f"Error: {self.response.errorString()}")

    def provide_authentication(self, network_reply: QNetworkReply, authenticator: QAuthenticator) -> None:
        # Method just connected to the signal.
        # possible error source if 401 response.
        authenticator.setUser(self.username)
        authenticator.setPassword("robotics")

    def send_request(self):
        request, payload = self.build_request()
        self.ui_incoming_messages.append(f"Sending request to {request.url().toString()}")
        self.ui_incoming_messages.append(f"Payload: {payload}")
        self._response = self.network_manager.post(request, payload)
        self.response.readyRead.connect(self.handle_response)
        self.response.finished.connect(self.handle_response)

    def set_ip(self, ip: str):
        self.ip = ip

    def set_password(self, password: str):
        self.ui_incoming_messages.append(f"Password set to {"*" * len(password) if password else "None"}")
        self.password = password

    def set_username(self, username: str):
        self.ui_incoming_messages.append(f"Username set to {username}")
        self.username = username

    def use_default_credentials(self):
        self.ui_user_field.setText("Default User")
        self.ui_pass_field.setText("robotics")
        self.ui_url_field.setText("http://192.168.64.61/rw/signals")
        self.ui_payload_field.setText("action=show")

    def _build_ui(self):
        layout = QVBoxLayout()

        self.ui_incoming_messages = QTextEdit()
        self.ui_incoming_messages.setReadOnly(True)
        layout.addWidget(self.ui_incoming_messages)

        credentials_layout = self._build_credential_ui()
        layout.addLayout(credentials_layout)

        payload_layout, url_layout = self._build_request_ui()
        layout.addLayout(url_layout)
        layout.addLayout(payload_layout)

        self.ui_abb_button = QPushButton("Connect to ABB")
        self.ui_abb_button.clicked.connect(self.send_request)
        layout.addWidget(self.ui_abb_button)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def _build_request_ui(self):
        url_layout = QHBoxLayout()
        url_layout.addWidget(QLabel("URL:"))
        self.ui_url_field = QLineEdit()
        self.ui_url_field.setPlaceholderText("http://")
        url_layout.addWidget(self.ui_url_field)
        payload_layout = QHBoxLayout()
        payload_layout.addWidget(QLabel("Payload:"))
        self.ui_payload_field = QLineEdit()
        self.ui_payload_field.setPlaceholderText("key1=value1&key2=value2")
        payload_layout.addWidget(self.ui_payload_field)
        return payload_layout, url_layout

    def _build_credential_ui(self):
        credentials_layout = QHBoxLayout()
        self.ui_user_field = QLineEdit()
        self.ui_user_field.setPlaceholderText("Username")
        self.ui_user_field.textChanged.connect(self.set_username)
        credentials_layout.addWidget(self.ui_user_field)
        self.ui_pass_field = QLineEdit()
        self.ui_pass_field.setEchoMode(QLineEdit.EchoMode.Password)
        self.ui_pass_field.textChanged.connect(self.set_password)
        self.ui_pass_field.setPlaceholderText("Password")
        credentials_layout.addWidget(self.ui_pass_field)
        self.ui_default_button = QPushButton("Use Default")
        self.ui_default_button.clicked.connect(self.use_default_credentials)
        credentials_layout.addWidget(self.ui_default_button)
        return credentials_layout


if __name__ == "__main__":
    app = QApplication([])
    window = ABBConnectionTester()
    window.show()
    server = Server()
    server.show()

    app.exec()
