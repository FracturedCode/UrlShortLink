#include <openssl/ssl.h>
#include <WinSock2.h>
#include <iostream>
#include <openssl/err.h>
#include <WS2tcpip.h>
#include <future>
#include <thread>
#include <mutex>
#define SERVER_PORT "8001"
#define TIMEOUT_UNTIL_THREAD_TERMINATE 20

struct Client {
	SOCKET Socket;
	SSL* Ssl;
	WSAPOLLFD* PollHandle;
	Client() {}
	Client(WSAPOLLFD* pollHandle) {
		PollHandle = pollHandle;
	}
	void Reconfigure(SOCKET sock, SSL* sslPointer) {
		Ssl = sslPointer;
		Socket = sock;
		PollHandle->fd = sock;
		PollHandle->events = POLLRDNORM;
		PollHandle->revents = 0;
	}
};

class Server {
	SOCKET _listenSocket;
	std::mutex _shouldHandleStopLock;
	bool _shouldHandleStop;
	addrinfo* _sockAddr;
	HANDLE _hThreadAcceptor;
	HANDLE _hThreadPoll;
	std::string _reply;
	Client _clientList[500];
	WSAPOLLFD _fdList[500];

	static SSL_CTX* newTlsContext() {
		SSL_library_init();
		SSL_load_error_strings();
		SSL_CTX* ctx;
		if ((ctx = SSL_CTX_new(TLS_server_method())) == NULL) {
			std::cout << "Fail creating SSL context. Exact error:\n";
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}

		if (_wchdir(L"E:\\repos\\UrlSL\\UrlSL\\x64\\Debug\\") != 0) {
			std::cout << "_wchdir failed. Could not change the cwd\n";
			exit(EXIT_FAILURE);
		}
		if (!SSL_CTX_use_certificate_file(ctx, "localhost.crt", SSL_FILETYPE_PEM) ||
			!SSL_CTX_use_PrivateKey_file(ctx, "localhost.key", SSL_FILETYPE_PEM) ||
			!SSL_CTX_check_private_key(ctx)) {
			std::cout << "Failed to open certificates or load them. Exact error: \n";
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
		return ctx;
	}

	addrinfo* initWSA() {
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
			std::cout << "WSAStartup failed\n" << WSAGetLastError();
			exit(EXIT_FAILURE);
		}

		struct addrinfo hints;
		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET6;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		hints.ai_flags = AI_PASSIVE;

		struct addrinfo* result = NULL;
		if (getaddrinfo(NULL, SERVER_PORT, &hints, &result) != 0) {
			std::cout << "getaddrinfo failed\n" << WSAGetLastError();
			WSACleanup();
			exit(EXIT_FAILURE);
		}
		return result;
	}

	static void handleTls(void* s) {
		Server* self = (Server*)s;
		SSL_CTX* ctx = newTlsContext();
		if ((self->_listenSocket = socket(self->_sockAddr->ai_family, self->_sockAddr->ai_socktype, self->_sockAddr->ai_protocol)) == INVALID_SOCKET
			|| bind(self->_listenSocket, self->_sockAddr->ai_addr, (int)(self->_sockAddr->ai_addrlen)) == SOCKET_ERROR
			|| listen(self->_listenSocket, SOMAXCONN) == SOCKET_ERROR) {
			std::cout << "Could not open the listening socket\n" << WSAGetLastError();
			WSACleanup();
			exit(EXIT_FAILURE);
		}
		SSL* ssl = NULL;
		SOCKET clientSocket;
		int count = 0;
		while (!self->_shouldHandleStop) {
			ssl = SSL_new(ctx);
			if ((clientSocket = WSAAccept(self->_listenSocket, NULL, NULL, NULL, NULL)) == INVALID_SOCKET) {
				std::cout << "Could not accept client\n" << WSAGetLastError();
				continue;
			}
			std::cout << "Serving " << ++count << std::endl;
			if (count >= 500) count = 0;
			SSL_set_fd(ssl, clientSocket);
			self->_clientList[count].Reconfigure(clientSocket, ssl);
		}
		freeaddrinfo(self->_sockAddr);
		shutdown(self->_listenSocket, SD_SEND);
	 	closesocket(self->_listenSocket);
	}
	
	static void handleHTTP(void* s) {
		
	}

	static void pollReads(void* s) {
		Server* self = (Server*)s;
		char buf[1024];
		while (!self->_shouldHandleStop) {
			WSAPoll(self->_fdList, 500, 1);
			for (int i = 0; i < 500; i++) {
				if (self->_fdList[i].revents & POLLRDNORM) {
					SSL_accept(self->_clientList[i].Ssl);
					int bytes = SSL_read(self->_clientList[i].Ssl, buf, sizeof(buf));
					std::cout << buf << std::endl;
					SSL_write(self->_clientList[i].Ssl, self->_reply.c_str(), self->_reply.length());
					SSL_free(self->_clientList[i].Ssl);
					shutdown(self->_clientList[i].Socket, SD_SEND);
					closesocket(self->_clientList[i].Socket);
					std::cout << "Done " << i << std::endl;
				}
			}
		}
	}

	public:
		bool StopHandling(bool forciblyStop = false) {
			_shouldHandleStopLock.lock();
			_shouldHandleStop = true;
			_shouldHandleStopLock.unlock();
			if (WaitForSingleObject(_hThreadAcceptor, forciblyStop ? TIMEOUT_UNTIL_THREAD_TERMINATE : INFINITE) != WAIT_OBJECT_0) {
				if (forciblyStop) return TerminateThread(_hThreadAcceptor, NULL);
				else return false;
			}
		}
		void StartHandling() {
			_hThreadAcceptor = (HANDLE)_beginthread(Server::handleTls, 0, (void*)this);
			_hThreadPoll = (HANDLE)_beginthread(Server::pollReads, 0, (void*)this);
		}

		Server() : _shouldHandleStop(false), _listenSocket(INVALID_SOCKET), _sockAddr(initWSA()) {
			this->_reply = "HTTP/1.1 301 Moved Permanently\r\nCache-Control: max-age=1\r\nLocation: https://google.com/ \r\n\r\n";
			for (int i = 0; i < 500; i++) {
				_clientList[i] = Client(&_fdList[i]);
			}
			StartHandling();
		}
};

int main(int argc, char** argv) {
	
	Server s;
	getchar();
	s.StopHandling();
	
	WSACleanup();
	return 0;
}