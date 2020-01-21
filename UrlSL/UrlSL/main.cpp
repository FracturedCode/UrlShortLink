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

class Server {
	SOCKET _listenSocket;
	bool _shouldHandleStop;
	addrinfo* _sockAddr;
	HANDLE _hThread;
	std::string _reply;
	std::list<ServerThread> _serverThreads;

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
		hints.ai_family = AF_INET;
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
		char buf[1024];
		int count = 0;
		while (!self->_shouldHandleStop) {
			ssl = SSL_new(ctx);
			if ((clientSocket = WSAAccept(self->_listenSocket, NULL, NULL, NULL, NULL)) == INVALID_SOCKET) {
				std::cout << "Could not accept client\n" << WSAGetLastError();
				continue;
			}
			std::cout << "Serving " << ++count << std::endl;
			SSL_set_fd(ssl, clientSocket);
			SSL_accept(ssl);
			int bytes = SSL_read(ssl, buf, sizeof(buf));
			std::cout << buf << std::endl;
			SSL_write(ssl, self->_reply.c_str(), self->_reply.length());
			SSL_free(ssl);
			shutdown(clientSocket, SD_SEND);
			closesocket(clientSocket);
			std::cout << "Done " << count << std::endl;
		}
		freeaddrinfo(self->_sockAddr);
		shutdown(self->_listenSocket, SD_SEND);
	 	closesocket(self->_listenSocket);
	}
	
	static void handleHTTP(void* s) {

	}

	public:
		bool StopHandling(bool forciblyStop = false) {
			_shouldHandleStop = true;
			if (WaitForSingleObject(_hThread, forciblyStop ? TIMEOUT_UNTIL_THREAD_TERMINATE : INFINITE) != WAIT_OBJECT_0) {
				if (forciblyStop) return TerminateThread(_hThread, NULL);
				else return false;
			}
		}
		void StartHandling() {
			_hThread = (HANDLE)_beginthread(Server::handleTls, 0, (void*)this);
		}
		
		Server() : _shouldHandleStop(false), _listenSocket(INVALID_SOCKET), _sockAddr(initWSA()) {
			_reply = "HTTP/1.1 301 Moved Permanently\r\nCache-Control: max-age=1\r\nLocation: https://google.com/ \r\n\r\n";
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