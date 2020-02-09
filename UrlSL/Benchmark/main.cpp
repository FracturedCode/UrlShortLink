#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <thread>
#pragma comment(lib, "ws2_32")
const int simulatedClientsPerThread = 200;

struct Client {
	SSL* ssl;
	SOCKET sock;
};

class ClientRequestor {
	HANDLE _thread;
	bool _shouldStop;

	static void connector(void* c) {
		ClientRequestor* cl = static_cast<ClientRequestor*>(c);
		Client clients[simulatedClientsPerThread];
		SSL_library_init();
		SSL_load_error_strings();
		SSL_CTX* ctx;
		if ((ctx = SSL_CTX_new(TLS_client_method())) == NULL) {
			std::cout << "Fail creating SSL context. Exact error:\n";//TODO error logging
			ERR_print_errors_fp(stderr);
			exit(EXIT_FAILURE);
		}
		SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
			
		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
			std::cout << "WSAStartup failed\n" << WSAGetLastError();	//TODO Use log func
			exit(EXIT_FAILURE);
		}

		char buf[20] = "Hello my old friend";
		char response[200] = { 0 };

		SSL* ssl;
		struct addrinfo hints;
		struct addrinfo* result;
		ZeroMemory(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_protocol = IPPROTO_TCP;
		getaddrinfo("127.0.0.1", "8001", &hints, &result);
		while (!cl->_shouldStop) {
			for (int i = 0; i < simulatedClientsPerThread; i++) {
				clients[i].ssl = SSL_new(ctx);
				clients[i].sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
				SSL_set_fd(clients[i].ssl, clients[i].sock);
			}
			for (int i = 0; i < simulatedClientsPerThread; i++) {
				connect(clients[i].sock, result->ai_addr, (int)result->ai_addrlen);
			}
			for (int i = 0; i < simulatedClientsPerThread; i++) {
				SSL_connect(clients[i].ssl);
			}
			for (int i = 0; i < simulatedClientsPerThread; i++) {
				SSL_write(clients[i].ssl, buf, 20);
				SSL_read(clients[i].ssl, response, 200);
				SSL_shutdown(clients[i].ssl);
				shutdown(clients[i].sock, SD_SEND);
				closesocket(clients[i].sock);
				SSL_free(clients[i].ssl);
			}
		}
		WSACleanup();
	}
public:
	ClientRequestor() : _shouldStop(false) {
		
	}
	void Start() {
		_thread = (HANDLE)_beginthread(ClientRequestor::connector, 0, (void*)this);
	}
	void Stop() {
		_shouldStop = true;
		if (WaitForSingleObject(_thread, 20) != WAIT_OBJECT_0) {
			TerminateThread(_thread, NULL);
		}
	}
};

int main() {
	const int cliThreadCount = 1;
	ClientRequestor clients[cliThreadCount];
	for (int i = 0; i < cliThreadCount; i++) {
		clients[i].Start();
		Sleep(100);
	}
	getchar();
	for (int i = 0; i < cliThreadCount; i++) {
		clients[i].Stop();
	}
}