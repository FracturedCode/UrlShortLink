#include <openssl/ssl.h>
#include <WinSock2.h>
#include <iostream>
#include <openssl/err.h>
#include <WS2tcpip.h>
#define SERVER_PORT "8000"
int main(int argc, char** argv) {
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
		std::cout << "WSAStartup failed\n";
		return -1;
	}

	struct addrinfo hints;
	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	struct addrinfo* result = NULL;
	if (getaddrinfo(NULL, SERVER_PORT, &hints, &result) != 0) {
		std::cout << "getaddrinfo failed\n";
		WSACleanup();
		return -1;
	}

	SOCKET ListenSocket = INVALID_SOCKET;
	if ((ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) == INVALID_SOCKET
		|| bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen) == SOCKET_ERROR
		|| listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
		std::cout << "Could not open the listening socket\n";
		WSACleanup();
		return -1;
	}
	freeaddrinfo(result);


	SSL_library_init();
	SSL_load_error_strings();
	SSL_CTX* ctx;
	if ((ctx = SSL_CTX_new(TLS_server_method())) == NULL) {
		std::cout << "Fail creating context. Exact error:\n";
		ERR_print_errors_fp(stderr);
		return -1;
	}
	
	if (_wchdir(L"E:\\repos\\UrlSL\\UrlSL\\x64\\Debug\\") != 0) {
		std::cout << "_wchdir failed. Could not change the cwd\n";
		return -1;
	}
	if (!SSL_CTX_use_certificate_file(ctx, "localhost.crt", SSL_FILETYPE_PEM) ||
		!SSL_CTX_use_PrivateKey_file(ctx, "localhost.key", SSL_FILETYPE_PEM) ||
		!SSL_CTX_check_private_key(ctx)) {
		std::cout << "Failed to open certificates or load them. Exact error: \n";
		ERR_print_errors_fp(stderr);
		return -1;
	}

	return 0;
}