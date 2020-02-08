#include <openssl/ssl.h>
#include <WinSock2.h>
#include <iostream>
#include <openssl/err.h>
#include <WS2tcpip.h>
#include <future>
#include <thread>
#include <mutex>
#include <Windows.h>
#include <list>
#include <stdint.h>

#define MAX_CONNECTION_COUNT 1000
#define BUFFER_SIZE 1024
#define SERVER_PORT "8001"
#define TIMEOUT_UNTIL_THREAD_TERMINATE 20
#define MAX_PACKET_COUNT 3

void log(std::string logString, int errorNo = NULL) {
	std::cout << logString << " " << errorNo << std::endl;	//TODO advanced error logging mechanisms
}

uint64_t s[] = {clock(), clock()};
uint64_t nextXorShift128(void) {
	uint64_t s1 = s[0];
	uint64_t s0 = s[1];
	uint64_t result = s0 + s1;
	s[0] = s0;
	s1 ^= s1 << 23; // a
	s[1] = s1 ^ s0 ^ (s1 >> 18) ^ (s0 >> 5); // b, c
	return result;
}



class Client {
	std::mutex _readWriteLock;
	short _readCount;
	bool _isDestroyed;
	SOCKET _socket;
	WSAPOLLFD _pollFd;
	SSL* _ssl;


	bool destroy() {
		SSL_shutdown(_ssl);
		SSL_free(_ssl);	//TODO vrv
		shutdown(_socket, SD_SEND);//TODO order of shutdown/send
		closesocket(_socket);//nonblocking close and shutdown?
		_pollFd.fd = NULL;
		_isDestroyed = true;
		_readWriteLock.try_lock();
		_readWriteLock.unlock();
		return true;
	}


public:
	char Buffer[BUFFER_SIZE];
	int MessageSize;


	Client() : MessageSize(0), _isDestroyed(true) {
		_pollFd.events = POLLRDNORM;
	}


	bool ReconfigureIfReady(SOCKET sock, SSL* ssl) {
		if (_isDestroyed && _readWriteLock.try_lock()) {
			_ssl = ssl;
			_socket = sock;
			_pollFd.fd = sock;
			MessageSize = 0;
			_readCount = 0;
			_isDestroyed = false;
			_readWriteLock.unlock();
			return true;
		}
		else return false;
	}

	void ReadNotCompleted() {
		if (_readCount >= MAX_PACKET_COUNT && !_isDestroyed) {
			destroy();
			log("A client was destroyed as it surpassed the maximum number of reads limit.");
		}
		else {
			_readWriteLock.try_lock();
			_readWriteLock.unlock();
		}
	}

	bool ReadIfReady() {
		if (!_isDestroyed && _readWriteLock.try_lock()) {
			WSAPoll(&_pollFd, 1, 0);
			if (_pollFd.revents & POLLRDNORM) {
				SSL* ssl = _ssl;
				MessageSize += SSL_read(ssl, &Buffer[MessageSize - 1], BUFFER_SIZE - MessageSize);//TODO vrv
				_ssl = ssl;
				_readCount++;
				return true;
			}
			else {
				_readWriteLock.unlock();
				return false;
			}
		}
		else return false;
	}

	bool WriteAndDestroy(std::string* reply) {
		if (!_isDestroyed) {
			SSL_write(_ssl, reply->c_str(), reply->length());	//TODO vrv
			destroy();
			return true;
		}
		else {
			log("A clientHandler tried to write to an already destroyed or currently-being-handled client.");
			return false;
		}
	}

	bool WaitForDestruction() {
		for (int i = 0; i < 10 && !_isDestroyed; i++) {
			_readWriteLock.lock();
			_readWriteLock.unlock();
		}
		return _isDestroyed;
	}
};

class WorkManager {
	Client _clients[MAX_CONNECTION_COUNT];

public:
	Client* GetNextWork() {
		unsigned int i = 0;
		while (!_clients[i].ReadIfReady()) {
			if (++i == MAX_CONNECTION_COUNT) {
				i = 0;
				Sleep(1);
			}
		}
		return &_clients[i];
	}

	void AddWork(SOCKET sock, SSL* ssl) {
		unsigned int i = 0;
		while (!_clients[i].ReconfigureIfReady(sock, ssl)) {
			if (++i == MAX_CONNECTION_COUNT) {
				i = 0;
				log("Could not find available slots to hold new connections. The system might not be keeping up with the amount of requests.");
				Sleep(1);
			}
		}
	}
};

class Server {
private:
	std::vector<HANDLE> _threads;
	HANDLE _hThreadAcceptor;
	bool _shouldStop;
	WorkManager _wm;

	static void clientHandler(void* s) {
		Server* self = static_cast<Server*>(s);

		std::string reply = "HTTP/1.1 301 Moved Permanently\r\nCache-Control: max-age=1\r\nLocation: https://google.com/ \r\n\r\n";
		bool condition = false;	//TODO probably just look for a CRLF CRLF after Read()
		Client* client = NULL;
		while (!self->_shouldStop) {
			client = self->_wm.GetNextWork();
			if (condition) client->ReadNotCompleted();
			else if (!client->WriteAndDestroy(&reply)) {
				client->WriteAndDestroy(&reply);
			}
		}
	}

	static void tlsAcceptor(void* s) {
		Server* self = static_cast<Server*>(s);

		SSL_library_init();
		SSL_load_error_strings();
		SSL_CTX* ctx;
		if ((ctx = SSL_CTX_new(TLS_server_method())) == NULL) {
			std::cout << "Fail creating SSL context. Exact error:\n";//TODO error logging
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

		WSADATA wsaData;
		if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
			std::cout << "WSAStartup failed\n" << WSAGetLastError();	//TODO Use log func
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

		SOCKET listenSocket;
		if ((listenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) == INVALID_SOCKET
			|| bind(listenSocket, result->ai_addr, (int)(result->ai_addrlen)) == SOCKET_ERROR
			|| listen(listenSocket, MAX_CONNECTION_COUNT) == SOCKET_ERROR) {
			std::cout << "Could not open the listening socket\n" << WSAGetLastError();
			WSACleanup();
			exit(EXIT_FAILURE);
		}

		SSL* ssl = NULL;
		SOCKET clientSocket;
		while (!self->_shouldStop) {
			ssl = SSL_new(ctx);
			if ((clientSocket = WSAAccept(listenSocket, NULL, NULL, NULL, NULL)) == INVALID_SOCKET) {	//TODO implement callback func
				log("Could not accept client\n", WSAGetLastError());
				continue;
			}
			SSL_set_fd(ssl, clientSocket);	//TODO vrv
			SSL_accept(ssl);
			self->_wm.AddWork(clientSocket, ssl);
		}
	}

public:
	Server() : _shouldStop(false) { // TODO destructor
		_hThreadAcceptor = (HANDLE)_beginthread(Server::tlsAcceptor, 0, (void*)this);	// TODO vrv

		int handlerThreadCount = (std::thread::hardware_concurrency() - 1) * 2;	// TODO Needs to be a bit more advanced and generous
		if (handlerThreadCount <= 0) handlerThreadCount = 1;
		handlerThreadCount = 6;
		for (int i = 0; i < handlerThreadCount; i++) { _threads.push_back((HANDLE)_beginthread(Server::clientHandler, 0, (void*)this)); }
	}

	bool Stop(bool forceTerminate = false) {
		this->_shouldStop = true;
		bool success = true;
		if (WaitForMultipleObjects(_threads.size(), _threads.data(), true, forceTerminate ? TIMEOUT_UNTIL_THREAD_TERMINATE : INFINITE) != WAIT_OBJECT_0) {	//TODO forceterminate is the only thing that works rn
			if (forceTerminate) {
				for (std::vector<HANDLE>::iterator it = _threads.begin(); it != _threads.end(); it++) {
					if (!TerminateThread(*it, NULL)) success = false;
				}
			}
			else success = false;
		}
		if (WaitForSingleObject(_hThreadAcceptor, forceTerminate ? TIMEOUT_UNTIL_THREAD_TERMINATE : INFINITE) != WAIT_OBJECT_0) {
			if (forceTerminate && !TerminateThread(_hThreadAcceptor, NULL)) success = false;
		}
		return success;
	}
};

int main() {
	Server* s = new Server();
	getchar();
	s->Stop(true); // TODO vrv
	delete s;
	WSACleanup();
	return 0;
}