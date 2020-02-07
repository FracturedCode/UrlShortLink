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
#define CLIENT_HANDLER_CHUNK_LENGTH 200

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


	bool destroy() {
		SSL_shutdown(Ssl);
		SSL_free(Ssl);	//TODO vrv
		shutdown(Socket, SD_SEND);//TODO order of shutdown/send
		closesocket(Socket);//nonblocking close and shutdown?
		PollFd->fd = NULL;
		_isDestroyed = true;
		_readWriteLock.try_lock();
		_readWriteLock.unlock();
		return true;
	}


public:
	SOCKET Socket;
	WSAPOLLFD* PollFd;
	SSL* Ssl;
	char Buffer[BUFFER_SIZE];
	int MessageSize;


	Client() : MessageSize(0), _isDestroyed(true) {}


	bool IsDestroyed() { return _isDestroyed; }


	void Reconfigure(SOCKET sock, SSL* ssl) {
		_readWriteLock.lock();//TODO deadlock potential
		Ssl = ssl;
		Socket = sock;
		PollFd->fd = sock;
		PollFd->events = POLLRDNORM;
		PollFd->revents = 0;
		MessageSize = 0;
		_readCount = 0;
		_readWriteLock.unlock();
	}

	void ReadNotCompleted() {
		if (_readCount >= MAX_PACKET_COUNT && !_isDestroyed && _readWriteLock.try_lock()) {
			destroy();
		}
		else {
			_readWriteLock.try_lock();
			_readWriteLock.unlock();
		}
	}

	bool Read() {	//TODO think about orders of locks in Read -> ReadNotCompleted -> WriteAndDestroy context
		if (!_isDestroyed && _readWriteLock.try_lock()) {
			MessageSize += SSL_read(Ssl, &Buffer[MessageSize-1], BUFFER_SIZE - MessageSize);//TODO vrv
			_readCount++;
			PollFd->revents = 0;
			_readWriteLock.unlock();
			return true;
		}
		else return false;
	}

	void WriteAndDestroy(std::string* reply) {
		if (!_isDestroyed && _readWriteLock.try_lock()) {
			SSL_write(Ssl, reply->c_str(), reply->length());	//TODO vrv
			destroy();
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
	WSAPOLLFD _pollFds[MAX_CONNECTION_COUNT];
	std::mutex _workLock;
	int _getIterator;
	int _setIterator;


public:
	WorkManager() : _setIterator(0), _getIterator(0) {}


	Client* GetNextWork() {
		std::scoped_lock(_workLock);
		if (++_getIterator == MAX_CONNECTION_COUNT) _getIterator = 0;
		return &_clients[_getIterator];
	}

	void AddWork(SOCKET sock, SSL* ssl) {					// TODO knowing me _setIterator obo probably.
		for (int i = 0; i < MAX_CONNECTION_COUNT; i++) {	// Cycle through the queue once,
			if (_setIterator == MAX_CONNECTION_COUNT) _setIterator = 0;
			if (_clients[_setIterator].IsDestroyed()) {		// Return early if a candidate is found
				_clients[_setIterator].Reconfigure(sock, ssl);
				_setIterator++;
				return;
			}
			_setIterator++;
		}
		if (_clients[_setIterator].WaitForDestruction()) {	// Otherwise just wait for a client to finish up.
			_clients[_setIterator].Reconfigure(sock, ssl);
		}
		else {
			log("Could not AddWork() successfully. The system might not be keeping up with the amount of requests.");
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

		Client* client = NULL;
		Client& c = *client;
		while (!self->_shouldStop) {
			client = self->_wm.GetNextWork();
			
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
		for (int i = 0; i < handlerThreadCount; i++) { _threads.push_back((HANDLE)_beginthread(Server::clientHandler, 0, (void*)this)); }
	}

	bool Stop(bool forceTerminate = false) {
		this->_shouldStop = true;
		bool success = true;
		if (WaitForSingleObject(_hThreadAcceptor, forceTerminate ? TIMEOUT_UNTIL_THREAD_TERMINATE : INFINITE) != WAIT_OBJECT_0) {
			if (forceTerminate && !TerminateThread(_hThreadAcceptor, NULL)) success = false;
		}
		if (WaitForMultipleObjects(_threads.size(), _threads.data(), true, forceTerminate ? TIMEOUT_UNTIL_THREAD_TERMINATE : INFINITE) != WAIT_OBJECT_0) {
			if (forceTerminate) {
				for (std::vector<HANDLE>::iterator it = _threads.begin(); it != _threads.end(); it++) {
					if (!TerminateThread(*it, NULL)) success = false;
				}
			}
		}
		return success;
	}
};

int main() {
	Server* s = new Server();
	getchar();
	s->Stop(); // TODO vrv
	delete s;
	WSACleanup();
	return 0;
}