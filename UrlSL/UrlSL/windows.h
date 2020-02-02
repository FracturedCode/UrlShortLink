
#include "definitions.h"
#include <openssl/ssl.h>
#include <WinSock2.h>
#include <iostream>
#include <openssl/err.h>
#include <WS2tcpip.h>
#include <mutex>
#include <list>

#define TLS_SERVER_PORT 8001
#define HTTP_SERVER_PORT 8003
#define TIMEOUT_UNTIL_THREAD_TERMINATE 20

#pragma once
Server::ServerThread::ServerThread(SOCKET listenSocket, ServerThreadType type, SSL_CTX* tlsCtx)
    : _listenSocket(listenSocket), _type(type), _tlsCtx(tlsCtx), _continueThread(true) {
    _hThread = (HANDLE)_beginthread(type==Tls ? ServerThread::handleTls : ServerThread::handleHttp, 0, (void*)this);
}

bool Server::ServerThread::StopThread(bool forciblyStop) {
    _continueThread = true;
    if (WaitForSingleObject(_hThread, forciblyStop ? TIMEOUT_UNTIL_THREAD_TERMINATE : INFINITE) != WAIT_OBJECT_0) {
        return forciblyStop ? TerminateThread(_hThread, NULL) : false;
    }
}

void Server::ServerThread::handleTls(void* s) {
    ServerThread* self = (ServerThread*)s;
    std::string _reply = "HTTP/1.1 301 Moved Permanently\r\nCache-Control: max-age=1\r\nLocation: https://google.com/ \r\n\r\n";
    SSL* ssl = NULL;
    SOCKET clientSocket;
    char buf[512];
    while (self->_continueThread) {
        ssl = SSL_new(self->_tlsCtx);
        self->_acceptMutex->lock();
        clientSocket = WSAAccept(self->_listenSocket, NULL, NULL, NULL, NULL);
        std::cout << "Serving\n";
        if (clientSocket == INVALID_SOCKET) {
            self->_acceptMutex->unlock();
            SSL_free(ssl);
            std::cout << "WSAGetLastError " << WSAGetLastError();
            return;
            continue;//TODO
        } else {
            self->_acceptMutex->unlock();
            SSL_set_fd(ssl, clientSocket); //TODO check return values
            SSL_accept(ssl);
            int bytes = SSL_read(ssl, buf, sizeof(buf));
            std::cout << buf << std::endl;
            SSL_write(ssl, _reply.c_str(), _reply.length());
            SSL_free(ssl);
            shutdown(clientSocket, SD_SEND);
            closesocket(clientSocket);
        }
    }
}

void Server::ServerThread::handleHttp(void* s) {

}


Server::Server(unsigned int tlsThreadCount, bool createHttpThread)
    : _tlsCtx(createTlsCtx()) {

    struct addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo* result = NULL;
    if (getaddrinfo(NULL, "8001", &hints, &result) != 0) {
        std::cout << "getaddrinfo failed\n" << WSAGetLastError();
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    if ((_tlsListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) == INVALID_SOCKET
        || bind(_tlsListenSocket, result->ai_addr, (int)(result->ai_addrlen)) == SOCKET_ERROR
        || listen(_tlsListenSocket, SOMAXCONN) == SOCKET_ERROR) {
        std::cout << "Could not open the listening socket\n" << WSAGetLastError();
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i<tlsThreadCount; i++) {
        _serverThreads.push_back(ServerThread(_tlsListenSocket, Tls, &_tlsAcceptMutex, _tlsCtx));
    }
    if (createHttpThread) {
        //TODO
    }
}

bool Server::StopAllThreads(bool forciblyStop) {
    bool success = true;
    for (auto &s : _serverThreads) {
        if (!s.StopThread(forciblyStop)) {
            success = false;
        }
    }
    return success;
}

SSL_CTX* Server::createTlsCtx() {
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

SOCKET Server::createListenSocket(int port) {//TODO port
    SOCKET returnSock = INVALID_SOCKET;

    struct addrinfo hints;
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    struct addrinfo* result = NULL;
    if (getaddrinfo(NULL, "8001", &hints, &result) != 0) {
        std::cout << "getaddrinfo failed\n" << WSAGetLastError();
        WSACleanup();
        exit(EXIT_FAILURE);
    }

    if ((returnSock = socket(result->ai_family, result->ai_socktype, result->ai_protocol)) == INVALID_SOCKET
        || bind(returnSock, result->ai_addr, (int)(result->ai_addrlen)) == SOCKET_ERROR
        || listen(returnSock, SOMAXCONN) == SOCKET_ERROR) {
        std::cout << "Could not open the listening socket\n" << WSAGetLastError();
        WSACleanup();
        exit(EXIT_FAILURE);
    }
    return returnSock;
}

Server::~Server() {
    SSL_CTX_free(_tlsCtx);
}