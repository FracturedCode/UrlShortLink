#pragma once
ServerThread::ServerThread(SOCKET listenSocket, ServerThreadType type, std::mutex* acceptMutex, SSL_CTX* tlsCtx)
    : _listenSocket(listenSocket), _type(type), _acceptMutext(acceptMutex), _tlsCtx(tlsCtx), _continueThread(true) {
    _hThread = (HANDLE)_beginthread(type==ServerThreadType.Tls ? ServerThread::handleTls : ServerThread::handleHttp, 0, (void*)this);
}

bool ServerThread::StopThread(bool forciblyStop=false) {
    _continueThread = true;
    return (WaitForSingleObject(_hThread, forciblyStop ? TIMEOUT_UNTIL_THREAD_TERMINATE : INFINITE) != WAIT_OBJECT_0 
        ? true : (forciblyStop ? TerminateThread(_hThread, NULL) : false))
}

void ServerThread::handleTls(void* s) {
    ServerThread* self = (ServerThread*)s;
    SSL* ssl = NULL;
    SOCKET clientSocket;
    char buf[512];
    while (self->_continueThread) {
        ssl = SSL_new(self->_tlsCtx);
        _acceptMutex.lock();
        if ((clientSocket = WSAAccept(self->_listenSocket, NULL, NULL, NULL, NULL)) == INVALID_SOCKET) {
            continue;
        } else {
            SSL_set_fd(ssl, clientSocket);
            SSL_accept(ssl);
            int bytes = SSL_read(ssl, buf, sizeof(buf));
            std::cout << buf << std::endl;
            SSL_write(ssl, self->_reply.c_str(), self->_reply.length());
            SSL_free(ssl);
            shutdown(clientSocket, SD_SEND);
            closesocket(clientSocket);
        }
    }
}


Server::Server(unsigned int tlsThreadCount, unsigned int httpThreadCount)
    : _tlsListenSocket(createListenSocket(TLS_SERVER_PORT)), _tlsCtx(createTlsCtx()) {
    for (int i = 0; i<tlsThreadCount; i++) {
        _serverThreads.push_back(ServerThread(_tlsListenSocket, ServerThreadType.Tls, &_tlsAcceptMutex, _tlsCtx))
    }
    for (int i = 0; i<httpThreadCount; i++) {

    }
}

bool Server::StopAllThreads(bool forciblyStop=false) {
    bool success = true;
    for (auto const& i : _serverThreads) {
        if (!i.StopThread(forciblyStop)) {
            success = false;
        }
    }
    return success;
}

SSL_CTX* Server::createTlsCtx() {

}