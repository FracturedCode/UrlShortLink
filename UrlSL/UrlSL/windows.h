#pragma once
ServerThread::ServerThread(SOCKET listenSocket, ServerThreadType type, std::mutex* acceptMutex, SSL_CTX* tlsCtx)
    : _listenSocket(listenSocket), _type(type), _acceptMutext(acceptMutex), _tlsCtx(tlsCtx), _continueThread(false) {
    _hThread = (HANDLE)_beginthread(type==ServerThreadType.Tls ? ServerThread::handleTls : ServerThread::handleHttp, 0, (void*)this);
}

ServerThread::StopThread(bool forciblyStop=false) {
    _shouldHandleStop = true;
    return (WaitForSingleObject(_hThread, forciblyStop ? TIMEOUT_UNTIL_THREAD_TERMINATE : INFINITE) != WAIT_OBJECT_0 
        ? true : (forciblyStop ? TerminateThread(_hThread, NULL) : false))
}

ServerThread::handleTls(void* s) {
    ServerThread* self = (ServerThread*)s;
    while (self->_continueThread) {

    }
}