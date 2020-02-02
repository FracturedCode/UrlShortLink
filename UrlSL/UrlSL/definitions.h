#include <mutex>
#include <list>
#pragma once
enum ServerThreadType {
    Tls,
    Http
};

class Server {
private:
    class ServerThread {
    private:
        SOCKET _listenSocket;
        ServerThreadType _type;
        HANDLE _hThread;
        SSL_CTX* _tlsCtx;
        bool _continueThread;

        static void handleTls(void* s);
        static void handleHttp(void* s);    //TODO
    public:
        ServerThread(SOCKET listenSocket, ServerThreadType type, SSL_CTX* tlsCtx);

        ServerThreadType GetType() const { return _type; }

        bool StopThread(bool forciblyStop = false);
    };

    SOCKET _tlsListenSocket;
    std::list<ServerThread> _serverThreads;
    std::mutex _tlsAcceptMutex;
    SSL_CTX* _tlsCtx;

    static SOCKET createListenSocket(int port);
    static SSL_CTX* createTlsCtx();
public:
    Server(unsigned int TlsThreadCount, bool createHttpThread);
    ~Server();

    SOCKET accept(SOCKET listenSocket);
    bool StopAllThreads(bool forciblyStop = false);
};