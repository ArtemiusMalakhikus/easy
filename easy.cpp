#include <iostream>
#include <fstream>
#include <csignal>
#include <chrono>
#include <vector>
#include <string>
#include <array>
#include <list>
#include <map>

#define WINDOWS
#define TCP_SOCKET
#include "may_socket.h"

std::string_view connectStr{ "CONNECT" };
std::string_view status200{ "HTTP/1.1 200 OK\r\n\r\n" };

struct Node
{
    ~Node()
    {
        clientSocket.Close();
        if (clientSocket.error != 0)
            std::cout << clientSocket.errorStr;

        hostSocket.Close();
        if (hostSocket.error != 0)
            std::cout << hostSocket.errorStr;
    }

    bool httpConnect{ false };
    bool tcpConnect{ false };

    may::TCPSocket clientSocket;
    std::vector<uint8_t> clientBuffer;

    may::TCPSocket hostSocket;
    std::vector<uint8_t> hostBuffer;

    struct Timeout
    {
        std::chrono::steady_clock::time_point connect;
        std::chrono::steady_clock::time_point request;
    } timeout;
};

bool work = true;

void Out(int first)
{
    if (first == SIGINT)
        work = false;
}

int main()
{
    std::vector<uint8_t> buffer(4096);
    std::list<Node> nodes;

    may::EnableLibrary();

    std::ifstream file("easy.txt", std::ios::in);
    if (!file)
    {
        std::cout << "not found easy.txt file\n";
        return 1;
    }

    std::string addressStr;        //адрес в формате 00.00.00.00:0000
    std::string connectTimeoutStr; //таймаут на подключение по TCP в миллисекундах
    std::string requestTimeoutStr; //таймаут на приём и передачу данных в миллисекундах
    file >> addressStr;
    file >> connectTimeoutStr;
    file >> requestTimeoutStr;
    file.close();

    may::SocketAddress address;
    address.InitSocketAddressIPv4(addressStr);

    may::TCPSocket listeningTcpSocket;
    listeningTcpSocket.CreateSocket(may::AddressFamily::IPV4);
    if (listeningTcpSocket.error != 0)
    {
        std::cout << listeningTcpSocket.errorStr;
        return 1;
    }

    listeningTcpSocket.Bind(address);
    if (listeningTcpSocket.error != 0)
    {
        std::cout << listeningTcpSocket.errorStr;
        return 1;
    }

    listeningTcpSocket.Listen();
    if (listeningTcpSocket.error != 0)
    {
        std::cout << listeningTcpSocket.errorStr;
        return 1;
    }

    listeningTcpSocket.SetNonBlockingMode();
    if (listeningTcpSocket.error != 0)
    {
        std::cout << listeningTcpSocket.errorStr;
        return 1;
    }

    signal(SIGINT, Out);

    may::SocketAddress temporatyAddress;
    may::TCPSocket temporarySocket;

    std::chrono::milliseconds connectTimeout = std::chrono::milliseconds{ std::stoll(connectTimeoutStr) };
    std::chrono::milliseconds requestTimeout = std::chrono::milliseconds{ std::stoll(requestTimeoutStr) };

    std::cout << "easy is running\n";

    while (work)
    {
        temporarySocket.socketID = listeningTcpSocket.Accept(temporatyAddress);
        if (temporarySocket.socketID != -1)
        {
            Node& node = nodes.emplace_back();
            node.clientSocket.socketID = temporarySocket.socketID;
            node.clientSocket.SetNonBlockingMode();
            if (node.clientSocket.error != 0)
            {
                std::cout << node.clientSocket.errorStr;
                return 1;
            }
        }

        for (auto nodeIter = nodes.begin(); nodeIter != nodes.end();)
        {
            Node& node = *nodeIter;
            std::chrono::steady_clock::time_point timePoint = std::chrono::steady_clock::now();

            if (timePoint - node.timeout.connect < connectTimeout)
            {
                ++nodeIter;
                continue;
            }

            if (timePoint - node.timeout.request < requestTimeout)
            {
                ++nodeIter;
                continue;
            }

            if (!node.clientBuffer.empty())
            {
                node.clientSocket.Send(reinterpret_cast<const char*>(node.clientBuffer.data()), node.clientBuffer.size());
                if (node.clientSocket.result < static_cast<int>(node.clientBuffer.size()))
                {
                    size_t index = 0;
                    size_t size = 0;
                    if (node.clientSocket.error == SOCKET_WOULDBLOCK)
                    {
                        size = node.clientBuffer.size();
                    }
                    else if (node.clientSocket.error == 0)
                    {
                        index = node.clientBuffer.size();
                        size = node.clientBuffer.size() - node.clientSocket.result;
                    }
                    else
                    {
                        std::cout << "error: " << node.clientSocket.error
                            << ". close socket: " << node.clientSocket.socketID << ", " << node.hostSocket.socketID
                            << ". socket of counter: " << nodes.size() - 1 << std::endl;
                        nodeIter = nodes.erase(nodeIter);
                        continue;
                    }

                    if (!node.clientBuffer.empty())
                        memcpy(buffer.data(), node.clientBuffer.data(), node.clientBuffer.size());

                    node.clientBuffer.resize(size);
                    memcpy(node.clientBuffer.data(), &buffer[index], node.clientBuffer.size());
                }
                else
                {
                    node.clientBuffer.clear();
                }

                node.timeout.request = std::chrono::steady_clock::now();
                ++nodeIter;
                continue;
            }

            if (!node.hostBuffer.empty())
            {
                node.hostSocket.Send(reinterpret_cast<const char*>(node.hostBuffer.data()), node.hostBuffer.size());
                if (node.hostSocket.result < static_cast<int>(node.hostBuffer.size()))
                {
                    size_t index = 0;
                    size_t size = 0;
                    if (node.hostSocket.error == SOCKET_WOULDBLOCK)
                    {
                        size = node.hostBuffer.size();
                    }
                    else if (node.hostSocket.error == 0)
                    {
                        index = node.hostBuffer.size();
                        size = node.hostBuffer.size() - node.hostSocket.result;
                    }
                    else
                    {
                        std::cout << "error: " << node.hostSocket.error
                            << ". close socket: " << node.clientSocket.socketID << ", " << node.hostSocket.socketID
                            << ". socket of counter: " << nodes.size() - 1 << std::endl;
                        nodeIter = nodes.erase(nodeIter);
                        continue;
                    }

                    if (!node.hostBuffer.empty())
                        memcpy(buffer.data(), node.hostBuffer.data(), node.hostBuffer.size());

                    node.hostBuffer.resize(size);
                    memcpy(node.hostBuffer.data(), &buffer[index], node.hostBuffer.size());
                }
                else
                {
                    node.hostBuffer.clear();
                }

                node.timeout.request = std::chrono::steady_clock::now();
                ++nodeIter;
                continue;
            }

            node.clientSocket.Receive(reinterpret_cast<char*>(buffer.data()), buffer.size());
            if (node.clientSocket.result > 0)
            {
                if (node.httpConnect && node.tcpConnect)
                {
                    node.hostSocket.Send(reinterpret_cast<const char*>(buffer.data()), node.clientSocket.result);
                    if (node.hostSocket.result < node.clientSocket.result)
                    {
                        size_t index = 0;
                        size_t size = 0;
                        if (node.hostSocket.error == SOCKET_WOULDBLOCK)
                        {
                            size = node.clientSocket.result;
                        }
                        else if (node.hostSocket.error == 0)
                        {
                            index = node.clientSocket.result;
                            size = node.clientSocket.result - node.hostSocket.result;
                        }
                        else
                        {
                            std::cout << "host send error: " << node.hostSocket.error
                                << ". close socket: " << node.clientSocket.socketID << ", " << node.hostSocket.socketID
                                << ". socket of counter: " << nodes.size() - 1 << std::endl;
                            nodeIter = nodes.erase(nodeIter);
                            continue;
                        }

                        node.hostBuffer.resize(size);
                        memcpy(node.hostBuffer.data(), &buffer[index], node.hostBuffer.size());
                    }

                    node.timeout.request = std::chrono::steady_clock::now();
                    ++nodeIter;
                    continue;
                }
                else if (memcmp(buffer.data(), connectStr.data(), connectStr.size()) == 0)
                {
                    /*for (uint32_t i = 0; i < client.clientSocket.result; ++i)
                        std::cout << buffer[i];*/

                    node.clientSocket.Send(status200.data(), status200.size());
                    if (node.clientSocket.result != static_cast<int>(status200.size()))
                    {
                        std::cout << "status 200 not send: " << node.clientSocket.result << std::endl;
                        nodeIter = nodes.erase(nodeIter);
                        continue;
                    }

                    node.httpConnect = true;

                    size_t i = connectStr.size() + 1;
                    for (; i < buffer.size(); ++i)
                        if (buffer[i] == ' ')
                            break;

                    std::string host;
                    host.resize(i - connectStr.size() - 1);
                    memcpy(host.data(), &buffer[connectStr.size() + 1], host.size());

                    //std::cout << "new host: " << host;

                    int32_t index = host.find(':');
                    std::string domianName{ host.substr(0, index) };
                    std::string portName{ host.substr(index + 1, host.size() - index - 1) };

                    addrinfo hint{};
                    hint.ai_family = static_cast<int>(may::AddressFamily::IPV4);
                    hint.ai_socktype = SOCK_STREAM;
                    hint.ai_protocol = IPPROTO_TCP;

                    //auto t = std::chrono::steady_clock::now();
                    std::vector<may::AddressInfo> addressInfos;
                    int result = may::GetAddressInfo(domianName, portName, &hint, addressInfos);
                    //float t1 = std::chrono::milliseconds((std::chrono::steady_clock::now() - t).count()).count();
                    //std::cout << "t: " << t1 << std::endl;
                    if (!addressInfos.empty())
                    {
                        node.hostSocket.CreateSocket(may::AddressFamily::IPV4);
                        if (node.hostSocket.error != 0)
                        {
                            std::cout << node.hostSocket.errorStr;
                            return 1;
                        }

                        node.hostSocket.SetNonBlockingMode();
                        if (node.hostSocket.error != 0)
                        {
                            std::cout << node.hostSocket.errorStr;
                            return 1;
                        }

                        for (auto& addressInfo : addressInfos)
                        {
                            node.hostSocket.Connect(addressInfo.addr);
                            if (node.hostSocket.result == 0)
                            {
                                node.timeout.connect = std::chrono::steady_clock::now();
                                node.tcpConnect = true;
                                break;
                            }
                        }

                        if (!node.tcpConnect)
                        {
                            std::cout << "host connect is fail, error: " << node.hostSocket.error << std::endl;
                            nodeIter = nodes.erase(nodeIter);
                            continue;
                        }
                    }
                    else
                    {
                        std::cout << host << " - address not found, error: " << result << std::endl;
                        nodeIter = nodes.erase(nodeIter);
                        continue;
                    }

                    ++nodeIter;
                    continue;
                }
                else
                {
                    std::cout << "unknown format" << std::endl;
                    nodeIter = nodes.erase(nodeIter);
                    continue;
                }
            }
            else if (node.clientSocket.result == 0 || node.clientSocket.error != SOCKET_WOULDBLOCK)
            {
                if (node.clientSocket.error != 0 && node.clientSocket.error != SOCKET_WOULDBLOCK)
                {
                    std::cout << "client receive error: " << node.clientSocket.error
                        << ". close socket: " << node.clientSocket.socketID << ", " << node.hostSocket.socketID
                        << ". socket of counter: " << nodes.size() - 1 << std::endl;
                }
                nodeIter = nodes.erase(nodeIter);
                continue;
            }

            if (node.tcpConnect)
            {
                node.hostSocket.Receive(reinterpret_cast<char*>(buffer.data()), buffer.size());
                if (node.hostSocket.result > 0)
                {
                    node.clientSocket.Send(reinterpret_cast<const char*>(buffer.data()), node.hostSocket.result);
                    if (node.clientSocket.result < node.hostSocket.result)
                    {
                        size_t index = 0;
                        size_t size = 0;
                        if (node.clientSocket.error == SOCKET_WOULDBLOCK)
                        {
                            size = node.hostSocket.result;
                        }
                        else if (node.clientSocket.error == 0)
                        {
                            index = node.hostSocket.result;
                            size = node.hostSocket.result - node.clientSocket.result;
                        }
                        else
                        {
                            std::cout << "client send error: " << node.clientSocket.error
                                << ". close socket: " << node.clientSocket.socketID << ", " << node.hostSocket.socketID
                                << ". socket of counter: " << nodes.size() - 1 << std::endl;
                            nodeIter = nodes.erase(nodeIter);
                            continue;
                        }

                        node.clientBuffer.resize(size);
                        memcpy(node.clientBuffer.data(), &buffer[index], node.clientBuffer.size());
                    }
                }
                else if (node.hostSocket.result == 0 || node.hostSocket.error != SOCKET_WOULDBLOCK)
                {
                    if (node.hostSocket.error != 0 && node.hostSocket.error != SOCKET_WOULDBLOCK)
                    {
                        std::cout << "host receive error: " << node.hostSocket.error
                            << ". close socket: " << node.clientSocket.socketID << ", " << node.hostSocket.socketID
                            << ". socket of counter: " << nodes.size() - 1 << std::endl;
                    }
                    nodeIter = nodes.erase(nodeIter);
                    continue;
                }

                node.timeout.request = std::chrono::steady_clock::now();
                ++nodeIter;
                continue;
            }

            ++nodeIter;
        }
    }

    nodes.clear();

    listeningTcpSocket.Close();
    if (listeningTcpSocket.error != 0)
        std::cout << listeningTcpSocket.errorStr;

    may::DisableLibrary();

    std::cout << "close easy\n";
    return 0;
}