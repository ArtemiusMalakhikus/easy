#include <iostream>
#include <fstream>
#include <csignal>
#include <chrono>
#include <thread>
#include <vector>
#include <string>
#include <array>
#include <list>
#include <map>
#include <set>

#define HOST_NAME_DEBUG 

#define WINDOWS
#define TCP_SOCKET
#include "may_socket.h"

std::string_view httpsConnectStr{ "CONNECT" };
std::string_view httpConnectStr{ "GET" };
std::string_view status200{ "HTTP/1.1 200 OK\r\n\r\n" };
std::string_view status502{ "HTTP/1.1 502 Bad Gateway\r\n\r\n" };
//std::string_view status407{ "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"abc\"\r\n\r\n" };

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

        if (authorization)
        {
            auto iter = Node::allowedIP.find(static_cast<std::string>(clientAddress.GetIP()));
            if (iter != Node::allowedIP.end())
            {
                --iter->second.first;
                if (iter->second.first == 0)
                    iter->second.second = std::chrono::steady_clock::now();
            }
        }
    }

    static inline std::map<std::string, std::pair<uint32_t, std::chrono::steady_clock::time_point>> allowedIP;

    bool httpConnect{ false };
    bool tcpConnect{ false };
    bool authorization{ false };

    may::SocketAddress clientAddress;

    may::TCPSocket clientSocket;
    std::vector<uint8_t> clientBuffer;

    may::TCPSocket hostSocket;
    std::vector<uint8_t> hostBuffer;

    struct Timeout
    {
        std::chrono::steady_clock::time_point connect;
    } timeout;
};

bool work = true;

#if defined UNIX
void Out(int first)
{
    if (first == SIGINT)
        work = false;
}
#endif

int main()
{
    std::vector<uint8_t> buffer(8192);
    std::list<Node> nodes;

#if defined UNIX
    signal(SIGINT, Out);
    signal(SIGPIPE, SIG_IGN);
#endif

    may::EnableLibrary();

    std::ifstream file("easy.txt", std::ios::in);
    if (!file)
    {
        std::cout << "not found easy.txt file\n";
        return 1;
    }

    std::string addressStr;           //адрес в формате 00.00.00.00:0000
    std::string connectTimeoutStr;    //таймаут на подключение по TCP в миллисекундах
    file >> addressStr;
    file >> connectTimeoutStr;
    file.close();

    /*std::fstream IPfile("ip.txt", std::ios::in | std::ios::binary);
    if (IPfile)
    {
        IPfile.seekg(0, std::ios::end);
        size_t size = IPfile.tellg();
        IPfile.seekg(0, std::ios::beg);

        std::vector<uint8_t> data(size);
        IPfile.read(reinterpret_cast<char*>(data.data()), data.size());

        for (uint8_t* dataPtr = data.data(); dataPtr != data.data() + size;)
        {
            if (*dataPtr == 4)
            {
                allowedIp.emplace(std::string_view{ reinterpret_cast<char*>(dataPtr + 1), 4 });
                dataPtr += 5;
            }
            else if (*dataPtr == 16)
            {
                allowedIp.emplace(std::string_view{ reinterpret_cast<char*>(dataPtr + 1), 16 });
                dataPtr += 17;
            }
        }
    }
    else
    {
        IPfile.open("ip.txt", std::ios::out | std::ios::binary);
    }

    IPfile.close();*/

    may::TCPSocket listeningTcpSocket;
    listeningTcpSocket.CreateSocket(may::AddressFamily::IPV4);
    if (listeningTcpSocket.error != 0)
    {
        std::cout << listeningTcpSocket.errorStr;
        return 1;
    }

    listeningTcpSocket.Bind(addressStr);
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

    may::SocketAddress temporatyAddress(may::AddressFamily::IPV4);
    may::TCPSocket temporarySocket;

    /*may::TCPSocket listeningTcpSocketIPv6;
    listeningTcpSocketIPv6.CreateSocket(may::AddressFamily::IPV6);
    if (listeningTcpSocketIPv6.error != 0)
    {
        std::cout << listeningTcpSocketIPv6.errorStr;
        return 1;
    }

    listeningTcpSocketIPv6.Bind({ "[fd6c:5177:92c4:0:93bd:1633:6998:ee4a]:3000" });
    if (listeningTcpSocketIPv6.error != 0)
    {
        std::cout << listeningTcpSocketIPv6.errorStr;
        return 1;
    }

    listeningTcpSocketIPv6.Listen();
    if (listeningTcpSocketIPv6.error != 0)
    {
        std::cout << listeningTcpSocketIPv6.errorStr;
        return 1;
    }

    listeningTcpSocketIPv6.SetNonBlockingMode();
    if (listeningTcpSocketIPv6.error != 0)
    {
        std::cout << listeningTcpSocketIPv6.errorStr;
        return 1;
    }

    may::SocketAddress temporatyAddressIPv6(may::AddressFamily::IPV6);
    may::TCPSocket temporarySocketIPv6;*/

    std::chrono::steady_clock::time_point timePoint = std::chrono::steady_clock::now();
    std::chrono::milliseconds connectTimeout = std::chrono::milliseconds{ std::stoll(connectTimeoutStr) };

    std::cout << "easy is running\n";

    try
    {
        while (work)
        {
            temporarySocket.socketID = listeningTcpSocket.Accept(temporatyAddress);
            if (temporarySocket.socketID != -1)
            {
                Node& node = nodes.emplace_back();
                node.clientAddress = temporatyAddress;
                node.clientSocket.socketID = temporarySocket.socketID;
                node.clientSocket.SetNonBlockingMode();
                if (node.clientSocket.error != 0)
                {
                    std::cout << node.clientSocket.errorStr;
                    return 1;
                }
            }

            /*temporarySocketIPv6.socketID = listeningTcpSocketIPv6.Accept(temporatyAddressIPv6);
            if (temporarySocketIPv6.socketID != -1)
            {
                Node& node = nodes.emplace_back();
                node.timeout.request = std::chrono::steady_clock::now();
                node.clientSocket.socketID = temporarySocketIPv6.socketID;
                node.clientSocket.SetNonBlockingMode();
                if (node.clientSocket.error != 0)
                {
                    std::cout << node.clientSocket.errorStr;
                    return 1;
                }
            }*/

            if (!Node::allowedIP.empty())
            {
                timePoint = std::chrono::steady_clock::now();
                for (auto iter = Node::allowedIP.begin(); iter != Node::allowedIP.end();)
                {
                    if (iter->second.first == 0 && (timePoint - iter->second.second > std::chrono::minutes(30)))
                        iter = Node::allowedIP.erase(iter);
                    else
                        ++iter;
                }
            }

            if (nodes.empty())
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));

            for (auto nodeIter = nodes.begin(); nodeIter != nodes.end();)
            {
                Node& node = *nodeIter;

                if (std::chrono::steady_clock::now() - node.timeout.connect < connectTimeout)
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
                            index = node.clientSocket.result;
                            size = node.clientBuffer.size() - node.clientSocket.result;
                        }
                        else
                        {
                            std::cout << "client send error: " << node.clientSocket.error
                                << ". close socket: " << node.clientSocket.socketID << ", " << node.hostSocket.socketID
                                << ". socket of counter: " << nodes.size() - 1 << std::endl;
                            nodeIter = nodes.erase(nodeIter);
                            continue;
                        }

                        memcpy(buffer.data(), node.clientBuffer.data(), node.clientBuffer.size());

                        node.clientBuffer.resize(size);
                        memcpy(node.clientBuffer.data(), &buffer[index], node.clientBuffer.size());
                    }
                    else
                    {
                        node.clientBuffer.clear();
                    }

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
                            index = node.hostSocket.result;
                            size = node.hostBuffer.size() - node.hostSocket.result;
                        }
                        else
                        {
                            std::cout << "host send error: " << node.hostSocket.error
                                << ". close socket: " << node.clientSocket.socketID << ", " << node.hostSocket.socketID
                                << ". socket of counter: " << nodes.size() - 1 << std::endl;
                            nodeIter = nodes.erase(nodeIter);
                            continue;
                        }

                        memcpy(buffer.data(), node.hostBuffer.data(), node.hostBuffer.size());

                        node.hostBuffer.resize(size);
                        memcpy(node.hostBuffer.data(), &buffer[index], node.hostBuffer.size());
                    }
                    else
                    {
                        node.hostBuffer.clear();
                    }

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
                                index = node.hostSocket.result;
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

                        ++nodeIter;
                        continue;
                    }
                    else if (memcmp(buffer.data(), httpsConnectStr.data(), httpsConnectStr.size()) == 0)
                    {
                        size_t i = httpsConnectStr.size() + 1;
                        for (; i < buffer.size(); ++i)
                            if (buffer[i] == ' ')
                                break;

                        std::string host;
                        host.resize(i - httpsConnectStr.size() - 1);
                        memcpy(host.data(), &buffer[httpsConnectStr.size() + 1], host.size());

#ifdef HOST_NAME_DEBUG
                        std::cout << "new host: " << host << std::endl;
#endif // HOST_NAME_DEBUG

                        int32_t index = host.find(':');
                        std::string domianName{ host.substr(0, index) };
                        std::string portName{ host.substr(index + 1, host.size() - index - 1) };

                        if (memcmp(&buffer[node.clientSocket.result - 4], "\r\n\r\n", 4) != 0)
                            std::cout << "message is not fulled: " << std::endl;

                        auto ipAddress = node.clientAddress.GetIP();
                        auto iter = Node::allowedIP.find(static_cast<std::string>(ipAddress));
                        if (iter == Node::allowedIP.end())
                        {
                            if (domianName != "mathprofi.ru")
                            {
                                std::cout << "unknown ip address" << std::endl;
                                nodeIter = nodes.erase(nodeIter);
                                continue;
                            }
                            else
                            {
                                node.authorization = true;
                                Node::allowedIP.emplace(ipAddress, std::pair{ 1, std::chrono::steady_clock::now() });
                            }
                        }
                        else
                        {
                            node.authorization = true;
                            ++iter->second.first;
                        }

                        addrinfo hint{};
                        hint.ai_family = static_cast<int>(may::AddressFamily::IPV4);
                        hint.ai_socktype = SOCK_STREAM;
                        hint.ai_protocol = IPPROTO_TCP;

                        std::vector<may::AddressInfo> addressInfos;
                        int result = may::GetAddressInfo(domianName, portName, &hint, addressInfos);
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
                                node.hostSocket.Connect({ addressInfo.addr, static_cast<may::AddressLength>(addressInfo.addrlen) });
                                if (node.hostSocket.result == 0)
                                {
                                    node.timeout.connect = std::chrono::steady_clock::now();
                                    node.tcpConnect = true;
                                    break;
                                }
                            }

                            if (node.tcpConnect)
                            {
                                node.clientSocket.Send(status200.data(), status200.size());
                                if (node.clientSocket.result != static_cast<int>(status200.size()))
                                {
                                    std::cout << "status 200 not send, error: " << node.clientSocket.error << std::endl;
                                    nodeIter = nodes.erase(nodeIter);
                                    continue;
                                }

                                node.httpConnect = true;
                            }
                            else
                            {
                                std::cout << "host connect is fail, error: " << node.hostSocket.error << std::endl;

                                node.clientSocket.Send(status502.data(), status502.size());
                                if (node.clientSocket.result != static_cast<int>(status502.size()))
                                    std::cout << "status 502 not send, error: " << node.clientSocket.error << std::endl;

                                nodeIter = nodes.erase(nodeIter);
                                continue;
                            }
                        }
                        else
                        {
                            std::cout << host << " - address not found, error: " << result << std::endl;

                            node.clientSocket.Send(status502.data(), status502.size());
                            if (node.clientSocket.result != static_cast<int>(status502.size()))
                                std::cout << "status 502 not send, error: " << node.clientSocket.error << std::endl;

                            nodeIter = nodes.erase(nodeIter);
                            continue;
                        }

                        ++nodeIter;
                        continue;
                    }
                    else if (memcmp(buffer.data(), httpConnectStr.data(), httpConnectStr.size()) == 0)
                    {
                        std::string_view bufferStr{ reinterpret_cast<char*>(buffer.data()), static_cast<size_t>(node.clientSocket.result) };
                        auto pos1 = bufferStr.find("Host: ");
                        if (pos1 != -1)
                        {
                            pos1 += std::string_view{ "Host: " }.size();
                            auto pos2 = bufferStr.find("\r\n", pos1);
                            std::string domianName{ bufferStr.substr(pos1, pos2 - pos1) };

                            auto ipAddress = node.clientAddress.GetIP();
                            auto iter = Node::allowedIP.find(static_cast<std::string>(ipAddress));
                            if (iter == Node::allowedIP.end())
                            {
                                if (domianName != "mathprofi.ru")
                                {
                                    std::cout << "unknown ip address" << std::endl;
                                    nodeIter = nodes.erase(nodeIter);
                                    continue;
                                }
                                else
                                {
                                    node.authorization = true;
                                    Node::allowedIP.emplace(ipAddress, std::pair{ 1, std::chrono::steady_clock::now() });
                                }
                            }
                            else
                            {
                                node.authorization = true;
                                ++iter->second.first;
                            }
                            
                            addrinfo hint{};
                            hint.ai_family = static_cast<int>(may::AddressFamily::IPV4);
                            hint.ai_socktype = SOCK_STREAM;
                            hint.ai_protocol = IPPROTO_TCP;

                            std::vector<may::AddressInfo> addressInfos;
                            int result = may::GetAddressInfo(domianName, "80", &hint, addressInfos);
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
                                    node.hostSocket.Connect({ addressInfo.addr, static_cast<may::AddressLength>(addressInfo.addrlen) });
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

                                node.httpConnect = true;
                                node.hostBuffer.resize(bufferStr.size());
                                memcpy(node.hostBuffer.data(), bufferStr.data(), bufferStr.size());

                                ///*
                                //* Копирование в буфер отправки на хост всех заголовков, кроме заголовка Proxy-Connection,
                                //* а также изменение запроса GET на корректный (без http://домен)
                                //*/

                                //std::vector<std::string> headers;
                                //auto pos = bufferStr.find_first_of(domianName);
                                //pos += domianName.size();
                                //std::string endHeader{ bufferStr.substr(pos, bufferStr.find_first_of("\r\n") + 2 - pos) };
                                //headers.push_back("GET " + endHeader);
                                //size_t headersSize = headers[0].size();

                                //for (pos = bufferStr.find_first_of("\r\n"); pos != -1; pos = bufferStr.find_first_of("\r\n", pos))
                                //{
                                //    pos += 2;
                                //    std::string header{ bufferStr.substr(pos, bufferStr.find_first_of("\r\n", pos) + 2 - pos) };
                                //    if (!header.empty() && header.find("Proxy-Connection") == -1)
                                //    {
                                //        headers.push_back(header);
                                //        headersSize += header.size();
                                //    }
                                //}

                                //node.hostBuffer.resize(headersSize);
                                //uint8_t* hostBufferPtr = node.hostBuffer.data();
                                //for (auto& header : headers)
                                //{
                                //    memcpy(hostBufferPtr, header.data(), header.size());
                                //    hostBufferPtr += header.size();
                                //}
                            }
                            else
                            {
                                std::cout << domianName << " - address not found, error: " << result << std::endl;
                                nodeIter = nodes.erase(nodeIter);
                                continue;
                            }
                        }
                        else
                        {
                            for (uint32_t i = 0; i < node.clientSocket.result; ++i)
                                std::cout << buffer[i];

                            std::cout << "unknown format" << std::endl;
                            nodeIter = nodes.erase(nodeIter);
                            continue;
                        }

                        ++nodeIter;
                        continue;
                    }
                    else
                    {
                        for (uint32_t i = 0; i < node.clientSocket.result; ++i)
                            std::cout << buffer[i];

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
                                index = node.clientSocket.result;
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

                    ++nodeIter;
                    continue;
                }

                ++nodeIter;
            }
        }
    }
    catch (std::exception& e)
    {
        std::cerr << e.what() << std::endl;
    }

    nodes.clear();

    listeningTcpSocket.Close();
    if (listeningTcpSocket.error != 0)
        std::cout << listeningTcpSocket.errorStr;

    may::DisableLibrary();

    std::cout << "close easy\n";
    return 0;
}
