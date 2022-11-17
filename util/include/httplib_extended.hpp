#pragma once
#include "httplib.h"
#include "Logger.hpp"

using namespace httplib;

namespace httplibExtended {
class AuthorizedClient : public ClientImpl {
 public:
  // HTTP only interface
  explicit AuthorizedClient(const std::string &host);
  explicit AuthorizedClient(const std::string &host, int port, const int client_authorized_port);
  explicit AuthorizedClient(const std::string &host,
                            int port,
                            const int client_authorized_port,
                            const std::string &client_cert_path,
                            const std::string &client_key_path);
  virtual ~AuthorizedClient() = default;
  bool create_and_connect_socket(Socket &socket, Error &error) override;

 private:
  // Socket endoint information
  socket_t create_client_socket(Error &error) const;

  socket_t create_client_socket(const std::string &host,
                                const std::string &ip,
                                int port,
                                int address_family,
                                bool tcp_nodelay,
                                SocketOptions socket_options,
                                time_t connection_timeout_sec,
                                time_t connection_timeout_usec,
                                time_t read_timeout_sec,
                                time_t read_timeout_usec,
                                time_t write_timeout_sec,
                                time_t write_timeout_usec,
                                const std::string &intf,
                                Error &error) const;

  /*template <typename BindOrConnect>
  socket_t create_socket(const std::string &host, const std::string &ip, int port,
                 int address_family, int socket_flags, bool tcp_nodelay,
                 SocketOptions socket_options,
                 BindOrConnect bind_or_connect) const ;*/
  // Socket endoint information
  int c_port_;
  logging::Logger my_logger_;
};

inline AuthorizedClient::AuthorizedClient(const std::string &host)
    : ClientImpl(host, 8080), c_port_(7888), my_logger_(logging::getLogger("concord.secretretriever")) {}

inline AuthorizedClient::AuthorizedClient(const std::string &host, int port, const int client_authorized_port)
    : ClientImpl(host, port),
      c_port_(client_authorized_port),
      my_logger_(logging::getLogger("concord.secretretriever")) {}

inline AuthorizedClient::AuthorizedClient(const std::string &host,
                                          int port,
                                          const int client_authorized_port,
                                          const std::string &client_cert_path,
                                          const std::string &client_key_path)
    : ClientImpl(host, port, client_cert_path, client_key_path),
      c_port_(client_authorized_port),
      my_logger_(logging::getLogger("concord.secretretriever")) {}

inline bool AuthorizedClient::create_and_connect_socket(Socket &socket, Error &error) {
  auto sock = create_client_socket(error);
  if (sock == INVALID_SOCKET) {
    return false;
  }
  socket.sock = sock;
  return true;
}

inline socket_t AuthorizedClient::create_client_socket(Error &error) const {
  if (!proxy_host_.empty() && proxy_port_ != -1) {
    return create_client_socket(proxy_host_,
                                std::string(),
                                proxy_port_,
                                address_family_,
                                tcp_nodelay_,
                                socket_options_,
                                connection_timeout_sec_,
                                connection_timeout_usec_,
                                read_timeout_sec_,
                                read_timeout_usec_,
                                write_timeout_sec_,
                                write_timeout_usec_,
                                interface_,
                                error);
  }

  // Check is custom IP specified for host_
  std::string ip;
  auto it = addr_map_.find(host_);
  if (it != addr_map_.end()) ip = it->second;
  return create_client_socket(host_,
                              ip,
                              port_,
                              address_family_,
                              tcp_nodelay_,
                              socket_options_,
                              connection_timeout_sec_,
                              connection_timeout_usec_,
                              read_timeout_sec_,
                              read_timeout_usec_,
                              write_timeout_sec_,
                              write_timeout_usec_,
                              interface_,
                              error);
}

inline socket_t AuthorizedClient::create_client_socket(const std::string &host,
                                                       const std::string &ip,
                                                       int port,
                                                       int address_family,
                                                       bool tcp_nodelay,
                                                       SocketOptions socket_options,
                                                       time_t connection_timeout_sec,
                                                       time_t connection_timeout_usec,
                                                       time_t read_timeout_sec,
                                                       time_t read_timeout_usec,
                                                       time_t write_timeout_sec,
                                                       time_t write_timeout_usec,
                                                       const std::string &intf,
                                                       Error &error) const {
  auto sock = httplib::detail::create_socket(
      host,
      ip,
      port,
      address_family,
      0,
      tcp_nodelay,
      std::move(socket_options),
      [&](socket_t sock2, struct addrinfo &ai) -> bool {
        if (!intf.empty()) {
#ifdef USE_IF2IP
          auto ip_from_if = httplib::detail::if2ip(address_family, intf);
          if (ip_from_if.empty()) {
            ip_from_if = intf;
          }
          if (!httplib::detail::bind_ip_address(sock2, ip_from_if.c_str())) {
            error = Error::BindIPAddress;
            return false;
          }
#endif
        }
        LOG_INFO(my_logger_, "create_socket called with  " << c_port_);
        if (c_port_ != -1) {
          struct addrinfo hints;
          struct addrinfo *result;

          memset(&hints, 0, sizeof(struct addrinfo));
          hints.ai_family = AF_UNSPEC;
          hints.ai_socktype = SOCK_STREAM;
          hints.ai_protocol = 0;

          if (getaddrinfo(host.c_str(), std::to_string(c_port_).c_str(), &hints, &result)) {
            return false;
          }
          LOG_INFO(my_logger_, "Binding the socker with " << c_port_);
          auto ret = false;
          for (auto rp = result; rp; rp = rp->ai_next) {
            const auto &ai = *rp;
            if (!::bind(sock2, ai.ai_addr, static_cast<socklen_t>(ai.ai_addrlen))) {
              ret = true;
              break;
            }
          }

          freeaddrinfo(result);
        }

        httplib::detail::set_nonblocking(sock2, true);

        auto ret = ::connect(sock2, ai.ai_addr, static_cast<socklen_t>(ai.ai_addrlen));

        if (ret < 0) {
          if (httplib::detail::is_connection_error()) {
            error = Error::Connection;
            return false;
          }
          error = httplib::detail::wait_until_socket_is_ready(sock2, connection_timeout_sec, connection_timeout_usec);
          if (error != Error::Success) {
            return false;
          }
        }

        httplib::detail::set_nonblocking(sock2, false);

        {
#ifdef _WIN32
          auto timeout = static_cast<uint32_t>(read_timeout_sec * 1000 + read_timeout_usec / 1000);
          setsockopt(sock2, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));
#else
          timeval tv;
          tv.tv_sec = static_cast<long>(read_timeout_sec);
          tv.tv_usec = static_cast<decltype(tv.tv_usec)>(read_timeout_usec);
          setsockopt(sock2, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv));
#endif
        }
        {

#ifdef _WIN32
          auto timeout = static_cast<uint32_t>(write_timeout_sec * 1000 + write_timeout_usec / 1000);
          setsockopt(sock2, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(timeout));
#else
          timeval tv;
          tv.tv_sec = static_cast<long>(write_timeout_sec);
          tv.tv_usec = static_cast<decltype(tv.tv_usec)>(write_timeout_usec);
          setsockopt(sock2, SOL_SOCKET, SO_SNDTIMEO, (char *)&tv, sizeof(tv));
#endif
        }

        error = Error::Success;
        return true;
      });

  if (sock != INVALID_SOCKET) {
    error = Error::Success;
  } else {
    if (error == Error::Success) {
      error = Error::Connection;
    }
  }

  return sock;
}

}  // namespace httplibExtended
   // namespace httplibExtended
