#pragma once
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace boost_http = boost::beast::http;

namespace progressive::http {

using RequestHandler = std::function<boost_http::response<boost_http::string_body>(
    boost_http::request<boost_http::string_body>&&)>;

class HttpServer {
public:
  HttpServer(boost::asio::io_context& ioc, std::string_view address, uint16_t port,
             bool tls = false, std::string_view cert_path = "", std::string_view key_path = "");
  ~HttpServer();

  void set_handler(RequestHandler handler);
  void start();
  uint16_t port() const { return port_; }

private:
  void do_accept();
  void on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket);

  boost::asio::io_context& ioc_;
  boost::asio::ip::tcp::acceptor acceptor_;
  uint16_t port_;
  RequestHandler handler_;
  bool tls_;
  std::unique_ptr<boost::asio::ssl::context> ssl_ctx_;
};

class HttpSession : public std::enable_shared_from_this<HttpSession> {
public:
  HttpSession(boost::asio::ip::tcp::socket socket, RequestHandler handler,
              boost::asio::ssl::context* ssl_ctx);
  void run();

private:
  void do_read();
  void on_read(boost::beast::error_code ec, std::size_t bytes);
  void on_write(bool close, boost::beast::error_code ec, std::size_t bytes);
  void do_ssl_handshake();
  void on_ssl_handshake(boost::beast::error_code ec);

  boost::asio::ip::tcp::socket socket_;
  RequestHandler handler_;
  boost::beast::flat_buffer buffer_{8192};
  boost_http::request<boost_http::string_body> req_;
  std::shared_ptr<boost_http::response<boost_http::string_body>> res_;
  bool tls_;
  std::unique_ptr<boost::beast::ssl_stream<boost::asio::ip::tcp::socket&>> ssl_stream_;
};

}  // namespace progressive::http
