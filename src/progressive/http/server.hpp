#pragma once
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace boost_beast = boost::beast;
namespace boost_http = boost::beast::http;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

namespace progressive::http {

using RequestHandler = std::function<boost_http::response<boost_http::string_body>(
    boost_http::request<boost_http::string_body>&&)>;

class HttpServer {
public:
  HttpServer(net::io_context& ioc, std::string_view address, uint16_t port);

  ~HttpServer();

  void set_handler(RequestHandler handler);
  void start();

  uint16_t port() const { return port_; }

private:
  void do_accept();
  void on_accept(boost::beast::error_code ec, tcp::socket socket);

  net::io_context& ioc_;
  tcp::acceptor acceptor_;
  uint16_t port_;
  RequestHandler handler_;
};

class HttpSession : public std::enable_shared_from_this<HttpSession> {
public:
  HttpSession(tcp::socket socket, RequestHandler handler);
  void run();

private:
  void do_read();
  void on_read(boost::beast::error_code ec, std::size_t bytes);
  void on_write(bool close, boost::beast::error_code ec, std::size_t bytes);

  tcp::socket socket_;
  RequestHandler handler_;
  boost::beast::flat_buffer buffer_{8192};
  boost_http::request<boost_http::string_body> req_;
  std::shared_ptr<boost_http::response<boost_http::string_body>> res_;
};

}  // namespace progressive::http
