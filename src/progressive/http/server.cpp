#include "server.hpp"

#include <iostream>

namespace progressive::http {

HttpServer::HttpServer(boost::asio::io_context& ioc, std::string_view address, uint16_t port,
                       bool tls, std::string_view cert_path, std::string_view key_path)
    : ioc_(ioc),
      acceptor_(ioc, boost::asio::ip::tcp::endpoint(boost::asio::ip::make_address(address), port)),
      port_(port),
      tls_(tls) {
  if (tls_) {
    ssl_ctx_ =
        std::make_unique<boost::asio::ssl::context>(boost::asio::ssl::context::tlsv12_server);

    if (!cert_path.empty() && !key_path.empty()) {
      ssl_ctx_->use_certificate_chain_file(std::string(cert_path));
      ssl_ctx_->use_private_key_file(std::string(key_path), boost::asio::ssl::context::pem);
    } else {
      // Self-signed for development
      ssl_ctx_->set_options(boost::asio::ssl::context::default_workarounds |
                            boost::asio::ssl::context::no_sslv2 |
                            boost::asio::ssl::context::single_dh_use);
      // Use a temporary self-signed cert
      ssl_ctx_->use_certificate_chain(boost::asio::buffer(ssl_ctx_->native_handle(), 0));
    }
  }
}

HttpServer::~HttpServer() {
  boost::beast::error_code ec;
  acceptor_.close(ec);
}

void HttpServer::set_handler(RequestHandler handler) {
  handler_ = std::move(handler);
}

void HttpServer::start() {
  do_accept();
}

void HttpServer::do_accept() {
  acceptor_.async_accept([this](boost::beast::error_code ec, boost::asio::ip::tcp::socket socket) {
    on_accept(ec, std::move(socket));
  });
}

void HttpServer::on_accept(boost::beast::error_code ec, boost::asio::ip::tcp::socket socket) {
  if (ec) {
    std::cerr << "[http] accept error: " << ec.message() << std::endl;
    return;
  }
  auto session = std::make_shared<HttpSession>(std::move(socket), handler_, ssl_ctx_.get());
  session->run();
  do_accept();
}

HttpSession::HttpSession(boost::asio::ip::tcp::socket socket, RequestHandler handler,
                         boost::asio::ssl::context* ssl_ctx)
    : socket_(std::move(socket)), handler_(std::move(handler)) {
  if (ssl_ctx) {
    tls_ = true;
    ssl_stream_ = std::make_unique<boost::beast::ssl_stream<boost::asio::ip::tcp::socket&>>(
        socket_, *ssl_ctx);
  } else {
    tls_ = false;
  }
}

void HttpSession::run() {
  if (tls_) {
    do_ssl_handshake();
  } else {
    do_read();
  }
}

void HttpSession::do_ssl_handshake() {
  auto self = shared_from_this();
  ssl_stream_->async_handshake(boost::asio::ssl::stream_base::server,
                               [self](boost::beast::error_code ec) { self->on_ssl_handshake(ec); });
}

void HttpSession::on_ssl_handshake(boost::beast::error_code ec) {
  if (ec)
    return;
  do_read();
}

void HttpSession::do_read() {
  auto self = shared_from_this();
  if (tls_) {
    boost_http::async_read(
        *ssl_stream_, buffer_, req_,
        [self](boost::beast::error_code ec, std::size_t bytes) { self->on_read(ec, bytes); });
  } else {
    boost_http::async_read(
        socket_, buffer_, req_,
        [self](boost::beast::error_code ec, std::size_t bytes) { self->on_read(ec, bytes); });
  }
}

void HttpSession::on_read(boost::beast::error_code ec, std::size_t) {
  if (ec == boost_http::error::end_of_stream) {
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    return;
  }
  if (ec)
    return;

  auto response = handler_(std::move(req_));
  res_ = std::make_shared<boost_http::response<boost_http::string_body>>(std::move(response));

  auto self = shared_from_this();
  if (tls_) {
    boost_http::async_write(
        *ssl_stream_, *res_,
        [self, close = res_->need_eof()](boost::beast::error_code ec, std::size_t bytes) {
          self->on_write(close, ec, bytes);
        });
  } else {
    boost_http::async_write(
        socket_, *res_,
        [self, close = res_->need_eof()](boost::beast::error_code ec, std::size_t bytes) {
          self->on_write(close, ec, bytes);
        });
  }
}

void HttpSession::on_write(bool close, boost::beast::error_code ec, std::size_t) {
  if (ec)
    return;
  if (close) {
    boost::beast::error_code ec2;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec2);
    return;
  }
  req_ = {};
  do_read();
}

}  // namespace progressive::http
