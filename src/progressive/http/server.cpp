#include "server.hpp"

#include <iostream>

namespace progressive::http {

HttpServer::HttpServer(net::io_context& ioc, std::string_view address, uint16_t port)
    : ioc_(ioc), acceptor_(ioc, tcp::endpoint(net::ip::make_address(address), port)), port_(port) {}

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
  acceptor_.async_accept([this](boost::beast::error_code ec, tcp::socket socket) {
    on_accept(ec, std::move(socket));
  });
}

void HttpServer::on_accept(boost::beast::error_code ec, tcp::socket socket) {
  if (ec) {
    std::cerr << "[http] accept error: " << ec.message() << std::endl;
    return;
  }
  auto session = std::make_shared<HttpSession>(std::move(socket), handler_);
  session->run();
  do_accept();
}

HttpSession::HttpSession(tcp::socket socket, RequestHandler handler)
    : socket_(std::move(socket)), handler_(std::move(handler)) {}

void HttpSession::run() {
  do_read();
}

void HttpSession::do_read() {
  auto self = shared_from_this();
  boost_http::async_read(
      socket_, buffer_, req_,
      [self](boost::beast::error_code ec, std::size_t bytes) { self->on_read(ec, bytes); });
}

void HttpSession::on_read(boost::beast::error_code ec, std::size_t) {
  if (ec == boost_http::error::end_of_stream) {
    socket_.shutdown(tcp::socket::shutdown_send, ec);
    return;
  }
  if (ec)
    return;

  auto response = handler_(std::move(req_));
  auto res = std::make_shared<boost_http::response<boost_http::string_body>>(std::move(response));
  res_ = res;

  auto self = shared_from_this();
  boost_http::async_write(
      socket_, *res_,
      [self, close = res_->need_eof()](boost::beast::error_code ec, std::size_t bytes) {
        self->on_write(close, ec, bytes);
      });
}

void HttpSession::on_write(bool close, boost::beast::error_code ec, std::size_t) {
  if (ec)
    return;
  if (close) {
    boost::beast::error_code ec2;
    socket_.shutdown(tcp::socket::shutdown_send, ec2);
    return;
  }
  req_ = {};
  do_read();
}

}  // namespace progressive::http
