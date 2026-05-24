#pragma once
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <string_view>

#include "../storage/database.hpp"
#include "parser.hpp"
#include "services.hpp"

namespace progressive::irc {

class IrcServer {
public:
  IrcServer(boost::asio::io_context& ioc, uint16_t port, std::string_view server_name,
            storage::DatabasePool& db);
  void start();

  void send_numeric(const std::string& target, int code, const std::string& msg);
  void broadcast(const std::string& channel, const std::string& sender, const std::string& cmd,
                 const std::string& msg);

  storage::DatabasePool& db() { return db_; }
  std::string server_name() const { return server_name_; }

private:
  void do_accept();
  void on_accept(boost::system::error_code ec, boost::asio::ip::tcp::socket socket);

  boost::asio::io_context& ioc_;
  boost::asio::ip::tcp::acceptor acceptor_;
  std::string server_name_;
  storage::DatabasePool& db_;
  IrcServices services_;
  std::map<std::string, std::shared_ptr<class IrcClient>> clients_;
  std::map<std::string, IrcChannel, std::less<>> channels_;

  friend class IrcClient;
};

class IrcClient : public std::enable_shared_from_this<IrcClient> {
public:
  IrcClient(boost::asio::ip::tcp::socket socket, IrcServer& server);
  void start();
  void send(std::string msg);
  void send_reply(int code, const std::string& msg);

  IrcSession& session() { return session_; }
  IrcServer& server() { return server_; }

private:
  void do_read();
  void on_read(boost::system::error_code ec, std::size_t bytes);
  void handle_message(const IrcMessage& msg);
  void do_write();

  boost::asio::ip::tcp::socket socket_;
  IrcServer& server_;
  IrcSession session_;
  boost::beast::flat_buffer buffer_{512};
  std::string write_buffer_;
  bool writing_ = false;
};

}  // namespace progressive::irc
