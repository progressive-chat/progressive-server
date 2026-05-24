#pragma once
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <string_view>

#include "../storage/database.hpp"

namespace progressive::xmpp {

struct XmppStanza {
  std::string from;
  std::string to;
  std::string type;
  std::string id;
  std::string body;
  std::string show;    // presence
  std::string status;  // presence status
};

class XmppServer {
public:
  XmppServer(boost::asio::io_context& ioc, uint16_t port, std::string_view server_name,
             storage::DatabasePool& db);
  void start();
  void broadcast_presence(const std::string& jid, const std::string& show,
                          const std::string& status);

  storage::DatabasePool& db() { return db_; }
  std::string server_name() const { return server_name_; }

private:
  void do_accept();
  void on_accept(boost::system::error_code ec, boost::asio::ip::tcp::socket socket);

  boost::asio::io_context& ioc_;
  boost::asio::ip::tcp::acceptor acceptor_;
  std::string server_name_;
  storage::DatabasePool& db_;
  std::map<std::string, std::shared_ptr<class XmppClient>, std::less<>> clients_;
  std::map<std::string, std::set<std::string>, std::less<>> rooms_;  // room_jid -> members

  friend class XmppClient;
};

class XmppClient : public std::enable_shared_from_this<XmppClient> {
public:
  XmppClient(boost::asio::ip::tcp::socket socket, XmppServer& server);
  void start();
  void send(std::string_view xml);
  std::string jid() const { return jid_; }
  XmppServer& server() { return server_; }

private:
  void do_read();
  void on_read(boost::system::error_code ec, std::size_t bytes);
  void handle_open_stream(std::string_view data);
  void handle_stanza(const XmppStanza& s);
  void do_write();

  boost::asio::ip::tcp::socket socket_;
  XmppServer& server_;
  std::string jid_;
  bool stream_open_ = false;
  bool authenticated_ = false;
  boost::beast::flat_buffer buffer_{4096};
  std::string write_buffer_;
  bool writing_ = false;
};

}  // namespace progressive::xmpp
