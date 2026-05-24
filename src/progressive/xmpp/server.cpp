#include "server.hpp"

#include <array>
#include <iostream>
#include <regex>
#include <sstream>

#include "../storage/database.hpp"
#include "../util/random.hpp"
#include "../util/time.hpp"

namespace progressive::xmpp {

static std::string xml_content(std::string_view xml, std::string_view tag) {
  std::string open_tag = "<" + std::string(tag) + ">";
  std::string close_tag = "</" + std::string(tag) + ">";
  auto start = xml.find(open_tag);
  if (start == std::string::npos)
    return "";
  start += open_tag.size();
  auto end = xml.find(close_tag, start);
  if (end == std::string::npos)
    return "";
  return std::string(xml.substr(start, end - start));
}

XmppServer::XmppServer(boost::asio::io_context& ioc, uint16_t port, std::string_view server_name,
                       storage::DatabasePool& db)
    : ioc_(ioc),
      acceptor_(ioc, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
      server_name_(server_name),
      db_(db) {}

void XmppServer::start() {
  do_accept();
}

void XmppServer::do_accept() {
  acceptor_.async_accept([this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
    if (!ec) {
      auto c = std::make_shared<XmppClient>(std::move(socket), *this);
      c->start();
    }
    do_accept();
  });
}

void XmppServer::broadcast_presence(const std::string& jid, const std::string& show,
                                    const std::string& status) {
  std::stringstream xml;
  xml << "<presence from='" << jid << "'";
  if (!show.empty())
    xml << "><show>" << show << "</show>";
  if (!status.empty())
    xml << "<status>" << status << "</status>";
  xml << "</presence>";
  for (auto& [cj, client] : clients_)
    client->send(xml.str());
}

XmppClient::XmppClient(boost::asio::ip::tcp::socket socket, XmppServer& server)
    : socket_(std::move(socket)), server_(server) {}

void XmppClient::start() {
  do_read();
}

void XmppClient::send(std::string_view xml) {
  auto self = shared_from_this();
  writing_ = true;
  boost::asio::async_write(
      socket_, boost::asio::buffer(std::string(xml)),
      [self](boost::system::error_code, std::size_t) { self->writing_ = false; });
}

void XmppClient::do_read() {
  auto buf = std::make_shared<std::array<char, 2048>>();
  auto self = shared_from_this();
  socket_.async_read_some(
      boost::asio::buffer(*buf), [self, buf](boost::system::error_code ec, std::size_t len) {
        if (ec)
          return;
        std::string data(buf->data(), len);
        if (!self->stream_open_) {
          self->handle_open_stream(data);
          self->do_read();
          return;
        }
        if (data.find("<message") != std::string::npos) {
          XmppStanza s;
          s.from = xml_content(data, "from");
          s.to = xml_content(data, "to");
          s.type = xml_content(data, "type");
          s.body = xml_content(data, "body");
          self->handle_stanza(s);
        } else if (data.find("<presence") != std::string::npos) {
          self->server_.broadcast_presence(self->jid_, "online", "");
        } else if (data.find("<iq") != std::string::npos) {
          std::string id = xml_content(data, "id");
          std::stringstream reply;
          reply << "<iq type='result' id='" << id << "' from='" << self->server_.server_name()
                << "' to='" << self->jid_ << "'/>";
          self->send(reply.str());
        }
        if (data.find("</stream:stream>") != std::string::npos) {
          self->send("</stream:stream>");
          self->server_.clients_.erase(self->jid_);
          return;
        }
        self->do_read();
      });
}

void XmppClient::handle_open_stream(std::string_view) {
  std::stringstream header;
  header << "<?xml version='1.0'?>\r\n"
         << "<stream:stream xmlns='jabber:client' "
         << "xmlns:stream='http://etherx.jabber.org/streams' "
         << "from='" << server_.server_name() << "' "
         << "id='" << util::random_token(16) << "' version='1.0'>\r\n"
         << "<stream:features>"
         << "<mechanisms "
            "xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms>"
         << "</stream:features>";
  send(header.str());
  stream_open_ = true;
  authenticated_ = true;
  jid_ = "user@" + server_.server_name();
  server_.clients_[jid_] = shared_from_this();

  server_.db().execute("INSERT OR IGNORE INTO users (id,creation_ts) VALUES ('@" + jid_ + ":" +
                       server_.server_name() + "'," + std::to_string(util::now_ms()) + ")");
}

void XmppClient::handle_stanza(const XmppStanza& s) {
  if (!s.body.empty()) {
    std::stringstream reply;
    reply << "<message from='" << s.to << "' to='" << jid_ << "' type='chat'><body>" << s.body
          << "</body></message>";
    send(reply.str());
  }
}

}  // namespace progressive::xmpp
