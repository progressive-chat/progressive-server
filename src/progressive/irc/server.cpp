#include "server.hpp"

#include <iomanip>
#include <iostream>
#include <sstream>

#include "../events/event_factory.hpp"
#include "../types/matrix_id.hpp"
#include "../util/random.hpp"
#include "../util/time.hpp"

namespace progressive::irc {

IrcServer::IrcServer(boost::asio::io_context& ioc, uint16_t port, std::string_view server_name,
                     storage::DatabasePool& db)
    : ioc_(ioc),
      acceptor_(ioc, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)),
      server_name_(server_name),
      db_(db) {}

void IrcServer::start() {
  do_accept();
}

void IrcServer::do_accept() {
  acceptor_.async_accept([this](boost::system::error_code ec, boost::asio::ip::tcp::socket socket) {
    if (!ec) {
      auto client = std::make_shared<IrcClient>(std::move(socket), *this);
      client->start();
    }
    do_accept();
  });
}

void IrcServer::send_numeric(const std::string& target, int code, const std::string& msg) {
  auto it = clients_.find(target);
  if (it != clients_.end()) {
    std::stringstream ss;
    ss << ':' << server_name_ << ' ' << std::setw(3) << std::setfill('0') << code << ' ' << target
       << ' ' << msg << "\r\n";
    it->second->send(ss.str());
  }
}

void IrcServer::broadcast(const std::string& channel, const std::string& sender,
                          const std::string& cmd, const std::string& msg) {
  auto& ch = channels_[channel];
  for (auto& [nick, _] : ch.members) {
    if (nick != sender) {
      std::stringstream ss;
      ss << ':' << sender << '!' << sender << "@" << server_name_ << ' ' << cmd << ' ' << channel
         << " :" << msg << "\r\n";
      auto it = clients_.find(nick);
      if (it != clients_.end())
        it->second->send(ss.str());
    }
  }
}

IrcClient::IrcClient(boost::asio::ip::tcp::socket socket, IrcServer& server)
    : socket_(std::move(socket)), server_(server) {}

void IrcClient::start() {
  do_read();
}

void IrcClient::send(std::string msg) {
  writing_ = true;
  boost::asio::async_write(socket_, boost::asio::buffer(msg),
                           [this](boost::system::error_code ec, std::size_t) { writing_ = false; });
}

void IrcClient::send_reply(int code, const std::string& msg) {
  server_.send_numeric(session_.nick, code, msg);
}

void IrcClient::do_read() {
  auto buf = std::make_shared<std::array<char, 512>>();
  auto self = shared_from_this();
  socket_.async_read_some(boost::asio::buffer(*buf),
                          [self, buf](boost::system::error_code ec, std::size_t len) {
                            if (ec)
                              return;
                            std::string data(buf->data(), len);
                            std::istringstream ss(data);
                            std::string line;
                            while (std::getline(ss, line)) {
                              while (!line.empty() && line.back() == '\r')
                                line.pop_back();
                              if (line.empty())
                                continue;
                              self->handle_message(IrcMessage::parse(line));
                            }
                            self->do_read();
                          });
}

void IrcClient::handle_message(const IrcMessage& msg) {
  auto cmd = msg.command;
  auto& sess = session_;
  auto& db = server_.db();
  auto sv = server_.server_name();
  uint64_t now = util::now_ms();

  if (cmd == "NICK") {
    std::string new_nick;
    if (!msg.params.empty())
      new_nick = msg.params[0];
    if (new_nick.empty()) {
      send_reply(431, ":No nickname given");
      return;
    }
    if (server_.clients_.find(new_nick) != server_.clients_.end()) {
      send_reply(433, new_nick + " :Nickname is already in use");
      return;
    }
    if (!sess.nick.empty()) {
      std::string old = sess.nick;
      server_.clients_.erase(old);
      for (auto& [ch, _] : server_.channels_)
        server_.broadcast(ch, old, "NICK", new_nick);
    }
    sess.nick = new_nick;
    server_.clients_[new_nick] = shared_from_this();
  } else if (cmd == "USER") {
    if (msg.params.size() < 4) {
      send_reply(461, "USER :Not enough parameters");
      return;
    }
    sess.user = msg.params[0];
    sess.realname = msg.trailing;
  } else if (cmd == "PING") {
    send(":" + sv + " PONG " + sv + " :" + msg.trailing + "\r\n");
  } else if (cmd == "QUIT") {
    for (auto& [ch, _] : server_.channels_) {
      server_.broadcast(ch, sess.nick, "QUIT", msg.trailing);
      server_.channels_[ch].members.erase(sess.nick);
    }
    server_.clients_.erase(sess.nick);
    return;
  } else if (cmd == "JOIN" || cmd == "PART") {
    if (!sess.registered) {
      send_reply(451, ":Register first");
      return;
    }
    auto ch = !msg.params.empty() ? msg.params[0] : msg.trailing;
    if (cmd == "JOIN") {
      server_.channels_[ch].members[sess.nick] = false;
      server_.broadcast(ch, sess.nick, "JOIN", "");
      send_reply(353, "= " + ch + " :" + sess.nick);
      send_reply(366, ch + " :End of /NAMES list");
    } else {
      server_.channels_[ch].members.erase(sess.nick);
      server_.broadcast(ch, sess.nick, "PART", msg.trailing);
    }
  } else if (cmd == "PRIVMSG") {
    auto target = msg.params[0];
    std::string body = msg.trailing;
    if (target[0] == '#') {
      server_.broadcast(target, sess.nick, "PRIVMSG", body);
    } else {
      auto it = server_.clients_.find(target);
      if (it != server_.clients_.end()) {
        std::stringstream ss;
        ss << ':' << sess.nick << " PRIVMSG " << target << " :" << body << "\r\n";
        it->second->send(ss.str());
      }
    }
  }

  // Registration check
  if (!sess.registered && !sess.nick.empty() && !sess.user.empty()) {
    sess.registered = true;
    send_reply(1, ":Welcome to Progressive IRC, " + sess.nick);
    send_reply(2, ":Your host is " + sv + " running Progressive");
    send_reply(4, sv + " Progressive v0.1.0 MX+IRC+XMPP");
    send_reply(376, ":End of /MOTD command");
  }
}

}  // namespace progressive::irc
