#pragma once
#include <functional>
#include <map>
#include <nlohmann/json.hpp>
#include <queue>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace progressive::xmpp {

struct MucRoom {
  std::string jid;
  std::string name;
  std::string subject;
  std::set<std::string> members;
  std::set<std::string> owners;
  bool persistent = false;
};

struct MessageArchive {
  std::string id;
  std::string from;
  std::string to;
  std::string body;
  int64_t timestamp;
};

struct PubSubNode {
  std::string id;
  std::string name;
  std::string creator;
  std::vector<nlohmann::json> items;
};

class XmppExtensions {
public:
  // MUC
  MucRoom create_room(std::string_view jid, std::string_view owner);
  MucRoom* get_room(std::string_view jid);
  void join_room(std::string_view jid, std::string_view user);
  void leave_room(std::string_view jid, std::string_view user);

  // MAM
  void archive_message(std::string_view from, std::string_view to, std::string_view body);
  std::vector<MessageArchive> query_archive(std::string_view user, int limit = 20);

  // Carbons
  void enable_carbons(std::string_view user);
  void disable_carbons(std::string_view user);
  bool has_carbons(std::string_view user) const;

  // PubSub
  PubSubNode create_node(std::string_view name, std::string_view creator);
  PubSubNode* get_node(std::string_view name);
  void publish_item(std::string_view node, const nlohmann::json& item);

  // Stream management
  void set_stream_id(std::string_view user, std::string_view sid);
  std::string get_stream_id(std::string_view user) const;
  void increment_sent(std::string_view user);
  void increment_received(std::string_view user);
  int get_sent(std::string_view user) const;

private:
  std::map<std::string, MucRoom, std::less<>> rooms_;
  std::map<std::string, std::vector<MessageArchive>, std::less<>> archives_;
  std::set<std::string> carbon_users_;
  std::map<std::string, PubSubNode, std::less<>> pubsub_nodes_;
  std::map<std::string, std::string, std::less<>> stream_ids_;
  std::map<std::string, int, std::less<>> stream_sent_;
  std::map<std::string, int, std::less<>> stream_recv_;
};

}  // namespace progressive::xmpp
