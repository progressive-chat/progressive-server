#include "extensions.hpp"

#include "../util/time.hpp"

namespace progressive::xmpp {

MucRoom XmppExtensions::create_room(std::string_view jid, std::string_view owner) {
  MucRoom r;
  r.jid = jid;
  r.owners.insert(std::string(owner));
  r.persistent = true;
  rooms_[std::string(jid)] = r;
  return r;
}

MucRoom* XmppExtensions::get_room(std::string_view jid) {
  auto it = rooms_.find(std::string(jid));
  return it != rooms_.end() ? &it->second : nullptr;
}

void XmppExtensions::join_room(std::string_view jid, std::string_view user) {
  rooms_[std::string(jid)].members.insert(std::string(user));
}

void XmppExtensions::leave_room(std::string_view jid, std::string_view user) {
  rooms_[std::string(jid)].members.erase(std::string(user));
}

void XmppExtensions::archive_message(std::string_view from, std::string_view to,
                                     std::string_view body) {
  MessageArchive ma;
  ma.id = "msg_" + std::to_string(util::now_ms());
  ma.from = from;
  ma.to = to;
  ma.body = body;
  ma.timestamp = util::now_ms();
  archives_[std::string(to)].push_back(ma);
}

std::vector<MessageArchive> XmppExtensions::query_archive(std::string_view user, int limit) {
  auto& msgs = archives_[std::string(user)];
  if (msgs.size() <= static_cast<size_t>(limit))
    return msgs;
  return {msgs.end() - limit, msgs.end()};
}

void XmppExtensions::enable_carbons(std::string_view user) {
  carbon_users_.insert(std::string(user));
}

void XmppExtensions::disable_carbons(std::string_view user) {
  carbon_users_.erase(std::string(user));
}

bool XmppExtensions::has_carbons(std::string_view user) const {
  return carbon_users_.find(std::string(user)) != carbon_users_.end();
}

PubSubNode XmppExtensions::create_node(std::string_view name, std::string_view creator) {
  PubSubNode n;
  n.id = std::string(name);
  n.name = std::string(name);
  n.creator = std::string(creator);
  pubsub_nodes_[std::string(name)] = n;
  return n;
}

PubSubNode* XmppExtensions::get_node(std::string_view name) {
  auto it = pubsub_nodes_.find(std::string(name));
  return it != pubsub_nodes_.end() ? &it->second : nullptr;
}

void XmppExtensions::publish_item(std::string_view node, const nlohmann::json& item) {
  pubsub_nodes_[std::string(node)].items.push_back(item);
}

void XmppExtensions::set_stream_id(std::string_view user, std::string_view sid) {
  stream_ids_[std::string(user)] = std::string(sid);
}

std::string XmppExtensions::get_stream_id(std::string_view user) const {
  auto it = stream_ids_.find(std::string(user));
  return it != stream_ids_.end() ? it->second : "";
}

void XmppExtensions::increment_sent(std::string_view user) {
  stream_sent_[std::string(user)]++;
}
void XmppExtensions::increment_received(std::string_view user) {
  stream_recv_[std::string(user)]++;
}
int XmppExtensions::get_sent(std::string_view user) const {
  auto it = stream_sent_.find(std::string(user));
  return it != stream_sent_.end() ? it->second : 0;
}

}  // namespace progressive::xmpp
