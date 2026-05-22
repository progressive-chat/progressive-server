#include <gtest/gtest.h>
#include <unordered_set>
#include <progressive/types/matrix_id.hpp>
#include <progressive/types/requester.hpp>
#include <progressive/types/state_map.hpp>
#include <progressive/json/canonical.hpp>
#include <progressive/events/event.hpp>
#include <progressive/util/random.hpp>

using namespace progressive;
using namespace progressive::events;

TEST(MatrixID, UserIDParsing) {
  auto uid = UserID::from_string("@alice:example.com");
  EXPECT_EQ(uid.localpart(), "alice");
  EXPECT_EQ(uid.domain(), "example.com");
  EXPECT_EQ(uid.to_string(), "@alice:example.com");
}

TEST(MatrixID, RoomIDParsing) {
  auto rid = RoomID::from_string("!room:example.com");
  EXPECT_EQ(rid.localpart(), "room");
  EXPECT_EQ(rid.domain(), "example.com");
  EXPECT_EQ(rid.to_string(), "!room:example.com");
}

TEST(MatrixID, EventIDParsing) {
  auto eid = EventID::from_string("$hash:example.com");
  EXPECT_EQ(eid.localpart(), "hash");
  EXPECT_EQ(eid.domain(), "example.com");
}

TEST(MatrixID, RoomAliasParsing) {
  auto alias = RoomAlias::from_string("#myroom:example.com");
  EXPECT_EQ(alias.localpart(), "myroom");
  EXPECT_EQ(alias.domain(), "example.com");
  EXPECT_EQ(alias.to_string(), "#myroom:example.com");
}

TEST(MatrixID, InvalidSigil) {
  EXPECT_THROW(UserID::from_string("@alice"), InvalidMatrixId);
  EXPECT_THROW(RoomID::from_string("room:example.com"), InvalidMatrixId);
}

TEST(MatrixID, Equality) {
  auto a = UserID::from_string("@alice:example.com");
  auto b = UserID::from_string("@alice:example.com");
  auto c = UserID::from_string("@bob:example.com");
  EXPECT_EQ(a, b);
  EXPECT_NE(a, c);
  EXPECT_LT(UserID::from_string("@a:x"), UserID::from_string("@b:x"));
}

TEST(MatrixID, Hash) {
  std::unordered_set<UserID, UserID::hash> set;
  set.insert(UserID::from_string("@alice:example.com"));
  EXPECT_TRUE(set.contains(UserID::from_string("@alice:example.com")));
}

TEST(Requester, Basic) {
  Requester req(UserID::from_string("@alice:example.com"), "token123");
  EXPECT_EQ(req.user.to_string(), "@alice:example.com");
  EXPECT_EQ(req.access_token_id.value(), "token123");
  EXPECT_FALSE(req.is_guest);
}

TEST(CanonicalJSON, EmptyObject) {
  auto j = nlohmann::json::object();
  EXPECT_EQ(json::canonical_json(j), "{}");
}

TEST(CanonicalJSON, SimpleObject) {
  auto j = nlohmann::json::object({{"a", 1}, {"b", 2}});
  EXPECT_EQ(json::canonical_json(j), R"({"a":1,"b":2})");
}

TEST(CanonicalJSON, NestedObject) {
  auto j = nlohmann::json::object({
    {"type", "m.room.message"},
    {"content", {{"body", "hello"}}}
  });
  std::string canon = json::canonical_json(j);
  EXPECT_TRUE(canon.find("\"content\"") != std::string::npos);
  EXPECT_TRUE(canon.find("\"type\"") != std::string::npos);
}

TEST(CanonicalJSON, Arrays) {
  auto j = nlohmann::json::array({1, 2, 3});
  EXPECT_EQ(json::canonical_json(j), "[1,2,3]");
}

TEST(CanonicalJSON, Types) {
  EXPECT_EQ(json::canonical_json(nlohmann::json(true)), "true");
  EXPECT_EQ(json::canonical_json(nlohmann::json(false)), "false");
  EXPECT_EQ(json::canonical_json(nlohmann::json(nullptr)), "null");
}

TEST(Event, CreateAndSerialize) {
  Event ev;
  ev.event_id = EventID::from_string("$abc:example.com");
  ev.type = "m.room.message";
  ev.sender = "@alice:example.com";
  ev.room_id = RoomID::from_string("!room:example.com");
  ev.content = {{"msgtype", "m.text"}, {"body", "hello"}};
  ev.depth = 3;
  ev.origin_server_ts = "2025-01-01T00:00:00.000Z";

  auto j = ev.to_json();
  EXPECT_EQ(j["event_id"], "$abc:example.com");
  EXPECT_EQ(j["type"], "m.room.message");
  EXPECT_EQ(j["sender"], "@alice:example.com");
  EXPECT_EQ(j["room_id"], "!room:example.com");
  EXPECT_EQ(j["content"]["body"], "hello");
  EXPECT_EQ(j["depth"], 3);
}

TEST(Event, RoundTrip) {
  Event ev;
  ev.event_id = EventID::from_string("$evt:example.com");
  ev.type = "m.room.message";
  ev.sender = "@alice:example.com";
  ev.room_id = RoomID::from_string("!room:example.com");
  ev.content = {{"body", "test"}};
  ev.depth = 1;
  ev.origin_server_ts = "2025-01-01T00:00:00.000Z";

  auto j = ev.to_json();
  auto ev2 = Event::from_json(j);

  EXPECT_EQ(ev2.event_id.to_string(), ev.event_id.to_string());
  EXPECT_EQ(ev2.type, ev.type);
  EXPECT_EQ(ev2.sender, ev.sender);
  EXPECT_EQ(ev2.room_id.to_string(), ev.room_id.to_string());
  EXPECT_EQ(ev2.depth, ev.depth);
}

TEST(Event, StateEvent) {
  Event ev;
  ev.event_id = EventID::from_string("$state:example.com");
  ev.type = "m.room.name";
  ev.sender = "@alice:example.com";
  ev.room_id = RoomID::from_string("!room:example.com");
  ev.content = {{"name", "My Room"}};
  ev.state_key = "";
  ev.origin_server_ts = "2025-01-01T00:00:00.000Z";

  EXPECT_TRUE(ev.is_state());
  EXPECT_EQ(ev.state_key_str(), "");

  auto j = ev.to_json();
  EXPECT_TRUE(j.contains("state_key"));
  EXPECT_EQ(j["state_key"], "");
}

TEST(Random, TokenGeneration) {
  auto t1 = util::random_token(32);
  auto t2 = util::random_token(32);
  EXPECT_EQ(t1.size(), 32u);
  EXPECT_EQ(t2.size(), 32u);
  EXPECT_NE(t1, t2);
}

TEST(Random, UInt64) {
  auto x = util::random_uint64();
  auto y = util::random_uint64();
  // Very unlikely to collide
  (void)x; (void)y;
}

TEST(StreamToken, RoundTrip) {
  StreamToken tok;
  tok.room_key = "s1234";
  tok.presence_key = 100;
  tok.typing_key = 200;
  tok.receipt_key = 300;

  auto s = tok.to_string();
  auto tok2 = StreamToken::from_string(s);

  EXPECT_EQ(tok.room_key, tok2.room_key);
  EXPECT_EQ(tok.presence_key, tok2.presence_key);
  EXPECT_EQ(tok.typing_key, tok2.typing_key);
  EXPECT_EQ(tok.receipt_key, tok2.receipt_key);
}
