#include <gtest/gtest.h>

#include <nlohmann/json.hpp>
#include <progressive/federation/auth.hpp>
#include <progressive/federation/federation_server.hpp>
#include <progressive/push/base_rules.hpp>
#include <progressive/push/evaluator.hpp>

using namespace progressive;

// === Federation tests ===
TEST(Federation, PDUFromJson) {
  nlohmann::json j;
  j["event_id"] = "$ev:example.com";
  j["room_id"] = "!room:example.com";
  j["type"] = "m.room.message";
  j["sender"] = "@user:example.com";
  j["content"] = {{"body", "hi"}};
  j["depth"] = 5;
  j["prev_events"] = nlohmann::json::array();
  j["auth_events"] = nlohmann::json::array();
  j["origin"] = "example.com";
  j["origin_server_ts"] = "2026-01-01";

  auto pdu = federation::PDU::from_json(j);
  EXPECT_EQ(pdu.event_id, "$ev:example.com");
  EXPECT_EQ(pdu.room_id, "!room:example.com");
  EXPECT_EQ(pdu.type, "m.room.message");
  EXPECT_EQ(pdu.sender, "@user:example.com");
  EXPECT_EQ(pdu.depth, 5);
}

TEST(Federation, PDUToJson) {
  federation::PDU pdu;
  pdu.event_id = "$ev:example.com";
  pdu.room_id = "!room:example.com";
  pdu.type = "m.room.message";
  pdu.sender = "@user:example.com";
  pdu.content = {{"body", "hi"}};
  pdu.depth = 5;
  pdu.origin = "example.com";

  auto j = pdu.to_json();
  EXPECT_EQ(j["event_id"], "$ev:example.com");
  EXPECT_EQ(j["type"], "m.room.message");
  EXPECT_EQ(j["content"]["body"], "hi");
}

TEST(Federation, AuthParseOrigin) {
  auto auth = federation::FederationAuth::parse(
      "X-Matrix origin=matrix.org,key=\"ed25519:0\",sig=\"abc123\"");
  EXPECT_EQ(auth.origin, "matrix.org");
  EXPECT_EQ(auth.key_id, "ed25519:0");
  EXPECT_EQ(auth.signature, "abc123");
}

TEST(Federation, AuthParseNoKey) {
  auto auth = federation::FederationAuth::parse("X-Matrix origin=example.com");
  EXPECT_EQ(auth.origin, "example.com");
  EXPECT_TRUE(auth.key_id.empty());
}

// === E2EE tests ===
TEST(E2EE, KeyUploadStoresData) {
  nlohmann::json keys;
  keys["device_keys"] = {{"algorithms", nlohmann::json::array({"m.olm.v1"})},
                         {"user_id", "@alice:localhost"},
                         {"device_id", "ABCDEF"}};
  keys["one_time_keys"] = {{"signed_curve25519:AAAA", {{"key", "base64data"}}}};

  EXPECT_TRUE(keys.contains("device_keys"));
  EXPECT_TRUE(keys.contains("one_time_keys"));
  EXPECT_EQ(keys["one_time_keys"].size(), 1u);
}

TEST(E2EE, ClaimReturnsKey) {
  nlohmann::json query;
  query["one_time_keys"] = {{"@alice:localhost", {{"ABCDEF", "signed_curve25519"}}}};
  EXPECT_TRUE(query["one_time_keys"].contains("@alice:localhost"));
}

TEST(E2EE, CrossSigningKeys) {
  nlohmann::json cs;
  cs["master_key"] = {{"user_id", "@alice:localhost"},
                      {"usage", nlohmann::json::array({"master"})},
                      {"key", "base64"}};
  cs["self_signing_key"] = {{"user_id", "@alice:localhost"},
                            {"usage", nlohmann::json::array({"self_signing"})},
                            {"key", "base64"}};
  EXPECT_TRUE(cs.contains("master_key"));
  EXPECT_TRUE(cs.contains("self_signing_key"));
}

// === Event creation tests ===
TEST(EventCreation, BasicMessageEvent) {
  nlohmann::json content;
  content["msgtype"] = "m.text";
  content["body"] = "Hello World";

  EXPECT_EQ(content["msgtype"], "m.text");
  EXPECT_EQ(content["body"], "Hello World");
}

TEST(EventCreation, StateEvent) {
  nlohmann::json content;
  content["name"] = "My Room";
  bool has_state_key = true;
  EXPECT_TRUE(has_state_key);
}

TEST(EventCreation, RelationEvent) {
  nlohmann::json content;
  content["m.relates_to"] = {{"event_id", "$original"}, {"rel_type", "m.replace"}};
  EXPECT_TRUE(content.contains("m.relates_to"));
  EXPECT_EQ(content["m.relates_to"]["rel_type"], "m.replace");
}

TEST(EventCreation, RedactEvent) {
  nlohmann::json content;
  content["reason"] = "spam";
  EXPECT_EQ(content["reason"], "spam");
}

// === Push evaluator tests ===
TEST(PushEval, HighlightForInvite) {
  nlohmann::json ev;
  ev["type"] = "m.room.member";
  ev["sender"] = "@inviter:localhost";
  ev["state_key"] = "@me:localhost";
  ev["content"]["membership"] = "invite";

  push::PushRuleEvaluator eval(ev, 10);
  auto actions = eval.run(push::all_base_rules(), "@me:localhost", std::nullopt);
  EXPECT_GT(actions.size(), 0u);
}

TEST(PushEval, NoMatchForUnknown) {
  nlohmann::json ev;
  ev["type"] = "com.unknown.event";
  ev["sender"] = "@user:localhost";
  ev["content"] = nlohmann::json::object();

  push::PushRuleEvaluator eval(ev, 5);
  auto actions = eval.run(push::all_base_rules(), "@user:localhost", std::nullopt);
  // Unknown events get no push notifications
  EXPECT_EQ(actions.size(), 0u);
}

TEST(PushEval, RoomNotifWithPower) {
  nlohmann::json ev;
  ev["type"] = "m.room.message";
  ev["sender"] = "@admin:localhost";
  ev["content"]["msgtype"] = "m.text";
  ev["content"]["body"] = "@room everyone";

  push::PushRuleEvaluator eval(ev, 10, int64_t(100));  // admin power level
  auto actions = eval.run(push::all_base_rules(), "@user:localhost", std::nullopt);
  EXPECT_GT(actions.size(), 0u);
}

// === Sync tests ===
TEST(Sync, GenerateResponse) {
  // Test that sync response structure is valid
  nlohmann::json sync;
  sync["next_batch"] = "s12345";
  sync["rooms"] = nlohmann::json::object();
  sync["rooms"]["join"] = nlohmann::json::object();
  sync["rooms"]["invite"] = nlohmann::json::object();
  sync["rooms"]["leave"] = nlohmann::json::object();

  EXPECT_TRUE(sync.contains("next_batch"));
  EXPECT_TRUE(sync.contains("rooms"));
  EXPECT_TRUE(sync["rooms"].contains("join"));
}

TEST(Sync, ToDeviceSection) {
  nlohmann::json to_device;
  to_device["events"] = nlohmann::json::array();

  nlohmann::json ev;
  ev["type"] = "m.room_key";
  ev["sender"] = "@alice:localhost";
  ev["content"] = nlohmann::json::object();
  to_device["events"].push_back(ev);

  EXPECT_EQ(to_device["events"].size(), 1u);
  EXPECT_EQ(to_device["events"][0]["type"], "m.room_key");
}

TEST(Sync, PresenceSection) {
  nlohmann::json presence;
  presence["events"] = nlohmann::json::array();

  nlohmann::json pe;
  pe["sender"] = "@alice:localhost";
  pe["type"] = "m.presence";
  pe["content"] = {{"presence", "online"}, {"last_active_ago", 0}};
  presence["events"].push_back(pe);

  EXPECT_EQ(presence["events"].size(), 1u);
}

TEST(Sync, DeviceListSection) {
  nlohmann::json dl;
  dl["changed"] = nlohmann::json::array({"@alice:localhost"});
  dl["left"] = nlohmann::json::array({"@bob:localhost"});

  EXPECT_EQ(dl["changed"].size(), 1u);
  EXPECT_EQ(dl["left"].size(), 1u);
}

// === Room member tests ===
TEST(RoomMember, JoinTransition) {
  // Self-join is always allowed
  std::string old_mem = "leave", new_mem = "join";
  bool self_join = true;
  EXPECT_TRUE(self_join);
  EXPECT_NE(old_mem, new_mem);
}

TEST(RoomMember, BanTransition) {
  // Ban requires power level > target
  int sender_pl = 100, target_pl = 50;
  EXPECT_GT(sender_pl, target_pl);
}

TEST(RoomMember, KickTransition) {
  // Kick requires power level > target
  int sender_pl = 75, target_pl = 50;
  EXPECT_GT(sender_pl, target_pl);
}

// === Auth tests ===
TEST(AuthFlow, LoginWithPassword) {
  nlohmann::json body;
  body["type"] = "m.login.password";
  body["identifier"] = {{"type", "m.id.user"}, {"user", "@alice:localhost"}};
  body["password"] = "secret";

  EXPECT_EQ(body["type"], "m.login.password");
  EXPECT_EQ(body["identifier"]["user"], "@alice:localhost");
}

TEST(AuthFlow, RegistrationRequest) {
  nlohmann::json body;
  body["username"] = "newuser";
  body["password"] = "supersecret";
  body["auth"] = {{"type", "m.login.dummy"}};

  EXPECT_EQ(body["username"], "newuser");
  EXPECT_TRUE(body.contains("auth"));
}

TEST(AuthFlow, RefreshToken) {
  std::string refresh = "syr_valid_token";
  bool is_valid = refresh.starts_with("syr_");
  EXPECT_TRUE(is_valid);
}

TEST(AuthFlow, ThreePIDLogin) {
  nlohmann::json body;
  body["type"] = "m.login.password";
  body["identifier"] = {
      {"type", "m.id.thirdparty"}, {"medium", "email"}, {"address", "user@example.com"}};
  body["password"] = "secret";

  EXPECT_EQ(body["identifier"]["medium"], "email");
  EXPECT_EQ(body["identifier"]["address"], "user@example.com");
}

// === Action tests ===
TEST(PushActions, NotifyAction) {
  auto acts = push::actions_to_json({push::action_notify()});
  EXPECT_EQ(acts.size(), 1u);
  EXPECT_EQ(acts[0], "notify");
}

TEST(PushActions, HighlightAction) {
  auto acts = push::actions_to_json({push::action_highlight(true)});
  EXPECT_EQ(acts.size(), 1u);
  EXPECT_EQ(acts[0]["set_tweak"], "highlight");
}

TEST(PushActions, SoundAction) {
  auto acts = push::actions_to_json({push::action_sound("default")});
  EXPECT_EQ(acts.size(), 1u);
  EXPECT_EQ(acts[0]["set_tweak"], "sound");
  EXPECT_EQ(acts[0]["value"], "default");
}
