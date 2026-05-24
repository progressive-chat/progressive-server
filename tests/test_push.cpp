#include <gtest/gtest.h>

#include <progressive/push/base_rules.hpp>
#include <progressive/push/evaluator.hpp>
#include <progressive/push/types.hpp>
#include <progressive/push/utils.hpp>

using namespace progressive::push;

TEST(PushBaseRules, AllRulesNonEmpty) {
  auto& rules = all_base_rules();
  EXPECT_GT(rules.size(), 5u);
}

TEST(PushBaseRules, SuppressNotices) {
  auto& rules = all_base_rules();
  bool found = false;
  for (auto& r : rules) {
    if (r.rule_id == "global/override/.m.rule.suppress_notices") {
      found = true;
      EXPECT_EQ(r.priority_class, PriorityClass::Override);
      EXPECT_EQ(r.conditions.size(), 1u);
      break;
    }
  }
  EXPECT_TRUE(found);
}

TEST(PushBaseRules, InviteForMe) {
  auto& rules = all_base_rules();
  bool found = false;
  for (auto& r : rules) {
    if (r.rule_id == "global/override/.m.rule.invite_for_me") {
      found = true;
      EXPECT_EQ(r.conditions.size(), 3u);
      EXPECT_GT(r.actions.size(), 0u);
      break;
    }
  }
  EXPECT_TRUE(found);
}

TEST(PushBaseRules, MasterRuleDisabled) {
  auto& rules = all_base_rules();
  bool found = false;
  for (auto& r : rules) {
    if (r.rule_id == "global/override/.m.rule.master") {
      found = true;
      EXPECT_FALSE(r.default_enabled);
      break;
    }
  }
  EXPECT_TRUE(found);
}

TEST(GlobMatcher, LiteralWhole) {
  Matcher m("m.room.message", GlobMatchType::Whole);
  EXPECT_TRUE(m.is_match("m.room.message"));
  EXPECT_TRUE(m.is_match("M.room.MESSAGE"));  // case insensitive
  EXPECT_FALSE(m.is_match("something.else"));
}

TEST(GlobMatcher, WildcardStar) {
  Matcher m("m.room.*", GlobMatchType::Whole);
  EXPECT_TRUE(m.is_match("m.room.message"));
  EXPECT_TRUE(m.is_match("m.room.tombstone"));
  EXPECT_FALSE(m.is_match("m.room"));
}

TEST(GlobMatcher, WildcardQuestion) {
  Matcher m("m.call.??????", GlobMatchType::Whole);
  EXPECT_TRUE(m.is_match("m.call.invite"));
  EXPECT_TRUE(m.is_match("m.call.hangup"));
}

TEST(GlobMatcher, WordMatch) {
  Matcher m("@room", GlobMatchType::Word);
  EXPECT_TRUE(m.is_match("hello @room everyone"));
  EXPECT_TRUE(m.is_match("@room hello"));
  EXPECT_FALSE(m.is_match("@rooms are noisy"));
}

TEST(GlobMatcher, WordMatchLocalpart) {
  Matcher m("alice", GlobMatchType::Word);
  EXPECT_TRUE(m.is_match("hello alice how are you"));
  EXPECT_TRUE(m.is_match("alice says hi"));
  EXPECT_FALSE(m.is_match("alicebot responds"));
}

TEST(GlobMatcher, CaseInsensitive) {
  Matcher m("hello", GlobMatchType::Word);
  EXPECT_TRUE(m.is_match("HELLO world"));
  EXPECT_TRUE(m.is_match("Hello World"));
}

TEST(GetLocalpart, Normal) {
  EXPECT_EQ(get_localpart_from_id("@alice:matrix.org"), "alice");
  EXPECT_EQ(get_localpart_from_id("@bob:server"), "bob");
  EXPECT_EQ(get_localpart_from_id("!room:server"), "room");
}

TEST(GetLocalpart, NoColon) {
  EXPECT_EQ(get_localpart_from_id("@alice"), "alice");
}

TEST(EventFlatten, Basic) {
  nlohmann::json ev;
  ev["type"] = "m.room.message";
  ev["sender"] = "@alice:localhost";
  ev["content"]["msgtype"] = "m.text";
  ev["content"]["body"] = "hello world";
  ev["state_key"] = "";

  auto flat = flatten_event(ev);
  EXPECT_TRUE(flat.contains("type"));
  EXPECT_TRUE(flat.contains("content.msgtype"));
  EXPECT_TRUE(flat.contains("content.body"));
  EXPECT_TRUE(flat.contains("sender"));
}

TEST(EventFlatten, EscapedDots) {
  nlohmann::json ev;
  ev["content"]["m.relates_to"]["rel_type"] = "m.replace";

  auto flat = flatten_event(ev);
  EXPECT_TRUE(flat.contains("content.m\\.relates_to.rel_type"));
}

TEST(EventFlatten, BooleanValues) {
  nlohmann::json ev;
  ev["content"]["m.mentions"]["room"] = true;

  auto flat = flatten_event(ev);
  EXPECT_TRUE(flat.contains("content.m\\.mentions.room"));
}

TEST(PushEvaluator, BasicMessageNoDisplayName) {
  nlohmann::json ev;
  ev["type"] = "m.room.message";
  ev["sender"] = "@bob:localhost";
  ev["content"]["msgtype"] = "m.text";
  ev["content"]["body"] = "hello world";

  PushRuleEvaluator evaluator(ev, 10);
  auto& rules = all_base_rules();
  auto actions = evaluator.run(rules, "@alice:localhost", std::nullopt);

  // Should match .m.rule.message underride rule (notify)
  EXPECT_GT(actions.size(), 0u);
}

TEST(PushEvaluator, NoticeSuppressed) {
  nlohmann::json ev;
  ev["type"] = "m.room.message";
  ev["sender"] = "@bob:localhost";
  ev["content"]["msgtype"] = "m.notice";
  ev["content"]["body"] = "system message";

  PushRuleEvaluator evaluator(ev, 10);
  auto& rules = all_base_rules();
  auto actions = evaluator.run(rules, "@alice:localhost", std::nullopt);

  // .m.rule.suppress_notices should match first, return empty actions
  EXPECT_EQ(actions.size(), 0u);
}

TEST(PushEvaluator, RoomNotif) {
  nlohmann::json ev;
  ev["type"] = "m.room.message";
  ev["sender"] = "@bob:localhost";
  ev["content"]["msgtype"] = "m.text";
  ev["content"]["body"] = "@room attention everyone";

  PushRuleEvaluator evaluator(ev, 10, int64_t(100));
  auto& rules = all_base_rules();
  auto actions = evaluator.run(rules, "@alice:localhost", std::nullopt);

  // .m.rule.roomnotif should match (sender has power, body has @room)
  // Returns highlight action
  EXPECT_GT(actions.size(), 0u);
}

TEST(PushEvaluator, ContainsDisplayName) {
  nlohmann::json ev;
  ev["type"] = "m.room.message";
  ev["sender"] = "@bob:localhost";
  ev["content"]["msgtype"] = "m.text";
  ev["content"]["body"] = "hey Alice are you there?";

  PushRuleEvaluator evaluator(ev, 10);
  auto& rules = all_base_rules();
  auto actions =
      evaluator.run(rules, "@alice:localhost", std::make_optional(std::string_view("Alice")));

  // .m.rule.contains_display_name should match
  EXPECT_GT(actions.size(), 0u);
}

TEST(PushEvaluator, MemberEventSuppressed) {
  nlohmann::json ev;
  ev["type"] = "m.room.member";
  ev["sender"] = "@admin:localhost";
  ev["state_key"] = "@bob:localhost";
  ev["content"]["membership"] = "join";

  PushRuleEvaluator evaluator(ev, 10);
  auto& rules = all_base_rules();
  auto actions = evaluator.run(rules, "@alice:localhost", std::nullopt);

  // .m.rule.member_event should suppress all membership events
  EXPECT_EQ(actions.size(), 0u);
}

TEST(PushEvaluator, InviteForMe) {
  nlohmann::json ev;
  ev["type"] = "m.room.member";
  ev["sender"] = "@admin:localhost";
  ev["state_key"] = "@alice:localhost";
  ev["content"]["membership"] = "invite";

  PushRuleEvaluator evaluator(ev, 10);
  auto& rules = all_base_rules();
  auto actions = evaluator.run(rules, "@alice:localhost", std::nullopt);

  // invite_for_me should match (invite + state_key matches user_id)
  EXPECT_GT(actions.size(), 0u);
}

TEST(PushEvaluator, OneToOneRoom) {
  nlohmann::json ev;
  ev["type"] = "m.room.message";
  ev["sender"] = "@bob:localhost";
  ev["content"]["msgtype"] = "m.text";
  ev["content"]["body"] = "hi";

  PushRuleEvaluator evaluator(ev, 2);  // 2 members = 1:1
  auto& rules = all_base_rules();
  auto actions = evaluator.run(rules, "@alice:localhost", std::nullopt);

  // .m.rule.room_one_to_one should match (message + 2 members)
  EXPECT_GT(actions.size(), 0u);
}

TEST(PushEvaluator, IsUserMention) {
  nlohmann::json ev;
  ev["type"] = "m.room.message";
  ev["sender"] = "@bob:localhost";
  ev["content"]["msgtype"] = "m.text";
  ev["content"]["body"] = "hey";
  ev["content"]["m.mentions"]["user_ids"] = {"@alice:localhost", "@charlie"};

  PushRuleEvaluator evaluator(ev, 10);
  auto& rules = all_base_rules();
  auto actions = evaluator.run(rules, "@alice:localhost", std::nullopt);

  // is_user_mention should match
  EXPECT_GT(actions.size(), 0u);
}

TEST(PushEvaluator, ReactionSuppressed) {
  nlohmann::json ev;
  ev["type"] = "m.reaction";
  ev["sender"] = "@bob:localhost";
  ev["content"]["m.relates_to"]["event_id"] = "$original";

  PushRuleEvaluator evaluator(ev, 10);
  auto& rules = all_base_rules();
  auto actions = evaluator.run(rules, "@alice:localhost", std::nullopt);

  // .m.rule.reaction should suppress
  EXPECT_EQ(actions.size(), 0u);
}

TEST(ActionsToJson, Notify) {
  auto acts = std::vector<Action>{action_notify()};
  auto j = actions_to_json(acts);
  EXPECT_EQ(j.size(), 1u);
  EXPECT_EQ(j[0], "notify");
}

TEST(ActionsToJson, Highlight) {
  auto acts = std::vector<Action>{action_highlight(true)};
  auto j = actions_to_json(acts);
  EXPECT_EQ(j.size(), 1u);
  EXPECT_EQ(j[0]["set_tweak"], "highlight");
}

TEST(PushEvaluator, CallInvite) {
  nlohmann::json ev;
  ev["type"] = "m.call.invite";
  ev["sender"] = "@bob:localhost";
  ev["content"]["call_id"] = "call123";
  PushRuleEvaluator evaluator(ev, 10);
  auto actions = evaluator.run(all_base_rules(), "@alice:localhost", std::nullopt);
  EXPECT_GT(actions.size(), 0u);
}

TEST(PushEvaluator, EncryptedEvent) {
  nlohmann::json ev;
  ev["type"] = "m.room.encrypted";
  ev["sender"] = "@bob:localhost";
  ev["content"]["algorithm"] = "m.megolm.v1";
  PushRuleEvaluator evaluator(ev, 10);
  auto actions = evaluator.run(all_base_rules(), "@alice:localhost", std::nullopt);
  EXPECT_GT(actions.size(), 0u);
}

TEST(PushEvaluator, NoMatchForUnknownType) {
  nlohmann::json ev;
  ev["type"] = "com.example.unknown";
  ev["sender"] = "@bob:localhost";
  ev["content"] = nlohmann::json::object();
  PushRuleEvaluator evaluator(ev, 10);
  auto actions = evaluator.run(all_base_rules(), "@alice:localhost", std::nullopt);
  EXPECT_EQ(actions.size(), 0u);
}

TEST(PushEvaluator, TombstoneNotification) {
  nlohmann::json ev;
  ev["type"] = "m.room.tombstone";
  ev["sender"] = "@admin:localhost";
  ev["state_key"] = "";
  ev["content"]["replacement_room"] = "!new:localhost";
  PushRuleEvaluator evaluator(ev, 10);
  auto actions = evaluator.run(all_base_rules(), "@alice:localhost", std::nullopt);
  EXPECT_GT(actions.size(), 0u);
}

TEST(PushEvaluator, BulkEvaluation) {
  nlohmann::json ev;
  ev["type"] = "m.room.message";
  ev["sender"] = "@bob:localhost";
  ev["content"]["msgtype"] = "m.text";
  ev["content"]["body"] = "hello";
  PushRuleEvaluator evaluator(ev, 10);
  auto& rules = all_base_rules();
  for (auto uid : {"@alice:localhost", "@charlie:localhost"}) {
    auto actions = evaluator.run(rules, uid, std::nullopt);
    EXPECT_GT(actions.size(), 0u) << "Failed for user " << uid;
  }
}

TEST(EventFlatten, NestedRelatesTo) {
  nlohmann::json ev;
  ev["content"]["m.relates_to"]["rel_type"] = "m.replace";
  ev["content"]["m.relates_to"]["event_id"] = "$original";
  auto flat = flatten_event(ev);
  EXPECT_TRUE(flat.contains("content.m\\.relates_to.rel_type"));
}
