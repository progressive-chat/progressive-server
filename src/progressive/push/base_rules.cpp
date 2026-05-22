#include "base_rules.hpp"

namespace progressive::push {

// Helper macros for defining conditions/actions concisely
static Condition c_event_match(std::string k, std::string p) {
  return {EventMatchCondition{std::move(k), std::move(p)}};
}
static Condition c_event_match_type(std::string k, std::string pt) {
  return {EventMatchTypeCondition{std::move(k), std::move(pt)}};
}
static Condition c_property_is(std::string k, SimpleJsonValue v) {
  return {EventPropertyIsCondition{std::move(k), std::move(v)}};
}
static Condition c_property_contains_type(std::string k, std::string vt) {
  return {ExactEventPropertyContainsType{std::move(k), std::move(vt)}};
}
static Condition c_member_count(std::string is) {
  return {RoomMemberCount{std::move(is)}};
}
static Condition c_sender_notif(std::string k) {
  return {SenderNotificationPermission{std::move(k)}};
}
static Condition c_display_name() {
  return {std::string("contains_display_name")};
}

static std::vector<Action> a_notify() {
  return {action_notify()};
}
static std::vector<Action> a_notify_highlight() {
  return {action_notify(), action_highlight(true), action_sound("default")};
}
static std::vector<Action> a_notify_highlight_sound() {
  return {action_notify(), action_highlight(true), action_sound("default")};
}
static std::vector<Action> a_notify_highlight_only() {
  return {action_notify(), action_highlight(true)};
}
static std::vector<Action> a_notify_sound() {
  return {action_notify(), action_sound("default")};
}
static std::vector<Action> a_notify_ring() {
  return {action_notify(), action_sound("ring"), action_highlight(false)};
}
static std::vector<Action> a_suppress() {
  return {};
}

static PushRule make_rule(std::string id, PriorityClass pc, std::vector<Condition> conds,
                          std::vector<Action> acts, bool enabled = true) {
  PushRule r;
  r.rule_id = std::move(id);
  r.priority_class = pc;
  r.conditions = std::move(conds);
  r.actions = std::move(acts);
  r.is_default = true;
  r.default_enabled = enabled;
  return r;
}

// --- PREPEND OVERRIDE (1 rule) ---
static const std::vector<PushRule> kPrependOverride = {
    make_rule("global/override/.m.rule.master", PriorityClass::Override, {}, {}, false),
};

// --- APPEND OVERRIDE (14 rules) ---
static const std::vector<PushRule> kAppendOverride = {
    make_rule("global/override/.org.matrix.msc4028.encrypted_event", PriorityClass::Override,
              {c_event_match("type", "m.room.encrypted")}, a_notify()),

    make_rule("global/override/.m.rule.suppress_notices", PriorityClass::Override,
              {c_event_match("content.msgtype", "m.notice")}, a_suppress()),

    make_rule(
        "global/override/.m.rule.invite_for_me", PriorityClass::Override,
        {c_event_match("type", "m.room.member"), c_event_match("content.membership", "invite"),
         c_event_match_type("state_key", "user_id")},
        a_notify_highlight_sound()),

    make_rule("global/override/.m.rule.member_event", PriorityClass::Override,
              {c_event_match("type", "m.room.member")}, a_suppress()),

    make_rule("global/override/.m.rule.is_user_mention", PriorityClass::Override,
              {c_property_contains_type("content.m\\.mentions.user_ids", "user_id")},
              a_notify_highlight_sound()),

    make_rule("global/override/.m.rule.contains_display_name", PriorityClass::Override,
              {c_display_name()}, a_notify_highlight_sound()),

    make_rule(
        "global/override/.m.rule.is_room_mention", PriorityClass::Override,
        {c_property_is("content.m\\.mentions.room", SimpleJsonValue(true)), c_sender_notif("room")},
        a_notify_highlight_only()),

    make_rule("global/override/.m.rule.roomnotif", PriorityClass::Override,
              {c_sender_notif("room"), c_event_match("content.body", "@room")},
              a_notify_highlight_only()),

    make_rule("global/override/.m.rule.tombstone", PriorityClass::Override,
              {c_event_match("type", "m.room.tombstone"), c_event_match("state_key", "")},
              a_notify_highlight_only()),

    make_rule("global/override/.m.rule.reaction", PriorityClass::Override,
              {c_event_match("type", "m.reaction")}, a_suppress()),

    make_rule("global/override/.m.rule.room.server_acl", PriorityClass::Override,
              {c_event_match("type", "m.room.server_acl"), c_event_match("state_key", "")},
              a_suppress()),

    make_rule("global/override/.m.rule.suppress_edits", PriorityClass::Override,
              {c_property_is("content.m\\.relates_to.rel_type",
                             SimpleJsonValue(std::string("m.replace")))},
              a_suppress()),

    make_rule("global/override/.org.matrix.msc3930.rule.poll_response", PriorityClass::Override,
              {c_event_match("type", "org.matrix.msc3381.poll.response")}, a_suppress()),

    make_rule("global/override/.im.nheko.msc3664.reply", PriorityClass::Override,
              {c_property_contains_type("sender", "user_id")}, a_notify_highlight_sound()),
};

// --- APPEND CONTENT (1 rule) ---
static const std::vector<PushRule> kAppendContent = {
    make_rule("global/content/.m.rule.contains_user_name", PriorityClass::Content,
              {c_event_match_type("content.body", "user_localpart")}, a_notify_highlight_sound()),
};

// --- APPEND POSTCONTENT (2 rules) --- (simplified: MSC4306 omitted)
static const std::vector<PushRule> kAppendPostcontent = {};

// --- APPEND UNDERRIDE (22 rules) ---
static const std::vector<PushRule> kAppendUnderride = {
    make_rule("global/underride/.m.rule.call", PriorityClass::Underride,
              {c_event_match("type", "m.call.invite")}, a_notify_ring()),

    make_rule("global/underride/.m.rule.encrypted_room_one_to_one", PriorityClass::Underride,
              {c_event_match("type", "m.room.encrypted"), c_member_count("2")}, a_notify_sound()),

    make_rule("global/underride/.m.rule.room_one_to_one", PriorityClass::Underride,
              {c_event_match("type", "m.room.message"), c_member_count("2")}, a_notify_sound()),

    make_rule("global/underride/.m.rule.message", PriorityClass::Underride,
              {c_event_match("type", "m.room.message")}, a_notify()),

    make_rule("global/underride/.m.rule.encrypted", PriorityClass::Underride,
              {c_event_match("type", "m.room.encrypted")}, a_notify()),

    make_rule("global/underride/.im.vector.jitsi", PriorityClass::Underride,
              {c_event_match("type", "im.vector.modular.widgets"),
               c_event_match("content.type", "jitsi"), c_event_match("state_key", "*")},
              a_notify()),

    make_rule("global/underride/.org.matrix.msc3930.rule.poll_start_one_to_one",
              PriorityClass::Underride,
              {c_member_count("2"), c_event_match("type", "org.matrix.msc3381.poll.start")},
              a_notify_sound()),

    make_rule("global/underride/.org.matrix.msc3930.rule.poll_start", PriorityClass::Underride,
              {c_event_match("type", "org.matrix.msc3381.poll.start")}, a_notify()),

    make_rule("global/underride/.org.matrix.msc3930.rule.poll_end_one_to_one",
              PriorityClass::Underride,
              {c_member_count("2"), c_event_match("type", "org.matrix.msc3381.poll.end")},
              a_notify_sound()),

    make_rule("global/underride/.org.matrix.msc3930.rule.poll_end", PriorityClass::Underride,
              {c_event_match("type", "org.matrix.msc3381.poll.end")}, a_notify()),
};

static std::vector<PushRule> build_all_rules() {
  std::vector<PushRule> all;
  auto append = [&](auto& rules) { all.insert(all.end(), rules.begin(), rules.end()); };

  // Evaluation order: prepend_override → append_override → append_content →
  // append_postcontent → append_underride
  // Note: user rules (override, content, room, sender, underride) are inserted
  // between these in the real Flow. For base rules only, we just concatenate.
  append(kPrependOverride);
  append(kAppendOverride);
  append(kAppendContent);
  append(kAppendPostcontent);
  append(kAppendUnderride);
  return all;
}

const std::vector<PushRule>& base_prepend_override_rules() {
  return kPrependOverride;
}
const std::vector<PushRule>& base_append_override_rules() {
  return kAppendOverride;
}
const std::vector<PushRule>& base_append_content_rules() {
  return kAppendContent;
}
const std::vector<PushRule>& base_append_postcontent_rules() {
  return kAppendPostcontent;
}
const std::vector<PushRule>& base_append_underride_rules() {
  return kAppendUnderride;
}

const std::vector<PushRule>& all_base_rules() {
  static const auto rules = build_all_rules();
  return rules;
}

}  // namespace progressive::push
