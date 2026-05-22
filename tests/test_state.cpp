#include <gtest/gtest.h>

#include <progressive/state/event_auth.hpp>
#include <progressive/state/room_version.hpp>
#include <progressive/state/state_resolution.hpp>
#include <progressive/state/types.hpp>

using namespace progressive::state;

// Helper: create a basic event
static ResolvableEvent make_event(std::string eid, std::string type, std::string state_key,
                                  std::string sender, int depth, int64_t ts = 100) {
  ResolvableEvent e;
  e.event_id = eid;
  e.type = type;
  e.state_key = state_key;
  e.sender = sender;
  e.depth = depth;
  e.origin_server_ts = ts;
  return e;
}

TEST(RoomVersion, KnownVersions) {
  auto& v = get_room_version("10");
  EXPECT_EQ(v.identifier, "10");
  EXPECT_EQ(v.state_res, StateResVersion::V2);
  EXPECT_TRUE(v.restricted_join_rule);

  auto& v1 = get_room_version("1");
  EXPECT_EQ(v1.state_res, StateResVersion::V1);
  EXPECT_TRUE(v1.special_case_aliases_auth);
}

TEST(RoomVersion, DefaultVersion) {
  auto& v = get_room_version("999");
  EXPECT_EQ(v.identifier, "10");
}

TEST(AuthTypes, CreateEvent) {
  auto v = get_room_version("10");
  ResolvableEvent e = make_event("$ev", "m.room.create", "", "@c", 1);
  auto types = auth_types_for_event(v, e);
  EXPECT_TRUE(types.empty());
}

TEST(AuthTypes, MessageEvent) {
  auto v = get_room_version("10");
  ResolvableEvent e = make_event("$ev", "m.room.message", "", "@s", 2);
  auto types = auth_types_for_event(v, e);
  EXPECT_GE(types.size(), 3u);
  EXPECT_TRUE(types.contains(make_key("m.room.create", "")));
  EXPECT_TRUE(types.contains(make_key("m.room.power_levels", "")));
  EXPECT_TRUE(types.contains(make_key("m.room.member", "@s")));
}

TEST(AuthTypes, MemberEvent) {
  auto v = get_room_version("10");
  ResolvableEvent e = make_event("$ev", "m.room.member", "@u", "@s", 3);
  auto types = auth_types_for_event(v, e);
  EXPECT_TRUE(types.contains(make_key("m.room.member", "@u")));
  EXPECT_TRUE(types.contains(make_key("m.room.join_rules", "")));
}

TEST(PowerEvent, Detection) {
  auto pl = make_event("$pl", "m.room.power_levels", "", "@admin", 1);
  EXPECT_TRUE(is_power_event(pl));

  auto jr = make_event("$jr", "m.room.join_rules", "", "@admin", 1);
  EXPECT_TRUE(is_power_event(jr));

  auto create = make_event("$c", "m.room.create", "", "@admin", 1);
  EXPECT_TRUE(is_power_event(create));

  auto msg = make_event("$msg", "m.room.message", "", "@user", 2);
  EXPECT_FALSE(is_power_event(msg));
}

TEST(StateSeparation, NoConflict) {
  StateMap s1 = {{make_key("m.room.name", ""), "$e1"}};
  StateMap s2 = {{make_key("m.room.name", ""), "$e1"}};
  auto [un, con] = separate({s1, s2});
  EXPECT_EQ(un.size(), 1u);
  EXPECT_EQ(con.size(), 0u);
  EXPECT_EQ(un[make_key("m.room.name", "")], "$e1");
}

TEST(StateSeparation, Conflict) {
  StateMap s1 = {{make_key("m.room.name", ""), "$e1"}};
  StateMap s2 = {{make_key("m.room.name", ""), "$e2"}};
  auto [un, con] = separate({s1, s2});
  EXPECT_EQ(un.size(), 0u);
  EXPECT_EQ(con.size(), 1u);
  auto& eids = con[make_key("m.room.name", "")];
  EXPECT_TRUE(eids.contains("$e1"));
  EXPECT_TRUE(eids.contains("$e2"));
}

TEST(StateSeparation, NewKeyInLaterSet) {
  StateMap s1;
  StateMap s2 = {{make_key("m.room.topic", ""), "$e1"}};
  auto [un, con] = separate({s1, s2});
  EXPECT_EQ(un.size(), 1u);
  EXPECT_EQ(un[make_key("m.room.topic", "")], "$e1");
}

// ---- V2 Resolution Tests ----

TEST(StateResolutionV2, SingleStateSet) {
  StateMap s1 = {
      {make_key("m.room.create", ""), "$c"},
      {make_key("m.room.member", "@a"), "$m1"},
  };
  EventMap em;
  em["$c"] = make_event("$c", "m.room.create", "", "@a", 1, 1);
  em["$c"].auth_event_ids = {};
  em["$m1"] = make_event("$m1", "m.room.member", "@a", "@a", 2, 2);
  em["$m1"].auth_event_ids = {"$c"};

  auto v = get_room_version("10");
  auto resolved = resolve_events(v, {s1}, em);
  EXPECT_EQ(resolved.size(), 2u);
  EXPECT_EQ(resolved[make_key("m.room.create", "")], "$c");
}

TEST(StateResolutionV2, TwoIdenticalSets) {
  StateMap s1 = {{make_key("m.room.name", ""), "$e1"}};
  StateMap s2 = {{make_key("m.room.name", ""), "$e1"}};
  EventMap em;
  em["$e1"] = make_event("$e1", "m.room.name", "", "@a", 1, 1);
  em["$e1"].auth_event_ids = {};

  auto v = get_room_version("10");
  auto resolved = resolve_events(v, {s1, s2}, em);
  EXPECT_EQ(resolved.size(), 1u);
  EXPECT_EQ(resolved[make_key("m.room.name", "")], "$e1");
}

TEST(StateResolutionV2, ConflictDeeperWins) {
  // $e2 is deeper than $e1, so $e2 should win the conflict
  StateMap s1 = {{make_key("m.room.name", ""), "$e1"}};
  StateMap s2 = {{make_key("m.room.name", ""), "$e2"}};

  EventMap em;
  em["$e1"] = make_event("$e1", "m.room.name", "", "@a", 1, 100);
  em["$e1"].auth_event_ids = {};
  em["$e2"] = make_event("$e2", "m.room.name", "", "@a", 5, 200);
  em["$e2"].auth_event_ids = {};

  auto v = get_room_version("10");
  auto resolved = resolve_events(v, {s1, s2}, em);
  EXPECT_EQ(resolved[make_key("m.room.name", "")], "$e2");
}

TEST(StateResolutionV2, PowerEventConflict) {
  StateMap s1 = {{make_key("m.room.power_levels", ""), "$pl1"}};
  StateMap s2 = {{make_key("m.room.power_levels", ""), "$pl2"}};

  EventMap em;
  em["$pl1"] = make_event("$pl1", "m.room.power_levels", "", "@admin", 2, 100);
  em["$pl1"].auth_event_ids = {};
  em["$pl1"].power_level = 100;
  em["$pl2"] = make_event("$pl2", "m.room.power_levels", "", "@admin", 3, 200);
  em["$pl2"].auth_event_ids = {};
  em["$pl2"].power_level = 100;

  auto v = get_room_version("10");
  auto resolved = resolve_events(v, {s1, s2}, em);
  // $pl2 has higher origin_server_ts
  auto pl_key = make_key("m.room.power_levels", "");
  EXPECT_NE(resolved.find(pl_key), resolved.end());
}

TEST(StateResolutionV2, V1Fallback) {
  StateMap s1 = {{make_key("m.room.name", ""), "$e1"}};
  StateMap s2 = {{make_key("m.room.name", ""), "$e2"}};

  EventMap em;
  em["$e1"] = make_event("$e1", "m.room.name", "", "@a", 1, 100);
  em["$e1"].auth_event_ids = {};
  em["$e2"] = make_event("$e2", "m.room.name", "", "@a", 2, 200);
  em["$e2"].auth_event_ids = {};

  auto v = get_room_version("1");
  auto resolved = resolve_events(v, {s1, s2}, em);
  // V1 should also resolve (deeper wins in normal events)
  EXPECT_EQ(resolved[make_key("m.room.name", "")], "$e2");
}
