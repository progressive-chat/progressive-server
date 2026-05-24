#include <gtest/gtest.h>

#include <progressive/activitypub/types.hpp>
#include <progressive/federation/auth.hpp>
#include <progressive/irc/parser.hpp>
#include <progressive/irc/services.hpp>
#include <progressive/xmpp/extensions.hpp>

using namespace progressive::irc;
using namespace progressive::xmpp;
using namespace progressive::federation;

TEST(IrcParser, BasicMessage) {
  auto msg = IrcMessage::parse("NICK alice");
  EXPECT_EQ(msg.command, "NICK");
  EXPECT_EQ(msg.params.size(), 1u);
  EXPECT_EQ(msg.params[0], "alice");
}

TEST(IrcParser, PrefixMessage) {
  auto msg = IrcMessage::parse(":server.example.com 001 alice :Welcome");
  EXPECT_EQ(msg.prefix, "server.example.com");
  EXPECT_EQ(msg.command, "001");
  EXPECT_EQ(msg.params[0], "alice");
  EXPECT_EQ(msg.trailing, "Welcome");
}

TEST(IrcParser, Privmsg) {
  auto msg = IrcMessage::parse(":bob!bob@host PRIVMSG #channel :Hello world");
  EXPECT_EQ(msg.prefix, "bob!bob@host");
  EXPECT_EQ(msg.command, "PRIVMSG");
  EXPECT_EQ(msg.params[0], "#channel");
  EXPECT_EQ(msg.trailing, "Hello world");
}

TEST(IrcParser, FullRegistration) {
  auto msg = IrcMessage::parse("USER alice 0 * :Alice Realname");
  EXPECT_EQ(msg.command, "USER");
  EXPECT_EQ(msg.params[0], "alice");
  EXPECT_EQ(msg.params[1], "0");
  EXPECT_EQ(msg.params[2], "*");
  EXPECT_EQ(msg.trailing, "Alice Realname");
}

TEST(IrcServices, RegisterAndIdentify) {
  IrcServices svc;
  EXPECT_TRUE(svc.register_nick("alice", "secret"));
  EXPECT_TRUE(svc.identify_nick("alice", "secret"));
  EXPECT_FALSE(svc.identify_nick("alice", "wrong"));
}

TEST(IrcServices, ChannelRegister) {
  IrcServices svc;
  EXPECT_TRUE(svc.register_channel("#test", "alice"));
  EXPECT_EQ(svc.get_founder("#test"), "alice");
  EXPECT_EQ(svc.get_founder("#none"), "");
}

TEST(IrcServices, FloodProtection) {
  IrcServices svc;
  for (int i = 0; i < 5; i++)
    EXPECT_TRUE(svc.check_flood("bob"));
  EXPECT_FALSE(svc.check_flood("bob"));  // 6th message should be blocked
}

TEST(FederationAuth, ParseValidHeader) {
  auto auth =
      FederationAuth::parse("X-Matrix origin=example.com,key=\"ed25519:0\",sig=\"base64sig\"");
  EXPECT_EQ(auth.origin, "example.com");
  EXPECT_EQ(auth.key_id, "ed25519:0");
  EXPECT_EQ(auth.signature, "base64sig");
}

TEST(FederationAuth, ParsePartial) {
  auto auth = FederationAuth::parse("X-Matrix origin=damien");
  EXPECT_EQ(auth.origin, "damien");
  EXPECT_TRUE(auth.key_id.empty()) << "Partial header should have empty key_id";
}

TEST(XmppExtensions, MucCreateAndJoin) {
  XmppExtensions ext;
  ext.create_room("test@conference.localhost", "admin@localhost");
  ext.join_room("test@conference.localhost", "user@localhost");
  auto* got = ext.get_room("test@conference.localhost");
  ASSERT_NE(got, nullptr);
  EXPECT_EQ(got->owners.size(), 1u);
  EXPECT_GT(got->members.size(), 0u);
}

TEST(ActivityPub, WebFingerResponse) {
  auto json = progressive::activitypub::webfinger_response("acct:alice@example.com", "example.com");
  EXPECT_EQ(json["subject"], "acct:alice@example.com");
  EXPECT_GT(json["links"].size(), 0u);
  EXPECT_EQ(json["links"][0]["rel"], "self");
}

TEST(ActivityPub, ActivityJson) {
  progressive::activitypub::Activity a;
  a.type = "Create";
  a.actor = "https://example.com/users/alice";
  a.object = "https://example.com/post/1";
  auto j = a.to_json();
  EXPECT_EQ(j["type"], "Create");
  EXPECT_EQ(j["actor"], "https://example.com/users/alice");
  EXPECT_EQ(j["object"], "https://example.com/post/1");
}
