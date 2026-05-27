#pragma once
// push_rule.hpp - push_rule.py C++ translation
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"
namespace progressive::storage { using json = nlohmann::json;

struct PushRule {
  std::string user_id; std::string rule_id;
  std::string kind; // override, underride, content, sender, room
  std::string actions; // JSON array of actions
  std::vector<std::pair<std::string,std::string>> conditions;
  int64_t priority_class{0}; int64_t priority{0};
  bool enabled{true}; bool default_rule{false};
};

class PushRuleStore {
public:
  explicit PushRuleStore(DatabasePool& db);
  // Get push rules for user
  std::vector<PushRule> get_push_rules(const std::string& user_id);
  // Get enabled push rules
  std::vector<PushRule> get_enabled_push_rules(const std::string& user_id);
  // Get single push rule
  std::optional<PushRule> get_push_rule(const std::string& user_id, const std::string& rule_id);
  // Add push rule
  void add_push_rule(const std::string& user_id, const PushRule& rule);
  // Update push rule
  void update_push_rule(const std::string& user_id, const std::string& rule_id,
      const PushRule& rule);
  // Delete push rule
  void delete_push_rule(const std::string& user_id, const std::string& rule_id);
  // Enable/disable push rule
  void set_push_rule_enabled(const std::string& user_id, const std::string& rule_id, bool enabled);
  // Set push rule actions
  void set_push_rule_actions(const std::string& user_id, const std::string& rule_id,
      const std::string& actions);
  // Copy default rules for user
  void copy_default_rules(const std::string& user_id);
  // Check if rule exists
  bool rule_exists(const std::string& user_id, const std::string& rule_id);
  // Bulk get rules for users
  std::map<std::string, std::vector<PushRule>> bulk_get_push_rules(
      const std::vector<std::string>& user_ids);
private:
  DatabasePool& db_;
};
} // namespace
