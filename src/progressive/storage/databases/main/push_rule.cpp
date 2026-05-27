#include "progressive/storage/databases/main/push_rule.hpp"
#include <nlohmann/json.hpp>
using json=nlohmann::json;
namespace progressive::storage{
static const char* PR_DDL=R"SQL(
CREATE TABLE IF NOT EXISTS push_rules(id BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT,user_id TEXT NOT NULL,rule_id TEXT NOT NULL,priority_class INTEGER NOT NULL,priority INTEGER NOT NULL DEFAULT 0,conditions TEXT NOT NULL,actions TEXT NOT NULL,default_rule BOOLEAN DEFAULT 0,enabled BOOLEAN DEFAULT 1);
CREATE INDEX IF NOT EXISTS pr_user_idx ON push_rules(user_id);
CREATE INDEX IF NOT EXISTS pr_user_priority_idx ON push_rules(user_id,priority_class,priority);
CREATE TABLE IF NOT EXISTS push_rules_enable(user_id TEXT NOT NULL,rule_id TEXT NOT NULL,enabled BOOLEAN NOT NULL,CONSTRAINT pre_pk PRIMARY KEY(user_id,rule_id));
)SQL";
void PushRuleStore::add_push_rule_txn(LoggingTransaction& txn,const std::string& uid,const json& rule,bool is_default){txn.execute("INSERT INTO push_rules(user_id,rule_id,priority_class,priority,conditions,actions,default_rule,enabled) VALUES(?,?,?,?,?,?,?,?)",{uid,rule["rule_id"],rule["priority_class"],rule.value("priority",0),rule.value("conditions",json::array()).dump(),rule["actions"].dump(),is_default?1:0,rule.value("enabled",true)?1:0});}
void PushRuleStore::delete_push_rule_txn(LoggingTransaction& txn,const std::string& uid,const std::string& rid){txn.execute("DELETE FROM push_rules WHERE user_id=? AND rule_id=? AND default_rule=0",{uid,rid});}
void PushRuleStore::set_push_rule_enabled_txn(LoggingTransaction& txn,const std::string& uid,const std::string& rid,bool en){txn.execute("UPDATE push_rules SET enabled=? WHERE user_id=? AND rule_id=?",{en?1:0,uid,rid});txn.execute("INSERT INTO push_rules_enable VALUES(?,?,?) ON CONFLICT(user_id,rule_id) DO UPDATE SET enabled=excluded.enabled",{uid,rid,en?1:0});}
void PushRuleStore::set_push_rule_actions_txn(LoggingTransaction& txn,const std::string& uid,const std::string& rid,const json& actions){txn.execute("UPDATE push_rules SET actions=? WHERE user_id=? AND rule_id=?",{actions.dump(),uid,rid});}
std::vector<json> PushRuleStore::get_push_rules_for_user_txn(LoggingTransaction& txn,const std::string& uid){
  std::vector<json> r;auto rows=txn.select("SELECT rule_id,priority_class,priority,conditions,actions,default_rule,enabled FROM push_rules WHERE user_id=? ORDER BY priority_class,priority",{uid});
  for(auto& row:rows){json rule;rule["rule_id"]=row.get<std::string>(0);rule["priority_class"]=row.get<int>(1);rule["priority"]=row.get<int>(2);rule["conditions"]=json::parse(row.get<std::string>(3));rule["actions"]=json::parse(row.get<std::string>(4));rule["default"]=row.get<int64_t>(5)!=0;rule["enabled"]=row.get<int64_t>(6)!=0;r.push_back(rule);}return r;
}
json PushRuleStore::get_push_rules_enabled_for_user_txn(LoggingTransaction& txn,const std::string& uid){
  json en=json::object();auto rows=txn.select("SELECT rule_id,enabled FROM push_rules_enable WHERE user_id=?",{uid});for(auto& row:rows)en[row.get<std::string>(0)]=row.get<int64_t>(1)!=0;return en;
}
void PushRuleStore::copy_default_push_rules_to_user_txn(LoggingTransaction& txn,const std::string& uid){txn.execute("INSERT INTO push_rules(user_id,rule_id,priority_class,priority,conditions,actions,default_rule,enabled) SELECT ?,rule_id,priority_class,priority,conditions,actions,1,enabled FROM push_rules WHERE user_id=''",{uid});}
} // namespace
