#pragma once
// federation_stores.hpp - appservice, keys, signatures, transactions stores
#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>
#include "progressive/storage/database.hpp"
namespace progressive::storage { using json = nlohmann::json;

// ---- AppServiceStore (appservice.py) ----
struct ApplicationService {
  std::string id; std::string url; std::string hs_token; std::string as_token;
  std::string sender_localpart; std::vector<std::string> namespaces_users;
  std::vector<std::string> namespaces_rooms; std::vector<std::string> namespaces_aliases;
  std::string protocol; bool supports_ephemeral{false}; bool rate_limited{true};
};
struct AppServiceTransaction {
  std::string id; std::string service_id; int64_t events_count{0}; int64_t result{0}; int64_t txn_id{0};
};
class AppServiceStore { public:
  explicit AppServiceStore(DatabasePool& db);
  void add_appservice(const ApplicationService& svc);
  void update_appservice(const ApplicationService& svc);
  void remove_appservice(const std::string& id);
  std::vector<ApplicationService> get_appservices();
  std::optional<ApplicationService> get_appservice(const std::string& id);
  std::optional<ApplicationService> get_appservice_by_token(const std::string& token);
  int64_t create_appservice_txn(const std::string& service_id, const std::string& id);
  void complete_appservice_txn(const std::string& service_id, int64_t txn_id);
  int64_t get_oldest_unsent_txn(const std::string& service_id);
  std::vector<AppServiceTransaction> get_appservice_txns(const std::string& service_id);
  void set_appservice_last_pos(const std::string& service_id, int64_t pos);
  int64_t get_appservice_last_pos(const std::string& service_id);
  bool is_exclusive_alias(const std::string& alias);
  bool is_exclusive_user(const std::string& user_id);
  bool is_interested_in_room(const std::string& service_id, const std::string& room_id);
  bool is_interested_in_user(const std::string& service_id, const std::string& user_id);
  std::vector<std::string> get_services_for_event(const std::string& event_id, const std::string& room_id);
private: DatabasePool& db_;
};

// ---- KeyStore (keys.py) ----
struct ServerKey {
  std::string server_name; std::string key_id; std::string verify_key;
  int64_t valid_until_ts{0}; int64_t ts_added{0}; std::string key_json;
  std::string from_server;
};
class KeyStore { public:
  explicit KeyStore(DatabasePool& db);
  void store_server_keys(const std::string& server_name, const std::string& from_server,
      const std::vector<ServerKey>& keys, int64_t ts_added);
  std::vector<ServerKey> get_server_keys(const std::string& server_name,
      const std::set<std::string>& key_ids = {});
  void store_server_certificate(const std::string& server_name, const std::string& tls_cert,
      int64_t valid_until_ts, int64_t ts_added);
  std::optional<std::string> get_server_certificate(const std::string& server_name);
  void store_server_signature_keys(const std::string& server_name, const std::string& from_server,
      const std::string& key_json, int64_t ts_added);
  std::optional<json> get_server_signature_keys(const std::string& server_name);
  std::set<std::string> get_all_server_names();
  void delete_old_server_keys(int64_t before_ts);
  int64_t count_server_keys();
private: DatabasePool& db_;
};

// ---- SignatureStore (signatures.py) ----
class SignatureStore { public:
  explicit SignatureStore(DatabasePool& db);
  void store_signature(const std::string& event_id, const std::string& signature,
      const std::string& signer, const std::string& key_id);
  std::map<std::string, std::map<std::string, std::string>> get_signatures(
      const std::vector<std::string>& event_ids);
  void delete_signatures(const std::string& event_id);
  void bulk_store_signatures(const std::string& event_id,
      const std::map<std::string, std::map<std::string, std::string>>& sigs);
  void store_event_reference(const std::string& event_id, const std::string& ref_hash);
  std::vector<std::string> get_event_references(const std::string& event_id);
  // Verify signatures (application-layer)
  bool verify_event_signatures(const std::string& event_id, const json& event);
private: DatabasePool& db_;
};

// ---- TransactionStore (transactions.py) ----
struct FederationTransaction {
  std::string transaction_id; std::string origin; int64_t ts{0};
  std::string response_json; bool has_been_responded{false};
};
class TransactionStore { public:
  explicit TransactionStore(DatabasePool& db);
  void add_transaction(const std::string& txn_id, const std::string& origin, int64_t ts);
  void mark_transaction_responded(const std::string& txn_id, const std::string& origin,
      const std::string& response_json);
  bool has_transaction(const std::string& txn_id, const std::string& origin);
  std::optional<FederationTransaction> get_transaction(const std::string& txn_id,
      const std::string& origin);
  void delete_old_transactions(int64_t before_ts);
  std::vector<FederationTransaction> get_pending_transactions(const std::string& origin);
  int64_t count_transactions();
  // Clean up old PDU/EDU entries
  void delete_old_pdus(int64_t before_ts);
  void delete_old_edus(int64_t before_ts);
  void add_transaction_id_to_pdu(const std::string& txn_id, const std::string& pdu_id);
  void add_transaction_id_to_edu(const std::string& txn_id, const std::string& edu_id);
private: DatabasePool& db_;
};

} // namespace
