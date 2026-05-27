// federation_stores.cpp - appservice, keys, signatures, transactions
#include "federation_stores.hpp"
#include <chrono>
namespace progressive::storage { using json = nlohmann::json;

// ====== AppServiceStore ======
AppServiceStore::AppServiceStore(DatabasePool& db) : db_(db) {}
void AppServiceStore::add_appservice(const ApplicationService& svc) {
  db_.runInteraction("add_as", [&](LoggingTransaction& txn) {
    txn.execute("INSERT INTO application_services (id,url,hs_token,as_token,sender_localpart,protocol,rate_limited) VALUES (?,?,?,?,?,?,?)",
      {svc.id,svc.url,svc.hs_token,svc.as_token,svc.sender_localpart,svc.protocol,svc.rate_limited?1:0});
  });
}
void AppServiceStore::update_appservice(const ApplicationService& svc) { remove_appservice(svc.id); add_appservice(svc); }
void AppServiceStore::remove_appservice(const std::string& id) { db_.runInteraction("rm_as", [&](LoggingTransaction& txn) { txn.execute("DELETE FROM application_services WHERE id=?",{id}); }); }
std::vector<ApplicationService> AppServiceStore::get_appservices() {
  return db_.runInteraction("get_as", [&](LoggingTransaction& txn) -> std::vector<ApplicationService> {
    txn.execute("SELECT id,url,hs_token,as_token,sender_localpart,protocol,rate_limited FROM application_services");
    std::vector<ApplicationService> r;
    for(auto& row:txn.fetchall()) { ApplicationService s; s.id=row.at(0).value.value_or(""); s.url=row.at(1).value.value_or("");
      s.hs_token=row.at(2).value.value_or(""); s.as_token=row.at(3).value.value_or("");
      s.sender_localpart=row.at(4).value.value_or(""); s.protocol=row.at(5).value.value_or(""); s.rate_limited=row.at(6).value.value_or("1")=="1"; r.push_back(s); }
    return r;
  });
}
std::optional<ApplicationService> AppServiceStore::get_appservice(const std::string& id) {
  auto svcs = get_appservices();
  for(auto& s:svcs) if(s.id==id) return s;
  return std::nullopt;
}
std::optional<ApplicationService> AppServiceStore::get_appservice_by_token(const std::string& token) {
  auto svcs = get_appservices();
  for(auto& s:svcs) if(s.as_token==token||s.hs_token==token) return s;
  return std::nullopt;
}
int64_t AppServiceStore::create_appservice_txn(const std::string& sid, const std::string& id) {
  return db_.runInteraction("create_as_txn", [&](LoggingTransaction& txn)->int64_t {
    int64_t ts=std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    txn.execute("INSERT INTO application_services_txns (service_id,id,ts) VALUES (?,?,?)",{sid,id,ts});
    return ts;
  });
}
void AppServiceStore::complete_appservice_txn(const std::string& sid, int64_t tid) {
  db_.runInteraction("complete_as_txn",[&](LoggingTransaction& txn){txn.execute("DELETE FROM application_services_txns WHERE service_id=? AND txn_id=?",{sid,tid});});
}
int64_t AppServiceStore::get_oldest_unsent_txn(const std::string& sid) {
  return db_.runInteraction("oldest_txn",[&](LoggingTransaction& txn)->int64_t{
    txn.execute("SELECT COALESCE(MIN(ts),0) FROM application_services_txns WHERE service_id=?",{sid}); auto r=txn.fetchone(); return r&&r->at(0).value?std::stoll(*r->at(0).value):0;
  });
}
std::vector<AppServiceTransaction> AppServiceStore::get_appservice_txns(const std::string& sid) {
  return db_.runInteraction("get_as_txns",[&](LoggingTransaction& txn)->std::vector<AppServiceTransaction>{
    txn.execute("SELECT id,ts FROM application_services_txns WHERE service_id=? ORDER BY ts",{sid});
    std::vector<AppServiceTransaction> r;
    for(auto& row:txn.fetchall()) r.push_back({row.at(0).value.value_or(""),sid,0,0,std::stoll(row.at(1).value.value_or("0"))});
    return r;
  });
}
void AppServiceStore::set_appservice_last_pos(const std::string& sid,int64_t p) {
  db_.runInteraction("set_as_pos",[&](LoggingTransaction& txn){txn.execute("INSERT INTO appservice_stream_position (service_id,stream_ordering) VALUES (?,?) ON CONFLICT(service_id) DO UPDATE SET stream_ordering=EXCLUDED.stream_ordering",{sid,p});});
}
int64_t AppServiceStore::get_appservice_last_pos(const std::string& sid) {
  return db_.runInteraction("get_as_pos",[&](LoggingTransaction& txn)->int64_t{
    txn.execute("SELECT stream_ordering FROM appservice_stream_position WHERE service_id=?",{sid}); auto r=txn.fetchone(); return r&&r->at(0).value?std::stoll(*r->at(0).value):0;
  });
}
bool AppServiceStore::is_exclusive_alias(const std::string& a) { auto svcs=get_appservices(); for(auto& s:svcs) for(auto& n:s.namespaces_aliases) if(a.find(n)!=std::string::npos) return true; return false; }
bool AppServiceStore::is_exclusive_user(const std::string& uid) { auto svcs=get_appservices(); for(auto& s:svcs) for(auto& n:s.namespaces_users) if(uid.find(n)!=std::string::npos) return true; return false; }
bool AppServiceStore::is_interested_in_room(const std::string& sid, const std::string& rid) { return true; }
bool AppServiceStore::is_interested_in_user(const std::string& sid, const std::string& uid) { return true; }
std::vector<std::string> AppServiceStore::get_services_for_event(const std::string&, const std::string&) { return {}; }

// ====== KeyStore ======
KeyStore::KeyStore(DatabasePool& db) : db_(db) {}
void KeyStore::store_server_keys(const std::string& sn, const std::string& from,
    const std::vector<ServerKey>& keys, int64_t ta) {
  db_.runInteraction("store_keys",[&](LoggingTransaction& txn){
    for(auto& k:keys) txn.execute("INSERT INTO server_keys_json (server_name,key_id,from_server,ts_added,ts_valid_until_ms,key_json) VALUES (?,?,?,?,?,?) ON CONFLICT(server_name,key_id) DO UPDATE SET key_json=EXCLUDED.key_json,ts_added=EXCLUDED.ts_added",
      {sn,k.key_id,from,ta,k.valid_until_ts,k.key_json});
  });
}
std::vector<ServerKey> KeyStore::get_server_keys(const std::string& sn, const std::set<std::string>& kids) {
  return db_.runInteraction("get_keys",[&](LoggingTransaction& txn)->std::vector<ServerKey>{
    std::string sql="SELECT key_id,verify_key,valid_until_ts,key_json,from_server,ts_added FROM server_keys_json WHERE server_name=?";
    if(!kids.empty()){ sql+=" AND key_id IN ("; bool f=true; for(auto&k:kids){if(!f)sql+=","; sql+="?"; f=false;} sql+=")"; }
    std::vector<SQLParam> params={sn}; for(auto&k:kids) params.push_back(k);
    txn.execute(sql,params);
    std::vector<ServerKey> r;
    for(auto& row:txn.fetchall()) r.push_back({sn,row.at(0).value.value_or(""),row.at(1).value.value_or(""),std::stoll(row.at(2).value.value_or("0")),std::stoll(row.at(5).value.value_or("0")),row.at(3).value.value_or("{}"),row.at(4).value.value_or("")});
    return r;
  });
}
void KeyStore::store_server_certificate(const std::string& sn, const std::string& cert, int64_t vts, int64_t ta) {
  db_.runInteraction("store_cert",[&](LoggingTransaction& txn){txn.execute("INSERT INTO server_tls_certificates (server_name,tls_certificate,valid_until_ts,ts_added) VALUES (?,?,?,?)",{sn,cert,vts,ta});});
}
std::optional<std::string> KeyStore::get_server_certificate(const std::string& sn) {
  return db_.runInteraction("get_cert",[&](LoggingTransaction& txn)->std::optional<std::string>{
    txn.execute("SELECT tls_certificate FROM server_tls_certificates WHERE server_name=? ORDER BY valid_until_ts DESC LIMIT 1",{sn}); auto r=txn.fetchone(); if(r&&r->at(0).value)return *r->at(0).value; return std::nullopt;
  });
}
void KeyStore::store_server_signature_keys(const std::string& sn, const std::string& from, const std::string& kj, int64_t ta) {
  db_.runInteraction("store_sig_keys",[&](LoggingTransaction& txn){txn.execute("INSERT INTO server_signature_keys (server_name,from_server,key_json,ts_added) VALUES (?,?,?,?)",{sn,from,kj,ta});});
}
std::optional<json> KeyStore::get_server_signature_keys(const std::string& sn) {
  return db_.runInteraction("get_sig_keys",[&](LoggingTransaction& txn)->std::optional<json>{
    txn.execute("SELECT key_json FROM server_signature_keys WHERE server_name=? ORDER BY ts_added DESC LIMIT 1",{sn}); auto r=txn.fetchone(); if(r&&r->at(0).value) try{return json::parse(*r->at(0).value);}catch(...){} return std::nullopt;
  });
}
std::set<std::string> KeyStore::get_all_server_names() {
  return db_.runInteraction("get_all_sn",[&](LoggingTransaction& txn)->std::set<std::string>{
    txn.execute("SELECT DISTINCT server_name FROM server_keys_json"); std::set<std::string> r; for(auto& row:txn.fetchall()) if(row.at(0).value) r.insert(*row.at(0).value); return r;
  });
}
void KeyStore::delete_old_server_keys(int64_t bt) { db_.runInteraction("del_old_keys",[&](LoggingTransaction& txn){txn.execute("DELETE FROM server_keys_json WHERE ts_valid_until_ms<?",{bt});}); }
int64_t KeyStore::count_server_keys() { return db_.runInteraction("count_keys",[&](LoggingTransaction& txn)->int64_t{txn.execute("SELECT COUNT(*) FROM server_keys_json"); auto r=txn.fetchone(); return r&&r->at(0).value?std::stoll(*r->at(0).value):0;}); }

// ====== SignatureStore ======
SignatureStore::SignatureStore(DatabasePool& db) : db_(db) {}
void SignatureStore::store_signature(const std::string& eid, const std::string& sig, const std::string& signer, const std::string& kid) {
  db_.runInteraction("store_sig",[&](LoggingTransaction& txn){txn.execute("INSERT INTO event_signatures (event_id,signature,signer,key_id) VALUES (?,?,?,?)",{eid,sig,signer,kid});});
}
std::map<std::string,std::map<std::string,std::string>> SignatureStore::get_signatures(const std::vector<std::string>& eids) {
  return db_.runInteraction("get_sigs",[&](LoggingTransaction& txn)->std::map<std::string,std::map<std::string,std::string>>{
    std::map<std::string,std::map<std::string,std::string>> r;
    for(auto& eid:eids){ txn.execute("SELECT signer,signature FROM event_signatures WHERE event_id=?",{eid}); for(auto& row:txn.fetchall()) r[eid][row.at(0).value.value_or("")]=row.at(1).value.value_or(""); }
    return r;
  });
}
void SignatureStore::delete_signatures(const std::string& eid) { db_.runInteraction("del_sigs",[&](LoggingTransaction& txn){txn.execute("DELETE FROM event_signatures WHERE event_id=?",{eid});}); }
void SignatureStore::bulk_store_signatures(const std::string& eid, const std::map<std::string,std::map<std::string,std::string>>& sigs) {
  db_.runInteraction("bulk_sigs",[&](LoggingTransaction& txn){for(auto&[s,kmap]:sigs)for(auto&[k,v]:kmap)txn.execute("INSERT INTO event_signatures(event_id,signature,signer,key_id)VALUES(?,?,?,?)",{eid,v,s,k});});
}
void SignatureStore::store_event_reference(const std::string& eid, const std::string& rh) { db_.runInteraction("store_ref",[&](LoggingTransaction& txn){txn.execute("INSERT INTO event_reference_hashes(event_id,ref_hash)VALUES(?,?)",{eid,rh});}); }
std::vector<std::string> SignatureStore::get_event_references(const std::string& eid) {
  return db_.runInteraction("get_refs",[&](LoggingTransaction& txn)->std::vector<std::string>{txn.execute("SELECT ref_hash FROM event_reference_hashes WHERE event_id=?",{eid}); std::vector<std::string> r; for(auto& row:txn.fetchall()) if(row.at(0).value) r.push_back(*row.at(0).value); return r;});
}
bool SignatureStore::verify_event_signatures(const std::string&, const json&) { return true; }

// ====== TransactionStore ======
TransactionStore::TransactionStore(DatabasePool& db) : db_(db) {}
void TransactionStore::add_transaction(const std::string& tid, const std::string& origin, int64_t ts) {
  db_.runInteraction("add_txn",[&](LoggingTransaction& txn){txn.execute("INSERT INTO received_transactions(transaction_id,origin,ts)VALUES(?,?,?)",{tid,origin,ts});});
}
void TransactionStore::mark_transaction_responded(const std::string& tid, const std::string& origin, const std::string& rj) {
  db_.runInteraction("mark_txn",[&](LoggingTransaction& txn){txn.execute("UPDATE received_transactions SET response_json=?,has_been_responded=1 WHERE transaction_id=? AND origin=?",{rj,tid,origin});});
}
bool TransactionStore::has_transaction(const std::string& tid, const std::string& origin) {
  return db_.runInteraction("has_txn",[&](LoggingTransaction& txn)->bool{txn.execute("SELECT 1 FROM received_transactions WHERE transaction_id=? AND origin=?",{tid,origin}); return txn.fetchone().has_value();});
}
std::optional<FederationTransaction> TransactionStore::get_transaction(const std::string& tid, const std::string& origin) {
  return db_.runInteraction("get_txn",[&](LoggingTransaction& txn)->std::optional<FederationTransaction>{
    txn.execute("SELECT ts,response_json,has_been_responded FROM received_transactions WHERE transaction_id=? AND origin=?",{tid,origin}); auto r=txn.fetchone(); if(!r)return std::nullopt; return FederationTransaction{tid,origin,std::stoll(r->at(0).value.value_or("0")),r->at(1).value.value_or(""),r->at(2).value.value_or("0")=="1"};});
}
void TransactionStore::delete_old_transactions(int64_t bt) { db_.runInteraction("del_old_txn",[&](LoggingTransaction& txn){txn.execute("DELETE FROM received_transactions WHERE ts<?",{bt});}); }
std::vector<FederationTransaction> TransactionStore::get_pending_transactions(const std::string& origin) {
  return db_.runInteraction("pending_txn",[&](LoggingTransaction& txn)->std::vector<FederationTransaction>{
    txn.execute("SELECT transaction_id,ts FROM received_transactions WHERE origin=? AND has_been_responded=0",{origin}); std::vector<FederationTransaction> r; for(auto& row:txn.fetchall()) r.push_back({row.at(0).value.value_or(""),origin,std::stoll(row.at(1).value.value_or("0"))}); return r;
  });
}
int64_t TransactionStore::count_transactions() { return db_.runInteraction("count_txn",[&](LoggingTransaction& txn)->int64_t{txn.execute("SELECT COUNT(*) FROM received_transactions"); auto r=txn.fetchone(); return r&&r->at(0).value?std::stoll(*r->at(0).value):0;}); }
void TransactionStore::delete_old_pdus(int64_t bt) { db_.runInteraction("del_old_pdus",[&](LoggingTransaction& txn){txn.execute("DELETE FROM received_transactions WHERE ts<?",{bt});}); }
void TransactionStore::delete_old_edus(int64_t bt) { db_.runInteraction("del_old_edus",[&](LoggingTransaction& txn){txn.execute("DELETE FROM received_transactions WHERE ts<? AND has_been_responded=1",{bt});}); }
void TransactionStore::add_transaction_id_to_pdu(const std::string& tid, const std::string& pid) {}
void TransactionStore::add_transaction_id_to_edu(const std::string& tid, const std::string& eid) {}

} // namespace
