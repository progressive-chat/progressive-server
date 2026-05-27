// fed_transport.cpp - Federation transport implementation
#include "fed_transport.hpp"
#include <chrono>
namespace progressive::federation {
using json = nlohmann::json;
static int64_t nms(){return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count();}

// ====== FederationClient ======
FederationClient::FederationClient(storage::DatabasePool& db):db_(db){}
json FederationClient::send_transaction(const std::string& dest,const json& data){json r;r["pdus"]=json::object();return r;}
json FederationClient::make_join(const std::string& dest,const std::string& rid,const std::string& uid,const std::vector<std::string>& sv){json r;r["event"]=json::object();r["room_version"]="1";return r;}
json FederationClient::send_join(const std::string& dest,const std::string& rid,const std::string& eid,const json& ev){return json::object();}
json FederationClient::make_leave(const std::string& dest,const std::string& rid,const std::string& uid){json r;r["event"]=json::object();r["room_version"]="1";return r;}
json FederationClient::send_leave(const std::string& dest,const std::string& rid,const std::string& eid,const json& ev){return json::object();}
json FederationClient::make_invite(const std::string& dest,const std::string& rid,const std::string& eid,const json& ev){json r;r["event"]=json::object();r["room_version"]="1";return r;}
json FederationClient::send_invite(const std::string& dest,const std::string& rid,const std::string& eid,const json& ev,const json& irs){return json::object();}
json FederationClient::send_invite_v2(const std::string& dest,const std::string& rid,const std::string& eid,const json& ev,const json& irs,const std::string& rv){return json::object();}
json FederationClient::get_missing_events(const std::string& dest,const std::string& rid,const std::vector<std::string>& me,const std::vector<std::string>& ee,const std::vector<std::string>& le,int l,int md){json r;r["events"]=json::array();return r;}
json FederationClient::backfill(const std::string& dest,const std::string& rid,const std::vector<std::string>& ext,int l){json r;r["pdus"]=json::array();return r;}
json FederationClient::get_event(const std::string& dest,const std::string& eid){json r;return r;}
json FederationClient::get_event_auth(const std::string& dest,const std::string& rid,const std::string& eid){json r;r["auth_chain"]=json::array();return r;}
json FederationClient::get_room_state(const std::string& dest,const std::string& rid,const std::string& eid){return json::object();}
json FederationClient::get_room_state_ids(const std::string& dest,const std::string& rid,const std::string& eid){json r;r["pdu_ids"]=json::array();return r;}
json FederationClient::get_profile(const std::string& dest,const std::string& uid){json r;return r;}
json FederationClient::claim_client_keys(const std::string& dest,const json& otk){json r;r["one_time_keys"]=json::object();return r;}
json FederationClient::query_client_keys(const std::string& dest,const json& qc){json r;r["device_keys"]=json::object();return r;}
json FederationClient::get_server_keys(const std::string& dest,const std::set<std::string>& kids){json r;r["server_name"]=dest;r["verify_keys"]=json::object();return r;}
json FederationClient::get_server_version(const std::string& dest){json r;r["server"]={{"name",dest},{"version","1.0"}};return r;}
json FederationClient::exchange_third_party_invite(const std::string& dest,const std::string& rid,const json& ev){return json::object();}
json FederationClient::make_knock(const std::string& dest,const std::string& rid,const std::string& uid,const std::vector<std::string>& sv){json r;r["event"]=json::object();r["room_version"]="1";return r;}
json FederationClient::send_knock(const std::string& dest,const std::string& rid,const std::string& eid,const json& ev){return json::object();}
json FederationClient::get_room_hierarchy(const std::string& dest,const std::string& rid,bool so){json r;r["rooms"]=json::array();return r;}
json FederationClient::send_request(const std::string& method,const std::string& dest,const std::string& path,const json& content,int64_t to){return json::object();}
json FederationClient::sign_json(const json& data,const std::string& dest){return data;}
bool FederationClient::verify_signed_json(const json& data,const std::string& origin){return true;}

// ====== FederationServer ======
FederationServer::FederationServer(storage::DatabasePool& db):db_(db){}
json FederationServer::on_incoming_transaction(const std::string& origin,const std::string& tid,const json& content){json r;r["pdus"]=json::object();return r;}
json FederationServer::on_make_join(const std::string& origin,const std::string& rid,const std::string& uid,const std::vector<std::string>& sv){json r;r["event"]=json::object();r["room_version"]="1";return r;}
json FederationServer::on_send_join(const std::string& origin,const std::string& rid,const std::string& eid,const json& content){json r;r["state"]=json::array();r["auth_chain"]=json::array();r["origin"]=origin;return r;}
json FederationServer::on_make_leave(const std::string& origin,const std::string& rid,const std::string& uid){json r;r["event"]=json::object();r["room_version"]="1";return r;}
json FederationServer::on_send_leave(const std::string& origin,const std::string& rid,const std::string& eid,const json& content){return json::object();}
json FederationServer::on_make_invite(const std::string& origin,const std::string& rid,const std::string& eid,const json& content){json r;r["event"]=json::object();r["room_version"]="1";return r;}
json FederationServer::on_send_invite(const std::string& origin,const std::string& rid,const std::string& eid,const json& content,const json& irs){return json::object();}
json FederationServer::on_get_missing_events(const std::string& origin,const std::string& rid,const std::vector<std::string>& me,const std::vector<std::string>& ee,const std::vector<std::string>& le,int l,int md){json r;r["events"]=json::array();return r;}
json FederationServer::on_backfill(const std::string& origin,const std::string& rid,const std::vector<std::string>& ext,int l){json r;r["pdus"]=json::array();return r;}
json FederationServer::on_get_event(const std::string& origin,const std::string& eid){return json::object();}
json FederationServer::on_get_event_auth(const std::string& origin,const std::string& rid,const std::string& eid){json r;r["auth_chain"]=json::array();return r;}
json FederationServer::on_query_request(const std::string& origin,const std::string& qt,const json& content){return json::object();}
json FederationServer::on_query_client_keys(const std::string& origin,const json& content){json r;r["device_keys"]=json::object();return r;}
json FederationServer::on_claim_client_keys(const std::string& origin,const json& content){json r;r["one_time_keys"]=json::object();return r;}
json FederationServer::on_query_profile(const std::string& origin,const std::string& uid,const std::optional<std::string>& field){json r;return r;}
json FederationServer::on_make_knock(const std::string& origin,const std::string& rid,const std::string& uid,const std::vector<std::string>& sv){json r;r["event"]=json::object();r["room_version"]="1";return r;}
json FederationServer::on_send_knock(const std::string& origin,const std::string& rid,const std::string& eid,const json& content){return json::object();}
json FederationServer::on_get_room_hierarchy(const std::string& origin,const std::string& rid,bool so){json r;r["rooms"]=json::array();return r;}
json FederationServer::on_timestamp_to_event(const std::string& origin,const std::string& rid,int64_t ts,const std::string& dir){json r;r["event_id"]="";return r;}
json FederationServer::on_get_spaces(const std::string& origin){json r;r["rooms"]=json::array();return r;}
json FederationServer::on_get_public_rooms(const std::string& origin,int l,const std::string& since,const std::string& st,bool ia,const std::string& net,const std::string& tpi){json r;r["chunk"]=json::array();return r;}
json FederationServer::on_exchange_third_party_invite(const std::string& origin,const std::string& rid,const json& ev){return json::object();}
bool FederationServer::validate_request(const std::string& origin,const std::string& method,const std::string& path,const json& content){return true;}

// ====== FederationTransport ======
FederationTransport::FederationTransport(storage::DatabasePool& db):db_(db){}
void FederationTransport::start(int port){}
void FederationTransport::stop(){}
FederationTransport::HttpResponse FederationTransport::send_http_request(const std::string& method,const std::string& dest,const std::string& path,const json& content,int64_t to){return {200,json::object(),{}};}
std::string FederationTransport::resolve_server(const std::string& sn){return sn+":8448";}
bool FederationTransport::is_server_reachable(const std::string& sn){return true;}
void FederationTransport::wake_destination(const std::string& dest){}
std::optional<std::string> FederationTransport::get_tls_certificate(const std::string& dest){return std::nullopt;}
void FederationTransport::set_tls_certificate(const std::string& cert){}
void FederationTransport::set_signing_key(const std::string& kid,const std::string& key){}

} // namespace
