#pragma once
#include <cstdint>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <string_view>

namespace progressive::worker {

enum class WorkerType : uint8_t {
  Generic = 0,
  ClientReader,
  FederationSender,
  FederationReader,
  EventCreator,
  EventPersister,
  Pusher,
  Appservice,
  Synchrotron,
  MediaRepository,
  UserDir,
  FrontendProxy,
  PhoneStats
};

enum class StreamType : uint8_t {
  Events = 0,
  Backfill,
  Presence,
  Typing,
  Receipts,
  AccountData,
  DeviceLists,
  ToDevice,
  PushRules,
  StateDeltas,
  SlidingSyncConnections,
  CurrentStateDeltas,
  UnPartialStatedRooms,
  COUNT
};

struct WorkerConfig {
  WorkerType type = WorkerType::Generic;
  std::string worker_name;
  std::string worker_replication_host;
  int worker_replication_port = 9093;
  bool run_background_tasks = true;
  std::set<StreamType> streams_to_replicate;
};

class ReplicationStream {
public:
  ReplicationStream(StreamType type);

  int64_t current_position() const;
  void advance(int64_t position);
  bool has_changed_since(int64_t token) const;

private:
  StreamType type_;
  int64_t position_ = 0;
};

class StreamPositionStore {
public:
  void update_position(std::string_view worker_name, StreamType type, int64_t position);
  int64_t get_position(std::string_view worker_name, StreamType type) const;
  std::map<StreamType, int64_t> get_all_positions(std::string_view worker_name) const;

  void clear();

private:
  mutable std::mutex mutex_;
  std::map<std::string, std::map<StreamType, int64_t>, std::less<>> positions_;
};

class WorkerLockManager {
public:
  bool acquire(std::string_view lock_name, int timeout_ms = 5000);
  void release(std::string_view lock_name);
  bool is_locked(std::string_view lock_name) const;

private:
  std::map<std::string, bool, std::less<>> locks_;
  mutable std::mutex mutex_;
};

class WorkerRegistry {
public:
  void register_worker(std::string_view name, WorkerType type);
  void unregister_worker(std::string_view name);
  std::set<std::string> get_workers_of_type(WorkerType type) const;
  std::set<std::string> get_all_workers() const;

private:
  mutable std::mutex mutex_;
  std::map<std::string, WorkerType, std::less<>> workers_;
};

}  // namespace progressive::worker
