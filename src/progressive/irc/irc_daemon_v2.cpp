// progressive-server: IRC Daemon / Network Layer
// Reference: InspIRCd socketengines/socketengine_epoll.cpp (3,200 lines),
//           core_info/unix_socket.cpp, modulemanager.cpp, config_reader.cpp
// Full epoll-based async network engine for IRC protocol

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <csignal>
#include <cstring>
#include <cerrno>
#include <cstdarg>
#include <ctime>
#include <string>
#include <atomic>
#include <thread>
#include <vector>
#include <deque>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <unordered_map>
#include <unordered_set>

namespace progressive {
namespace irc {

// Forward declarations
class IrcUser;
class IrcChannel;
class IrcServerInstance;

static constexpr size_t MAX_EVENTS = 1024;
static constexpr size_t READ_BUFFER_SIZE = 16384;
static constexpr size_t MAX_LINE_LENGTH = 8192;
static constexpr int DEFAULT_PORT = 6667;
static constexpr int SSL_PORT = 6697;
static constexpr int BACKLOG = 128;

// =============================================================================
// Connection buffer
// =============================================================================
struct ConnBuffer {
    std::array<char, READ_BUFFER_SIZE> read_buf{};
    size_t read_pos = 0;
    std::deque<std::string> send_queue;
    std::string partial_line;
    bool closed = false;
    bool write_pending = false;

    void append_data(const char* data, size_t len) {
        std::string_view view(data, len);
        partial_line.append(data, len);
        // Extract complete lines (terminated by \r\n or \n)
        while (true) {
            size_t crlf = partial_line.find("\r\n");
            size_t lf = partial_line.find('\n');
            size_t delim = std::string::npos;

            if (crlf != std::string::npos && (lf == std::string::npos || crlf <= lf)) {
                delim = crlf;
            } else if (lf != std::string::npos) {
                delim = lf;
            } else break;

            std::string line = partial_line.substr(0, delim);
            size_t skip = (partial_line[delim] == '\r') ? 2 : 1;
            partial_line.erase(0, delim + skip);

            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (!line.empty()) {
                lines.push_back(std::move(line));
                if (lines.size() > 1000) lines.pop_front();  // prevent memory blowout
            }
        }
        if (partial_line.size() > MAX_LINE_LENGTH) {
            // Oversized line - truncate
            partial_line = partial_line.substr(partial_line.size() - MAX_LINE_LENGTH);
        }
    }

    std::deque<std::string> lines;
};

// =============================================================================
// TCP listener socket
// =============================================================================
struct ListenSocket {
    int fd = -1;
    int port = 0;
    bool ssl = false;
    std::string bind_addr;
    std::string type; // "clients", "servers"

    bool is_valid() const { return fd >= 0; }
    void close() {
        if (fd >= 0) { ::close(fd); fd = -1; }
    }
};

// =============================================================================
// Client connection
// =============================================================================
struct ClientConnection {
    int fd = -1;
    std::string uuid;
    std::string remote_addr;
    uint16_t remote_port = 0;
    ConnBuffer buffer;
    time_t connected_at = 0;
    time_t last_activity = 0;
    time_t last_data = 0;
    int64_t bytes_in = 0;
    int64_t bytes_out = 0;
    bool registered = false;
    bool ssl = false;
    bool zombie = false;       // marked for deletion
    bool sendq_exceeded = false;
    int penalty = 0;           // anti-flood penalty
    int penalty_counter = 0;
    void* ssl_ctx = nullptr;  // SSL* pointer (opaque)

    void reset() {
        buffer = ConnBuffer{};
        partial_line.clear();
        zombie = false;
        sendq_exceeded = false;
        penalty = 0;
        penalty_counter = 0;
    }

    std::string partial_line;
};

// =============================================================================
// Rate limiter for connections
// =============================================================================
class ConnectionRateLimiter {
public:
    ConnectionRateLimiter(int max_per_ip = 5, int max_total = 5000, int timeout_sec = 60)
        : max_per_ip_(max_per_ip), max_total_(max_total), timeout_sec_(timeout_sec) {}

    bool allow(const std::string& ip) {
        std::lock_guard lock(mutex_);
        auto now = std::time(nullptr);

        // Cleanup stale entries
        for (auto it = per_ip_.begin(); it != per_ip_.end(); ) {
            if (now - it->second.last_access > timeout_sec_) {
                it = per_ip_.erase(it);
            } else {
                ++it;
            }
        }

        // Check global limit
        if ((int)total_connections_ >= max_total_) return false;

        // Check per-IP limit
        auto& entry = per_ip_[ip];
        if (entry.connections >= max_per_ip_) return false;

        entry.connections++;
        entry.last_access = now;
        total_connections_++;
        return true;
    }

    void release(const std::string& ip) {
        std::lock_guard lock(mutex_);
        auto it = per_ip_.find(ip);
        if (it != per_ip_.end() && it->second.connections > 0) {
            it->second.connections--;
        }
        if (total_connections_ > 0) total_connections_--;
    }

private:
    struct IpEntry {
        int connections = 0;
        time_t last_access = 0;
    };

    int max_per_ip_;
    int max_total_;
    int timeout_sec_;
    std::unordered_map<std::string, IpEntry> per_ip_;
    int total_connections_ = 0;
    std::mutex mutex_;
};

// =============================================================================
// DNS resolver (async, non-blocking)
// =============================================================================
class DnsResolver {
public:
    struct ResolveRequest {
        std::string hostname;
        std::string service;
        int family = AF_UNSPEC;  // AF_INET, AF_INET6, AF_UNSPEC
        std::function<void(std::vector<struct sockaddr_storage>, int error)> callback;
    };

    struct ResolveResult {
        std::string hostname;
        std::vector<std::string> addresses;
        bool resolved = false;
        int error = 0;
        time_t completed_at = 0;
    };

    void resolve(const std::string& hostname, const std::string& service,
                 std::function<void(const std::string&, bool)> callback) {
        struct addrinfo hints{};
        struct addrinfo* result = nullptr;

        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_ADDRCONFIG;

        int ret = getaddrinfo(hostname.c_str(), service.c_str(), &hints, &result);
        bool success = (ret == 0);
        std::string addr;

        if (success && result) {
            char addr_buf[INET6_ADDRSTRLEN];
            void* src = nullptr;

            if (result->ai_family == AF_INET) {
                auto* ipv4 = (struct sockaddr_in*)result->ai_addr;
                src = &ipv4->sin_addr;
            } else if (result->ai_family == AF_INET6) {
                auto* ipv6 = (struct sockaddr_in6*)result->ai_addr;
                src = &ipv6->sin6_addr;
            }

            if (src) {
                inet_ntop(result->ai_family, src, addr_buf, sizeof(addr_buf));
                addr = addr_buf;
            }

            freeaddrinfo(result);
        }

        if (callback) callback(addr, success);
    }

    // Reverse DNS lookup
    void reverse_lookup(const std::string& ip,
                        std::function<void(const std::string&, bool)> callback) {
        struct sockaddr_storage addr{};
        socklen_t addr_len = 0;

        if (ip.find(':') != std::string::npos) {
            // IPv6
            auto* ipv6 = (struct sockaddr_in6*)&addr;
            ipv6->sin6_family = AF_INET6;
            inet_pton(AF_INET6, ip.c_str(), &ipv6->sin6_addr);
            addr_len = sizeof(struct sockaddr_in6);
        } else {
            // IPv4
            auto* ipv4 = (struct sockaddr_in*)&addr;
            ipv4->sin_family = AF_INET;
            inet_pton(AF_INET, ip.c_str(), &ipv4->sin_addr);
            addr_len = sizeof(struct sockaddr_in);
        }

        char host[NI_MAXHOST];
        int ret = getnameinfo((struct sockaddr*)&addr, addr_len,
                              host, sizeof(host), nullptr, 0, NI_NAMEREQD);
        if (callback) {
            std::string hostname = (ret == 0) ? std::string(host) : ip;
            callback(hostname, ret == 0);
        }
    }
};

// =============================================================================
// Epoll Engine
// =============================================================================
class EpollEngine {
public:
    EpollEngine() {
        epfd_ = epoll_create1(EPOLL_CLOEXEC);
        if (epfd_ < 0) {
            throw std::runtime_error("epoll_create1 failed: " +
                                     std::string(strerror(errno)));
        }
    }

    ~EpollEngine() {
        if (epfd_ >= 0) { close(epfd_); }
    }

    // Register a file descriptor for events
    bool add_fd(int fd, uint32_t events, void* ptr = nullptr) {
        struct epoll_event ev{};
        ev.events = events;
        ev.data.ptr = ptr;

        if (epoll_ctl(epfd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
            return false;
        }
        return true;
    }

    bool mod_fd(int fd, uint32_t events) {
        struct epoll_event ev{};
        ev.events = events;
        ev.data.ptr = nullptr;

        // We need to restore the data pointer; fetch current
        // In practice, manage this via the fd_map
        auto it = fd_map_.find(fd);
        if (it != fd_map_.end()) {
            ev.data.ptr = it->second;
        }

        return epoll_ctl(epfd_, EPOLL_CTL_MOD, fd, &ev) >= 0;
    }

    bool del_fd(int fd) {
        fd_map_.erase(fd);
        return epoll_ctl(epfd_, EPOLL_CTL_DEL, fd, nullptr) >= 0;
    }

    void set_ptr(int fd, void* ptr) {
        fd_map_[fd] = ptr;
    }

    // Wait for events
    int wait(struct epoll_event* events, int maxevents, int timeout_ms) {
        return epoll_wait(epfd_, events, maxevents, timeout_ms);
    }

    int fd() const { return epfd_; }

private:
    int epfd_ = -1;
    std::unordered_map<int, void*> fd_map_;
};

// =============================================================================
// Socket helpers
// =============================================================================
inline int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

inline int set_nodelay(int fd) {
    int opt = 1;
    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));
}

inline int set_keepalive(int fd, int idle = 60, int interval = 10, int count = 3) {
    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
#ifdef TCP_KEEPIDLE
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof(idle));
#endif
#ifdef TCP_KEEPINTVL
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &interval, sizeof(interval));
#endif
#ifdef TCP_KEEPCNT
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &count, sizeof(count));
#endif
    return 0;
}

inline int create_listen_socket(const std::string& bind_addr, int port,
                                 bool ipv6 = false) {
    int domain = ipv6 ? AF_INET6 : AF_INET;
    int fd = socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        // Fallback for older systems without SOCK_NONBLOCK
        fd = socket(domain, SOCK_STREAM, 0);
        if (fd >= 0) {
            set_nonblocking(fd);
        }
    }
    if (fd < 0) return -1;

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    if (ipv6) {
        // Enable dual-stack (IPv4 mapped)
        int optval = 0;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &optval, sizeof(optval));

        struct sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        if (bind_addr.empty() || bind_addr == "*") {
            addr.sin6_addr = in6addr_any;
        } else {
            inet_pton(AF_INET6, bind_addr.c_str(), &addr.sin6_addr);
        }

        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(fd);
            return -1;
        }
    } else {
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        if (bind_addr.empty() || bind_addr == "*") {
            addr.sin_addr.s_addr = INADDR_ANY;
        } else {
            inet_pton(AF_INET, bind_addr.c_str(), &addr.sin_addr);
        }

        if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(fd);
            return -1;
        }
    }

    if (listen(fd, BACKLOG) < 0) {
        close(fd);
        return -1;
    }

    set_nonblocking(fd);
    return fd;
}

inline int connect_to_host(const std::string& host, int port, bool ipv6 = false) {
    int domain = ipv6 ? AF_INET6 : AF_INET;
    int fd = socket(domain, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    set_nodelay(fd);

    if (ipv6) {
        struct sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(port);
        inet_pton(AF_INET6, host.c_str(), &addr.sin6_addr);
        connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    } else {
        struct sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
        connect(fd, (struct sockaddr*)&addr, sizeof(addr));
    }

    return fd; // Non-blocking, will complete in background
}

// =============================================================================
// IRC Daemon
// =============================================================================
class IrcDaemon {
public:
    IrcDaemon() : server_(std::make_shared<IrcServerInstance>()) {}

    ~IrcDaemon() {
        stop();
    }

    // ========== Configuration ==========
    struct IrcConfig {
        std::string server_name = "progressive.local";
        std::string network_name = "Progressive";
        std::string server_desc = "Progressive IRC Server";
        std::string bind_addr = "0.0.0.0";
        std::vector<int> ports = {6667, 6697};
        std::vector<int> ssl_ports = {6697};
        int max_clients = 10000;
        int ping_timeout = 120;
        int ping_frequency = 60;
        int max_sendq = 262144;        // 256KB
        int max_channel = 100;
        int max_nick_length = 30;
        int max_topic_length = 390;
        int max_kick_length = 1024;
        int max_away_length = 360;
        int max_quit_length = 512;
        int connect_timeout = 10;
        int handshake_timeout = 30;
        int registration_timeout = 60;
        std::string motd_file;
        std::string rules_file;
        std::string server_password;
        bool hide_server_notices = false;
        bool hide_uline_servers = false;
        bool announce_invites = true;
        bool cycle_hosts = false;
        bool disable_auth = false;
        bool require_ssl = false;
        bool ipv6 = false;
        bool soft_ban = false;
    };

    void configure(const IrcConfig& cfg) {
        config_ = cfg;
        server_->set_server_name(cfg.server_name);
        server_->set_network_name(cfg.network_name);
        server_->set_server_desc(cfg.server_desc);
        server_->set_version_string("progressive-server-irc-0.1.0");
        if (!cfg.server_password.empty()) {
            server_->set_server_password(cfg.server_password);
        }
        // Load MOTD from file if set
        if (!cfg.motd_file.empty()) {
            load_motd_file(cfg.motd_file);
        }
    }

    void load_motd_file(const std::string& path) {
        std::ifstream file(path);
        if (!file.is_open()) return;
        std::vector<std::string> lines;
        std::string line;
        while (std::getline(file, line)) {
            if (line.size() > 400) line = line.substr(0, 400);
            lines.push_back(line);
        }
        server_->set_motd(lines);
    }

    // ========== Start / Stop ==========
    bool start() {
        if (running_.exchange(true)) return false;

        engine_ = std::make_unique<EpollEngine>();

        // Create listen sockets
        for (int port : config_.ports) {
            bool is_ssl = false;
            for (int sp : config_.ssl_ports) {
                if (sp == port) { is_ssl = true; break; }
            }

            int fd = create_listen_socket(config_.bind_addr, port, config_.ipv6);
            if (fd >= 0) {
                ListenSocket ls;
                ls.fd = fd;
                ls.port = port;
                ls.ssl = is_ssl;
                ls.bind_addr = config_.bind_addr;
                ls.type = "clients";

                engine_->add_fd(fd, EPOLLIN);
                engine_->set_ptr(fd, (void*)(intptr_t)(-1 - port)); // neg marker = listener
                listen_sockets_.push_back(ls);
            }
        }

        if (listen_sockets_.empty()) {
            running_ = false;
            return false;
        }

        // Start worker thread
        worker_thread_ = std::thread(&IrcDaemon::event_loop, this);
        return true;
    }

    void stop() {
        running_.store(false);

        if (engine_ && epfd() >= 0) {
            // Wake epoll
            ::write(wakeup_pipe_[1], "x", 1);
        }

        if (worker_thread_.joinable()) {
            worker_thread_.join();
        }

        // Close all connections
        for (auto& [fd, conn] : connections_) {
            close_connection(fd);
        }
        connections_.clear();

        // Close listen sockets
        for (auto& ls : listen_sockets_) {
            ls.close();
        }
        listen_sockets_.clear();

        client_ptrs_.clear();
        engine_.reset();
    }

    // ========== Event loop ==========
    void event_loop() {
        struct epoll_event events[MAX_EVENTS];
        time_t last_ping_check = std::time(nullptr);

        while (running_.load(std::memory_order_relaxed)) {
            int nfds = engine_->wait(events, MAX_EVENTS, 1000); // 1 sec timeout

            time_t now = std::time(nullptr);

            // Periodic ping check
            if (now - last_ping_check >= static_cast<time_t>(config_.ping_frequency)) {
                send_pings(now);
                last_ping_check = now;
            }

            // Process events
            for (int i = 0; i < nfds; i++) {
                int fd = events[i].data.fd;
                uint32_t ev = events[i].events;

                // Check if this is a listen socket
                if (is_listen_socket(fd)) {
                    if (ev & EPOLLIN) {
                        accept_connection(fd);
                    }
                    continue;
                }

                // Client connection
                if (ev & (EPOLLERR | EPOLLHUP)) {
                    cleanup_connection(fd, "Connection error");
                    continue;
                }

                if (ev & EPOLLIN) {
                    handle_read(fd);
                }

                if (ev & EPOLLOUT) {
                    handle_write(fd);
                }
            }

            // Flush send queues
            flush_send_queues();

            // Cleanup zombies
            cleanup_zombies();
        }
    }

    // ========== Connection handling ==========
    void accept_connection(int listen_fd) {
        struct sockaddr_storage addr{};
        socklen_t addr_len = sizeof(addr);
        int client_fd = accept4(listen_fd, (struct sockaddr*)&addr, &addr_len,
                                SOCK_NONBLOCK | SOCK_CLOEXEC);

        if (client_fd < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                // Real error
            }
            return;
        }

        if (static_cast<int>(connections_.size()) >= config_.max_clients) {
            close(client_fd);
            return;
        }

        // Extract remote address
        char remote_ip[INET6_ADDRSTRLEN];
        uint16_t remote_port = 0;

        if (addr.ss_family == AF_INET) {
            auto* ipv4 = (struct sockaddr_in*)&addr;
            inet_ntop(AF_INET, &ipv4->sin_addr, remote_ip, sizeof(remote_ip));
            remote_port = ntohs(ipv4->sin_port);
        } else if (addr.ss_family == AF_INET6) {
            auto* ipv6 = (struct sockaddr_in6*)&addr;
            inet_ntop(AF_INET6, &ipv6->sin6_addr, remote_ip, sizeof(remote_ip));
            remote_port = ntohs(ipv6->sin6_port);
        }

        std::string ip_str(remote_ip);
        if (!rate_limiter_.allow(ip_str)) {
            close(client_fd);
            return;
        }

        // Set socket options
        set_nodelay(client_fd);
        set_keepalive(client_fd);

        // Create connection
        auto& conn = connections_[client_fd];
        conn.fd = client_fd;
        conn.uuid = generate_uuid();
        conn.remote_addr = ip_str;
        conn.remote_port = remote_port;
        conn.connected_at = std::time(nullptr);
        conn.last_activity = conn.connected_at;
        conn.last_data = conn.connected_at;

        // Create user object
        auto user = std::make_shared<IrcUser>(conn.uuid);
        user->set_server_name(config_.server_name);
        auto& stats = user->stats();
        stats.remote_addr = ip_str;
        stats.remote_port = remote_port;
        stats.connected_at = conn.connected_at;
        client_ptrs_[conn.uuid] = user;
        server_->add_user(user);

        // Register with epoll
        if (engine_->add_fd(client_fd, EPOLLIN | EPOLLOUT | EPOLLET)) {
            conn.last_activity = std::time(nullptr);
        } else {
            cleanup_connection(client_fd, "Epoll add failed");
        }
    }

    // ========== Read / Write ==========
    void handle_read(int fd) {
        auto it = connections_.find(fd);
        if (it == connections_.end()) return;

        auto& conn = it->second;
        auto user = find_client(fd);
        if (!user) return;

        char buf[READ_BUFFER_SIZE];
        ssize_t nread = 0;
        size_t total_read = 0;

        while (true) {
            nread = ::read(fd, buf, sizeof(buf));
            if (nread > 0) {
                total_read += nread;
                conn.bytes_in += nread;
                conn.buffer.append_data(buf, nread);
                conn.last_data = std::time(nullptr);
                conn.last_activity = conn.last_data;
            } else if (nread == 0) {
                // Connection closed by peer
                cleanup_connection(fd, "Connection closed");
                return;
            } else {
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                if (errno == EINTR) continue;
                cleanup_connection(fd, strerror(errno));
                return;
            }
        }

        // Process parsed lines
        while (!conn.buffer.lines.empty()) {
            std::string line = std::move(conn.buffer.lines.front());
            conn.buffer.lines.pop_front();
            process_line(fd, conn, line);
        }
    }

    void handle_write(int fd) {
        auto it = connections_.find(fd);
        if (it == connections_.end()) return;

        auto& conn = it->second;
        if (conn.buffer.send_queue.empty()) return;

        // Build iovec for scatter/gather write
        const size_t max_iov = 32;
        struct iovec iov[max_iov];
        size_t iov_count = 0;
        size_t total_to_send = 0;

        for (auto& msg : conn.buffer.send_queue) {
            if (iov_count >= max_iov) break;
            iov[iov_count].iov_base = (void*)msg.data();
            iov[iov_count].iov_len = msg.size();
            total_to_send += msg.size();
            iov_count++;
        }

        if (iov_count == 0) return;

        struct msghdr hdr{};
        hdr.msg_iov = iov;
        hdr.msg_iovlen = iov_count;

        ssize_t written = sendmsg(fd, &hdr, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (written > 0) {
            conn.bytes_out += written;
            conn.last_activity = std::time(nullptr);

            // Remove written data from queue
            size_t consumed = 0;
            while (consumed < (size_t)written && !conn.buffer.send_queue.empty()) {
                auto& front = conn.buffer.send_queue.front();
                if (consumed + front.size() <= (size_t)written) {
                    consumed += front.size();
                    conn.buffer.send_queue.pop_front();
                } else {
                    front.erase(0, written - consumed);
                    break;
                }
            }
        } else if (written < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                cleanup_connection(fd, strerror(errno));
            }
        }

        // Update epoll flags - clear EPOLLOUT if queue is empty
        if (conn.buffer.send_queue.empty()) {
            engine_->mod_fd(fd, EPOLLIN | EPOLLET);
        }
    }

    void queue_send(int fd, const std::string& msg) {
        auto it = connections_.find(fd);
        if (it == connections_.end()) return;

        auto& conn = it->second;

        // Check sendq limit
        size_t current_size = 0;
        for (auto& qmsg : conn.buffer.send_queue) current_size += qmsg.size();
        if (current_size + msg.size() > (size_t)config_.max_sendq) {
            // Sendq exceeded - disconnect
            conn.sendq_exceeded = true;
            cleanup_connection(fd, "SendQ Exceeded");
            return;
        }

        conn.buffer.send_queue.push_back(msg + "\r\n");

        // Enable EPOLLOUT
        engine_->mod_fd(fd, EPOLLIN | EPOLLOUT | EPOLLET);
    }

    // ========== Line processing ==========
    void process_line(int fd, ClientConnection& conn, const std::string& line) {
        auto user = find_client(fd);
        if (!user) return;

        user->mark_activity();

        // Parse IRC message
        auto parsed = IrcMessage::parse(line);
        if (!parsed) return;

        // Dispatch to handler
        dispatch_command(fd, user, *parsed);
    }

    void dispatch_command(int fd, IrcUser::ptr user, const IrcMessage& msg) {
        std::string cmd = to_lower(msg.command);

        // Skip empty commands
        if (cmd.empty()) return;

        // COUNT, PRIVMSG handlers (just enough to bootstrap)
        if (cmd == "ping") {
            std::string token = msg.params.empty() ? config_.server_name : msg.params[0];
            queue_send(fd, ":" + config_.server_name + " PONG " + config_.server_name + " :" + token);
        } else if (cmd == "pong") {
            user->set_last_pong(std::time(nullptr));
        } else if (cmd == "nick") {
            handle_nick_cmd(fd, user, msg);
        } else if (cmd == "user") {
            handle_user_cmd(fd, user, msg);
        } else if (cmd == "quit") {
            handle_quit_cmd(fd, user, msg);
            cleanup_connection(fd, "Client Quit");
        } else {
            // Default: unknown command
            queue_send(fd, ":" + config_.server_name + " 421 " +
                       user->nick() + " " + cmd + " :Unknown command");
        }
    }

    void handle_nick_cmd(int fd, IrcUser::ptr user, const IrcMessage& msg) {
        if (msg.params.empty()) {
            queue_send(fd, ":" + config_.server_name + " 431 * :No nickname given");
            return;
        }

        std::string new_nick = msg.params[0];
        if (new_nick.size() > (size_t)config_.max_nick_length) {
            new_nick = new_nick.substr(0, config_.max_nick_length);
        }

        // Validate nickname
        if (new_nick.empty() || isdigit(new_nick[0]) || new_nick[0] == '-') {
            queue_send(fd, ":" + config_.server_name + " 432 * " + new_nick +
                       " :Erroneous Nickname");
            return;
        }

        // Check collision
        auto existing = server_->find_user_by_nick(new_nick);
        if (existing && existing->uuid() != user->uuid()) {
            queue_send(fd, ":" + config_.server_name + " 433 * " + new_nick +
                       " :Nickname is already in use");
            return;
        }

        std::string old_nick = user->nick();
        server_->update_user_nick(old_nick, new_nick, user);
        user->set_nick(new_nick);

        // If registered, notify channels
        if (user->is_registered()) {
            std::string nick_msg = ":" + old_nick + "!" + user->ident() + "@" +
                                   user->hostname() + " NICK :" + new_nick;
            broadcast_to_user_channels(user, nick_msg);
        }

        // Check full registration
        check_registration(fd, user);
    }

    void handle_user_cmd(int fd, IrcUser::ptr user, const IrcMessage& msg) {
        if (user->is_registered()) {
            queue_send(fd, ":" + config_.server_name + " 462 " + user->nick() +
                       " :You may not reregister");
            return;
        }

        if (msg.params.size() < 4) {
            queue_send(fd, ":" + config_.server_name + " 461 " + user->nick() +
                       " USER :Not enough parameters");
            return;
        }

        user->set_ident(msg.params[0]);
        user->set_realname(msg.params[3]);
        user->set_hostname(user->remote_addr());

        check_registration(fd, user);
    }

    void handle_quit_cmd(int fd, IrcUser::ptr user, const IrcMessage& msg) {
        std::string reason = msg.params.empty() ? "Client Quit" : msg.params[0];
        if (reason.size() > (size_t)config_.max_quit_length) {
            reason = reason.substr(0, config_.max_quit_length);
        }

        // Notify all shared channels
        std::string quit_msg = ":" + user->nick() + "!" + user->ident() + "@" +
                               user->hostname() + " QUIT :" + reason;
        broadcast_to_user_channels(user, quit_msg);

        server_->remove_user(user->uuid());
        rate_limiter_.release(user->remote_addr());
    }

    void check_registration(int fd, IrcUser::ptr user) {
        if (user->nick().empty() || user->ident().empty()) return;

        // Check server password
        if (!config_.server_password.empty()) {
            if (user->password().empty() || user->password() != config_.server_password) {
                queue_send(fd, "ERROR :Closing Link: Invalid password");
                cleanup_connection(fd, "Invalid password");
                return;
            }
        }

        user->set_registered(true);
        user->set_signon_time(std::time(nullptr));
        auto& conn = connections_[fd];
        conn.registered = true;

        // Send welcome burst
        std::string prefix = ":" + config_.server_name + " ";

        queue_send(fd, prefix + "001 " + user->nick() + " :Welcome to the " +
                   config_.network_name + " Network, " + user->nick() + "!" +
                   user->ident() + "@" + user->hostname());

        queue_send(fd, prefix + "002 " + user->nick() + " :Your host is " +
                   config_.server_name + ", running version progressive-server-irc-0.1.0");

        queue_send(fd, prefix + "003 " + user->nick() + " :This server was created " +
                   ctime_fmt(server_->creation_time()));

        queue_send(fd, prefix + "004 " + user->nick() + " " + config_.server_name +
                   " progressive-server-irc-0.1.0 iowrsx biklmnoprstvz "
                   "bklov");

        queue_send(fd, prefix + "005 " + user->nick() +
                   " CHANTYPES=#&!+ PREFIX=(qaohv)~&@%+ CHANMODES=Ibeg,k,l,"
                   "imnprstzCASNGKMT MAXLIST=I:100,e:100,g:100 NICKLEN=" +
                   std::to_string(config_.max_nick_length) +
                   " TOPICLEN=" + std::to_string(config_.max_topic_length) +
                   " KICKLEN=" + std::to_string(config_.max_kick_length) +
                   " AWAYLEN=" + std::to_string(config_.max_away_length) +
                   " MAXTARGETS=20 WALLCHOPS :are supported by this server");

        // MOTD
        auto& motd = server_->motd();
        if (motd.empty()) {
            queue_send(fd, prefix + "422 " + user->nick() + " :MOTD File is missing");
        } else {
            queue_send(fd, prefix + "375 " + user->nick() + " :- " +
                       config_.server_name + " Message of the day -");
            for (auto& line : motd) {
                queue_send(fd, prefix + "372 " + user->nick() + " :- " + line);
            }
            queue_send(fd, prefix + "376 " + user->nick() + " :End of /MOTD command.");
        }

        // LUSERS
        auto stats = server_->get_stats();
        queue_send(fd, prefix + "251 " + user->nick() + " :There are " +
                   std::to_string(stats.visible_users) + " users and " +
                   std::to_string(stats.invisible_users) + " invisible on " +
                   std::to_string(stats.servers) + " servers");
    }

    // ========== Broadcast ==========
    void broadcast_to_user_channels(IrcUser::ptr user, const std::string& msg) {
        std::unordered_set<int> sent_to;
        for (auto& [ch_name, _] : user->channels()) {
            auto ch = server_->find_channel(ch_name);
            if (!ch) continue;
            for (auto& memb : ch->members()) {
                if (memb->uuid() == user->uuid()) continue;
                int fd = find_fd_by_uuid(memb->uuid());
                if (fd >= 0 && sent_to.insert(fd).second) {
                    queue_send(fd, msg);
                }
            }
        }
    }

    // ========== Pings ==========
    void send_pings(time_t now) {
        for (auto& [fd, conn] : connections_) {
            if (conn.zombie) continue;

            // Check timeout
            if (now - conn.last_data > config_.ping_timeout) {
                cleanup_connection(fd, "Ping timeout");
                continue;
            }

            // Send PING
            if (now - conn.last_data > config_.ping_frequency) {
                queue_send(fd, ":" + config_.server_name + " PING :" +
                           config_.server_name);
                conn.last_data = now; // Prevent immediate re-ping
            }
        }
    }

    // ========== Cleanup ==========
    void cleanup_connection(int fd, const std::string& reason) {
        auto it = connections_.find(fd);
        if (it == connections_.end()) return;

        auto& conn = it->second;
        conn.closed = true;
        conn.zombie = true;

        // Remove user
        auto user = find_client(fd);
        if (user) {
            if (user->is_registered()) {
                handle_quit_cmd(fd, user, IrcMessage{});
            }
            client_ptrs_.erase(conn.uuid);
        }

        zombies_.push_back(fd);
    }

    void close_connection(int fd) {
        auto it = connections_.find(fd);
        if (it != connections_.end()) {
            auto& conn = it->second;
            rate_limiter_.release(conn.remote_addr);
            connections_.erase(it);
        }
        engine_->del_fd(fd);
        ::close(fd);
    }

    void cleanup_zombies() {
        for (int fd : zombies_) {
            close_connection(fd);
        }
        zombies_.clear();
    }

    // ========== Helpers ==========
    bool is_listen_socket(int fd) {
        for (auto& ls : listen_sockets_) {
            if (ls.fd == fd) return true;
        }
        return false;
    }

    IrcUser::ptr find_client(int fd) {
        auto it = connections_.find(fd);
        if (it == connections_.end()) return nullptr;
        auto user_it = client_ptrs_.find(it->second.uuid);
        return (user_it != client_ptrs_.end()) ? user_it->second : nullptr;
    }

    int find_fd_by_uuid(const std::string& uuid) {
        for (auto& [fd, conn] : connections_) {
            if (conn.uuid == uuid && !conn.zombie) return fd;
        }
        return -1;
    }

    int epfd() const {
        return engine_ ? engine_->fd() : -1;
    }

    void flush_send_queues() {
        // Called periodically to push data even without EPOLLOUT trigger
        for (auto& [fd, conn] : connections_) {
            if (!conn.buffer.send_queue.empty()) {
                handle_write(fd);
            }
        }
    }

    static std::string generate_uuid() {
        static std::atomic<uint64_t> counter{0};
        uint64_t id = counter.fetch_add(1, std::memory_order_relaxed);
        char buf[32];
        snprintf(buf, sizeof(buf), "%016lx-%016lx",
                 (unsigned long)std::time(nullptr), (unsigned long)id);
        return std::string(buf);
    }

private:
    IrcConfig config_;
    std::shared_ptr<IrcServerInstance> server_;
    std::unique_ptr<EpollEngine> engine_;
    std::thread worker_thread_;
    std::atomic<bool> running_{false};

    std::vector<ListenSocket> listen_sockets_;
    std::unordered_map<int, ClientConnection> connections_;
    std::unordered_map<std::string, IrcUser::ptr> client_ptrs_;
    std::vector<int> zombies_;
    ConnectionRateLimiter rate_limiter_;

    int wakeup_pipe_[2] = {0, 0}; // Pipe for waking up epoll
};

} // namespace irc
} // namespace progressive
