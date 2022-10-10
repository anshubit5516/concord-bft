#include <grpcpp/grpcpp.h>
#include <grpcpp/resource_quota.h>
#include <jaegertracing/Tracer.h>
#include "Logger.hpp"
#include <iostream>
#include <memory>
#include <sstream>
#include <string>

namespace concord::thin_replica {

class trs_state_manager {
 private:
  static trs_state_manager* instance;
  bool restart_rcs_needed;

  trs_state_manager() {
    thin_replica_server = nullptr;
    restart_rcs_needed = false;
  }

 public:
  static trs_state_manager* getInstance() {
    if (!instance) {
      instance = new trs_state_manager();
    }
    return instance;
  }

  bool isTrsRunning() { return (thin_replica_server != nullptr) ? true : false; }

  void setRestartRcsFlag(bool iVal) { restart_rcs_needed = iVal; }

  bool getRestartRcsFlag() { return restart_rcs_needed; }

  void restartThinReplicaServer(uint32_t dummy) {
    auto logger = logging::getLogger("concord.thin-replica-server");
    try {
      LOG_INFO(logger, "Received restart grpc command");
      trs_state_manager::getInstance()->setRestartRcsFlag(true);
      if (trs_state_manager::getInstance()->isTrsRunning()) {
        LOG_INFO(logger, "Shutting down thin-replica-server");
        trs_state_manager::getInstance()->thin_replica_server->Shutdown();
        trs_state_manager::getInstance()->thin_replica_server = nullptr;
      } else {
        LOG_INFO(logger, "thin-replica-server not running");
      }
      LOG_INFO(logger, "Done running restart grpc command");
    } catch (std::exception& e) {
      LOG_ERROR(logger, "An exception occurred while trying to Restart Thin Replia Server" << e.what());
    }
  }
  ~trs_state_manager() {
    if (isTrsRunning()) {
      thin_replica_server->Shutdown();
    }
    delete instance;
    instance = nullptr;
  }
  std::unique_ptr<grpc::Server> thin_replica_server;
};

trs_state_manager* trs_state_manager::instance = nullptr;
}  // namespace concord::thin_replica
