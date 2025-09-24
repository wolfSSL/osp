#include <stdexcept>

#include <boost/asio/io_service.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/trivial.hpp>
#include <boost/system/error_code.hpp>

#include "common/config/config.h"

#include "core/command_line/standard/command_line.h"

#include "core/network_virtual_layer_policies/link_policies/ssl_policy.h"
#include "core/network_virtual_layer_policies/link_policies/tcp_policy.h"
#include "core/network_virtual_layer_policies/link_authentication_policies/null_link_authentication_policy.h"
#include "core/network_virtual_layer_policies/bounce_protocol_policy.h"
#include "core/server/server.h"
#include "core/transport_virtual_layer_policies/transport_protocol_policy.h"

void Init() {
  boost::log::core::get()->set_filter(boost::log::trivial::severity >=
                                      boost::log::trivial::info);
}

int main(int argc, char **argv) {
#ifdef TLS_OVER_TCP_LINK
  using Server =
      ssf::SSFServer<ssf::SSLPolicy, ssf::NullLinkAuthenticationPolicy,
                     ssf::BounceProtocolPolicy, ssf::TransportProtocolPolicy>;
#elif TCP_ONLY_LINK
  using Server =
      ssf::SSFServer<ssf::TCPPolicy, ssf::NullLinkAuthenticationPolicy,
                     ssf::BounceProtocolPolicy, ssf::TransportProtocolPolicy>;
#endif

  Init();

  // The command line parser
  ssf::command_line::standard::CommandLine cmd(true);

  // Parse the command line
  boost::system::error_code ec;
  cmd.parse(argc, argv, ec);

  if (ec) {
    BOOST_LOG_TRIVIAL(error) << "server: wrong arguments" << std::endl;
    return 1;
  }

  // Load SSF config if any
  boost::system::error_code ec_config;
  ssf::Config ssf_config = ssf::LoadConfig(cmd.config_file(), ec_config);

  if (ec_config) {
    BOOST_LOG_TRIVIAL(error) << "server: invalid config file format"
                             << std::endl;
    return 1;
  }

  // Start the asynchronous engine
  boost::asio::io_service io_service;
  boost::asio::io_service::work worker(io_service);
  boost::thread_group threads;

  for (uint8_t i = 1; i <= boost::thread::hardware_concurrency(); ++i) {
    auto lambda = [&]() {
      boost::system::error_code ec;
      try {
        io_service.run(ec);
      } catch (std::exception e) {
        BOOST_LOG_TRIVIAL(error) << "server: exception in io_service run "
                                 << e.what();
      }
    };

    threads.create_thread(lambda);
  }

  BOOST_LOG_TRIVIAL(info) << "Start SSF server on port " << cmd.port();

  // Initiate and start the server
  Server server(io_service, ssf_config, cmd.port());

  server.run();

  getchar();
  server.stop();
  io_service.stop();
  threads.join_all();

  return 0;
}