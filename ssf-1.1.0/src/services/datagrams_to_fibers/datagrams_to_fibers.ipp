#ifndef SSF_SERVICES_DATAGRAMS_TO_FIBERS_DATAGRAMS_TO_FIBERS_IPP_
#define SSF_SERVICES_DATAGRAMS_TO_FIBERS_DATAGRAMS_TO_FIBERS_IPP_

#include <boost/log/trivial.hpp>

#include "common/network/session_forwarder.h"

namespace ssf { namespace services { namespace datagrams_to_fibers {
template <typename Demux>
DatagramsToFibers<Demux>::DatagramsToFibers(boost::asio::io_service& io_service,
                                            Demux& fiber_demux,
                                            uint16_t local_port,
                                            remote_port_type remote_port)
    : ssf::BaseService<Demux>::BaseService(io_service, fiber_demux),
      local_port_(local_port),
      remote_port_(remote_port),
      socket_(io_service),
      endpoint_(boost::asio::ip::udp::v4(), local_port_),
      send_to_(fiber_demux, remote_port),
      p_udp_operator_(UdpOperator::Create(socket_)) {
    }

template <typename Demux>
void DatagramsToFibers<Demux>::start(boost::system::error_code& ec) {
  BOOST_LOG_TRIVIAL(info) << "service datagrams to fibers: starting relay on local port udp " << local_port_;

  // Listen on all interfaces
  socket_.open(boost::asio::ip::udp::v4(), ec);
  socket_.bind(endpoint_, ec);

  if (!ec) {
    this->StartReceivingDatagrams();
  }
}

template <typename Demux>
void DatagramsToFibers<Demux>::stop(boost::system::error_code& ec) {
  BOOST_LOG_TRIVIAL(info) << "service datagrams to fibers: stopping";
  socket_.close(ec);

  if (ec) {
    BOOST_LOG_TRIVIAL(debug) << "service datagrams to fibers: error on stop " << ec.message() << std::endl;
  }

  p_udp_operator_->StopAll();
}

template <typename Demux>
uint32_t DatagramsToFibers<Demux>::service_type_id() { return factory_id; }

template <typename Demux>
void DatagramsToFibers<Demux>::StartReceivingDatagrams() {
  BOOST_LOG_TRIVIAL(trace) << "service datagrams to fibers: receiving new datagrams";

  socket_.async_receive_from(
      boost::asio::buffer(working_buffer_), endpoint_,
      Then(&DatagramsToFibers::SocketReceiveHandler, this->SelfFromThis()));
}

template <typename Demux>
void DatagramsToFibers<Demux>::SocketReceiveHandler(
    const boost::system::error_code& ec, size_t length) {
  if (!ec) {
    auto already_in = p_udp_operator_->Feed(
        endpoint_, boost::asio::buffer(working_buffer_), length);

    if (!already_in) {
      fiber_datagram left(this->get_demux().get_io_service(),
                          datagram_endpoint(this->get_demux(), 0));
      p_udp_operator_->AddLink(std::move(left), endpoint_, send_to_,
                            this->get_io_service());
      p_udp_operator_->Feed(endpoint_, boost::asio::buffer(working_buffer_),
                         length);
    }

    this->StartReceivingDatagrams();
  } else {
    // boost::system::error_code ec;
    // stop(ec);
  }
}

}  // datagrams_to_fibers
}  // services
}  // ssf

#endif  // SSF_SERVICES_DATAGRAMS_TO_FIBERS_DATAGRAMS_TO_FIBERS_IPP_
