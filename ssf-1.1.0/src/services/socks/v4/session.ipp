#ifndef SRC_SERVICES_SOCKS_V4_SESSION_IPP_
#define SRC_SERVICES_SOCKS_V4_SESSION_IPP_

#include <boost/bind.hpp>
#include <boost/bind/protect.hpp>
#include <boost/asio/spawn.hpp>

#include "services/socks/v4/request.h"
#include "services/socks/v4/reply.h"

#include <boost/asio/basic_stream_socket.hpp>

namespace ssf { namespace socks { namespace v4 {
//-----------------------------------------------------------------------------
template <typename Demux>
Session<Demux>::Session(SessionManager* p_session_manager, fiber client)
    : ssf::BaseSession(),
      io_service_(client.get_io_service()),
      p_session_manager_(p_session_manager),
      client_(std::move(client)),
      app_server_(client.get_io_service()) {}

//-----------------------------------------------------------------------------
template <typename Demux>
void Session<Demux>::HandleStop() {
  boost::system::error_code ec;
  p_session_manager_->stop(shared_from_this(), ec);
}


//-----------------------------------------------------------------------------
template <typename Demux>
void Session<Demux>::stop(boost::system::error_code&) {
  client_.close();
  boost::system::error_code ec;
  app_server_.close(ec);
  if (ec) {
    BOOST_LOG_TRIVIAL(error) << "socks session: stop error " << ec.message() << std::endl;
  }
}


//-----------------------------------------------------------------------------
template <typename Demux>
void Session<Demux>::start(boost::system::error_code&) {
  AsyncReadRequest(client_, &request_,
                   boost::bind(&Session::HandleRequestDispatch,
                               self_shared_from_this(),
                               boost::asio::placeholders::error,
                               boost::asio::placeholders::bytes_transferred));
}


//-----------------------------------------------------------------------------
template <typename Demux>
void Session<Demux>::HandleRequestDispatch(const boost::system::error_code& ec,
                                    std::size_t) {
  if (ec) {
    HandleStop();
    return;
  }

  // Dispatch request according to it's command id
  switch (request_.Command()) {
  case Request::kConnect:
    DoConnectRequest();
    break;

  case Request::kBind:
    DoBindRequest();
    break;

  default:
    fprintf(stderr, "[!][Session][0x%p] Invalid v4 command\n", (void*)this);
    break;
  }
}


//-----------------------------------------------------------------------------
template <typename Demux>
void Session<Demux>::DoConnectRequest() {
  auto handler = boost::bind(&Session::HandleApplicationServerConnect,
                             self_shared_from_this(),
                             boost::asio::placeholders::error);

  boost::system::error_code ec;
  boost::asio::ip::tcp::endpoint endpoint;

  if (request_.is_4a_version()) {
    // In the 4a version, the address needs to be resolved
    boost::asio::ip::tcp::resolver resolver(io_service_);
    boost::asio::ip::tcp::resolver::query query(
        request_.Domain(), std::to_string(request_.Port()));
    boost::asio::ip::tcp::resolver::iterator iterator(
        resolver.resolve(query, ec));

    if (!ec) {
      endpoint = *iterator;
    }
  } else {
    endpoint = request_.Endpoint();
  }

  if (ec) {
    HandleApplicationServerConnect(ec);
  } else {
    app_server_.async_connect(endpoint, handler);
  }
}


//-----------------------------------------------------------------------------
template <typename Demux>
void Session<Demux>::DoBindRequest() {
  fprintf(stderr, "[!][Session][0x%p] Bind Not implemented yet\n", (void*)this);
    HandleStop();
}


//-----------------------------------------------------------------------------
template <typename Demux>
void Session<Demux>::HandleApplicationServerConnect(const boost::system::error_code&
                                             err) {
  auto self = self_shared_from_this();
  auto p_reply = std::make_shared<Reply>(err, boost::asio::ip::tcp::endpoint());

  if (err) {  // Error connecting to the server, informing client and stopping
    AsyncSendReply(client_, *p_reply,
                    [this, self, p_reply](boost::system::error_code, std::size_t) {
                      HandleStop();
                    });
  } else {  // We successfully connect to application server
    AsyncSendReply(client_, *p_reply,
                    [this, self, p_reply](boost::system::error_code ec, std::size_t) {
                      if (ec) {
                        HandleStop();
                        return;
                      }  // reply successfully sent, Establishing link
                      EstablishLink();
                    });
  }
}


//-----------------------------------------------------------------------------
template <typename Demux>
void Session<Demux>::EstablishLink() {
  auto self = self_shared_from_this();

  upstream_.reset(new StreamBuff);
  downstream_.reset(new StreamBuff);


  // Two half duplex links
  AsyncEstablishHDLink(ssf::ReadFrom(client_), ssf::WriteTo(app_server_),
                       boost::asio::buffer(*upstream_),
                       boost::bind(&Session::HandleStop, self));

  AsyncEstablishHDLink(ssf::ReadFrom(app_server_), ssf::WriteTo(client_),
                       boost::asio::buffer(*downstream_),
                       boost::bind(&Session::HandleStop, self));
}
}  // v4
}  // socks
}  // ssf

#endif  // SRC_SERVICES_SOCKS_V4_SESSION_IPP_
