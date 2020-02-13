#pragma once

#include "use_asio.hpp"

namespace ark {

namespace detail {

#ifdef HTTP_CONFIG_SSL_ON
// TODO switch to boost::beast::ssl_stream when it moves out of experimental
template<typename Next_Layer>
class ssl_stream : public ssl::stream_base
{
    // This class (ssl_stream) is a derivative work based on Boost.Beast,
    // orignal copyright below:
    /*
  Copyright (c) 2016-2017 Vinnie Falco (vinnie dot falco at gmail dot com)

  Boost Software License - Version 1.0 - August 17th, 2003

  Permission is hereby granted, free of charge, to any person or organization
  obtaining a copy of the software and accompanying documentation covered by
  this license (the "Software") to use, reproduce, display, distribute,
  execute, and transmit the Software, and to prepare derivative works of the
  Software, and to permit third-parties to whom the Software is furnished to
  do so, all subject to the following:

  The copyright notices in the Software and this entire statement, including
  the above license grant, this restriction and the following disclaimer,
  must be included in all copies of the Software, in whole or in part, and
  all derivative works of the Software, unless such copies or derivative
  works are solely in the form of machine-executable object code generated by
  a source language processor.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
  SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
  FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
  ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
  DEALINGS IN THE SOFTWARE.
*/

    using stream_type = ssl::stream<Next_Layer>;

public:
    using native_handle_type = typename stream_type::native_handle_type;
    using impl_struct = typename stream_type::impl_struct;
    using next_layer_type = typename stream_type::next_layer_type;
    using lowest_layer_type = typename stream_type::lowest_layer_type;
    using executor_type = typename stream_type::executor_type;

    ssl_stream(Next_Layer&& arg, ssl::context& ctx)
        : _ptr{std::make_unique<stream_type>(std::move(arg), ctx)}
    {
    }

    executor_type get_executor() noexcept
    {
        return _ptr->get_executor();
    }

    native_handle_type native_handle()
    {
        return _ptr->native_handle();
    }

    next_layer_type const& next_layer() const
    {
        return _ptr->next_layer();
    }

    next_layer_type& next_layer()
    {
        return _ptr->next_layer();
    }

    lowest_layer_type& lowest_layer()
    {
        return _ptr->lowest_layer();
    }

    lowest_layer_type const& lowest_layer() const
    {
        return _ptr->lowest_layer();
    }

    void set_verify_mode(ssl::verify_mode v)
    {
        _ptr->set_verify_mode(v);
    }

    void set_verify_mode(ssl::verify_mode v, error_code& ec)
    {
        _ptr->set_verify_mode(v, ec);
    }

    void set_verify_depth(int depth)
    {
        _ptr->set_verify_depth(depth);
    }

    void set_verify_depth(int depth, error_code& ec)
    {
        _ptr->set_verify_depth(depth, ec);
    }

    template<typename VerifyCallback>
    void set_verify_callback(VerifyCallback callback)
    {
        _ptr->set_verify_callback(callback);
    }

    template<typename VerifyCallback>
    void set_verify_callback(VerifyCallback callback, error_code& ec)
    {
        _ptr->set_verify_callback(callback, ec);
    }

    void handshake(handshake_type type)
    {
        _ptr->handshake(type);
    }

    void handshake(handshake_type type, error_code& ec)
    {
        _ptr->handshake(type, ec);
    }

    template<typename ConstBufferSequence>
    void handshake(handshake_type type, ConstBufferSequence const& buffers)
    {
        _ptr->handshake(type, buffers);
    }

    template<typename ConstBufferSequence>
    void handshake(handshake_type type, ConstBufferSequence const& buffers, error_code& ec)
    {
        _ptr->handshake(type, buffers, ec);
    }

    template<typename HandshakeHandler>
    BOOST_ASIO_INITFN_RESULT_TYPE(HandshakeHandler, void(error_code))
    async_handshake(handshake_type type, BOOST_ASIO_MOVE_ARG(HandshakeHandler) handler)
    {
        return _ptr->async_handshake(type, BOOST_ASIO_MOVE_CAST(HandshakeHandler)(handler));
    }

    template<typename ConstBufferSequence, typename BufferedHandshakeHandler>
    BOOST_ASIO_INITFN_RESULT_TYPE(BufferedHandshakeHandler, void(error_code, std::size_t))
    async_handshake(
        handshake_type type, ConstBufferSequence const& buffers, BOOST_ASIO_MOVE_ARG(BufferedHandshakeHandler) handler)
    {
        return _ptr->async_handshake(type, buffers, BOOST_ASIO_MOVE_CAST(BufferedHandshakeHandler)(handler));
    }

    void shutdown()
    {
        _ptr->shutdown();
    }

    void shutdown(error_code& ec)
    {
        _ptr->shutdown(ec);
    }

    template<typename ShutdownHandler>
    BOOST_ASIO_INITFN_RESULT_TYPE(ShutdownHandler, void(error_code))
    async_shutdown(BOOST_ASIO_MOVE_ARG(ShutdownHandler) handler)
    {
        return _ptr->async_shutdown(BOOST_ASIO_MOVE_CAST(ShutdownHandler)(handler));
    }

    template<typename ConstBufferSequence>
    std::size_t write_some(ConstBufferSequence const& buffers)
    {
        return _ptr->write_some(buffers);
    }

    template<typename ConstBufferSequence>
    std::size_t write_some(ConstBufferSequence const& buffers, error_code& ec)
    {
        return _ptr->write_some(buffers, ec);
    }

    template<typename ConstBufferSequence, typename WriteHandler>
    BOOST_ASIO_INITFN_RESULT_TYPE(WriteHandler, void(error_code, std::size_t))
    async_write_some(ConstBufferSequence const& buffers, BOOST_ASIO_MOVE_ARG(WriteHandler) handler)
    {
        return _ptr->async_write_some(buffers, BOOST_ASIO_MOVE_CAST(WriteHandler)(handler));
    }

    template<typename MutableBufferSequence>
    std::size_t read_some(MutableBufferSequence const& buffers)
    {
        return _ptr->read_some(buffers);
    }

    template<typename MutableBufferSequence>
    std::size_t read_some(MutableBufferSequence const& buffers, error_code& ec)
    {
        return _ptr->read_some(buffers, ec);
    }

    template<typename MutableBufferSequence, typename ReadHandler>
    BOOST_ASIO_INITFN_RESULT_TYPE(ReadHandler, void(error_code, std::size_t))
    async_read_some(MutableBufferSequence const& buffers, BOOST_ASIO_MOVE_ARG(ReadHandler) handler)
    {
        return _ptr->async_read_some(buffers, BOOST_ASIO_MOVE_CAST(ReadHandler)(handler));
    }

    template<typename SyncStream>
    friend void teardown(websocket::role_type, ssl_stream<SyncStream>& stream, error_code& ec);

    template<typename AsyncStream, typename TeardownHandler>
    friend void async_teardown(websocket::role_type, ssl_stream<AsyncStream>& stream, TeardownHandler&& handler);

private:
    std::unique_ptr<stream_type> _ptr;
}; // class ssl_stream

template<typename SyncStream>
inline void teardown(websocket::role_type role, ssl_stream<SyncStream>& stream, error_code& ec)
{
    websocket::teardown(role, *stream._ptr, ec);
}

template<typename AsyncStream, typename TeardownHandler>
inline void async_teardown(websocket::role_type role, ssl_stream<AsyncStream>& stream, TeardownHandler&& handler)
{
    websocket::async_teardown(role, *stream._ptr, std::forward<TeardownHandler>(handler));
}
#endif // HTTP_CONFIG_SSL_ON

} // namespace detail

} // namespace ark
