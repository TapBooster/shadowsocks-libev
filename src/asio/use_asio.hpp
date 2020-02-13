/**
 * asio & beast header files
 */

#pragma once

#include <cstdint>
#include <cstdlib>
#include <cstdio>
#include <cctype>
#include <cstddef>
#include <csignal>
#include <iostream>
#include <string>
#include <memory>
#include <thread>
#include <vector>
#include <algorithm>
#include <functional>
#include <sstream>
#include <iomanip>
#include <array>
#include <deque>
#include <unordered_map>
#include <unordered_set>
#include <iterator>
#include <regex>
#include <chrono>
#include <utility>
#include <initializer_list>
#include <optional>
#include <limits>
#include <type_traits>

#include "config.hpp"

#include <boost/config.hpp>
#include <boost/asio.hpp>
#include <boost/beast.hpp>

#ifdef HTTP_CONFIG_SSL_ON
#include <boost/asio/ssl.hpp>
#endif

namespace ark {

// aliases
namespace net = boost::asio;
namespace beast = boost::beast;
namespace http = boost::beast::http;
namespace websocket = boost::beast::websocket;

#ifdef HTTP_CONFIG_SSL_ON
namespace ssl = boost::asio::ssl;
#endif // HTTP_CONFIG_SSL_ON

using tcp = boost::asio::ip::tcp;
using error_code = boost::system::error_code;
using method = boost::beast::http::verb;
using status = boost::beast::http::status;
using header = boost::beast::http::field;
using headers = boost::beast::http::fields;

using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>
using tcp_socket = boost::asio::ip::tcp::socket;
using ssl_socket = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;

} // namespace ark
