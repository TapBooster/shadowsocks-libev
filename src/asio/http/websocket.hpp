#pragma once

#include "use_asio.hpp"

namespace ark {

// store a type erased websocket
struct Websocket_Session
{
    // default deconstructor
    virtual ~Websocket_Session() = default;

    // send a message
    virtual void send(std::string const&&) = 0;
}; // struct Websocket_Session

} // namespace ark
