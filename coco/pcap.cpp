#include "pcap.hpp"
#include <coco/BufferWriter.hpp>


namespace coco {
namespace pcap {

AwaitableCoroutine readHeader(Buffer &buffer, Header &header, bool &error) {
    // read pcap header
    co_await buffer.read(sizeof(header));

    if (buffer.size() == sizeof(header)) {
        // read ok
        header = buffer.value<pcap::Header>();
        error = false;
    } else {
        // error: read failed or buffer too small
        error = true;
    }
}

AwaitableCoroutine readPacket(Buffer &buffer, PacketHeader &header, Array<uint8_t> data, bool &error) {
    // read packet header
    co_await buffer.read(sizeof(header));

    if (buffer.size() == sizeof(header)) {
        // read ok
        header = buffer.value<pcap::PacketHeader>();
        int len = header.incl_len;
        co_await buffer.read(len);
        int transferred = buffer.size();
        if (transferred == len && data.size() >= len) {
            // read ok
            std::copy(buffer.begin(), buffer.begin() + transferred, data.data());
        } else {
            // error: read failed or packet data smaller than indicated in header
            error = true;
        }
    } else {
        // error: read failed
        error = true;
    }
}

AwaitableCoroutine writeHeader(Buffer &buffer, const pcap::Header &header, bool &error) {
    // write pcap header
    co_await buffer.writeValue(header);

    // set error status
    error = buffer.size() == sizeof(header);
}

AwaitableCoroutine writePacket(Buffer &buffer, const pcap::PacketHeader &header, Array<const uint8_t> data, bool &error) {
    int len = header.incl_len;
    if (int(sizeof(header)) + len <= buffer.capacity() && data.size() >= len) {
        // ok
        BufferWriter w(buffer);
        w.value(header);
        w.data(data.data(), len);
        int size = w - buffer.begin();
        co_await buffer.write(size);

        // set error status
        error = buffer.size() == size;
    } else {
        // error: buffer too small or packet data smaller than indicated in header
        error = true;
    }
}

} // namespace pcap
} // namespace coco
