#pragma once

#include "use_asio.hpp"

namespace ark {

namespace detail {

// prototypes
inline std::string lowercase(std::string str);
inline std::optional<std::string> extension(std::string const& path);
inline std::vector<std::string> split(
    std::string const& str, std::string const& delim, std::size_t size = std::numeric_limits<std::size_t>::max());

// string to lowercase
inline std::string lowercase(std::string str)
{
    auto const to_lower = [](char& c) {
        if (c >= 'A' && c <= 'Z')
        {
            c += 'a' - 'A';
        }

        return c;
    };

    for (char& c : str)
    {
        c = to_lower(c);
    }

    return str;
}

// find extension if present in a string path
inline std::optional<std::string> extension(std::string const& path)
{
    if (path.empty() || path.size() < 2)
    {
        return {};
    }

    auto const pos = path.rfind(".");

    if (pos == std::string::npos || pos == path.size() - 1)
    {
        return {};
    }

    return path.substr(pos + 1);
}

// split a string by a delimiter 'n' times
inline std::vector<std::string> split(std::string const& str, std::string const& delim, std::size_t times)
{
    std::vector<std::string> vtok;
    std::size_t start{0};
    auto end = str.find(delim);

    while ((times-- > 0) && (end != std::string::npos))
    {
        vtok.emplace_back(str.substr(start, end - start));
        start = end + delim.length();
        end = str.find(delim, start);
    }
    vtok.emplace_back(str.substr(start, end));

    return vtok;
}

// convert object into a string
template<typename T>
inline std::string to_string(T const& t)
{
    std::stringstream ss;
    ss << t;

    return ss.str();
}

std::unordered_map<std::string, std::string> const mime_types{
    {"html", "text/html"},
    {"htm", "text/html"},
    {"shtml", "text/html"},
    {"css", "text/css"},
    {"xml", "text/xml"},
    {"gif", "image/gif"},
    {"jpg", "image/jpg"},
    {"jpeg", "image/jpg"},
    {"js", "application/javascript"},
    {"atom", "application/atom+xml"},
    {"rss", "application/rss+xml"},
    {"mml", "text/mathml"},
    {"txt", "text/plain"},
    {"jad", "text/vnd.sun.j2me.app-descriptor"},
    {"wml", "text/vnd.wap.wml"},
    {"htc", "text/x-component"},
    {"png", "image/png"},
    {"tif", "image/tiff"},
    {"tiff", "image/tiff"},
    {"wbmp", "image/vnd.wap.wbmp"},
    {"ico", "image/x-icon"},
    {"jng", "image/x-jng"},
    {"bmp", "image/x-ms-bmp"},
    {"svg", "image/svg+xml"},
    {"svgz", "image/svg+xml"},
    {"webp", "image/webp"},
    {"woff", "application/font-woff"},
    {"jar", "application/java-archive"},
    {"war", "application/java-archive"},
    {"ear", "application/java-archive"},
    {"json", "application/json"},
    {"hqx", "application/mac-binhex40"},
    {"doc", "application/msword"},
    {"pdf", "application/pdf"},
    {"ps", "application/postscript"},
    {"eps", "application/postscript"},
    {"ai", "application/postscript"},
    {"rtf", "application/rtf"},
    {"m3u8", "application/vnd.apple.mpegurl"},
    {"xls", "application/vnd.ms-excel"},
    {"eot", "application/vnd.ms-fontobject"},
    {"ppt", "application/vnd.ms-powerpoint"},
    {"wmlc", "application/vnd.wap.wmlc"},
    {"kml", "application/vnd.google-earth.kml+xml"},
    {"kmz", "application/vnd.google-earth.kmz"},
    {"7z", "application/x-7z-compressed"},
    {"cco", "application/x-cocoa"},
    {"jardiff", "application/x-java-archive-diff"},
    {"jnlp", "application/x-java-jnlp-file"},
    {"run", "application/x-makeself"},
    {"pm", "application/x-perl"},
    {"pl", "application/x-perl"},
    {"pdb", "application/x-pilot"},
    {"prc", "application/x-pilot"},
    {"rar", "application/x-rar-compressed"},
    {"rpm", "application/x-redhat-package-manager"},
    {"sea", "application/x-sea"},
    {"swf", "application/x-shockwave-flash"},
    {"sit", "application/x-stuffit"},
    {"tk", "application/x-tcl"},
    {"tcl", "application/x-tcl"},
    {"crt", "application/x-x509-ca-cert"},
    {"pem", "application/x-x509-ca-cert"},
    {"der", "application/x-x509-ca-cert"},
    {"xpi", "application/x-xpinstall"},
    {"xhtml", "application/xhtml+xml"},
    {"xspf", "application/xspf+xml"},
    {"zip", "application/zip"},
    {"dll", "application/octet-stream"},
    {"exe", "application/octet-stream"},
    {"bin", "application/octet-stream"},
    {"deb", "application/octet-stream"},
    {"dmg", "application/octet-stream"},
    {"img", "application/octet-stream"},
    {"iso", "application/octet-stream"},
    {"msm", "application/octet-stream"},
    {"msp", "application/octet-stream"},
    {"msi", "application/octet-stream"},
    {"docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"},
    {"xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"},
    {"pptx", "application/vnd.openxmlformats-officedocument.presentationml.presentation"},
    {"kar", "audio/midi"},
    {"midi", "audio/midi"},
    {"mid", "audio/midi"},
    {"mp3", "audio/mpeg"},
    {"ogg", "audio/ogg"},
    {"m4a", "audio/x-m4a"},
    {"ra", "audio/x-realaudio"},
    {"3gp", "video/3gpp"},
    {"3gpp", "video/3gpp"},
    {"ts", "video/mp2t"},
    {"mp4", "video/mp4"},
    {"mpg", "video/mpeg"},
    {"mpeg", "video/mpeg"},
    {"mov", "video/quicktime"},
    {"webm", "video/webm"},
    {"flv", "video/x-flv"},
    {"m4v", "video/x-m4v"},
    {"mng", "video/x-mng"},
    {"asf", "video/x-ms-asf"},
    {"asx", "video/x-ms-asf"},
    {"wmv", "video/x-ms-wmv"},
    {"avi", "video/x-msvideo"},
};

// prototypes
inline std::string mime_type(std::string const& path);

// find the mime type of a string path
inline std::string mime_type(std::string const& path)
{
    if (auto ext = detail::extension(path))
    {
        auto const str = detail::lowercase(ext.value());

        if (mime_types.find(str) != mime_types.end())
        {
            return mime_types.at(str);
        }
    }

    return "application/octet-stream";
}

} // namespace detail

} // namespace ark