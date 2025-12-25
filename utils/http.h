/*
 * MIT License
 *
 * Copyright (c) 2019 Maxwell Flynn
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 * Source-code taken from https://github.com/tinfoilboy/atomizes
 * Adopted by:  Miralem Mehic <miralem.mehic@etf.unsa.ba>
 */

#ifndef HTTP_CONTENT_H
#define HTTP_CONTENT_H

#include <string>
#include <unordered_map>
#include <cstdint>
#include <vector>
#include <sstream>
#include <algorithm>    // std::remove_if

#include "ns3/log.h"

namespace ns3 {

   /**
     * HTTP defines that any lines must be seperated with a carriage return.
     *
     * Define this as a constant to use across the library code and to change easily.
     */
    const std::string CarriageReturn = "\r\n";

    /**
     * The string for HTTP version 1.0
     */
    const std::string HTTPVersion1 = "HTTP/1.0";

    /**
     * The string for HTTP version 1.1
     */
    const std::string HTTPVersion11 = "HTTP/1.1";

    /**
     * The basic class to represent both HTTP requests and responses.
     *
     * Contains a method for grabbing the message as a string formatted for
     * sending through a server or other means.
     *
     * Allows for setting a message body that is represented by a vector of
     * 8-bit unsigned integers. This is to allow binary data to be sent through
     * the message. But, you also can use the included methods to send plain strings.
     *
     * This class returns as many methods as possible with a reference to the current
     * object, to try and allow for chaining methods.
     *
     * Note: for convenience, the header for Content-Length is automatically included
     * as it is grabbed from the `m_body` member. Though, it is only included if the
     * body member isn't empty.
     */
    class HTTPMessage
    {
    public:

        enum HttpMethod {
            NONE,
            DELETE, /**< Http Method Delete */
            GET, /**< Http Method GET */
            HEAD, /**< Http Method Head */
            PATCH, /**< Http Method Patch */
            POST, /**< Http Method Post */
            PUT /**< Http Method Put */
        };

        enum HttpStatus
        {
            Continue = 100,
            SwitchingProtocol = 101,
            Processing = 102,
            EarlyHints = 103,

            Ok = 200,
            Created = 201,
            Accepted = 202,
            NonAuthoritativeInformation = 203,
            NoContent = 204,
            ResetContent = 205,
            PartialContent = 206,
            MultiStatus = 207,
            AlreadyReported = 208,
            ImUsed = 226,

            MultipleChoice = 300,
            MovedPermanently = 301,
            Found = 302,
            SeeOther = 303,
            NotModified = 304,
            UseProxy = 305,
            TemporaryRedirect = 307,
            PermanentRedirect = 308,

            BadRequest = 400,
            Unauthorized = 401,
            PaymentRequired = 402,
            Forbidden = 403,
            NotFound = 404,
            MethodNotAllowed = 405,
            NotAcceptable = 406,
            ProxyAuthenticationRequired = 407,
            RequestTimeout = 408,
            Conflict = 409,
            Gone = 410,
            LengthRequired = 411,
            PreconditionFailed = 412,
            PayloadTooLarge = 413,
            UriTooLong = 414,
            UnsupportedMediaType = 415,
            RangeNotSatisfiable = 416,
            ExpectationFailed = 417,
            ImaTeapot = 418,
            MisdirectedRequest = 421,
            UnprocessableEntity = 422,
            Locked = 423,
            FailedDependency = 424,
            TooEarly = 425,
            UpgradeRequired = 426,
            PreconditionRequired = 428,
            TooManyRequests = 429,
            RequestHeaderFieldsTooLarge = 431,
            UnavailableForLegalReasons = 451,

            InternalServerError = 500,
            NotImplemented = 501,
            BadGateway = 502,
            ServiceUnavailable = 503,
            GatewayTimeout = 504,
            HttpVersionNotSupported = 505,
            VariantAlsoNegotiates = 506,
            InsufficientStorage = 507,
            LoopDetected = 508,
            NotExtended = 510,
            NetworkAuthenticationRequired = 511
        };



         /**
         * To be returned with a status code in a response is a status text describing the
         * status code by text rather than by a code.
         *
         * This method takes in one of those codes and tries to return a text for it.
         */
        inline HTTPMessage::HttpStatus GetStatus() const
        {
            switch (m_statusCode)
            {
            case 100:
                return HTTPMessage::HttpStatus::Continue;
            case 101:
                return HTTPMessage::HttpStatus::SwitchingProtocol;
            case 200:
                return HTTPMessage::HttpStatus::Ok;
            case 201:
                return HTTPMessage::HttpStatus::Created;
            case 202:
                return HTTPMessage::HttpStatus::Accepted;
            case 203:
                return HTTPMessage::HttpStatus::NonAuthoritativeInformation;
            case 204:
                return HTTPMessage::HttpStatus::NoContent;
            case 205:
                return HTTPMessage::HttpStatus::ResetContent;
            case 206:
                return HTTPMessage::HttpStatus::PartialContent;
            case 300:
                return HTTPMessage::HttpStatus::MultipleChoice;
            case 301:
                return HTTPMessage::HttpStatus::MovedPermanently;
            case 302:
                return HTTPMessage::HttpStatus::Found;
            case 303:
                return HTTPMessage::HttpStatus::SeeOther;
            case 304:
                return HTTPMessage::HttpStatus::NotModified;
            // 305 is deprecated and 306 is only reserved, skip
            case 307:
                return HTTPMessage::HttpStatus::TemporaryRedirect;
            case 308:
                return HTTPMessage::HttpStatus::PermanentRedirect;
            case 400:
                return HTTPMessage::HttpStatus::BadRequest;
            case 401:
                return HTTPMessage::HttpStatus::Unauthorized;
            case 402:
                // 402 is reserved for future use but has a status message, adding it
                return HTTPMessage::HttpStatus::PaymentRequired;
            case 403:
                return HTTPMessage::HttpStatus::Forbidden;
            case 404:
                return HTTPMessage::HttpStatus::NotFound;
            case 405:
                return HTTPMessage::HttpStatus::MethodNotAllowed;
            case 406:
                return HTTPMessage::HttpStatus::NotAcceptable;
            case 407:
                return HTTPMessage::HttpStatus::ProxyAuthenticationRequired;
            case 408:
                return HTTPMessage::HttpStatus::RequestTimeout;
            case 409:
                return HTTPMessage::HttpStatus::Conflict;
            case 410:
                return HTTPMessage::HttpStatus::Gone;
            case 411:
                return HTTPMessage::HttpStatus::LengthRequired;
            case 412:
                return HTTPMessage::HttpStatus::PreconditionFailed;
            case 413:
                return HTTPMessage::HttpStatus::PayloadTooLarge;
            case 414:
                return HTTPMessage::HttpStatus::UriTooLong;
            case 415:
                return HTTPMessage::HttpStatus::UnsupportedMediaType;
            case 416:
                return HTTPMessage::HttpStatus::RangeNotSatisfiable;
            case 417:
                return HTTPMessage::HttpStatus::ExpectationFailed;
            case 418:
                // might as well return the teapot joke
                return HTTPMessage::HttpStatus::ImaTeapot;
            case 421:
                return HTTPMessage::HttpStatus::MisdirectedRequest;
            case 425:
                return HTTPMessage::HttpStatus::TooEarly;
            case 426:
                return HTTPMessage::HttpStatus::UpgradeRequired;
            case 428:
                return HTTPMessage::HttpStatus::PreconditionRequired;
            case 429:
                return HTTPMessage::HttpStatus::TooManyRequests;
            case 431:
                return HTTPMessage::HttpStatus::RequestHeaderFieldsTooLarge;
            case 451:
                return HTTPMessage::HttpStatus::UnavailableForLegalReasons;
            case 500:
                return HTTPMessage::HttpStatus::InternalServerError;
            case 501:
                return HTTPMessage::HttpStatus::NotImplemented;
            case 502:
                return HTTPMessage::HttpStatus::BadGateway;
            case 503:
                return HTTPMessage::HttpStatus::ServiceUnavailable;
            case 504:
                return HTTPMessage::HttpStatus::GatewayTimeout;
            case 505:
                return HTTPMessage::HttpStatus::HttpVersionNotSupported;
            case 506:
                return HTTPMessage::HttpStatus::VariantAlsoNegotiates;
            case 507:
                return HTTPMessage::HttpStatus::InsufficientStorage;
            case 510:
                return HTTPMessage::HttpStatus::NotExtended;
            case 511:
                return HTTPMessage::HttpStatus::NetworkAuthenticationRequired;
            default:
                return HTTPMessage::HttpStatus::InternalServerError;
            }
        }

         /**
         * To be returned with a status code in a response is a status text describing the
         * status code by text rather than by a code.
         *
         * This method takes in one of those codes and tries to return a text for it.
         */
        inline std::string StatusTextFromStatusCode(const uint16_t statusCode)
        {
            switch (statusCode)
            {
            case 100:
                return "Continue";
            case 101:
                return "Switching Protocol";
            case 200:
                return "OK";
            case 201:
                return "Created";
            case 202:
                return "Accepted";
            case 203:
                return "Non-Authoritative Information";
            case 204:
                return "No Content";
            case 205:
                return "Reset Content";
            case 206:
                return "Partial Content";
            case 300:
                return "Multiple Choice";
            case 301:
                return "Moved Permanently";
            case 302:
                return "Found";
            case 303:
                return "See Other";
            case 304:
                return "Not Modified";
            // 305 is deprecated and 306 is only reserved, skip
            case 307:
                return "Temporary Redirect";
            case 308:
                return "Permanent Redirect";
            case 400:
                return "Bad Request";
            case 401:
                return "Unauthorized";
            case 402:
                // 402 is reserved for future use but has a status message, adding it
                return "Payment Required";
            case 403:
                return "Forbidden";
            case 404:
                return "Not Found";
            case 405:
                return "Method Not Allowed";
            case 406:
                return "Not Acceptable";
            case 407:
                return "Proxy Authentication Required";
            case 408:
                return "Request Timeout";
            case 409:
                return "Conflict";
            case 410:
                return "Gone";
            case 411:
                return "Length Required";
            case 412:
                return "Precondition Failed";
            case 413:
                return "Payload Too Large";
            case 414:
                return "URI Too Long";
            case 415:
                return "Unsupported Media Type";
            case 416:
                return "Requested Range Not Satisfiable";
            case 417:
                return "Expectation Failed";
            case 418:
                // might as well return the teapot joke
                return "I'm a teapot";
            case 421:
                return "Misdirected Request";
            case 425:
                return "Too Early";
            case 426:
                return "Upgrade Required";
            case 428:
                return "Precondition Required";
            case 429:
                return "Too Many Requests";
            case 431:
                return "Request Header Fields Too Large";
            case 451:
                return "Unavailable for Legal Reasons";
            case 500:
                return "Internal Server Error";
            case 501:
                return "Not Implemented";
            case 502:
                return "Bad Gateway";
            case 503:
                return "Service Unavailable";
            case 504:
                return "Gateway Timeout";
            case 505:
                return "HTTP Version Not Supported";
            case 506:
                return "Variant Also Negotiates";
            case 507:
                return "Insufficient Storage";
            case 510:
                return "Not Extended";
            case 511:
                return "Network Authentication Required";
            default:
                return "Undefined";
            }
        }

        /**
         * Set a header in the map to the value provided.
         */
        HTTPMessage& SetHeader(const std::string& name, const std::string& value)
        {
            m_headers[name] = value;

            if(name == "Content-Length") {
              m_contentLength = std::stoi(value);
            }else if(name == "Request URI"){
              m_request_uri = value;
            }else if(name == "Host"){
              if(m_domain.empty()){
                m_domain = value;
                m_uri = value + m_uri;
              }
            }

            return *this;
        }

        /**
         * @return The request uri value
         */
        std::string GetRequestUri() const{
          return m_request_uri;
        }

        /**
         * Set a number of headers based on a generic map of keys and values.
         */
        HTTPMessage& SetHeaders(const std::unordered_map<std::string, std::string>& headers)
        {
            m_headers.insert(headers.begin(), headers.end());
            return *this;
        }

        /**
         * Get the string value of a single header from the message.
         *
         * Will return an empty string if the header does not exist.
         */
        inline std::string GetHeader(const std::string& name) const
        {
            auto find = m_headers.find(name);

            if (find != m_headers.end())
                return find->second;

            return "";
        }

        /**
         * Set the associated message method for this message.
         *
         * Use `NONE` to switch this into a response.
         */
        void SetMethod (const std::string& m)
        {

          if (m == "DELETE")
              m_method = HTTPMessage::DELETE;
          else if (m == "GET")
              m_method = HTTPMessage::GET;
          else if (m == "HEAD")
              m_method = HTTPMessage::HEAD;
          else if (m == "PATCH")
              m_method = HTTPMessage::PATCH;
          else if (m == "POST")
              m_method = HTTPMessage::POST;
          else if (m == "PUT")
              m_method = HTTPMessage::PUT;

        }

        HTTPMessage::HttpMethod GetMethod() const
        {
          return m_method;
        }

        std::string GetMethodToString() const
        {
          switch (m_method)
          {
          case HTTPMessage::NONE:
            return "NONE";
            break;
          case HTTPMessage::DELETE:
            return "DELETE";
            break;
          case HTTPMessage::GET:
            return "GET";
            break;
          case HTTPMessage::HEAD:
            return "HEAD";
            break;
          case HTTPMessage::PATCH:
            return "PATCH";
            break;
          case HTTPMessage::POST:
            return "POST";
            break;
          case HTTPMessage::PUT:
            return "PUT";
            break;
          }
          return "NONE";
        }

        /**
         * Grab the uri
         */
        inline std::string GetUri() const
        {
            return m_uri;
        }

        /**
         * Set the path of this message, which will be used if it is a request.
         */
        void SetPath(const std::string& url)
        {
            const auto schemeEndPosition = url.find("://");
            if (schemeEndPosition != std::string::npos)
            {
                m_scheme = url.substr(0, schemeEndPosition);
                m_path = url.substr(schemeEndPosition + 3);
            }
            else
            {
                m_scheme = "http";
                m_path = url;
            }

            const auto fragmentPosition = m_path.find('#');

            // remove the fragment part
            if (fragmentPosition != std::string::npos)
                m_path.resize(fragmentPosition);

            const auto pathPosition = m_path.find('/');

            if (pathPosition == std::string::npos)
            {
                m_domain = m_path;
                m_path = "/";
            }
            else
            {
                m_domain = m_path.substr(0, pathPosition);
                m_path = m_path.substr(pathPosition);
            }

            const auto portPosition = m_domain.find(':');

            if (portPosition != std::string::npos)
            {
                m_domain.resize(portPosition);
            }
            m_uri = url;//;;m_domain + url;

        }

        /**
         * Grab the current associated path of this message.
         */
        inline std::string GetPath() const
        {
            return m_path;
        }

        /**
         * Set the version of this HTTP message to the string specified.
         */
        void SetVersion(const std::string& version)
        {
            m_version = version;
        }

        /**
         * Get the current HTTP version for this message.
         */
        inline std::string GetVersion() const
        {
            return m_version;
        }

        /**
         * Set the status code of this HTTP message.
         */
        void SetStatusCode(uint16_t code)
        {
            m_statusCode = code;
        }

        /**
         * Get the status code for this message.
         */
        inline uint16_t GetStatusCode() const
        {
            return m_statusCode;
        }

        /**
         * Set the status message of this HTTP message.
         */
        void SetStatusMessage(const std::string& message)
        {
            m_statusMessage = message;
        }

        /**
         * Get the current status message for this message.
         *
         * Returns an autogenerated status if one isn't specified.
         */
        inline std::string GetStatusMessage() const
        {
            return m_statusMessage;
        }

        /**
         * Takes the headers added to the message along with
         * the body and outputs it to a `std::string` for use
         * in client/server HTTP messages.
         */
        std::string ToString()
        {
            std::stringstream output;

            // begin by forming the start line of the message
            if (m_method == HTTPMessage::HttpMethod::NONE)
            {
                output << HTTPVersion11 << " " << m_statusCode << " ";

                if (m_statusMessage.empty())
                    output << StatusTextFromStatusCode(m_statusCode);
                else
                    output << m_statusMessage;
            }
            else
            {
                output << GetMethodToString() << " ";
                output << m_path << " ";
                output << HTTPVersion11;
            }

            // output the status lines line break to move on
            output << CarriageReturn;

            // output headers to the message string
            for (auto& header : m_headers)
                output << header.first << ": " << header.second << CarriageReturn;

            // automatically output the content length based on
            // the size of the body member if body isn't empty
            if (!m_contentLength && !m_body.empty()){
              m_contentLength = m_body.size();
              output << "Content-Length: " << m_contentLength << CarriageReturn;
            }

            // seperate headers and body with an extra carriage return
            output << CarriageReturn;

            m_headersLength = output.str().size();

            // convert the 8-bit unsigned body to a std::string for output
            std::string body(m_body.begin(), m_body.end());

            output << body;

            return output.str();
        }

        uint32_t GetHeadersSize(){
          if(m_headersLength == 0) ToString();
          return m_headersLength;
        }

        uint32_t GetSize(){
          return GetHeadersSize() + GetContentLength();
        }

        /**
         * Set the body of this message to a string value.
         */
        void SetMessageBody(const std::string& body)
        {
            SetMessageBody(std::vector<uint8_t>(body.begin(), body.end()));
        }

        /**
         * Set the body of this message to an unsigned 8-bit binary value.
         */
        void SetMessageBody(const std::vector<uint8_t>& body)
        {
            m_body = std::vector<uint8_t>(body);
        }

        /**
         * Get the body vector for this message.
         */
        inline std::vector<uint8_t>& GetMessageBody()
        {
            return m_body;
        }

        inline std::string GetMessageBodyString()
        {
            // convert the 8-bit unsigned body to a std::string for output
            return std::string(m_body.begin(), m_body.end());
        }

        /**
         * Return the size of the binary body vector.
         */
        inline size_t GetContentLength() const
        {
            return m_contentLength;
        }

        /**
         * Return the amount of headers in the message.
         */
        inline size_t HeaderCount()
        {
            return m_headers.size();
        }

        void CreateRequest(
          const std::string& url,
          const std::string& method
        )
        {
          CreateRequest(
            url,
            method,
            ""
          );
        }

        void CreateRequest(
          const std::string& url,
          const std::string& method,
          const std::string& body)
        {

          CreateRequest(
            url,
            method,
            std::vector<uint8_t>(body.begin(), body.end())
          );
        }

        void CreateRequest(
          const std::string& url,
          const std::string& method,
          const std::vector<uint8_t>& body
        ) {
          SetMethod(method);
          SetPath(url);
          SetHeader("User-Agent", "Test Agent");
          SetHeader("Host", m_domain);
          SetHeader("Accept-Language", "en-us,en;q=0.5");
          SetHeader("Accept-Encoding", "gzip,deflate");
          SetHeader("Accept-Charset", "ISO-8859-1,utf-8;q=0.7,*;q=0.7");
          SetHeader("Keep-Alive", "300");
          SetHeader("Connection", "keep-alive");
          SetHeader("Cookie", "PHPSESSID=r2t5uvjq435r4q7ib3vtdjq120");
          SetHeader("Pragma", "no-cache");
          SetHeader("Cache-Control", "no-cache");
          SetHeader("Content-Length", std::to_string(body.size()) );
          SetMessageBody(body);
        }

        void CreateResponse(
          const HttpStatus status
        ){
            CreateResponse(
              status,
              ""
            );
        }

        void CreateResponse(
          const HttpStatus status,
          const std::string& body
        ){
            CreateResponse(
              status,
              std::vector<uint8_t>(body.begin(), body.end())
            );
        }

        void CreateResponse(
          const HttpStatus status,
          const std::vector<uint8_t>& body
        ){
          //response
          SetMethod("NONE");
          SetStatusCode(status);
          SetHeader("Server", "QKDNetSim KMS/3.36");
          SetHeader("Date", "Sat, 28 Aug 2022 04:36:25 GMT");
          SetHeader("Connection", "close");
          SetHeader("Pragma", "public");
          SetHeader("Content-Encoding", "gzip");
          SetHeader("Vary", "Accept-Encoding, Cookie");
          SetHeader("Cache-Control", "max-age=3600, public");
          SetHeader("Content-Length", std::to_string(body.size()) );
          SetMessageBody(body);
        }
        void CreateResponse(
          const HttpStatus status,
          const std::string& body,
          const std::unordered_map<std::string, std::string>& headers
        ){
          SetHeaders(headers);
          CreateResponse(
            status,
            std::vector<uint8_t>(body.begin(), body.end())
          );
        }

        void CreateResponse(
          const HttpStatus status,
          const std::vector<uint8_t>& body,
          const std::unordered_map<std::string, std::string>& headers
        ){
          SetHeaders(headers);
          CreateResponse(
            status,
            body
          );
        }

        void SetFragmented(bool value)
        {
          m_fragmented = value;
        }

        bool IsFragmented() const
        {
          return m_fragmented;
        }

    private:
        /**
         * The HTTP method for this message.
         *
         * Defaults to `NONE` denoting a response.
         */
        HTTPMessage::HttpMethod m_method = HTTPMessage::HttpMethod::NONE;

        /**
         * A status code for this message.
         *
         * This is ignored if this is a request, as requests have no notion of statuses.
         */
        uint16_t m_statusCode = 0;

        /**
         * A status message to be associated with the status code for this message.
         *
         * Keep blank to use an automatically generated status message.
         */
        std::string m_statusMessage = "";

        /**
         * The path for the resource specified in the message. Only used for a request.
         *
         * Defaults to blank.
         */
        std::string m_path = "";

        std::string m_scheme;
        std::string m_domain;
        std::string m_uri;
        std::string m_request_uri;

        /**
         * The version used for this HTTP message as a string.
         *
         * Defaults to "HTTP/1.1"
         */
        std::string m_version = HTTPVersion11;

        /**
         * An `unordered_map` of headers using a `std::string` for both the key and the
         * value.
         */
        std::unordered_map<std::string, std::string> m_headers;

        /**
         * A vector of unsigned 8-bit integers used to store message bodies.
         */
        std::vector<uint8_t> m_body;

        /**
         * Whether the payload size is less then content-length
         * */
        bool m_fragmented = false;

        uint32_t m_contentLength = 0;
        uint32_t m_headersLength = 0;

    };

       /**
     * An enum of states that the HTTPMessageParser can be in.
     */
    enum class MessageParserState : uint8_t
    {
        NONE,
        PARSING_START_LINE,
        START_LINE_REQUEST,
        START_LINE_RESPONSE,
        HEADER_KEY,
        HEADER_VALUE,
        PARSING_BODY,
    };

    /**
     * A basic class to parse a HTTP message, both request and response.
     *
     * Allows for either string data to be passed in, or for a vector of
     * unsigned 8-bit integers to be passed in.
     *
     * Requires that a whole message be sent in for parsing.
     */
    class HTTPMessageParser
    {
    public:
        /**
         * Parse a std::string to a HTTP message.
         *
         * Pass in a pointer to an HTTPMessage which is then written to for headers
         * and other message data.
         *
         * note: this must be a complete HTTP message
         */
        void Parse(HTTPMessage* httpMessage, const std::string& buffer)
        {

          std::string cleanText = buffer;
          stripUnicode(cleanText);
          Parse(httpMessage, std::vector<uint8_t>(cleanText.begin(), cleanText.end()));
        }

        /**
         * Parse a binary vector to an HTTP message.
         *
         * Pass in a pointer to an HTTPMessage which is written to for headers and
         * other message data.
         *
         * note: shrink the vector buffer before passing it in with `shrink_to_fit`
         * otherwise empty characters will show up for the body
         * note: must be a complete HTTP message.
         */
        void Parse(HTTPMessage* httpMessage, const std::vector<uint8_t>& buffer)
        {
            // begin by parsing the start line without knowing if it is a
            // request or a response by setting as undetermined
            MessageParserState state = MessageParserState::PARSING_START_LINE;

            // a temporary string instance used for storing characters of a
            // current line in the message being parsed
            std::string temp = "";

            // whether to skip the next character (for a carriage return)
            bool skipNext = false;

            // the current key for a header
            std::string headerKey = "";

            // whether or not a message body is present
            bool hasMessageBody = false;

            // the index at which the message body begins
            size_t bodyStartIndex = 0;

            for (size_t index = 0; index < buffer.size(); index++)
            {
                uint8_t character = buffer[index];

                // skip this character as it was marked
                if (skipNext)
                {
                    skipNext = false;

                    continue;
                }

                // if we are parsing the body, then we only need to grab an index and break
                // out of this loop as we want to merely insert the data from this vector
                // into the body vector
                if (state == MessageParserState::PARSING_BODY)
                {
                    hasMessageBody = true;

                    bodyStartIndex = index;

                    break;
                }

                // if we are parsing the start line but neither a response or request
                if (state == MessageParserState::PARSING_START_LINE)
                {
                    // if we hit a space, we have to check if the start line begins
                    // with the HTTP version or the method verb
                    if (character == ' ')
                    {
                        // this message has a leading version string, thus it is
                        // a response and not a request
                        if (temp == HTTPVersion1 || temp == HTTPVersion11)
                        {
                            httpMessage->SetMethod("NONE");

                            state = MessageParserState::START_LINE_RESPONSE;

                            temp = "";

                            continue;
                        }
                        // this must be a request, so grab the HTTPMessage::HttpMethod type
                        // for the request, set it, and move on
                        else
                        {
                            httpMessage->SetMethod(temp);

                            state = MessageParserState::START_LINE_REQUEST;

                            temp = "";

                            continue;
                        }
                    }
                }
                // do actions for when the start line is a request
                else if (state == MessageParserState::START_LINE_REQUEST)
                {
                    // once a space is hit, add the path to the message
                    if (character == ' ')
                    {
                        httpMessage->SetPath(temp);

                        temp = "";

                        continue;
                    }
                    // when the beginning of a carriage return is hit, add the version string
                    // to the message and then skip the following new line character, setting
                    // the state of the parser to be parsing headers
                    else if (character == '\r')
                    {
                        httpMessage->SetVersion(temp);

                        temp = "";

                        state = MessageParserState::HEADER_KEY;

                        skipNext = true;

                        continue;
                    }
                }
                // do actions for when the start line is a response
                else if (state == MessageParserState::START_LINE_RESPONSE)
                {
                    // if we are at a space, then we have hit the status code for the response
                    if (character == ' ' && httpMessage->GetStatusCode() == 0)
                    {
                        int code = std::stoi(temp);

                        httpMessage->SetStatusCode(static_cast<uint16_t>(code));

                        temp = "";

                        continue;
                    }
                    // if we are at a carriage return start, then set the status message for
                    // the response, this can be blank in which it will use a generated status
                    //
                    // this will also set the state of the parser to move on to headers
                    else if (character == '\r')
                    {
                        httpMessage->SetStatusMessage(temp);

                        temp = "";

                        state = MessageParserState::HEADER_KEY;

                        skipNext = true;

                        continue;
                    }
                }
                // if we are parsing header keys and hit a colon, then the key for the header has
                // been fully parsed and should be added to the temporary key holder
                else if (state == MessageParserState::HEADER_KEY && character == ':')
                {
                    headerKey = temp;

                    temp = "";

                    state = MessageParserState::HEADER_VALUE;

                    // HTTP defines that the next character in a header should be a space
                    // so skip that for parsing the value of the header
                    skipNext = true;

                    continue;
                }
                // if we are parsing header values and hit the beginning of a carriage return then
                // it is time to add the header to the message with the key and value, and move the
                // state back to parsing keys
                else if (state == MessageParserState::HEADER_VALUE && character == '\r')
                {
                    httpMessage->SetHeader(headerKey, temp);

                    headerKey = "";
                    temp      = "";

                    state = MessageParserState::HEADER_KEY;

                    // skip the next character as it will just be a newline
                    skipNext = true;

                    continue;
                }
                // if we are parsing header keys and we hit a carriage return, then we should assume
                // that the headers have ended, and that we are now parsing a message body.
                else if (state == MessageParserState::HEADER_KEY && character == '\r')
                {
                    temp = "";

                    state = MessageParserState::PARSING_BODY;

                    // skip the next character as it'll be a newline
                    skipNext = true;

                    continue;
                }

                temp += character;
            }

            // add the body to the message if it is present
            if (hasMessageBody){
              httpMessage->GetMessageBody().insert(
                  httpMessage->GetMessageBody().begin(),
                  buffer.begin() + bodyStartIndex,
                  buffer.end()
              );
              if(httpMessage->GetContentLength() > httpMessage->GetMessageBody().size()){
                httpMessage->SetFragmented(true);
              }
            }

            /*
            std::cout << "\n\n\n <<<<<<<<<<<<<<<<<<<<<<<<< " << std::string{buffer.begin(), buffer.end()};
            std::cout << "content-length:" << httpMessage->GetContentLength() << "\n";
            std::cout << "body-length:" << buffer.end() - buffer.begin()+bodyStartIndex << "\n";
            std::cout << "body-size:" << httpMessage->GetMessageBody().size() << "\n";
            std::cout << "\n\n\n <<<<<<<<<<<<<<<<<<<<<<<<< \n";
            */

            if(httpMessage->GetContentLength() < httpMessage->GetMessageBody().size()){
              httpMessage->GetMessageBody().resize(
                  httpMessage->GetContentLength()
              );
            }
        }
 
        bool TryExtractHttpMessage(const std::string& bufferStr, std::string& outMessage, size_t& messageSize)
        {
          size_t headerEnd = bufferStr.find("\r\n\r\n");
          if (headerEnd == std::string::npos) {
            return false; // Headers not complete yet
          }

          std::string headerPart = bufferStr.substr(0, headerEnd + 4);
          size_t contentLength = 0;

          std::istringstream ss(headerPart);
          std::string line;
          while (std::getline(ss, line)) {
            if (line.find("Content-Length:") != std::string::npos) {
              try {
                contentLength = std::stoi(line.substr(line.find(":") + 1));
              } catch (...) {
                contentLength = 0;
              }
              break;
            }
          }

          size_t totalSize = headerEnd + 4 + contentLength;
          if (bufferStr.size() < totalSize) {
            return false; // Full message not yet available
          }

          outMessage = bufferStr.substr(0, totalSize);
          messageSize = totalSize;
          return true;
        }

      static bool invalidChar (char c)
      {
          return !(c>=0 && c <128);
      }
      void stripUnicode(std::string & str)
      {
          str.erase(
            std::remove_if(str.begin(),str.end(), invalidChar), str.end()
          );
      }

    };


} // end of `namespace ns3`


#endif /* HTTP_CONTENT_H */
