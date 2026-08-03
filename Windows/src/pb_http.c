#include "pb_internal.h"

// HTTP proxy: CONNECT tunnels (IPv4/IPv6).

// Read exactly one HTTP CONNECT response header without consuming bytes that belong to
// the tunneled protocol. A single recv() is not sufficient: proxy headers may be split
// across TCP segments, and returning after only the status line would leak the remaining
// header bytes into the TLS/SSH/etc. stream. The shared deadline bounds the whole header.
static int http_read_connect_response(SOCKET s, int *status_code)
{
    char response[4096];
    size_t used = 0;
    ULONGLONG deadline = GetTickCount64() + PROXY_HANDSHAKE_TIMEOUT_MS;
    BOOL complete = FALSE;

    if (status_code != NULL)
        *status_code = 0;

    while (used < sizeof(response) - 1)
    {
        ULONGLONG now = GetTickCount64();
        if (now >= deadline)
        {
            WSASetLastError(WSAETIMEDOUT);
            return -1;
        }

        ULONGLONG remaining = deadline - now;
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(s, &read_fds);
        struct timeval tv = {
            (long)(remaining / 1000),
            (long)((remaining % 1000) * 1000)
        };
        int ready = select(0, &read_fds, NULL, NULL, &tv);
        if (ready <= 0)
        {
            if (ready == 0) WSASetLastError(WSAETIMEDOUT);
            return -1;
        }

        // Peek first so we can locate the end of the proxy response without consuming
        // any immediately-following tunneled bytes (for example an SSH banner).
        int peeked = recv(s, &response[used], (int)(sizeof(response) - 1 - used), MSG_PEEK);
        if (peeked <= 0)
            return -1;

        size_t candidate_end = used + (size_t)peeked;
        size_t search_from = used > 3 ? used - 3 : 0;
        size_t header_end = 0;
        for (size_t i = search_from; i + 3 < candidate_end; i++)
        {
            if (memcmp(&response[i], "\r\n\r\n", 4) == 0)
            {
                header_end = i + 4;
                break;
            }
        }

        size_t consume = header_end != 0 ? header_end - used : (size_t)peeked;
        if (recv_n_until(s, &response[used], (int)consume, deadline) != (int)consume)
            return -1;
        used += consume;

        if (header_end != 0)
        {
            response[used] = '\0';
            complete = TRUE;
            break;
        }
    }

    if (!complete)
        return -1;
    if (strncmp(response, "HTTP/1.", 7) != 0)
        return -1;

    char *code_start = strchr(response, ' ');
    char *line_end = strstr(response, "\r\n");
    if (code_start == NULL || line_end == NULL || code_start >= line_end ||
        code_start + 4 > line_end ||
        code_start[1] < '0' || code_start[1] > '9' ||
        code_start[2] < '0' || code_start[2] > '9' ||
        code_start[3] < '0' || code_start[3] > '9')
        return -1;

    int code = (code_start[1] - '0') * 100 +
               (code_start[2] - '0') * 10 +
               (code_start[3] - '0');
    if (status_code != NULL)
        *status_code = code;
    return code == 200 ? 0 : -1;
}

int http_connect_v6(SOCKET s, const UINT8 dest_ip6[16], UINT16 dest_port, const PROXY_CONFIG *cfg)
{
    char request[HTTP_BUFFER_SIZE];
    int len;
    BOOL use_auth = (cfg != NULL && cfg->username[0] != '\0');

    // Format IPv6 address as [addr]:port per RFC 2732
    char addr_str[64];
    inet_ntop(AF_INET6, dest_ip6, addr_str, sizeof(addr_str));

    // Use the cached hostname only if this config opts to let the proxy resolve DNS.
    char cached_domain[256];
    const char *host_part;
    char host_buf[270];  // big enough for [ipv6]:port or domain
    if (cfg->send_domain_to_proxy && dns_cache_lookup_v6(dest_ip6, cached_domain, sizeof(cached_domain)))
    {
        host_part = cached_domain;
        strncpy_s(host_buf, sizeof(host_buf), cached_domain, _TRUNCATE);
    }
    else
    {
        snprintf(host_buf, sizeof(host_buf), "[%s]", addr_str);
        host_part = host_buf;
    }

    if (use_auth)
    {
        char credentials[SOCKS5_BUFFER_SIZE], encoded[HTTP_BUFFER_SIZE];
        snprintf(credentials, sizeof(credentials), "%s:%s", cfg->username, cfg->password);
        base64_encode(credentials, encoded, sizeof(encoded));
        len = snprintf(request, sizeof(request),
            "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Authorization: Basic %s\r\nProxy-Connection: keep-alive\r\n\r\n",
            host_part, dest_port, host_part, dest_port, encoded);
    }
    else
    {
        len = snprintf(request, sizeof(request),
            "CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\nProxy-Connection: keep-alive\r\n\r\n",
            host_part, dest_port, host_part, dest_port);
    }

    if (send(s, request, len, 0) != len) return -1;

    return http_read_connect_response(s, NULL);
}

int http_connect(SOCKET s, UINT32 dest_ip, UINT16 dest_port, const PROXY_CONFIG *cfg)
{
    char request[HTTP_BUFFER_SIZE];
    int len;
    BOOL use_auth = (cfg != NULL && cfg->username[0] != '\0');

    // Use the cached hostname only if this config opts to let the proxy resolve DNS.
    char cached_domain[256];
    char ip_str[32];
    const char *host_part;
    if (cfg->send_domain_to_proxy && dns_cache_lookup(dest_ip, cached_domain, sizeof(cached_domain)))
    {
        host_part = cached_domain;
    }
    else
    {
        format_ip_address(dest_ip, ip_str, sizeof(ip_str));
        host_part = ip_str;
    }

    if (use_auth)
    {
        // Create "username:password" string and encode as Base64
        char credentials[SOCKS5_BUFFER_SIZE];
        char encoded[HTTP_BUFFER_SIZE];
        snprintf(credentials, sizeof(credentials), "%s:%s", cfg->username, cfg->password);
        base64_encode(credentials, encoded, sizeof(encoded));

        len = snprintf(request, sizeof(request),
            "CONNECT %s:%d HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Proxy-Authorization: Basic %s\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n",
            host_part, dest_port, host_part, dest_port, encoded);
    }
    else
    {
        len = snprintf(request, sizeof(request),
            "CONNECT %s:%d HTTP/1.1\r\n"
            "Host: %s:%d\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n",
            host_part, dest_port, host_part, dest_port);
    }

    if (send(s, request, len, 0) != len)
    {
        log_message("HTTP: Failed to send CONNECT request");
        return -1;
    }

    int status_code = 0;
    if (http_read_connect_response(s, &status_code) != 0)
    {
        if (status_code != 0)
            log_message("HTTP: CONNECT failed with status %d", status_code);
        else
            log_message("HTTP: Failed to receive a complete CONNECT response header");
        return -1;
    }

    return 0;
}
