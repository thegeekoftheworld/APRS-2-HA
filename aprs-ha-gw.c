
/*
 * gw.c — APRS-IS <-> Home Assistant bridge (single-file)
 *
 * ✅ Listens on APRS-IS for messages addressed to login_callsign
 * ✅ Accepts ONLY senders whose BASE callsign matches allowed_base_callsign (e.g., K9RCP and K9RCP-*)
 * ✅ OTP (TOTP, 6 digits) for OTP-prefixed commands
 * ✅ "auth" command: "<OTP6> auth" authorizes ONLY the EXACT sender callsign for 5 minutes
 * ✅ During auth window, commands do NOT require OTP: "view IST", "toggle PORCH", "set THERM 70"
 * ✅ OTP rate limit: once OTP succeeds for a sender, next OTP-validated command blocked for 60 seconds
 * ✅ Debug flag: -3 (or -d) enables verbose logging
 * ✅ APRS-IS login verification: waits for "# logresp <callsign> ..." line; prints success message
 * ✅ Strips APRS message-id suffix like "{6" so "IST{6" matches "IST"
 * ✅ Auto-reloads config.ini every 10 seconds if file mtime changes
 * ✅ Auto-reconnects APRS-IS if [aprs] section changes (server/port/login/pass/filter)
 *
 * Build (Debian/Ubuntu):
 *   apt-get install -y build-essential libcurl4-openssl-dev libssl-dev
 *   gcc -O2 -Wall -Wextra -o gw gw.c -lcurl -lssl -lcrypto
 *
 * Run:
 *   ./gw -3 /etc/aprs-ha-bridge/config.ini
 *
 * Notes on lights:
 *   Use services like:
 *     service_toggle = light/toggle
 *     service_on     = light/turn_on
 *     service_off    = light/turn_off
 *
 * Example:
 *   [item_KITCHEN]
 *   type = light
 *   entity_id = light.kitchen
 *   service_toggle = light/toggle
 *   service_on = light/turn_on
 *   service_off = light/turn_off
 */

#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <openssl/hmac.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>   // strcasecmp, strncasecmp
#include <sys/socket.h>
#include <sys/stat.h>  // stat
#include <time.h>
#include <unistd.h>

#include <curl/curl.h>

/* ----------------------------- Debug ----------------------------- */

static int g_debug = 0;
#define DBG(fmt, ...) do { if (g_debug) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__); } while (0)

/* ----------------------------- tiny helpers ----------------------------- */

static void trim(char *s) {
  char *p = s;
  while (*p && isspace((unsigned char)*p)) p++;
  if (p != s) memmove(s, p, strlen(p) + 1);
  size_t n = strlen(s);
  while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = 0;
}

static int str_ieq(const char *a, const char *b) {
  return strcasecmp(a, b) == 0;
}

static void callsign_base(const char *in, char *out, size_t outsz) {
  size_t i = 0;
  while (in[i] && in[i] != '-' && i < outsz - 1) {
    out[i] = in[i];
    i++;
  }
  out[i] = 0;
}

static void tokenize(char *s, char **argv, int *argc, int max) {
  *argc = 0;
  while (*s && *argc < max) {
    while (*s && isspace((unsigned char)*s)) s++;
    if (!*s) break;
    argv[(*argc)++] = s;
    while (*s && !isspace((unsigned char)*s)) s++;
    if (*s) *s++ = 0;
  }
}

static int is_otp6(const char *s) {
  if (!s || strlen(s) != 6) return 0;
  for (int i = 0; i < 6; i++) if (!isdigit((unsigned char)s[i])) return 0;
  return 1;
}

/* Safe bounded copy using %.*s */
static void scpy(char *dst, size_t dstsz, const char *src) {
  if (!dst || dstsz == 0) return;
  if (!src) { dst[0] = 0; return; }
  snprintf(dst, dstsz, "%.*s", (int)dstsz - 1, src);
}

/* Remove APRS message-id suffix like "{6" or "{06" or "{123" and trim. */
static void strip_aprs_msgid(char *s) {
  if (!s) return;

  char *p = strchr(s, '{');
  if (p) *p = 0;

  // Some clients may have ack-ish fragments
  p = strchr(s, '}');
  if (p) *p = 0;

  trim(s);
}

/* ----------------------------- Config ----------------------------- */

typedef struct {
  char code[64];          // e.g., IST
  char type[64];          // sensor/switch/climate/light/etc
  char entity_id[256];    // e.g., sensor.inside_temperature

  char format[256];       // optional format for view, expects one %s

  char service_toggle[256];
  char service_on[256];
  char service_off[256];
  char service_set[256];
  char set_field[128];    // e.g. temperature / brightness / etc
} Item;

typedef struct {
  // APRS
  char aprs_server[256];
  int  aprs_port;
  char login_callsign[64];
  char aprs_passcode[32];
  char aprs_filter[256];

  // Security
  char allowed_base_callsign[64];
  char totp_secret_base32[256];
  int  totp_step_seconds;
  int  totp_accept_steps;

  // Home Assistant
  char ha_base_url[256];
  char ha_token[768];

  // Items
  Item items[128];
  int item_count;
} AppConfig;

static void cfg_defaults(AppConfig *cfg) {
  memset(cfg, 0, sizeof(*cfg));
  scpy(cfg->aprs_server, sizeof(cfg->aprs_server), "rotate.aprs2.net");
  cfg->aprs_port = 14580;
  cfg->totp_step_seconds = 30;
  cfg->totp_accept_steps = 1;
  scpy(cfg->aprs_filter, sizeof(cfg->aprs_filter), "m/1");
}

static const Item* cfg_find_item(const AppConfig *cfg, const char *code) {
  for (int i = 0; i < cfg->item_count; i++) {
    if (strcasecmp(cfg->items[i].code, code) == 0) return &cfg->items[i];
  }
  return NULL;
}

static int cfg_load(AppConfig *cfg, const char *path) {
  cfg_defaults(cfg);

  FILE *f = fopen(path, "r");
  if (!f) return 0;

  char line[512];
  char section[128] = "";
  int current_item_idx = -1;

  while (fgets(line, sizeof(line), f)) {
    trim(line);
    if (!line[0] || line[0] == ';' || line[0] == '#') continue;

    if (line[0] == '[') {
      char *end = strchr(line, ']');
      if (!end) continue;
      *end = 0;
      scpy(section, sizeof(section), line + 1);
      current_item_idx = -1;

      if (strncasecmp(section, "item_", 5) == 0) {
        const char *code = section + 5;

        for (int i = 0; i < cfg->item_count; i++) {
          if (strcasecmp(cfg->items[i].code, code) == 0) { current_item_idx = i; break; }
        }

        if (current_item_idx < 0 && cfg->item_count < 128) {
          current_item_idx = cfg->item_count++;
          memset(&cfg->items[current_item_idx], 0, sizeof(cfg->items[current_item_idx]));
          scpy(cfg->items[current_item_idx].code, sizeof(cfg->items[current_item_idx].code), code);
        }
      }
      continue;
    }

    char *eq = strchr(line, '=');
    if (!eq) continue;
    *eq = 0;

    char *k = line;
    char *v = eq + 1;
    trim(k); trim(v);

    char key[128], val[384];
    scpy(key, sizeof(key), k);
    scpy(val, sizeof(val), v);

    if (str_ieq(section, "aprs")) {
      if (str_ieq(key, "server")) scpy(cfg->aprs_server, sizeof(cfg->aprs_server), val);
      else if (str_ieq(key, "port")) cfg->aprs_port = atoi(val);
      else if (str_ieq(key, "login_callsign")) scpy(cfg->login_callsign, sizeof(cfg->login_callsign), val);
      else if (str_ieq(key, "aprs_passcode")) scpy(cfg->aprs_passcode, sizeof(cfg->aprs_passcode), val);
      else if (str_ieq(key, "filter")) scpy(cfg->aprs_filter, sizeof(cfg->aprs_filter), val);
    } else if (str_ieq(section, "security")) {
      if (str_ieq(key, "allowed_base_callsign")) scpy(cfg->allowed_base_callsign, sizeof(cfg->allowed_base_callsign), val);
      else if (str_ieq(key, "totp_secret_base32")) scpy(cfg->totp_secret_base32, sizeof(cfg->totp_secret_base32), val);
      else if (str_ieq(key, "totp_step_seconds")) cfg->totp_step_seconds = atoi(val);
      else if (str_ieq(key, "totp_accept_steps")) cfg->totp_accept_steps = atoi(val);
    } else if (str_ieq(section, "homeassistant")) {
      if (str_ieq(key, "base_url")) scpy(cfg->ha_base_url, sizeof(cfg->ha_base_url), val);
      else if (str_ieq(key, "token")) scpy(cfg->ha_token, sizeof(cfg->ha_token), val);
    } else if (current_item_idx >= 0) {
      Item *it = &cfg->items[current_item_idx];
      if (str_ieq(key, "type")) scpy(it->type, sizeof(it->type), val);
      else if (str_ieq(key, "entity_id")) scpy(it->entity_id, sizeof(it->entity_id), val);
      else if (str_ieq(key, "format")) scpy(it->format, sizeof(it->format), val);
      else if (str_ieq(key, "service_toggle")) scpy(it->service_toggle, sizeof(it->service_toggle), val);
      else if (str_ieq(key, "service_on")) scpy(it->service_on, sizeof(it->service_on), val);
      else if (str_ieq(key, "service_off")) scpy(it->service_off, sizeof(it->service_off), val);
      else if (str_ieq(key, "service_set")) scpy(it->service_set, sizeof(it->service_set), val);
      else if (str_ieq(key, "set_field")) scpy(it->set_field, sizeof(it->set_field), val);
    }
  }

  fclose(f);

  if (!cfg->login_callsign[0] || !cfg->aprs_passcode[0] ||
      !cfg->allowed_base_callsign[0] || !cfg->totp_secret_base32[0] ||
      !cfg->ha_base_url[0] || !cfg->ha_token[0]) {
    return 0;
  }
  return 1;
}

/* ----------------------------- APRS-IS ----------------------------- */

typedef struct {
  int sock;
} AprsIS;

static int aprsis_connect(AprsIS *a, const char *host, int port) {
  memset(a, 0, sizeof(*a));
  a->sock = -1;

  struct addrinfo hints = {0}, *res = NULL;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_family = AF_UNSPEC;

  char portstr[16];
  snprintf(portstr, sizeof(portstr), "%d", port);

  if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return 0;

  int s = -1;
  for (struct addrinfo *p = res; p; p = p->ai_next) {
    s = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (s < 0) continue;
    if (connect(s, p->ai_addr, p->ai_addrlen) == 0) break;
    close(s);
    s = -1;
  }
  freeaddrinfo(res);

  if (s < 0) return 0;
  a->sock = s;
  return 1;
}

static int aprsis_send_raw(AprsIS *a, const char *data, size_t len) {
  if (!a || a->sock < 0) return 0;
  ssize_t w = send(a->sock, data, len, 0);
  return (w == (ssize_t)len);
}

/* APRS-IS expects CRLF line endings — we always send "\r\n" */
static int aprsis_sendline(AprsIS *a, const char *line) {
  if (!a || a->sock < 0) return 0;
  DBG("TX(APRS-IS): %s", line);
  if (!aprsis_send_raw(a, line, strlen(line))) return 0;
  if (!aprsis_send_raw(a, "\r\n", 2)) return 0;
  return 1;
}

static int aprsis_login(AprsIS *a, const char *login_callsign, const char *passcode, const char *filter) {
  char line[768];
  snprintf(line, sizeof(line),
           "user %s pass %s vers aprs-ha-bridge 2.2 filter %s",
           login_callsign, passcode, (filter && *filter) ? filter : "m/1");
  return aprsis_sendline(a, line);
}

static int aprsis_readline(AprsIS *a, char *buf, int buflen) {
  if (!a || a->sock < 0 || !buf || buflen < 2) return 0;
  int i = 0;
  while (i < buflen - 1) {
    char c;
    ssize_t r = recv(a->sock, &c, 1, 0);
    if (r <= 0) return 0;
    if (c == '\n') break;
    if (c == '\r') continue;
    buf[i++] = c;
  }
  buf[i] = 0;
  return 1;
}

static void aprsis_close(AprsIS *a) {
  if (a && a->sock >= 0) close(a->sock);
  if (a) a->sock = -1;
}

/* Parse APRS message packet:
 * FROM>...::TO(9 chars padded):TEXT
 */
static int parse_aprs_message(const char *line,
                             char *from, size_t fromsz,
                             char *to, size_t tosz,
                             char *text, size_t textsz) {
  const char *gt = strchr(line, '>');
  if (!gt) return 0;
  snprintf(from, fromsz, "%.*s", (int)(gt - line), line);

  const char *dbl = strstr(line, "::");
  if (!dbl) return 0;

  const char *colon = strchr(dbl + 2, ':');
  if (!colon) return 0;

  int tolen = (int)(colon - (dbl + 2));
  if (tolen <= 0) return 0;
  if (tolen > (int)tosz - 1) tolen = (int)tosz - 1;
  memcpy(to, dbl + 2, tolen);
  to[tolen] = 0;
  while (tolen > 0 && to[tolen - 1] == ' ') to[--tolen] = 0;

  scpy(text, textsz, colon + 1);
  return 1;
}

static void send_aprs_msg(AprsIS *is, const char *from_login, const char *dest, const char *msg) {
  char to9[10];
  memset(to9, ' ', 9);
  to9[9] = 0;
  int n = (int)strlen(dest);
  if (n > 9) n = 9;
  memcpy(to9, dest, n);

  char shortmsg[80];
  snprintf(shortmsg, sizeof(shortmsg), "%.67s", msg);

  char line[320];
  snprintf(line, sizeof(line), "%s>APRS,TCPIP*::%s:%s", from_login, to9, shortmsg);
  aprsis_sendline(is, line);
}

static int aprsis_wait_logresp(AprsIS *is, const char *login_callsign, int timeout_seconds) {
  time_t start = time(NULL);
  char buf[1024];

  while ((time(NULL) - start) < timeout_seconds) {
    if (!aprsis_readline(is, buf, sizeof(buf))) return 0;

    DBG("RX(APRS-IS): %s", buf);

    if (buf[0] != '#') continue;

    if (strstr(buf, "logresp") && strstr(buf, login_callsign)) {
      if (strstr(buf, "verified")) {
        fprintf(stderr, "APRS-IS login OK (verified): %s\n", buf);
        return 1;
      }
      if (strstr(buf, "unverified")) {
        fprintf(stderr, "APRS-IS login OK (UNVERIFIED passcode?): %s\n", buf);
        return 1;
      }
      fprintf(stderr, "APRS-IS login response: %s\n", buf);
      return 1;
    }
  }

  fprintf(stderr, "APRS-IS login: no logresp within %d seconds (continuing)\n", timeout_seconds);
  return 1;
}

/* ----------------------------- TOTP (Base32 + HMAC-SHA1) ----------------------------- */

static int b32val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a';
  if (c >= '2' && c <= '7') return 26 + (c - '2');
  return -1;
}

static int base32_decode(const char *in, uint8_t *out, int out_max) {
  int buffer = 0, bits_left = 0, count = 0;
  for (const char *p = in; *p; p++) {
    if (*p == '=' || isspace((unsigned char)*p)) continue;
    int v = b32val(*p);
    if (v < 0) return -1;
    buffer = (buffer << 5) | v;
    bits_left += 5;
    if (bits_left >= 8) {
      bits_left -= 8;
      if (count >= out_max) return -1;
      out[count++] = (buffer >> bits_left) & 0xFF;
    }
  }
  return count;
}

static void hotp6(const uint8_t *key, int key_len, uint64_t counter, char out6[7]) {
  uint8_t msg[8];
  for (int i = 7; i >= 0; i--) { msg[i] = counter & 0xFF; counter >>= 8; }

  unsigned int mac_len = 0;
  unsigned char mac[EVP_MAX_MD_SIZE];
  HMAC(EVP_sha1(), key, key_len, msg, sizeof(msg), mac, &mac_len);

  int offset = mac[mac_len - 1] & 0x0F;
  uint32_t bin =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);

  uint32_t otp = bin % 1000000;
  snprintf(out6, 7, "%06u", otp);
}

static int totp_verify_6digit(const char *base32_secret, int step_seconds, int accept_steps,
                             const char *otp6, time_t now_utc) {
  if (!is_otp6(otp6)) return 0;

  uint8_t key[64];
  int key_len = base32_decode(base32_secret, key, (int)sizeof(key));
  if (key_len <= 0) return 0;

  uint64_t counter = (uint64_t)(now_utc / step_seconds);

  for (int delta = -accept_steps; delta <= accept_steps; delta++) {
    char gen[7];
    hotp6(key, key_len, counter + (int64_t)delta, gen);
    if (memcmp(gen, otp6, 6) == 0) return 1;
  }
  return 0;
}

/* ----------------------------- Tiny JSON extraction (HA state + unit) ----------------------------- */

static int json_extract_string_value(const char *json, const char *key, char *out, size_t outsz) {
  char pat[192];
  snprintf(pat, sizeof(pat), "\"%s\"", key);
  const char *p = strstr(json, pat);
  if (!p) return 0;
  p += strlen(pat);

  p = strchr(p, ':');
  if (!p) return 0;
  p++;
  while (*p && isspace((unsigned char)*p)) p++;

  if (*p != '"') return 0;
  p++;

  size_t i = 0;
  while (*p && *p != '"' && i < outsz - 1) {
    if (*p == '\\' && p[1]) p++;
    out[i++] = *p++;
  }
  out[i] = 0;
  return (*p == '"');
}

static int json_extract_unit_of_measurement(const char *json, char *out, size_t outsz) {
  const char *a = strstr(json, "\"attributes\"");
  if (!a) return 0;
  const char *brace = strchr(a, '{');
  if (!brace) return 0;

  const char *end = strchr(brace, '}');
  if (!end) return 0;

  size_t len = (size_t)(end - brace + 1);
  char *tmp = (char*)malloc(len + 1);
  if (!tmp) return 0;
  memcpy(tmp, brace, len);
  tmp[len] = 0;

  int ok = json_extract_string_value(tmp, "unit_of_measurement", out, outsz);
  free(tmp);
  return ok;
}

/* ----------------------------- Home Assistant REST (libcurl) ----------------------------- */

typedef struct {
  char *data;
  size_t len;
} Buf;

static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *userdata) {
  size_t n = size * nmemb;
  Buf *b = (Buf*)userdata;
  char *p = (char*)realloc(b->data, b->len + n + 1);
  if (!p) return 0;
  b->data = p;
  memcpy(b->data + b->len, ptr, n);
  b->len += n;
  b->data[b->len] = 0;
  return n;
}

typedef struct {
  char state[64];
  char unit[32];
} HaState;

static int ha_get_state(const char *base_url, const char *token, const char *entity_id, HaState *out) {
  if (!base_url || !token || !entity_id || !out) return 0;
  memset(out, 0, sizeof(*out));

  CURL *curl = curl_easy_init();
  if (!curl) return 0;

  char url[512];
  snprintf(url, sizeof(url), "%s/api/states/%s", base_url, entity_id);

  struct curl_slist *hdrs = NULL;
  char auth[1024];
  snprintf(auth, sizeof(auth), "Authorization: Bearer %s", token);
  hdrs = curl_slist_append(hdrs, auth);
  hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

  Buf b = {0};

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &b);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

  CURLcode rc = curl_easy_perform(curl);
  long code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

  curl_slist_free_all(hdrs);
  curl_easy_cleanup(curl);

  if (rc != CURLE_OK || code != 200 || !b.data) { free(b.data); return 0; }

  if (!json_extract_string_value(b.data, "state", out->state, sizeof(out->state))) {
    free(b.data);
    return 0;
  }
  json_extract_unit_of_measurement(b.data, out->unit, sizeof(out->unit));

  free(b.data);
  return out->state[0] != 0;
}

static int ha_call_service_json(const char *base_url, const char *token,
                                const char *domain, const char *service, const char *json_body) {
  if (!base_url || !token || !domain || !service || !json_body) return 0;

  CURL *curl = curl_easy_init();
  if (!curl) return 0;

  char url[512];
  snprintf(url, sizeof(url), "%s/api/services/%s/%s", base_url, domain, service);

  struct curl_slist *hdrs = NULL;
  char auth[1024];
  snprintf(auth, sizeof(auth), "Authorization: Bearer %s", token);
  hdrs = curl_slist_append(hdrs, auth);
  hdrs = curl_slist_append(hdrs, "Content-Type: application/json");

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
  curl_easy_setopt(curl, CURLOPT_POST, 1L);
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

  CURLcode rc = curl_easy_perform(curl);
  long code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

  curl_slist_free_all(hdrs);
  curl_easy_cleanup(curl);

  return (rc == CURLE_OK && (code == 200 || code == 201));
}

static void split_service(const char *svc, char *domain, size_t dsz, char *service, size_t ssz) {
  const char *slash = strchr(svc, '/');
  if (!slash) {
    scpy(domain, dsz, "homeassistant");
    scpy(service, ssz, svc);
    return;
  }
  snprintf(domain, dsz, "%.*s", (int)(slash - svc), svc);
  scpy(service, ssz, slash + 1);
}

/* ----------------------------- Sessions (per EXACT sender callsign) ----------------------------- */

typedef struct {
  char callsign[32];        // exact (e.g., K9RCP-9)
  time_t authorized_until;  // auth expiry
  time_t last_otp_accept;   // OTP rate-limit timestamp
} Session;

static Session g_sessions[64];

static Session* session_get(const char *callsign) {
  for (int i = 0; i < (int)(sizeof(g_sessions)/sizeof(g_sessions[0])); i++) {
    if (g_sessions[i].callsign[0] && strcasecmp(g_sessions[i].callsign, callsign) == 0)
      return &g_sessions[i];
  }
  for (int i = 0; i < (int)(sizeof(g_sessions)/sizeof(g_sessions[0])); i++) {
    if (!g_sessions[i].callsign[0]) {
      scpy(g_sessions[i].callsign, sizeof(g_sessions[i].callsign), callsign);
      g_sessions[i].authorized_until = 0;
      g_sessions[i].last_otp_accept = 0;
      DBG("Session created for %s", g_sessions[i].callsign);
      return &g_sessions[i];
    }
  }
  return NULL;
}

static int otp_rate_limited(Session *sess, time_t now) {
  return (sess && sess->last_otp_accept != 0 && (now - sess->last_otp_accept) < 60);
}

/* ----------------------------- Live config reload + APRS reconnect ----------------------------- */

static AppConfig g_cfg;
static char g_cfg_path[256] = "/etc/aprs-ha-bridge/config.ini";
static time_t g_cfg_last_check = 0;
static time_t g_cfg_last_mtime = 0;

typedef struct {
  char aprs_server[256];
  int  aprs_port;
  char login_callsign[64];
  char aprs_passcode[32];
  char aprs_filter[256];
} AprsConnSnapshot;

static AprsConnSnapshot g_aprs_snap;
static int g_reconnect_requested = 0;

static void snapshot_from_cfg(AprsConnSnapshot *s, const AppConfig *c) {
  scpy(s->aprs_server, sizeof(s->aprs_server), c->aprs_server);
  s->aprs_port = c->aprs_port;
  scpy(s->login_callsign, sizeof(s->login_callsign), c->login_callsign);
  scpy(s->aprs_passcode, sizeof(s->aprs_passcode), c->aprs_passcode);
  scpy(s->aprs_filter, sizeof(s->aprs_filter), c->aprs_filter);
}

static int snapshot_differs(const AprsConnSnapshot *a, const AprsConnSnapshot *b) {
  if (a->aprs_port != b->aprs_port) return 1;
  if (strcmp(a->aprs_server, b->aprs_server) != 0) return 1;
  if (strcmp(a->login_callsign, b->login_callsign) != 0) return 1;
  if (strcmp(a->aprs_passcode, b->aprs_passcode) != 0) return 1;
  if (strcmp(a->aprs_filter, b->aprs_filter) != 0) return 1;
  return 0;
}

static void maybe_reload_config(void) {
  time_t now = time(NULL);
  if (now - g_cfg_last_check < 10) return;
  g_cfg_last_check = now;

  struct stat st;
  if (stat(g_cfg_path, &st) != 0) return;

  if (g_cfg_last_mtime == 0) g_cfg_last_mtime = st.st_mtime;

  if (st.st_mtime != g_cfg_last_mtime) {
    AppConfig tmp;
    if (cfg_load(&tmp, g_cfg_path)) {
      AprsConnSnapshot new_snap;
      snapshot_from_cfg(&new_snap, &tmp);

      // Apply new config
      g_cfg = tmp;
      g_cfg_last_mtime = st.st_mtime;

      // If APRS connection-related settings changed, request reconnect
      if (snapshot_differs(&new_snap, &g_aprs_snap)) {
        g_reconnect_requested = 1;
        DBG("Config reload: APRS settings changed -> reconnect requested");
      } else {
        DBG("Config reload: APRS settings unchanged");
      }

      fprintf(stderr, "Config reloaded: %s (mtime=%ld)\n", g_cfg_path, (long)g_cfg_last_mtime);
    } else {
      fprintf(stderr, "Config reload FAILED (keeping old): %s\n", g_cfg_path);
    }
  }
}

/* ----------------------------- Main ----------------------------- */

int main(int argc, char **argv) {
  const char *cfg_path = "/etc/aprs-ha-bridge/config.ini";

  // args: -3 or -d enables debug; first non-flag arg is config path
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "-3") == 0 || strcmp(argv[i], "-d") == 0) {
      g_debug = 1;
    } else if (argv[i][0] != '-') {
      cfg_path = argv[i];
    }
  }

  scpy(g_cfg_path, sizeof(g_cfg_path), cfg_path);
  if (g_debug) fprintf(stderr, "[DEBUG] Using config: %s\n", g_cfg_path);

  if (!cfg_load(&g_cfg, g_cfg_path)) {
    fprintf(stderr, "Config load failed: %s\n", g_cfg_path);
    fprintf(stderr, "Required: [aprs] login_callsign/aprs_passcode, [security] allowed_base_callsign/totp_secret_base32, [homeassistant] base_url/token\n");
    return 2;
  }

  // baseline snapshot for reconnect detection
  snapshot_from_cfg(&g_aprs_snap, &g_cfg);

  curl_global_init(CURL_GLOBAL_DEFAULT);

  AprsIS is;
  memset(&is, 0, sizeof(is));
  is.sock = -1;

reconnect:
  if (is.sock >= 0) {
    fprintf(stderr, "Reconnecting APRS-IS...\n");
    aprsis_close(&is);
  }

  if (!aprsis_connect(&is, g_cfg.aprs_server, g_cfg.aprs_port)) {
    fprintf(stderr, "APRS-IS connect failed: %s:%d\n", g_cfg.aprs_server, g_cfg.aprs_port);
    sleep(3);
    goto reconnect; // keep trying
  }

  if (!aprsis_login(&is, g_cfg.login_callsign, g_cfg.aprs_passcode, g_cfg.aprs_filter)) {
    fprintf(stderr, "APRS-IS login failed (could not send login line)\n");
    sleep(3);
    goto reconnect;
  }

  fprintf(stderr, "Connected APRS-IS %s:%d as %s (waiting for logresp...)\n",
          g_cfg.aprs_server, g_cfg.aprs_port, g_cfg.login_callsign);

  if (!aprsis_wait_logresp(&is, g_cfg.login_callsign, 8)) {
    fprintf(stderr, "APRS-IS login did not complete\n");
    sleep(3);
    goto reconnect;
  }

  fprintf(stderr, "APRS-HA bridge ready. Send '<OTP6> auth' from %s-SSID to authorize 5 minutes.\n",
          g_cfg.allowed_base_callsign);

  char line[1024];
  while (1) {
    // periodic reload
    maybe_reload_config();
    if (g_reconnect_requested) {
      // update snapshot to new cfg before reconnecting
      snapshot_from_cfg(&g_aprs_snap, &g_cfg);
      g_reconnect_requested = 0;
      goto reconnect;
    }

    if (!aprsis_readline(&is, line, sizeof(line))) {
      DBG("APRS-IS read failed; reconnecting");
      sleep(1);
      goto reconnect;
    }

    if (line[0] == '#') { DBG("RX(APRS-IS): %s", line); continue; }

    char from[64], to[64], text[512];
    if (!parse_aprs_message(line, from, sizeof(from), to, sizeof(to), text, sizeof(text))) continue;

    // Only process messages addressed to our login callsign
    if (strcasecmp(to, g_cfg.login_callsign) != 0) continue;

    // Check sender base callsign allowlist
    char base[64];
    callsign_base(from, base, sizeof(base));
    if (strcasecmp(base, g_cfg.allowed_base_callsign) != 0) {
      DBG("IGNORED sender=%s base=%s (not allowed)", from, base);
      continue;
    }

    Session *sess = session_get(from);
    if (!sess) {
      send_aprs_msg(&is, g_cfg.login_callsign, from, "ERR session table full");
      continue;
    }

    DBG("RX msg from=%s to=%s text='%s' (auth_until=%ld now=%ld)",
        from, to, text, (long)sess->authorized_until, (long)time(NULL));

    // Copy and sanitize message text
    char tmp[512];
    scpy(tmp, sizeof(tmp), text);
    strip_aprs_msgid(tmp);

    char *av[10]; int ac = 0;
    tokenize(tmp, av, &ac, 10);
    if (ac < 1) continue;

    time_t now = time(NULL);

    const char *otp6 = NULL;
    const char *cmd = NULL;
    const char *item = NULL;
    int argi = 0;

    // Accepted formats:
    // 1) OTP-prefixed: <OTP6> <cmd> [item] [args...]
    // 2) Authorized:   <cmd> [item] [args...]
    if (is_otp6(av[0])) {
      otp6 = av[0];
      argi = 1;

      if (ac < 2) {
        send_aprs_msg(&is, g_cfg.login_callsign, from, "ERR format: <OTP6> <cmd> ...");
        continue;
      }

      if (otp_rate_limited(sess, now)) {
        send_aprs_msg(&is, g_cfg.login_callsign, from, "ERR OTP rate limit (60s)");
        DBG("OTP rate-limited for %s", from);
        continue;
      }

      if (!totp_verify_6digit(g_cfg.totp_secret_base32, g_cfg.totp_step_seconds, g_cfg.totp_accept_steps, otp6, now)) {
        send_aprs_msg(&is, g_cfg.login_callsign, from, "ERR bad OTP");
        DBG("Bad OTP from %s", from);
        continue;
      }

      sess->last_otp_accept = now; // lock OTP usage for 60 seconds
      cmd = av[argi++];
    } else {
      // No OTP => must be in authorized window for this EXACT callsign
      if (sess->authorized_until < now) {
        send_aprs_msg(&is, g_cfg.login_callsign, from, "ERR not authorized. Send: <OTP6> auth");
        DBG("Not authorized: %s", from);
        continue;
      }
      cmd = av[argi++];
    }

    // Special: auth (must be OTP-prefixed)
    if (strcasecmp(cmd, "auth") == 0) {
      if (!otp6) {
        send_aprs_msg(&is, g_cfg.login_callsign, from, "ERR auth requires OTP: <OTP6> auth");
        continue;
      }
      sess->authorized_until = now + 300; // 5 minutes
      send_aprs_msg(&is, g_cfg.login_callsign, from, "OK authorized 5 min");
      DBG("AUTH OK for %s until %ld", from, (long)sess->authorized_until);
      continue;
    }

    // All remaining commands require an item
    if (ac <= argi) {
      send_aprs_msg(&is, g_cfg.login_callsign, from, "ERR missing item");
      continue;
    }
    item = av[argi++];

    const Item *it = cfg_find_item(&g_cfg, item);
    if (!it || !it->entity_id[0]) {
      send_aprs_msg(&is, g_cfg.login_callsign, from, "ERR unknown item");
      DBG("Unknown item: %s", item);
      continue;
    }

    // view
    if (strcasecmp(cmd, "view") == 0) {
      HaState st;
      if (!ha_get_state(g_cfg.ha_base_url, g_cfg.ha_token, it->entity_id, &st)) {
        send_aprs_msg(&is, g_cfg.login_callsign, from, "ERR HA read failed");
        DBG("HA read failed: %s", it->entity_id);
        continue;
      }

      char reply[160];
      if (it->format[0]) {
        char val[120];
        if (st.unit[0]) snprintf(val, sizeof(val), "%s%s", st.state, st.unit);
        else scpy(val, sizeof(val), st.state);
        snprintf(reply, sizeof(reply), it->format, val);
      } else {
        if (st.unit[0]) snprintf(reply, sizeof(reply), "%s=%s%s", it->code, st.state, st.unit);
        else snprintf(reply, sizeof(reply), "%s=%s", it->code, st.state);
      }

      send_aprs_msg(&is, g_cfg.login_callsign, from, reply);
      DBG("view %s -> %s", it->entity_id, reply);
      continue;
    }

    // toggle/on/off
    if (strcasecmp(cmd, "toggle") == 0 || strcasecmp(cmd, "on") == 0 || strcasecmp(cmd, "off") == 0) {
      const char *svc_full = NULL;

      // If configured per-item, use it. Otherwise default to homeassistant/*
      if (strcasecmp(cmd, "toggle") == 0) svc_full = it->service_toggle[0] ? it->service_toggle : "homeassistant/toggle";
      if (strcasecmp(cmd, "on") == 0)     svc_full = it->service_on[0] ? it->service_on : "homeassistant/turn_on";
      if (strcasecmp(cmd, "off") == 0)    svc_full = it->service_off[0] ? it->service_off : "homeassistant/turn_off";

      char domain[96], service[96];
      split_service(svc_full, domain, sizeof(domain), service, sizeof(service));

      char body[320];
      snprintf(body, sizeof(body), "{\"entity_id\":\"%s\"}", it->entity_id);

      if (!ha_call_service_json(g_cfg.ha_base_url, g_cfg.ha_token, domain, service, body)) {
        send_aprs_msg(&is, g_cfg.login_callsign, from, "ERR HA service failed");
        DBG("HA service failed: %s/%s body=%s", domain, service, body);
        continue;
      }

      char ok[160];
      snprintf(ok, sizeof(ok), "%s %s", it->code, cmd);
      send_aprs_msg(&is, g_cfg.login_callsign, from, ok);
      DBG("service OK: %s/%s %s", domain, service, it->entity_id);
      continue;
    }

    // set <value>
    if (strcasecmp(cmd, "set") == 0) {
      if (ac <= argi) {
        send_aprs_msg(&is, g_cfg.login_callsign, from, "ERR set needs value");
        continue;
      }
      const char *value = av[argi];

      if (!it->service_set[0] || !it->set_field[0]) {
        send_aprs_msg(&is, g_cfg.login_callsign, from, "ERR item not settable");
        continue;
      }

      char domain[96], service[96];
      split_service(it->service_set, domain, sizeof(domain), service, sizeof(service));

      int is_num = 1;
      for (const char *p = value; *p; p++) {
        if (!(isdigit((unsigned char)*p) || *p == '.' || *p == '-')) { is_num = 0; break; }
      }

      char body[384];
      if (is_num)
        snprintf(body, sizeof(body), "{\"entity_id\":\"%s\",\"%s\":%s}", it->entity_id, it->set_field, value);
      else
        snprintf(body, sizeof(body), "{\"entity_id\":\"%s\",\"%s\":\"%s\"}", it->entity_id, it->set_field, value);

      if (!ha_call_service_json(g_cfg.ha_base_url, g_cfg.ha_token, domain, service, body)) {
        send_aprs_msg(&is, g_cfg.login_callsign, from, "ERR HA set failed");
        DBG("HA set failed: %s/%s body=%s", domain, service, body);
        continue;
      }

      char ok[160];
      snprintf(ok, sizeof(ok), "%s set %s", it->code, value);
      send_aprs_msg(&is, g_cfg.login_callsign, from, ok);
      DBG("set OK: %s=%s (%s/%s)", it->entity_id, value, domain, service);
      continue;
    }

    send_aprs_msg(&is, g_cfg.login_callsign, from, "ERR unknown cmd");
    DBG("Unknown cmd: %s", cmd);
  }

  // unreachable
  aprsis_close(&is);
  curl_global_cleanup();
  return 0;
}
