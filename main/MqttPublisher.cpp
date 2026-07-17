#include "MqttPublisher.hpp"

#include <cstddef>
#include <cstdint>
#include <cstdio>

#include "esp_check.h"
#include "esp_log.h"

namespace {

extern const uint8_t kEmbeddedCaCertStart[] asm("_binary_isrgrootx1_pem_start");
extern const uint8_t kEmbeddedCaCertEnd[] asm("_binary_isrgrootx1_pem_end");

enum class CertificateFileCheckResult {
    Found,
    NotFound,
    Unknown,
};

constexpr int kCertificateFilesystemIndex = 3;
constexpr int kCertificateUploadWindowMs = 10000;
constexpr int kBrokerPort = 8883;
constexpr const char *kBrokerTopic = "camper/raven/telemetry";
constexpr const char *kBrokerClientId = "camper-raven";
constexpr const char *kTlsCaCertFilename = "isrgrootx1.pem";
constexpr const char *kTlsCipherSuite0 = "0x0035";
constexpr const char *kTlsCipherSuite1 = "0x002F";

bool containsText(const std::string &text, const char *needle)
{
    return text.find(needle) != std::string::npos;
}

void appendJsonKey(std::string &payload, bool *needs_comma, const char *key)
{
    if (*needs_comma) {
        payload += ",";
    }

    payload += "\"";
    payload += key;
    payload += "\":";
    *needs_comma = true;
}

void appendJsonUnsigned(std::string &payload, bool *needs_comma, const char *key, uint64_t value)
{
    char buffer[32];

    appendJsonKey(payload, needs_comma, key);
    std::snprintf(buffer, sizeof(buffer), "%llu", static_cast<unsigned long long>(value));
    payload += buffer;
}

void appendJsonFloat(std::string &payload, bool *needs_comma, const char *key, float value)
{
    char buffer[32];

    appendJsonKey(payload, needs_comma, key);
    std::snprintf(buffer, sizeof(buffer), "%.3f", static_cast<double>(value));
    payload += buffer;
}

bool beginFilesystemSession(LteConnectionManager &lte_connection_manager, const char *tag, const int timeout_ms)
{
    std::string response;
    const esp_err_t err = lte_connection_manager.runAtCommand("AT+CFSINIT", timeout_ms, &response);
    if (err != ESP_OK) {
        ESP_LOGW(tag, "unable to open modem filesystem session for certificate checks");
        return false;
    }

    return true;
}

void endFilesystemSession(LteConnectionManager &lte_connection_manager, const int timeout_ms)
{
    std::string response;
    lte_connection_manager.runAtCommand("AT+CFSTERM", timeout_ms, &response);
}

void logCertificateFileLocation(
    LteConnectionManager &lte_connection_manager,
    const char *tag,
    const char *certificate_filename,
    const int timeout_ms)
{
    char command[256];
    std::string response;

    if (!beginFilesystemSession(lte_connection_manager, tag, timeout_ms)) {
        return;
    }

    for (int index = 0; index <= 3; ++index) {
        std::snprintf(command, sizeof(command), "AT+CFSGFIS=%d,\"%s\"", index, certificate_filename);
        if (lte_connection_manager.runAtCommand(command, timeout_ms, &response) == ESP_OK) {
            ESP_LOGI(tag, "certificate file located via %s:\n%s", command, response.c_str());
        }
    }

    endFilesystemSession(lte_connection_manager, timeout_ms);
}

CertificateFileCheckResult checkCertificateFileExists(
    LteConnectionManager &lte_connection_manager,
    const char *tag,
    const char *certificate_filename,
    const int timeout_ms)
{
    char command[256];
    std::string response;
    bool filesystem_probe_supported = true;

    if (!beginFilesystemSession(lte_connection_manager, tag, timeout_ms)) {
        return CertificateFileCheckResult::Unknown;
    }

    for (int index = 0; index <= 3; ++index) {
        std::snprintf(command, sizeof(command), "AT+CFSGFIS=%d,\"%s\"", index, certificate_filename);
        if (lte_connection_manager.runAtCommand(command, timeout_ms, &response) == ESP_OK) {
            endFilesystemSession(lte_connection_manager, timeout_ms);
            return CertificateFileCheckResult::Found;
        }

        if (containsText(response, "operation not allowed")) {
            filesystem_probe_supported = false;
        }
    }

    endFilesystemSession(lte_connection_manager, timeout_ms);
    if (!filesystem_probe_supported) {
        return CertificateFileCheckResult::Unknown;
    }

    return CertificateFileCheckResult::NotFound;
}

size_t embeddedCaCertificateSize()
{
    size_t size = static_cast<size_t>(kEmbeddedCaCertEnd - kEmbeddedCaCertStart);
    if (size > 0 && kEmbeddedCaCertEnd[-1] == '\0') {
        --size;
    }

    return size;
}

esp_err_t uploadEmbeddedCertificateFile(
    LteConnectionManager &lte_connection_manager,
    const char *tag,
    const char *certificate_filename,
    const int timeout_ms)
{
    const size_t certificate_size = embeddedCaCertificateSize();
    std::string response;
    char command[256];

    if (certificate_size == 0) {
        ESP_LOGE(tag, "embedded CA certificate payload is empty");
        return ESP_ERR_INVALID_SIZE;
    }

    if (certificate_size > 10240) {
        ESP_LOGE(tag, "embedded CA certificate payload is too large for CFSWFILE: %u bytes", static_cast<unsigned>(certificate_size));
        return ESP_ERR_INVALID_SIZE;
    }

    if (!beginFilesystemSession(lte_connection_manager, tag, timeout_ms)) {
        return ESP_FAIL;
    }

    std::snprintf(
        command,
        sizeof(command),
        "AT+CFSWFILE=%d,\"%s\",0,%u,%d",
        kCertificateFilesystemIndex,
        certificate_filename,
        static_cast<unsigned>(certificate_size),
        kCertificateUploadWindowMs);
    const esp_err_t upload_err = lte_connection_manager.runPromptedAtCommand(
        command,
        reinterpret_cast<const char *>(kEmbeddedCaCertStart),
        certificate_size,
        timeout_ms,
        &response);
    endFilesystemSession(lte_connection_manager, timeout_ms);

    if (upload_err != ESP_OK) {
        ESP_LOGE(tag, "failed to upload embedded CA certificate %s to modem filesystem", certificate_filename);
        return upload_err;
    }

    ESP_LOGI(
        tag,
        "uploaded embedded CA certificate %s (%u bytes) to modem filesystem index %d",
        certificate_filename,
        static_cast<unsigned>(certificate_size),
        kCertificateFilesystemIndex);
    return ESP_OK;
}

esp_err_t ensureCertificateFilePresent(
    LteConnectionManager &lte_connection_manager,
    const char *tag,
    const char *certificate_filename,
    const int timeout_ms)
{
    const CertificateFileCheckResult check_result =
        checkCertificateFileExists(lte_connection_manager, tag, certificate_filename, timeout_ms);
    if (check_result == CertificateFileCheckResult::Found) {
        return ESP_OK;
    }

    if (check_result == CertificateFileCheckResult::Unknown) {
        ESP_LOGW(
            tag,
            "unable to verify whether MQTT TLS root CA file %s exists; uploading embedded copy to be safe",
            certificate_filename);
    } else {
        ESP_LOGW(
            tag,
            "MQTT TLS root CA file %s was not found on modem filesystem; uploading embedded copy",
            certificate_filename);
    }

    ESP_RETURN_ON_ERROR(
        uploadEmbeddedCertificateFile(lte_connection_manager, tag, certificate_filename, timeout_ms),
        tag,
        "failed to provision modem CA certificate");

    const CertificateFileCheckResult post_upload_check =
        checkCertificateFileExists(lte_connection_manager, tag, certificate_filename, timeout_ms);
    if (post_upload_check == CertificateFileCheckResult::NotFound) {
        ESP_LOGE(tag, "uploaded CA certificate %s but modem still did not report it via CFSGFIS", certificate_filename);
        return ESP_ERR_NOT_FOUND;
    }

    return ESP_OK;
}

} // namespace

MqttPublisher::MqttPublisher(LteConnectionManager &lte_connection_manager)
    : lte_connection_manager_(lte_connection_manager)
{
}

esp_err_t MqttPublisher::publishTelemetryBatch(const TelemetrySample *samples, size_t sample_count) const
{
    if (CONFIG_CAMPER_MQTT_HOST[0] == '\0') {
        ESP_LOGE(kTag, "MQTT host is blank; set CONFIG_CAMPER_MQTT_HOST");
        return ESP_ERR_INVALID_STATE;
    }

    if (CONFIG_CAMPER_MQTT_USERNAME[0] == '\0') {
        ESP_LOGE(kTag, "MQTT username is blank; set CONFIG_CAMPER_MQTT_USERNAME");
        return ESP_ERR_INVALID_STATE;
    }

    if (CONFIG_CAMPER_MQTT_PASSWORD[0] == '\0') {
        ESP_LOGE(kTag, "MQTT password is blank; set CONFIG_CAMPER_MQTT_PASSWORD");
        return ESP_ERR_INVALID_STATE;
    }

    if (!lte_connection_manager_.isDataConnectionActive()) {
        ESP_LOGW(kTag, "LTE data is not active; skipping MQTT publish");
        return ESP_ERR_INVALID_STATE;
    }

    if (samples == nullptr || sample_count == 0) {
        ESP_LOGI(kTag, "telemetry batch is empty; nothing to publish");
        return ESP_OK;
    }

    const std::string topic = kBrokerTopic;
    const std::string payload = buildTelemetryPayload(samples, sample_count);
    esp_err_t err;

    err = configureTls();
    if (err != ESP_OK) {
        return err;
    }

    err = connectClient();
    if (err != ESP_OK) {
        return err;
    }

    err = publishMessage(topic, payload, sample_count);

    const esp_err_t disconnect_err = disconnectClient();
    if (disconnect_err != ESP_OK) {
        ESP_LOGW(kTag, "MQTT disconnect after telemetry publish failed: %s", esp_err_to_name(disconnect_err));
        if (err == ESP_OK) {
            err = disconnect_err;
        }
    }

    return err;
}

esp_err_t MqttPublisher::configureTls() const
{
    std::string response;
    char command[256];

    ESP_RETURN_ON_ERROR(
        ensureCertificateFilePresent(
            lte_connection_manager_,
            kTag,
            kTlsCaCertFilename,
            kDefaultTimeoutMs),
        kTag,
        "failed to ensure modem CA certificate is present");

    std::snprintf(command, sizeof(command), "AT+CSSLCFG=\"sslversion\",%d,3", kSslContextIndex);
    ESP_RETURN_ON_ERROR(
        lte_connection_manager_.runAtCommand(command, kDefaultTimeoutMs, &response),
        kTag,
        "failed to configure TLS version");

    std::snprintf(command, sizeof(command), "AT+CSSLCFG=\"ignorertctime\",%d,1", kSslContextIndex);
    ESP_RETURN_ON_ERROR(
        lte_connection_manager_.runAtCommand(command, kDefaultTimeoutMs, &response),
        kTag,
        "failed to disable modem RTC time checks during TLS validation");

    std::snprintf(command, sizeof(command), "AT+CSSLCFG=\"SNI\",%d,\"%s\"", kSslContextIndex, CONFIG_CAMPER_MQTT_HOST);
    ESP_RETURN_ON_ERROR(
        lte_connection_manager_.runAtCommand(command, kDefaultTimeoutMs, &response),
        kTag,
        "failed to configure TLS SNI hostname");

    std::snprintf(
        command,
        sizeof(command),
        "AT+CSSLCFG=\"ciphersuite\",%d,0,%s",
        kSslContextIndex,
        kTlsCipherSuite0);
    ESP_RETURN_ON_ERROR(
        lte_connection_manager_.runAtCommand(command, kDefaultTimeoutMs, &response),
        kTag,
        "failed to configure TLS cipher suite 0");

    std::snprintf(
        command,
        sizeof(command),
        "AT+CSSLCFG=\"ciphersuite\",%d,1,%s",
        kSslContextIndex,
        kTlsCipherSuite1);
    ESP_RETURN_ON_ERROR(
        lte_connection_manager_.runAtCommand(command, kDefaultTimeoutMs, &response),
        kTag,
        "failed to configure TLS cipher suite 1");

    std::snprintf(
        command,
        sizeof(command),
        "AT+CSSLCFG=\"convert\",2,\"%s\"",
        kTlsCaCertFilename);
    const esp_err_t convert_err =
        lte_connection_manager_.runAtCommand(command, kDefaultTimeoutMs, &response);
    if (convert_err != ESP_OK) {
        if (containsText(response, "operation not allowed")) {
            ESP_LOGW(
                kTag,
                "modem firmware rejected CSSLCFG convert for CA file %s; continuing with direct SMSSL binding",
                kTlsCaCertFilename);
        } else {
            ESP_LOGE(kTag, "failed to convert TLS root CA for modem SSL context");
            return convert_err;
        }
    }

    std::snprintf(
        command,
        sizeof(command),
        "AT+SMSSL=%d,\"%s\",\"\"",
        kSmSslIndex,
        kTlsCaCertFilename);
    ESP_RETURN_ON_ERROR(
        lte_connection_manager_.runAtCommand(command, kDefaultTimeoutMs, &response),
        kTag,
        "failed to bind MQTT client to TLS root CA");

    return ESP_OK;
}

esp_err_t MqttPublisher::connectClient() const
{
    std::string response;
    char command[512];

    std::snprintf(
        command,
        sizeof(command),
        "AT+SMCONF=\"URL\",\"%s\",\"%d\"",
        CONFIG_CAMPER_MQTT_HOST,
        kBrokerPort);
    ESP_RETURN_ON_ERROR(
        lte_connection_manager_.runAtCommand(command, kDefaultTimeoutMs, &response),
        kTag,
        "failed to configure broker URL");

    ESP_RETURN_ON_ERROR(
        lte_connection_manager_.runAtCommand("AT+SMCONF=\"KEEPTIME\",60", kDefaultTimeoutMs, &response),
        kTag,
        "failed to configure MQTT keepalive");
    ESP_RETURN_ON_ERROR(
        lte_connection_manager_.runAtCommand("AT+SMCONF=\"CLEANSS\",1", kDefaultTimeoutMs, &response),
        kTag,
        "failed to configure clean session");
    ESP_RETURN_ON_ERROR(
        lte_connection_manager_.runAtCommand("AT+SMCONF=\"QOS\",1", kDefaultTimeoutMs, &response),
        kTag,
        "failed to configure MQTT QoS");

    std::snprintf(
        command,
        sizeof(command),
        "AT+SMCONF=\"CLIENTID\",\"%s\"",
        kBrokerClientId);
    ESP_RETURN_ON_ERROR(
        lte_connection_manager_.runAtCommand(command, kDefaultTimeoutMs, &response),
        kTag,
        "failed to configure client id");

    std::snprintf(
        command,
        sizeof(command),
        "AT+SMCONF=\"USERNAME\",\"%s\"",
        CONFIG_CAMPER_MQTT_USERNAME);
    ESP_RETURN_ON_ERROR(
        lte_connection_manager_.runAtCommand(command, kDefaultTimeoutMs, &response),
        kTag,
        "failed to configure MQTT username");

    std::snprintf(
        command,
        sizeof(command),
        "AT+SMCONF=\"PASSWORD\",\"%s\"",
        CONFIG_CAMPER_MQTT_PASSWORD);
    ESP_RETURN_ON_ERROR(
        lte_connection_manager_.runAtCommand(command, kDefaultTimeoutMs, &response),
        kTag,
        "failed to configure MQTT password");

    const esp_err_t connect_err = lte_connection_manager_.runAtCommand("AT+SMCONN", kConnectTimeoutMs, &response);
    if (connect_err != ESP_OK) {
        std::string diag_response;

        if (lte_connection_manager_.runAtCommand("AT+SMSTATE?", kDefaultTimeoutMs, &diag_response) == ESP_OK) {
            ESP_LOGI(kTag, "MQTT state after failed connect:\n%s", diag_response.c_str());
        }

        if (lte_connection_manager_.runAtCommand("AT+SMCONF?", kDefaultTimeoutMs, &diag_response) == ESP_OK) {
            ESP_LOGI(kTag, "MQTT config after failed connect:\n%s", diag_response.c_str());
        }

        if (lte_connection_manager_.runAtCommand("AT+SMSSL?", kDefaultTimeoutMs, &diag_response) == ESP_OK) {
            ESP_LOGI(kTag, "MQTT SSL selection after failed connect:\n%s", diag_response.c_str());
        }

        std::snprintf(command, sizeof(command), "AT+CSSLCFG=\"CTXINDEX\",%d", kSslContextIndex);
        if (lte_connection_manager_.runAtCommand(command, kDefaultTimeoutMs, &diag_response) == ESP_OK) {
            ESP_LOGI(kTag, "SSL context %d after failed connect:\n%s", kSslContextIndex, diag_response.c_str());
        }

        if (lte_connection_manager_.runAtCommand("AT+CCLK?", kDefaultTimeoutMs, &diag_response) == ESP_OK) {
            ESP_LOGI(kTag, "modem clock after failed connect:\n%s", diag_response.c_str());
        }

        if (lte_connection_manager_.runAtCommand("AT+CGMR", kDefaultTimeoutMs, &diag_response) == ESP_OK) {
            ESP_LOGI(kTag, "modem firmware after failed connect:\n%s", diag_response.c_str());
        }

        logCertificateFileLocation(
            lte_connection_manager_,
            kTag,
            kTlsCaCertFilename,
            kDefaultTimeoutMs);

        ESP_LOGE(kTag, "connectClient(%d): failed to connect modem MQTT client", __LINE__);
        return connect_err;
    }

    return ESP_OK;
}

esp_err_t MqttPublisher::publishMessage(
    const std::string &topic,
    const std::string &payload,
    size_t sample_count) const
{
    std::string response;
    char command[256];

    std::snprintf(
        command,
        sizeof(command),
        "AT+SMPUB=\"%s\",%u,1,1",
        topic.c_str(),
        static_cast<unsigned>(payload.size()));
    ESP_RETURN_ON_ERROR(
        lte_connection_manager_.runPromptedAtCommand(
            command,
            payload.c_str(),
            payload.size(),
            kPublishTimeoutMs,
            &response),
        kTag,
        "failed to publish MQTT payload");

    ESP_LOGI(
        kTag,
        "published telemetry batch to topic %s sample_count=%u payload_bytes=%u",
        topic.c_str(),
        static_cast<unsigned>(sample_count),
        static_cast<unsigned>(payload.size()));
    return ESP_OK;
}

esp_err_t MqttPublisher::disconnectClient() const
{
    std::string response;
    const esp_err_t err = lte_connection_manager_.runAtCommand("AT+SMDISC", kDefaultTimeoutMs, &response);

    if (err != ESP_OK && !containsText(response, "ERROR")) {
        return err;
    }

    if (containsText(response, "ERROR")) {
        ESP_LOGW(kTag, "MQTT disconnect returned modem error: %s", response.c_str());
        return ESP_FAIL;
    }

    return ESP_OK;
}

std::string MqttPublisher::buildTelemetryPayload(const TelemetrySample *samples, size_t sample_count)
{
    std::string payload;

    payload.reserve(256 + (sample_count * 160));
    payload += "{\"transport\":\"sim7080g-sm-at\",\"samples\":[";

    for (size_t index = 0; index < sample_count; ++index) {
        bool needs_comma = false;

        if (index > 0) {
            payload += ",";
        }

        payload += "{";
        appendJsonUnsigned(payload, &needs_comma, "sample_uptime_ms", samples[index].sample_uptime_ms);

        if (samples[index].has_camper_battery_soc_pct) {
            appendJsonFloat(payload, &needs_comma, "camper_battery_soc_pct", samples[index].camper_battery_soc_pct);
        }

        if (samples[index].has_camper_battery_current_a) {
            appendJsonFloat(payload, &needs_comma, "camper_battery_current_a", samples[index].camper_battery_current_a);
        }

        if (samples[index].has_monitor_battery_pct) {
            appendJsonFloat(payload, &needs_comma, "monitor_battery_pct", samples[index].monitor_battery_pct);
        }

        if (samples[index].has_temperature_c) {
            appendJsonFloat(payload, &needs_comma, "temperature_c", samples[index].temperature_c);
        }

        if (samples[index].has_humidity_pct) {
            appendJsonFloat(payload, &needs_comma, "humidity_pct", samples[index].humidity_pct);
        }

        payload += "}";
    }

    payload += "]}";
    return payload;
}
