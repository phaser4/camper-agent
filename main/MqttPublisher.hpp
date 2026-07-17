#ifndef CAMPER_MQTT_PUBLISHER_HPP
#define CAMPER_MQTT_PUBLISHER_HPP

#include <cstddef>
#include <string>

#include "esp_err.h"

#include "LteConnectionManager.hpp"
#include "TelemetryTypes.hpp"

class MqttPublisher {
  public:
    explicit MqttPublisher(LteConnectionManager &lte_connection_manager);

    /* Publishes a telemetry batch after LTE data is active. */
    esp_err_t publishTelemetryBatch(const TelemetrySample *samples, size_t sample_count) const;

  private:
    static constexpr const char *kTag = "camper_mqtt";
    static constexpr int kDefaultTimeoutMs = 15000;
    static constexpr int kConnectTimeoutMs = 60000;
    static constexpr int kPublishTimeoutMs = 30000;
    static constexpr int kSslContextIndex = 1;
    static constexpr int kSmSslIndex = kSslContextIndex + 1;

    LteConnectionManager &lte_connection_manager_;

    esp_err_t configureTls() const;
    esp_err_t connectClient() const;
    esp_err_t publishMessage(const std::string &topic, const std::string &payload, size_t sample_count) const;
    esp_err_t disconnectClient() const;

    static std::string buildTelemetryPayload(const TelemetrySample *samples, size_t sample_count);
};

#endif
