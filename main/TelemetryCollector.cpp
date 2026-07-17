#include "TelemetryCollector.hpp"

#include "esp_log.h"
#include "esp_timer.h"

TelemetryCollector::TelemetryCollector(BluetoothScanner &bluetooth_scanner, TelemetryQueue &telemetry_queue)
    : bluetooth_scanner_(bluetooth_scanner),
      telemetry_queue_(telemetry_queue)
{
}

void TelemetryCollector::collectOnce() const
{
    TelemetrySample sample{};
    bool collected_any = false;

    sample.sample_uptime_ms = static_cast<uint64_t>(esp_timer_get_time() / 1000);

    if (collectVictronMetrics(&sample)) {
        collected_any = true;
    }

    if (collectMonitorBatteryMetrics(&sample)) {
        collected_any = true;
    }

    if (collectEnvironmentMetrics(&sample)) {
        collected_any = true;
    }

    if (!collected_any || !sample.hasAnyMetrics()) {
        ESP_LOGI(kTag, "collector found no telemetry sources ready; skipping enqueue");
        return;
    }

    telemetry_queue_.enqueue(sample);
    ESP_LOGI(kTag, "enqueued telemetry sample; queue depth is now %u", static_cast<unsigned>(telemetry_queue_.size()));
}

bool TelemetryCollector::collectVictronMetrics(TelemetrySample *sample_out) const
{
    BluetoothScanner::VictronTelemetrySnapshot snapshot{};

    if (sample_out == nullptr) {
        return false;
    }

    if (!bluetooth_scanner_.getLatestVictronTelemetry(&snapshot) || !snapshot.available) {
        ESP_LOGI(kTag, "Victron telemetry not yet available");
        return false;
    }

    if (snapshot.has_soc) {
        sample_out->has_camper_battery_soc_pct = true;
        sample_out->camper_battery_soc_pct = snapshot.soc_pct;
    }

    if (snapshot.has_current) {
        sample_out->has_camper_battery_current_a = true;
        sample_out->camper_battery_current_a = snapshot.current_a;
    }

    return sample_out->has_camper_battery_soc_pct || sample_out->has_camper_battery_current_a;
}

bool TelemetryCollector::collectMonitorBatteryMetrics(TelemetrySample *sample_out) const
{
    static_cast<void>(sample_out);
    return false;
}

bool TelemetryCollector::collectEnvironmentMetrics(TelemetrySample *sample_out) const
{
    static_cast<void>(sample_out);
    return false;
}
