#ifndef CAMPER_TELEMETRY_TYPES_HPP
#define CAMPER_TELEMETRY_TYPES_HPP

#include <array>
#include <cstddef>
#include <cstdint>

struct TelemetrySample {
    uint64_t sample_uptime_ms;
    bool has_camper_battery_soc_pct;
    float camper_battery_soc_pct;
    bool has_camper_battery_current_a;
    float camper_battery_current_a;
    bool has_monitor_battery_pct;
    float monitor_battery_pct;
    bool has_temperature_c;
    float temperature_c;
    bool has_humidity_pct;
    float humidity_pct;

    bool hasAnyMetrics() const
    {
        return has_camper_battery_soc_pct || has_camper_battery_current_a || has_monitor_battery_pct || has_temperature_c ||
               has_humidity_pct;
    }
};

struct TelemetryBatch {
    static constexpr size_t kMaxSamples = 32;

    std::array<TelemetrySample, kMaxSamples> samples;
    size_t count;
    uint32_t generation;
};

#endif
