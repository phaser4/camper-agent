#ifndef CAMPER_TELEMETRY_COLLECTOR_HPP
#define CAMPER_TELEMETRY_COLLECTOR_HPP

#include "BluetoothScanner.hpp"
#include "TelemetryQueue.hpp"

class TelemetryCollector {
  public:
    TelemetryCollector(BluetoothScanner &bluetooth_scanner, TelemetryQueue &telemetry_queue);

    /* Collects whichever telemetry sources are currently available and enqueues one partial sample. */
    void collectOnce() const;

  private:
    static constexpr const char *kTag = "telemetry_collector";

    BluetoothScanner &bluetooth_scanner_;
    TelemetryQueue &telemetry_queue_;

    /* Reads the latest Victron battery-monitor values from the scanner snapshot. */
    bool collectVictronMetrics(TelemetrySample *sample_out) const;

    /* Placeholder for the future backup-battery fuel-gauge integration. */
    bool collectMonitorBatteryMetrics(TelemetrySample *sample_out) const;

    /* Placeholder for the future temperature and humidity sensor integration. */
    bool collectEnvironmentMetrics(TelemetrySample *sample_out) const;
};

#endif
