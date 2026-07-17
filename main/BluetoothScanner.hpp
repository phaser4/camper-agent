#ifndef CAMPER_BLUETOOTH_SCANNER_HPP
#define CAMPER_BLUETOOTH_SCANNER_HPP

#include <cstddef>
#include <cstdint>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "host/ble_gap.h"
#include "host/ble_hs_adv.h"
#include "host/ble_hs.h"

class BluetoothScanner {
  public:
    struct VictronTelemetrySnapshot {
        bool available;
        uint64_t sample_uptime_ms;
        bool has_voltage;
        float voltage_v;
        bool has_current;
        float current_a;
        bool has_soc;
        float soc_pct;
    };

    /* Constructs the scanner object and prepares instance state. */
    BluetoothScanner();

    /* Configures NimBLE and starts passive BLE scanning. */
    void start();

    /* Copies the latest successfully decoded Victron telemetry snapshot, when available. */
    bool getLatestVictronTelemetry(VictronTelemetrySnapshot *snapshot_out) const;

  private:
    static constexpr const char *kTag = "camper_ble";
    static constexpr size_t kMaxCachedNameLen = 64;
    static constexpr uint8_t kMaxCachedPayloadLen = 31;
    static BluetoothScanner *active_instance_;

    struct TargetObservation {
        bool seen;
        bool ever_victron;
        int8_t last_rssi;
        uint8_t last_event_type;
        char best_name[kMaxCachedNameLen];
        uint8_t last_payload_len;
        uint8_t last_payload[kMaxCachedPayloadLen];
        uint8_t last_name_payload_len;
        uint8_t last_name_payload[kMaxCachedPayloadLen];
        int8_t last_mfg_rssi;
        uint8_t last_mfg_event_type;
        uint8_t last_mfg_payload_len;
        uint8_t last_mfg_payload[kMaxCachedPayloadLen];
        uint8_t last_mfg_data_len;
        uint8_t last_mfg_data[kMaxCachedPayloadLen];
    };

    TargetObservation target_observation_;
    bool indicator_task_running_;
    bool target_dump_task_running_;
    bool search_timeout_task_running_;
    bool target_found_;
    bool scan_active_;
    bool search_timeout_reached_;
    bool target_addr_configured_;
    bool victron_key_configured_;
    ble_addr_t target_addr_;
    uint8_t victron_key_[16];
    mutable StaticSemaphore_t telemetry_mutex_buffer_;
    mutable SemaphoreHandle_t telemetry_mutex_;
    VictronTelemetrySnapshot latest_victron_telemetry_;

    /* Formats a NimBLE address into a human-readable MAC string. */
    static void formatBleAddr(const ble_addr_t *addr, char *buffer, size_t buffer_len);

    /* Converts a byte array into a compact uppercase hex string for logging. */
    static void bytesToHex(const uint8_t *data, uint8_t len, char *buffer, size_t buffer_len);

    /* Compares two BLE addresses so configured targets can be recognized. */
    static bool sameBleAddr(const ble_addr_t *lhs, const ble_addr_t *rhs);

    /* Converts a single hexadecimal character into its numeric value. */
    static bool parseHexNibble(char ch, uint8_t *value_out);

    /* Converts two hexadecimal characters into a single byte. */
    static bool parseHexByte(const char *text, uint8_t *value_out);

    /* Parses the configured BLE MAC address string into NimBLE byte order. */
    static bool parseBleAddrString(const char *text, ble_addr_t *addr_out);

    /* Parses a configured hexadecimal key string into raw bytes. */
    static bool parseHexKeyString(const char *text, uint8_t *out, size_t out_len);

    /* Copies an advertised device name into a printable buffer when present. */
    static void extractDeviceName(const struct ble_hs_adv_fields *fields, char *buffer, size_t buffer_len);

    /* Finds a case-insensitive substring within a null-terminated string. */
    static bool containsIgnoreCase(const char *text, const char *needle);

    /* Loads the configured target address and Victron key from local ESP-IDF settings. */
    bool loadConfig();

    /* Checks whether a BLE address matches the configured Victron target. */
    bool isTargetDevice(const ble_addr_t *addr) const;

    /* Configures the onboard user LED GPIO used for scan feedback. */
    void configureIndicatorLed();

    /* Starts the search LED task so the board blinks until the target device is found. */
    void triggerVictronIndicator();

    /* Starts the periodic target-dump task used for unplugged field testing. */
    void startTargetDumpTask();

    /* Starts the one-shot timeout task that ends an unsuccessful search window. */
    void startSearchTimeoutTask();

    /* Merges the latest advertisement details into the dedicated target record. */
    void updateTargetObservation(
        const struct ble_gap_disc_desc *disc,
        const struct ble_hs_adv_fields *fields,
        bool is_victron);

    /* Logs the current contents of the dedicated target record so they survive USB disconnects. */
    void dumpTargetObservation() const;

    /* Logs a structured breakdown of the most recent target manufacturer packet. */
    void logTargetManufacturerBreakdown() const;

    /* Logs a conservative parsed view of the Victron target packet fields. */
    void logTargetParsedFrame() const;

    /* Stores the latest successfully decoded Victron battery-monitor telemetry for other classes. */
    void storeLatestVictronTelemetry(float voltage_v, bool has_voltage, float current_a, bool has_current, float soc_pct, bool has_soc);

    /* Logs the discovered advertisement address, RSSI, and payload details. */
    void logDiscovery(const struct ble_gap_disc_desc *disc, const struct ble_hs_adv_fields *fields) const;

    /* Decides whether a target discovery report should be logged based on payload changes. */
    bool shouldLogTargetDiscovery(const struct ble_gap_disc_desc *disc) const;

    /* Identifies advertisements that are likely to come from a Victron device. */
    bool isVictronCandidate(const struct ble_hs_adv_fields *fields) const;

    /* Starts passive BLE scanning with continuous discovery callbacks. */
    void startScan();

    /* Handles BLE discovery events and restarts scanning if the procedure ends. */
    int handleGapEvent(struct ble_gap_event *event);

    /* Logs BLE controller reset events for troubleshooting. */
    void handleReset(int reason) const;

    /* Finalizes BLE address setup and begins scanning once the host syncs. */
    void handleSync();

    /* Runs the NimBLE host loop on the FreeRTOS task created by the port layer. */
    static void hostTask(void *param);

    /* Bridges NimBLE discovery callbacks into the active scanner instance. */
    static int gapEventHandler(struct ble_gap_event *event, void *arg);

    /* Bridges NimBLE reset callbacks into the active scanner instance. */
    static void onReset(int reason);

    /* Bridges NimBLE sync callbacks into the active scanner instance. */
    static void onSync();

    /* Runs the onboard LED blink pattern on a short-lived FreeRTOS task. */
    static void indicatorTask(void *param);

    /* Periodically prints the dedicated target record while scanning continues. */
    static void targetDumpTask(void *param);

    /* Cancels BLE scanning if the target was not found within the search timeout window. */
    static void searchTimeoutTask(void *param);
};

#endif
