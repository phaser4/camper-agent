#include "BluetoothScanner.hpp"

#include <cctype>
#include <cstdio>
#include <cstring>

#include "aes/esp_aes.h"
#include "driver/gpio.h"
#include "esp_err.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/util/util.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

namespace {
constexpr gpio_num_t kIndicatorLedGpio = GPIO_NUM_15;
constexpr uint32_t kIndicatorBlinkStepMs = 250;
constexpr uint32_t kCacheDumpIntervalMs = 120000;
constexpr uint32_t kVictronSearchTimeoutMs = 120000;
constexpr uint16_t kVictronCompanyId = 0x02E1;
constexpr uint16_t kVictronInstantReadoutPrefix = 0x0210;
constexpr uint8_t kVictronBatteryMonitorReadoutType = 0x02;
constexpr size_t kVictronAesBlockSize = 16;
constexpr size_t kVictronMaxDecryptedLen = 32;

struct VictronAdvertisementFrame {
    uint16_t prefix;
    uint16_t model_id;
    uint8_t readout_type;
    uint16_t iv;
    const uint8_t *encrypted_data;
    size_t encrypted_len;
};

struct VictronBatteryMonitorTelemetry {
    uint16_t model_id;
    uint8_t readout_type;
    uint16_t iv;
    uint16_t alarm_reason;
    uint8_t aux_mode;
    bool has_remaining_mins;
    uint16_t remaining_mins;
    bool has_voltage;
    float voltage_v;
    bool has_current;
    float current_a;
    bool has_consumed_ah;
    float consumed_ah;
    bool has_soc;
    float soc_pct;
    bool has_temperature;
    float temperature_c;
    bool has_starter_voltage;
    float starter_voltage_v;
    bool has_midpoint_voltage;
    float midpoint_voltage_v;
};

enum class VictronDecryptResult {
    kOk,
    kKeyMismatch,
    kFrameTooShort,
    kBufferTooSmall,
    kAesError,
};

/* Reads a little-endian 16-bit integer from a byte buffer. */
uint16_t readLe16(const uint8_t *data)
{
    return static_cast<uint16_t>(data[0]) | (static_cast<uint16_t>(data[1]) << 8);
}

/* Sign-extends an unsigned bitfield into a signed 32-bit integer. */
int32_t signExtend(uint32_t value, uint8_t num_bits)
{
    const uint32_t sign_bit = 1UL << (num_bits - 1);

    return (value & sign_bit) != 0 ? static_cast<int32_t>(value - (1UL << num_bits)) : static_cast<int32_t>(value);
}

/* Interprets packed Victron bitfields from least-significant bit to most-significant bit. */
class VictronBitReader {
  public:
    /* Constructs a bit reader over a decrypted Victron payload. */
    explicit VictronBitReader(const uint8_t *data)
        : data_(data),
          bit_index_(0)
    {
    }

    /* Reads a single packed bit and advances the cursor. */
    uint32_t readBit()
    {
        const uint32_t bit = (data_[bit_index_ >> 3] >> (bit_index_ & 7U)) & 0x01U;

        ++bit_index_;
        return bit;
    }

    /* Reads an unsigned integer composed of the requested number of bits. */
    uint32_t readUnsignedInt(uint8_t num_bits)
    {
        uint32_t value = 0;

        for (uint8_t position = 0; position < num_bits; ++position) {
            value |= readBit() << position;
        }

        return value;
    }

    /* Reads a signed integer composed of the requested number of bits. */
    int32_t readSignedInt(uint8_t num_bits)
    {
        return signExtend(readUnsignedInt(num_bits), num_bits);
    }

  private:
    const uint8_t *data_;
    size_t bit_index_;
};

/* Parses the Victron Instant Readout framing that follows the company identifier bytes. */
bool parseVictronAdvertisementFrame(const uint8_t *data, size_t len, VictronAdvertisementFrame *frame_out)
{
    if (data == nullptr || frame_out == nullptr || len < 7) {
        return false;
    }

    frame_out->prefix = readLe16(data);
    frame_out->model_id = readLe16(data + 2);
    frame_out->readout_type = data[4];
    frame_out->iv = readLe16(data + 5);
    frame_out->encrypted_data = data + 7;
    frame_out->encrypted_len = len - 7;
    return true;
}

/* Builds one AES-CTR counter block using Victron's little-endian counter layout. */
void buildVictronCounterBlock(uint16_t iv, size_t block_index, uint8_t *counter_block)
{
    uint32_t counter_value = static_cast<uint32_t>(iv) + static_cast<uint32_t>(block_index);

    std::memset(counter_block, 0, kVictronAesBlockSize);
    counter_block[0] = static_cast<uint8_t>(counter_value & 0xFFU);
    counter_block[1] = static_cast<uint8_t>((counter_value >> 8) & 0xFFU);
    counter_block[2] = static_cast<uint8_t>((counter_value >> 16) & 0xFFU);
    counter_block[3] = static_cast<uint8_t>((counter_value >> 24) & 0xFFU);
}

/* Decrypts a Victron advertisement payload using the configured Instant Readout key. */
VictronDecryptResult decryptVictronPayload(
    const VictronAdvertisementFrame &frame,
    const uint8_t key[16],
    uint8_t *decrypted_out,
    size_t decrypted_capacity,
    size_t *decrypted_len_out)
{
    uint8_t padded_cipher[kVictronMaxDecryptedLen];
    uint8_t counter_block[kVictronAesBlockSize];
    uint8_t keystream[kVictronAesBlockSize];
    esp_aes_context aes_context;
    size_t cipher_len;
    size_t padded_len;
    size_t pad_len;
    int aes_result;

    if (frame.encrypted_len == 0) {
        return VictronDecryptResult::kFrameTooShort;
    }

    if (frame.encrypted_data[0] != key[0]) {
        return VictronDecryptResult::kKeyMismatch;
    }

    cipher_len = frame.encrypted_len - 1;
    pad_len = kVictronAesBlockSize - (cipher_len % kVictronAesBlockSize);
    if (pad_len == 0) {
        pad_len = kVictronAesBlockSize;
    }

    padded_len = cipher_len + pad_len;
    if (padded_len > sizeof(padded_cipher) || padded_len > decrypted_capacity) {
        return VictronDecryptResult::kBufferTooSmall;
    }

    std::memcpy(padded_cipher, frame.encrypted_data + 1, cipher_len);
    std::memset(padded_cipher + cipher_len, static_cast<int>(pad_len), pad_len);

    esp_aes_init(&aes_context);
    aes_result = esp_aes_setkey(&aes_context, key, 128);
    if (aes_result != 0) {
        esp_aes_free(&aes_context);
        return VictronDecryptResult::kAesError;
    }

    for (size_t block_index = 0; block_index < (padded_len / kVictronAesBlockSize); ++block_index) {
        buildVictronCounterBlock(frame.iv, block_index, counter_block);
        aes_result = esp_aes_crypt_ecb(&aes_context, ESP_AES_ENCRYPT, counter_block, keystream);
        if (aes_result != 0) {
            esp_aes_free(&aes_context);
            return VictronDecryptResult::kAesError;
        }

        for (size_t byte_index = 0; byte_index < kVictronAesBlockSize; ++byte_index) {
            const size_t output_index = (block_index * kVictronAesBlockSize) + byte_index;

            decrypted_out[output_index] = static_cast<uint8_t>(padded_cipher[output_index] ^ keystream[byte_index]);
        }
    }

    esp_aes_free(&aes_context);
    *decrypted_len_out = padded_len;
    return VictronDecryptResult::kOk;
}

/* Returns a human-readable Victron battery-monitor model name for common devices. */
const char *batteryMonitorModelName(uint16_t model_id)
{
    switch (model_id) {
    case 0xA380:
        return "BMV-710 Smart";
    case 0xA381:
        return "BMV-712 Smart";
    case 0xA382:
        return "BMV-710H Smart";
    case 0xA383:
        return "BMV-712 Smart";
    case 0xA389:
        return "SmartShunt 500A/50mV";
    case 0xA38A:
        return "SmartShunt 1000A/50mV";
    case 0xA38B:
        return "SmartShunt 2000A/50mV";
    case 0xA38C:
        return "SmartShunt IP67 500A/50mV";
    case 0xA38D:
        return "SmartShunt IP67 1000A/50mV";
    case 0xA38E:
        return "SmartShunt IP67 2000A/50mV";
    default:
        return "unknown battery monitor";
    }
}

/* Returns a short human-readable label for the Victron auxiliary input mode. */
const char *batteryAuxModeName(uint8_t aux_mode)
{
    switch (aux_mode) {
    case 0:
        return "starter_voltage";
    case 1:
        return "midpoint_voltage";
    case 2:
        return "temperature";
    case 3:
        return "disabled";
    default:
        return "unknown";
    }
}

/* Decodes a decrypted Victron battery-monitor payload into engineering values. */
bool parseVictronBatteryMonitorTelemetry(
    const VictronAdvertisementFrame &frame,
    const uint8_t *decrypted,
    size_t decrypted_len,
    VictronBatteryMonitorTelemetry *telemetry_out)
{
    uint32_t remaining_raw;
    uint32_t voltage_raw_unsigned;
    int32_t voltage_raw_signed;
    uint32_t alarm_raw;
    uint32_t aux_raw;
    uint32_t aux_mode_raw;
    uint32_t current_raw_unsigned;
    int32_t current_raw_signed;
    uint32_t consumed_raw;
    uint32_t soc_raw;

    if (telemetry_out == nullptr || decrypted == nullptr || decrypted_len < 16 ||
        frame.readout_type != kVictronBatteryMonitorReadoutType) {
        return false;
    }

    VictronBitReader reader(decrypted);
    remaining_raw = reader.readUnsignedInt(16);
    voltage_raw_unsigned = reader.readUnsignedInt(16);
    voltage_raw_signed = signExtend(voltage_raw_unsigned, 16);
    alarm_raw = reader.readUnsignedInt(16);
    aux_raw = reader.readUnsignedInt(16);
    aux_mode_raw = reader.readUnsignedInt(2);
    current_raw_unsigned = reader.readUnsignedInt(22);
    current_raw_signed = signExtend(current_raw_unsigned, 22);
    consumed_raw = reader.readUnsignedInt(20);
    soc_raw = reader.readUnsignedInt(10);

    telemetry_out->model_id = frame.model_id;
    telemetry_out->readout_type = frame.readout_type;
    telemetry_out->iv = frame.iv;
    telemetry_out->alarm_reason = static_cast<uint16_t>(alarm_raw);
    telemetry_out->aux_mode = static_cast<uint8_t>(aux_mode_raw);
    telemetry_out->has_remaining_mins = remaining_raw != 0xFFFFU;
    telemetry_out->remaining_mins = static_cast<uint16_t>(remaining_raw);
    telemetry_out->has_voltage = voltage_raw_unsigned != 0x7FFFU;
    telemetry_out->voltage_v = static_cast<float>(voltage_raw_signed) / 100.0f;
    telemetry_out->has_current = current_raw_unsigned != 0x3FFFFFU;
    telemetry_out->current_a = static_cast<float>(current_raw_signed) / 1000.0f;
    telemetry_out->has_consumed_ah = consumed_raw != 0xFFFFFU;
    telemetry_out->consumed_ah = -static_cast<float>(consumed_raw) / 10.0f;
    telemetry_out->has_soc = soc_raw != 0x3FFU;
    telemetry_out->soc_pct = static_cast<float>(soc_raw) / 10.0f;
    telemetry_out->has_temperature = false;
    telemetry_out->temperature_c = 0.0f;
    telemetry_out->has_starter_voltage = false;
    telemetry_out->starter_voltage_v = 0.0f;
    telemetry_out->has_midpoint_voltage = false;
    telemetry_out->midpoint_voltage_v = 0.0f;

    switch (telemetry_out->aux_mode) {
    case 0:
        telemetry_out->has_starter_voltage = true;
        telemetry_out->starter_voltage_v = static_cast<float>(signExtend(aux_raw, 16)) / 100.0f;
        break;
    case 1:
        telemetry_out->has_midpoint_voltage = true;
        telemetry_out->midpoint_voltage_v = static_cast<float>(aux_raw) / 100.0f;
        break;
    case 2:
        telemetry_out->has_temperature = true;
        telemetry_out->temperature_c = (static_cast<float>(aux_raw) / 100.0f) - 273.15f;
        break;
    default:
        break;
    }

    return true;
}
}

BluetoothScanner *BluetoothScanner::active_instance_ = nullptr;

/* Constructs the scanner object and prepares instance state. */
BluetoothScanner::BluetoothScanner()
    : target_observation_{},
      indicator_task_running_(false),
      target_dump_task_running_(false),
      search_timeout_task_running_(false),
      target_found_(false),
      scan_active_(false),
      search_timeout_reached_(false),
      target_addr_configured_(false),
      victron_key_configured_(false),
      target_addr_{},
      victron_key_{},
      telemetry_mutex_buffer_{},
      telemetry_mutex_(xSemaphoreCreateMutexStatic(&telemetry_mutex_buffer_)),
      latest_victron_telemetry_{}
{
    active_instance_ = this;
    latest_victron_telemetry_.available = false;
    latest_victron_telemetry_.sample_uptime_ms = 0;
    latest_victron_telemetry_.has_voltage = false;
    latest_victron_telemetry_.voltage_v = 0.0f;
    latest_victron_telemetry_.has_current = false;
    latest_victron_telemetry_.current_a = 0.0f;
    latest_victron_telemetry_.has_soc = false;
    latest_victron_telemetry_.soc_pct = 0.0f;
}

/* Configures NimBLE and starts passive BLE scanning. */
void BluetoothScanner::start()
{
    int rc;
    char addr_buffer[18];

    if (!loadConfig()) {
        return;
    }

    formatBleAddr(&target_addr_, addr_buffer, sizeof(addr_buffer));
    ESP_LOGI(kTag, "tracking configured Victron device %s", addr_buffer);
    ESP_LOGI(kTag, "Victron key configured=%s", victron_key_configured_ ? "yes" : "no");

    configureIndicatorLed();
    triggerVictronIndicator();
    startTargetDumpTask();
    startSearchTimeoutTask();

    nimble_port_init();

    ble_hs_cfg.reset_cb = onReset;
    ble_hs_cfg.sync_cb = onSync;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

    ble_svc_gap_init();
    ble_svc_gatt_init();

    rc = ble_svc_gap_device_name_set("camper-ble-scanner");
    if (rc != 0) {
        ESP_LOGE(kTag, "failed to set device name rc=%d", rc);
        return;
    }

    nimble_port_freertos_init(hostTask);
}

bool BluetoothScanner::getLatestVictronTelemetry(VictronTelemetrySnapshot *snapshot_out) const
{
    bool available;

    if (snapshot_out == nullptr) {
        return false;
    }

    if (telemetry_mutex_ == nullptr) {
        return false;
    }

    if (xSemaphoreTake(telemetry_mutex_, portMAX_DELAY) != pdTRUE) {
        return false;
    }

    *snapshot_out = latest_victron_telemetry_;
    available = latest_victron_telemetry_.available;

    xSemaphoreGive(telemetry_mutex_);
    return available;
}

/* Formats a NimBLE address into a human-readable MAC string. */
void BluetoothScanner::formatBleAddr(const ble_addr_t *addr, char *buffer, size_t buffer_len)
{
    snprintf(
        buffer,
        buffer_len,
        "%02X:%02X:%02X:%02X:%02X:%02X",
        addr->val[5],
        addr->val[4],
        addr->val[3],
        addr->val[2],
        addr->val[1],
        addr->val[0]);
}

/* Converts a byte array into a compact uppercase hex string for logging. */
void BluetoothScanner::bytesToHex(const uint8_t *data, uint8_t len, char *buffer, size_t buffer_len)
{
    size_t offset = 0;

    if (buffer_len == 0) {
        return;
    }

    for (size_t index = 0; index < len && (offset + 2) < buffer_len; ++index) {
        int written = snprintf(buffer + offset, buffer_len - offset, "%02X", data[index]);
        if (written < 0) {
            break;
        }
        offset += static_cast<size_t>(written);
    }

    buffer[offset] = '\0';
}

/* Compares two BLE addresses so cached devices can be recognized. */
bool BluetoothScanner::sameBleAddr(const ble_addr_t *lhs, const ble_addr_t *rhs)
{
    return std::memcmp(lhs->val, rhs->val, sizeof(lhs->val)) == 0;
}

/* Converts a single hexadecimal character into its numeric value. */
bool BluetoothScanner::parseHexNibble(char ch, uint8_t *value_out)
{
    if (ch >= '0' && ch <= '9') {
        *value_out = static_cast<uint8_t>(ch - '0');
        return true;
    }

    if (ch >= 'a' && ch <= 'f') {
        *value_out = static_cast<uint8_t>(10 + (ch - 'a'));
        return true;
    }

    if (ch >= 'A' && ch <= 'F') {
        *value_out = static_cast<uint8_t>(10 + (ch - 'A'));
        return true;
    }

    return false;
}

/* Converts two hexadecimal characters into a single byte. */
bool BluetoothScanner::parseHexByte(const char *text, uint8_t *value_out)
{
    uint8_t high_nibble;
    uint8_t low_nibble;

    if (!parseHexNibble(text[0], &high_nibble) || !parseHexNibble(text[1], &low_nibble)) {
        return false;
    }

    *value_out = static_cast<uint8_t>((high_nibble << 4) | low_nibble);
    return true;
}

/* Parses the configured BLE MAC address string into NimBLE byte order. */
bool BluetoothScanner::parseBleAddrString(const char *text, ble_addr_t *addr_out)
{
    char hex_digits[12];
    size_t hex_count = 0;

    if (text == nullptr || addr_out == nullptr) {
        return false;
    }

    for (size_t index = 0; text[index] != '\0'; ++index) {
        char ch = text[index];

        if (std::isxdigit(static_cast<unsigned char>(ch)) != 0) {
            if (hex_count >= sizeof(hex_digits)) {
                return false;
            }

            hex_digits[hex_count++] = ch;
            continue;
        }

        if (ch == ':' || ch == '-' || ch == ' ') {
            continue;
        }

        return false;
    }

    if (hex_count != sizeof(hex_digits)) {
        return false;
    }

    std::memset(addr_out, 0, sizeof(*addr_out));
    for (size_t index = 0; index < 6; ++index) {
        uint8_t parsed_byte;

        if (!parseHexByte(&hex_digits[index * 2], &parsed_byte)) {
            return false;
        }

        addr_out->val[5 - index] = parsed_byte;
    }

    return true;
}

/* Parses a configured hexadecimal key string into raw bytes. */
bool BluetoothScanner::parseHexKeyString(const char *text, uint8_t *out, size_t out_len)
{
    size_t hex_count = 0;

    if (text == nullptr || out == nullptr || out_len == 0) {
        return false;
    }

    std::memset(out, 0, out_len);

    for (size_t index = 0; text[index] != '\0'; ++index) {
        char ch = text[index];

        if (std::isxdigit(static_cast<unsigned char>(ch)) != 0) {
            if ((hex_count / 2) >= out_len) {
                return false;
            }

            if ((hex_count & 1U) == 0U) {
                uint8_t nibble;

                if (!parseHexNibble(ch, &nibble)) {
                    return false;
                }

                out[hex_count / 2] = static_cast<uint8_t>(nibble << 4);
            } else {
                uint8_t nibble;

                if (!parseHexNibble(ch, &nibble)) {
                    return false;
                }

                out[hex_count / 2] = static_cast<uint8_t>(out[hex_count / 2] | nibble);
            }

            ++hex_count;
            continue;
        }

        if (ch == ' ' || ch == ':' || ch == '-') {
            continue;
        }

        return false;
    }

    return hex_count == (out_len * 2);
}

/* Copies an advertised device name into a printable buffer when present. */
void BluetoothScanner::extractDeviceName(const struct ble_hs_adv_fields *fields, char *buffer, size_t buffer_len)
{
    size_t name_len;

    if (buffer_len == 0) {
        return;
    }

    if (fields->name == nullptr || fields->name_len == 0) {
        buffer[0] = '\0';
        return;
    }

    name_len = fields->name_len;
    if (name_len >= buffer_len) {
        name_len = buffer_len - 1;
    }

    std::memcpy(buffer, fields->name, name_len);
    buffer[name_len] = '\0';
}

/* Finds a case-insensitive substring within a null-terminated string. */
bool BluetoothScanner::containsIgnoreCase(const char *text, const char *needle)
{
    size_t needle_len;

    if (text == nullptr || needle == nullptr) {
        return false;
    }

    needle_len = std::strlen(needle);
    if (needle_len == 0) {
        return true;
    }

    for (size_t start = 0; text[start] != '\0'; ++start) {
        size_t offset = 0;
        while (needle[offset] != '\0' && text[start + offset] != '\0') {
            unsigned char text_char = static_cast<unsigned char>(text[start + offset]);
            unsigned char needle_char = static_cast<unsigned char>(needle[offset]);

            if (std::tolower(text_char) != std::tolower(needle_char)) {
                break;
            }

            ++offset;
        }

        if (offset == needle_len) {
            return true;
        }
    }

    return false;
}

/* Loads the configured target address and Victron key from local ESP-IDF settings. */
bool BluetoothScanner::loadConfig()
{
    const char *target_addr_text = CONFIG_CAMPER_VICTRON_TARGET_ADDR;
    const char *victron_key_text = CONFIG_CAMPER_VICTRON_KEY_HEX;

    target_addr_configured_ = false;
    victron_key_configured_ = false;

    if (target_addr_text == nullptr || target_addr_text[0] == '\0') {
        ESP_LOGE(kTag, "CONFIG_CAMPER_VICTRON_TARGET_ADDR is empty");
        return false;
    }

    if (!parseBleAddrString(target_addr_text, &target_addr_)) {
        ESP_LOGE(kTag, "invalid CONFIG_CAMPER_VICTRON_TARGET_ADDR format");
        return false;
    }

    target_addr_configured_ = true;

    if (victron_key_text == nullptr || victron_key_text[0] == '\0') {
        ESP_LOGW(kTag, "CONFIG_CAMPER_VICTRON_KEY_HEX is empty; decryption is not ready yet");
        return true;
    }

    if (!parseHexKeyString(victron_key_text, victron_key_, sizeof(victron_key_))) {
        ESP_LOGE(kTag, "invalid CONFIG_CAMPER_VICTRON_KEY_HEX format");
        return false;
    }

    victron_key_configured_ = true;
    return true;
}

/* Checks whether a BLE address matches the configured Victron target. */
bool BluetoothScanner::isTargetDevice(const ble_addr_t *addr) const
{
    return target_addr_configured_ && sameBleAddr(addr, &target_addr_);
}

/* Configures the onboard user LED GPIO used for scan feedback. */
void BluetoothScanner::configureIndicatorLed()
{
    gpio_reset_pin(kIndicatorLedGpio);
    gpio_set_direction(kIndicatorLedGpio, GPIO_MODE_INPUT);
}

/* Starts the search LED task so the board blinks until the target device is found. */
void BluetoothScanner::triggerVictronIndicator()
{
    BaseType_t task_created;

    if (indicator_task_running_) {
        return;
    }

    indicator_task_running_ = true;
    task_created = xTaskCreate(
        indicatorTask,
        "victron_led",
        2048,
        this,
        tskIDLE_PRIORITY + 1,
        nullptr);

    if (task_created != pdPASS) {
        indicator_task_running_ = false;
        ESP_LOGW(kTag, "failed to start indicator task");
    }
}

/* Starts the one-shot timeout task that ends an unsuccessful search window. */
void BluetoothScanner::startSearchTimeoutTask()
{
    BaseType_t task_created;

    if (search_timeout_task_running_) {
        return;
    }

    search_timeout_task_running_ = true;
    task_created = xTaskCreate(
        searchTimeoutTask,
        "victron_timeout",
        2048,
        this,
        tskIDLE_PRIORITY + 1,
        nullptr);

    if (task_created != pdPASS) {
        search_timeout_task_running_ = false;
        ESP_LOGW(kTag, "failed to start BLE search-timeout task");
    }
}

/* Starts the periodic target-dump task used for unplugged field testing. */
void BluetoothScanner::startTargetDumpTask()
{
    BaseType_t task_created;

    if (target_dump_task_running_) {
        return;
    }

    target_dump_task_running_ = true;
    task_created = xTaskCreate(
        targetDumpTask,
        "ble_target_dump",
        4096,
        this,
        tskIDLE_PRIORITY + 1,
        nullptr);

    if (task_created != pdPASS) {
        target_dump_task_running_ = false;
        ESP_LOGW(kTag, "failed to start target dump task");
    }
}

/* Merges the latest advertisement details into the dedicated target record. */
void BluetoothScanner::updateTargetObservation(
    const struct ble_gap_disc_desc *disc,
    const struct ble_hs_adv_fields *fields,
    bool is_victron)
{
    char name_buffer[kMaxCachedNameLen];
    uint8_t stored_len;

    stored_len = disc->length_data;
    if (stored_len > kMaxCachedPayloadLen) {
        stored_len = kMaxCachedPayloadLen;
    }

    target_observation_.seen = true;
    target_observation_.last_rssi = disc->rssi;
    target_observation_.last_event_type = disc->event_type;
    target_observation_.ever_victron = target_observation_.ever_victron || is_victron;

    extractDeviceName(fields, name_buffer, sizeof(name_buffer));
    if (name_buffer[0] != '\0' && std::strlen(name_buffer) >= std::strlen(target_observation_.best_name)) {
        std::snprintf(target_observation_.best_name, sizeof(target_observation_.best_name), "%s", name_buffer);
        target_observation_.last_name_payload_len = stored_len;
        std::memcpy(target_observation_.last_name_payload, disc->data, stored_len);
    }

    if (fields->mfg_data_len > 0) {
        target_observation_.last_mfg_rssi = disc->rssi;
        target_observation_.last_mfg_event_type = disc->event_type;
        target_observation_.last_mfg_payload_len = stored_len;
        std::memcpy(target_observation_.last_mfg_payload, disc->data, stored_len);
        target_observation_.last_mfg_data_len = fields->mfg_data_len;
        if (target_observation_.last_mfg_data_len > kMaxCachedPayloadLen) {
            target_observation_.last_mfg_data_len = kMaxCachedPayloadLen;
        }
        std::memcpy(target_observation_.last_mfg_data, fields->mfg_data, target_observation_.last_mfg_data_len);
    }

    target_observation_.last_payload_len = stored_len;
    std::memcpy(target_observation_.last_payload, disc->data, stored_len);
}

/* Logs the current contents of the dedicated target record so they survive USB disconnects. */
void BluetoothScanner::dumpTargetObservation() const
{
    char addr_buffer[18];
    char mfg_hex[256];

    formatBleAddr(&target_addr_, addr_buffer, sizeof(addr_buffer));

    if (!target_observation_.seen) {
        ESP_LOGI(kTag, "target dump addr=%s seen=no", addr_buffer);
        ESP_LOGI(kTag, "target dump complete target_found=%s", target_found_ ? "yes" : "no");
        return;
    }

    if (target_observation_.last_mfg_data_len > 0) {
        bytesToHex(target_observation_.last_mfg_data, target_observation_.last_mfg_data_len, mfg_hex, sizeof(mfg_hex));
    } else {
        std::snprintf(mfg_hex, sizeof(mfg_hex), "-");
    }

    if (target_observation_.best_name[0] != '\0') {
        ESP_LOGI(
            kTag,
            "target addr=%s seen=yes target_found=%s ever_victron=%s rssi=%d event_type=%u name=%s last_mfg_len=%u mfg=%s",
            addr_buffer,
            target_found_ ? "yes" : "no",
            target_observation_.ever_victron ? "yes" : "no",
            target_observation_.last_rssi,
            target_observation_.last_event_type,
            target_observation_.best_name,
            target_observation_.last_mfg_data_len,
            mfg_hex);
    } else {
        ESP_LOGI(
            kTag,
            "target addr=%s seen=yes target_found=%s ever_victron=%s rssi=%d event_type=%u last_mfg_len=%u mfg=%s",
            addr_buffer,
            target_found_ ? "yes" : "no",
            target_observation_.ever_victron ? "yes" : "no",
            target_observation_.last_rssi,
            target_observation_.last_event_type,
            target_observation_.last_mfg_data_len,
            mfg_hex);
    }

    ESP_LOGI(kTag, "target dump complete target_found=%s", target_found_ ? "yes" : "no");
    logTargetManufacturerBreakdown();
}

/* Logs a structured breakdown of the most recent target manufacturer packet. */
void BluetoothScanner::logTargetManufacturerBreakdown() const
{
    char mfg_hex[256];
    char body_hex[256];
    uint16_t company_id;

    if (!target_observation_.seen || target_observation_.last_mfg_data_len < 2) {
        ESP_LOGI(kTag, "target mfg breakdown unavailable");
        return;
    }

    company_id = static_cast<uint16_t>(target_observation_.last_mfg_data[0]) |
                 (static_cast<uint16_t>(target_observation_.last_mfg_data[1]) << 8);

    bytesToHex(target_observation_.last_mfg_data, target_observation_.last_mfg_data_len, mfg_hex, sizeof(mfg_hex));

    if (target_observation_.last_mfg_data_len > 2) {
        bytesToHex(
            target_observation_.last_mfg_data + 2,
            static_cast<uint8_t>(target_observation_.last_mfg_data_len - 2),
            body_hex,
            sizeof(body_hex));
    } else {
        body_hex[0] = '\0';
    }

    ESP_LOGI(
        kTag,
        "target mfg breakdown company_id=0x%04X mfg_len=%u mfg=%s",
        company_id,
        target_observation_.last_mfg_data_len,
        mfg_hex);

    if (target_observation_.last_mfg_data_len >= 4) {
        ESP_LOGI(
            kTag,
            "target mfg breakdown type=0x%02X subtype=0x%02X body=%s",
            target_observation_.last_mfg_data[2],
            target_observation_.last_mfg_data[3],
            body_hex);
    } else if (target_observation_.last_mfg_data_len == 3) {
        ESP_LOGI(
            kTag,
            "target mfg breakdown type=0x%02X body=%s",
            target_observation_.last_mfg_data[2],
            body_hex);
    }

    ESP_LOGI(
        kTag,
        "target mfg packet rssi=%d event_type=%u",
        target_observation_.last_mfg_rssi,
        target_observation_.last_mfg_event_type);

    logTargetParsedFrame();
}

/* Logs a conservative parsed view of the Victron target packet fields. */
void BluetoothScanner::logTargetParsedFrame() const
{
    VictronAdvertisementFrame frame;
    VictronBatteryMonitorTelemetry telemetry;
    char tail_hex[256];
    char decrypted_hex[256];
    char voltage_buffer[32];
    char current_buffer[32];
    char soc_buffer[32];
    char consumed_buffer[32];
    char remaining_buffer[32];
    uint8_t decrypted[kVictronMaxDecryptedLen];
    char product_hex[16];
    char vendor_flags_hex[16];
    uint16_t company_id;
    size_t tail_offset;
    uint8_t tail_len;
    size_t decrypted_len = 0;
    VictronDecryptResult decrypt_result;

    if (!target_observation_.seen || target_observation_.last_mfg_data_len < 5) {
        ESP_LOGI(kTag, "target parsed frame unavailable");
        return;
    }

    company_id = static_cast<uint16_t>(target_observation_.last_mfg_data[0]) |
                 (static_cast<uint16_t>(target_observation_.last_mfg_data[1]) << 8);

    bytesToHex(target_observation_.last_mfg_data + 4, 1, product_hex, sizeof(product_hex));
    bytesToHex(target_observation_.last_mfg_data + 2, 2, vendor_flags_hex, sizeof(vendor_flags_hex));

    tail_offset = 5;
    tail_len = static_cast<uint8_t>(target_observation_.last_mfg_data_len - tail_offset);
    bytesToHex(target_observation_.last_mfg_data + tail_offset, tail_len, tail_hex, sizeof(tail_hex));

    ESP_LOGI(
        kTag,
        "target parsed frame company_id=0x%04X record_type=0x%02X record_version=0x%02X header_byte_4=0x%02X",
        company_id,
        target_observation_.last_mfg_data[2],
        target_observation_.last_mfg_data[3],
        target_observation_.last_mfg_data[4]);

    ESP_LOGI(
        kTag,
        "target parsed frame header_bytes=%s class_byte=%s tail_len=%u tail=%s",
        vendor_flags_hex,
        product_hex,
        tail_len,
        tail_hex);

    ESP_LOGI(
        kTag,
        "target parsed frame note=tail bytes are preserved for later Victron-specific decryption");

    if (company_id != kVictronCompanyId || target_observation_.last_mfg_data_len <= 2) {
        ESP_LOGI(kTag, "target instant readout unavailable unsupported_company_id");
        return;
    }

    if (!parseVictronAdvertisementFrame(
            target_observation_.last_mfg_data + 2,
            static_cast<size_t>(target_observation_.last_mfg_data_len - 2),
            &frame)) {
        ESP_LOGI(kTag, "target instant readout unavailable frame_too_short");
        return;
    }

    if (frame.prefix != kVictronInstantReadoutPrefix) {
        ESP_LOGI(kTag, "target instant readout unavailable unexpected_prefix=0x%04X", frame.prefix);
        return;
    }

    if (!victron_key_configured_) {
        ESP_LOGI(kTag, "target instant readout unavailable key_not_configured");
        return;
    }

    decrypt_result = decryptVictronPayload(frame, victron_key_, decrypted, sizeof(decrypted), &decrypted_len);
    if (decrypt_result == VictronDecryptResult::kKeyMismatch) {
        ESP_LOGW(kTag, "target instant readout unavailable key_check_mismatch");
        return;
    }
    if (decrypt_result == VictronDecryptResult::kFrameTooShort) {
        ESP_LOGI(kTag, "target instant readout unavailable encrypted_payload_too_short");
        return;
    }
    if (decrypt_result == VictronDecryptResult::kBufferTooSmall) {
        ESP_LOGI(kTag, "target instant readout unavailable decrypted_buffer_too_small");
        return;
    }
    if (decrypt_result == VictronDecryptResult::kAesError) {
        ESP_LOGW(kTag, "target instant readout unavailable aes_error");
        return;
    }

    bytesToHex(decrypted, static_cast<uint8_t>(decrypted_len), decrypted_hex, sizeof(decrypted_hex));
    ESP_LOGI(
        kTag,
        "target instant readout model_id=0x%04X model=%s readout_type=0x%02X iv=0x%04X",
        frame.model_id,
        batteryMonitorModelName(frame.model_id),
        frame.readout_type,
        frame.iv);
    ESP_LOGI(kTag, "target instant readout decrypted=%s", decrypted_hex);

    if (!parseVictronBatteryMonitorTelemetry(frame, decrypted, decrypted_len, &telemetry)) {
        ESP_LOGI(kTag, "target instant readout parser unavailable readout_type=0x%02X", frame.readout_type);
        return;
    }

    const_cast<BluetoothScanner *>(this)->storeLatestVictronTelemetry(
        telemetry.voltage_v,
        telemetry.has_voltage,
        telemetry.current_a,
        telemetry.has_current,
        telemetry.soc_pct,
        telemetry.has_soc);

    if (telemetry.has_voltage) {
        std::snprintf(voltage_buffer, sizeof(voltage_buffer), "%.2fV", telemetry.voltage_v);
    } else {
        std::snprintf(voltage_buffer, sizeof(voltage_buffer), "-");
    }

    if (telemetry.has_current) {
        std::snprintf(current_buffer, sizeof(current_buffer), "%.3fA", telemetry.current_a);
    } else {
        std::snprintf(current_buffer, sizeof(current_buffer), "-");
    }

    if (telemetry.has_soc) {
        std::snprintf(soc_buffer, sizeof(soc_buffer), "%.1f%%", telemetry.soc_pct);
    } else {
        std::snprintf(soc_buffer, sizeof(soc_buffer), "-");
    }

    if (telemetry.has_consumed_ah) {
        std::snprintf(consumed_buffer, sizeof(consumed_buffer), "%.1fAh", telemetry.consumed_ah);
    } else {
        std::snprintf(consumed_buffer, sizeof(consumed_buffer), "-");
    }

    if (telemetry.has_remaining_mins) {
        std::snprintf(remaining_buffer, sizeof(remaining_buffer), "%umin", telemetry.remaining_mins);
    } else {
        std::snprintf(remaining_buffer, sizeof(remaining_buffer), "-");
    }

    ESP_LOGI(
        kTag,
        "target battery monitor voltage=%s current=%s soc=%s consumed=%s remaining=%s alarm=0x%04X aux_mode=%s",
        voltage_buffer,
        current_buffer,
        soc_buffer,
        consumed_buffer,
        remaining_buffer,
        telemetry.alarm_reason,
        batteryAuxModeName(telemetry.aux_mode));

    if (telemetry.has_temperature) {
        ESP_LOGI(kTag, "target battery monitor aux temperature=%.2fC", telemetry.temperature_c);
    } else if (telemetry.has_starter_voltage) {
        ESP_LOGI(kTag, "target battery monitor aux starter_voltage=%.2fV", telemetry.starter_voltage_v);
    } else if (telemetry.has_midpoint_voltage) {
        ESP_LOGI(kTag, "target battery monitor aux midpoint_voltage=%.2fV", telemetry.midpoint_voltage_v);
    }
}

void BluetoothScanner::storeLatestVictronTelemetry(
    float voltage_v,
    bool has_voltage,
    float current_a,
    bool has_current,
    float soc_pct,
    bool has_soc)
{
    if (telemetry_mutex_ == nullptr) {
        return;
    }

    if (xSemaphoreTake(telemetry_mutex_, portMAX_DELAY) != pdTRUE) {
        return;
    }

    latest_victron_telemetry_.available = has_voltage || has_current || has_soc;
    latest_victron_telemetry_.sample_uptime_ms = static_cast<uint64_t>(esp_timer_get_time() / 1000);
    latest_victron_telemetry_.has_voltage = has_voltage;
    latest_victron_telemetry_.voltage_v = voltage_v;
    latest_victron_telemetry_.has_current = has_current;
    latest_victron_telemetry_.current_a = current_a;
    latest_victron_telemetry_.has_soc = has_soc;
    latest_victron_telemetry_.soc_pct = soc_pct;

    xSemaphoreGive(telemetry_mutex_);
}

/* Logs the discovered advertisement address, RSSI, and payload details. */
void BluetoothScanner::logDiscovery(const struct ble_gap_disc_desc *disc, const struct ble_hs_adv_fields *fields) const
{
    char addr_buffer[18];
    char mfg_hex[256];
    char name_buffer[32];

    formatBleAddr(&disc->addr, addr_buffer, sizeof(addr_buffer));
    extractDeviceName(fields, name_buffer, sizeof(name_buffer));

    if (fields->mfg_data_len > 0) {
        bytesToHex(fields->mfg_data, fields->mfg_data_len, mfg_hex, sizeof(mfg_hex));
        if (name_buffer[0] != '\0') {
            ESP_LOGI(
                kTag,
                "match addr=%s rssi=%d event_type=%u name=%s mfg_len=%u mfg=%s",
                addr_buffer,
                disc->rssi,
                disc->event_type,
                name_buffer,
                fields->mfg_data_len,
                mfg_hex);
        } else {
            ESP_LOGI(
                kTag,
                "match addr=%s rssi=%d event_type=%u mfg_len=%u mfg=%s",
                addr_buffer,
                disc->rssi,
                disc->event_type,
                fields->mfg_data_len,
                mfg_hex);
        }
    } else {
        ESP_LOGI(
            kTag,
            "match addr=%s rssi=%d event_type=%u no manufacturer data",
            addr_buffer,
            disc->rssi,
            disc->event_type);
    }
}

/* Decides whether a target discovery report should be logged based on payload changes. */
bool BluetoothScanner::shouldLogTargetDiscovery(const struct ble_gap_disc_desc *disc) const
{
    uint8_t compare_len;

    if (!target_observation_.seen) {
        return true;
    }

    compare_len = disc->length_data;
    if (compare_len > kMaxCachedPayloadLen) {
        compare_len = kMaxCachedPayloadLen;
    }

    if (target_observation_.last_payload_len != compare_len) {
        return true;
    }

    return std::memcmp(target_observation_.last_payload, disc->data, compare_len) != 0;
}

/* Identifies advertisements that are likely to come from a Victron device. */
bool BluetoothScanner::isVictronCandidate(const struct ble_hs_adv_fields *fields) const
{
    char name_buffer[32];

    extractDeviceName(fields, name_buffer, sizeof(name_buffer));

    return (fields->mfg_data_len >= 2 && fields->mfg_data[0] == 0xE1 && fields->mfg_data[1] == 0x02) ||
           containsIgnoreCase(name_buffer, "victron") ||
           containsIgnoreCase(name_buffer, "smartshunt") ||
           containsIgnoreCase(name_buffer, "bmv");
}

/* Starts BLE scanning with continuous discovery callbacks and scan-response support. */
void BluetoothScanner::startScan()
{
    uint8_t own_addr_type;
    struct ble_gap_disc_params disc_params;
    int rc;

    if (search_timeout_reached_ && !target_found_) {
        ESP_LOGI(kTag, "BLE search window already expired without finding target; not restarting scan");
        return;
    }

    std::memset(&disc_params, 0, sizeof(disc_params));

    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        ESP_LOGE(kTag, "failed to infer own address type rc=%d", rc);
        return;
    }

    disc_params.passive = 0;
    disc_params.filter_duplicates = 0;
    disc_params.itvl = 0;
    disc_params.window = 0;
    disc_params.filter_policy = 0;
    disc_params.limited = 0;

    rc = ble_gap_disc(own_addr_type, BLE_HS_FOREVER, &disc_params, gapEventHandler, nullptr);
    if (rc != 0) {
        scan_active_ = false;
        ESP_LOGE(kTag, "failed to start scan rc=%d", rc);
        return;
    }

    scan_active_ = true;
    ESP_LOGI(kTag, "active BLE scan started");
}

/* Handles BLE discovery events and restarts scanning if the procedure ends. */
int BluetoothScanner::handleGapEvent(struct ble_gap_event *event)
{
    struct ble_hs_adv_fields fields;
    bool is_victron;
    int rc;

    switch (event->type) {
    case BLE_GAP_EVENT_DISC:
        std::memset(&fields, 0, sizeof(fields));
        rc = ble_hs_adv_parse_fields(&fields, event->disc.data, event->disc.length_data);
        if (rc != 0) {
            ESP_LOGW(kTag, "failed to parse advertisement payload rc=%d", rc);
            return 0;
        }

        if (!isTargetDevice(&event->disc.addr)) {
            return 0;
        }

        is_victron = isVictronCandidate(&fields);

        if (fields.mfg_data_len == 0 && fields.name_len == 0 && !is_victron) {
            return 0;
        }

        if (shouldLogTargetDiscovery(&event->disc)) {
            logDiscovery(&event->disc, &fields);
        }

        updateTargetObservation(&event->disc, &fields, is_victron);

        if (!target_found_) {
            target_found_ = true;
            ESP_LOGI(kTag, "target Victron device seen, stopping search LED");
            dumpTargetObservation();
        } else if (fields.mfg_data_len > 0) {
            logTargetManufacturerBreakdown();
        }
        return 0;

    case BLE_GAP_EVENT_DISC_COMPLETE:
        scan_active_ = false;
        if (target_found_) {
            ESP_LOGW(kTag, "scan completed reason=%d, restarting for continued telemetry updates", event->disc_complete.reason);
            startScan();
        } else if (!search_timeout_reached_) {
            ESP_LOGW(kTag, "scan completed reason=%d before timeout, restarting search", event->disc_complete.reason);
            startScan();
        } else {
            ESP_LOGI(kTag, "scan completed reason=%d after unsuccessful search timeout; staying idle to save power", event->disc_complete.reason);
        }
        return 0;

    default:
        return 0;
    }
}

/* Logs BLE controller reset events for troubleshooting. */
void BluetoothScanner::handleReset(int reason) const
{
    ESP_LOGE(kTag, "BLE stack reset reason=%d", reason);
}

/* Finalizes BLE address setup and begins scanning once the host syncs. */
void BluetoothScanner::handleSync()
{
    uint8_t own_addr_type;
    ble_addr_t addr;
    char addr_buffer[18];
    int rc;

    rc = ble_hs_util_ensure_addr(0);
    if (rc != 0) {
        ESP_LOGE(kTag, "failed to ensure BLE address rc=%d", rc);
        return;
    }

    rc = ble_hs_id_infer_auto(0, &own_addr_type);
    if (rc != 0) {
        ESP_LOGE(kTag, "failed to infer BLE address type rc=%d", rc);
        return;
    }

    rc = ble_hs_id_copy_addr(own_addr_type, addr.val, nullptr);
    if (rc != 0) {
        ESP_LOGE(kTag, "failed to copy BLE address rc=%d", rc);
        return;
    }

    addr.type = own_addr_type;
    formatBleAddr(&addr, addr_buffer, sizeof(addr_buffer));
    ESP_LOGI(kTag, "BLE host synced with scanner address %s", addr_buffer);

    if (search_timeout_reached_ && !target_found_) {
        ESP_LOGI(kTag, "BLE host synced after search timeout; leaving scanner idle");
        return;
    }

    startScan();
}

/* Runs the NimBLE host loop on the FreeRTOS task created by the port layer. */
void BluetoothScanner::hostTask(void *param)
{
    static_cast<void>(param);
    nimble_port_run();
    nimble_port_freertos_deinit();
}

/* Bridges NimBLE discovery callbacks into the active scanner instance. */
int BluetoothScanner::gapEventHandler(struct ble_gap_event *event, void *arg)
{
    static_cast<void>(arg);

    if (active_instance_ == nullptr) {
        return 0;
    }

    return active_instance_->handleGapEvent(event);
}

/* Bridges NimBLE reset callbacks into the active scanner instance. */
void BluetoothScanner::onReset(int reason)
{
    if (active_instance_ != nullptr) {
        active_instance_->handleReset(reason);
    }
}

/* Bridges NimBLE sync callbacks into the active scanner instance. */
void BluetoothScanner::onSync()
{
    if (active_instance_ != nullptr) {
        active_instance_->handleSync();
    }
}

/* Runs the onboard LED blink pattern on a short-lived FreeRTOS task. */
void BluetoothScanner::indicatorTask(void *param)
{
    BluetoothScanner *scanner = static_cast<BluetoothScanner *>(param);
    const TickType_t step_ticks = pdMS_TO_TICKS(kIndicatorBlinkStepMs);
    uint32_t step = 0;

    gpio_set_direction(kIndicatorLedGpio, GPIO_MODE_OUTPUT);

    while (scanner != nullptr && !scanner->target_found_ && !scanner->search_timeout_reached_) {
        gpio_set_level(kIndicatorLedGpio, static_cast<uint32_t>(step & 0x01U));
        ++step;
        vTaskDelay(step_ticks);
    }

    gpio_set_level(kIndicatorLedGpio, 0);
    gpio_set_direction(kIndicatorLedGpio, GPIO_MODE_INPUT);

    if (scanner != nullptr) {
        scanner->indicator_task_running_ = false;
    }

    vTaskDelete(nullptr);
}

/* Periodically prints the dedicated target record while scanning continues. */
void BluetoothScanner::targetDumpTask(void *param)
{
    BluetoothScanner *scanner = static_cast<BluetoothScanner *>(param);
    const TickType_t dump_ticks = pdMS_TO_TICKS(kCacheDumpIntervalMs);

    while (scanner != nullptr) {
        vTaskDelay(dump_ticks);

        if (scanner->search_timeout_reached_ && !scanner->target_found_) {
            ESP_LOGI(scanner->kTag, "stopping periodic target dumps after unsuccessful BLE search timeout");
            break;
        }

        ESP_LOGI(scanner->kTag, "periodic target dump starting");
        scanner->dumpTargetObservation();
    }

    if (scanner != nullptr) {
        scanner->target_dump_task_running_ = false;
    }

    vTaskDelete(nullptr);
}

/* Cancels BLE scanning if the target was not found within the search timeout window. */
void BluetoothScanner::searchTimeoutTask(void *param)
{
    BluetoothScanner *scanner = static_cast<BluetoothScanner *>(param);
    const TickType_t timeout_ticks = pdMS_TO_TICKS(kVictronSearchTimeoutMs);

    vTaskDelay(timeout_ticks);

    if (scanner != nullptr && !scanner->target_found_) {
        scanner->search_timeout_reached_ = true;

        if (scanner->scan_active_) {
            const int rc = ble_gap_disc_cancel();
            if (rc == 0) {
                ESP_LOGW(scanner->kTag, "Victron BLE search timed out after %u ms; stopping scan to preserve battery", kVictronSearchTimeoutMs);
            } else {
                ESP_LOGW(
                    scanner->kTag,
                    "Victron BLE search timed out after %u ms; scan cancel returned rc=%d",
                    kVictronSearchTimeoutMs,
                    rc);
            }
        } else {
            ESP_LOGW(
                scanner->kTag,
                "Victron BLE search timed out after %u ms before scan became active; future scan restarts are disabled",
                kVictronSearchTimeoutMs);
        }
    }

    if (scanner != nullptr) {
        scanner->search_timeout_task_running_ = false;
    }

    vTaskDelete(nullptr);
}
