#ifndef CAMPER_LTE_CONNECTION_MANAGER_HPP
#define CAMPER_LTE_CONNECTION_MANAGER_HPP

#include <cstddef>
#include <cstdint>
#include <string>

#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_err.h"

class LteConnectionManager {
  public:
    /* Brings the SIM7080G online, registers to the network, and activates data. */
    esp_err_t start();

    /* Gracefully powers the modem down and removes its switched 5 V rail. */
    esp_err_t stop();

    /* Indicates whether packet data is currently active for higher-level protocols. */
    bool isDataConnectionActive() const;

    /* Sends a generic AT command across the configured modem UART. */
    esp_err_t runAtCommand(
        const char *command,
        int timeout_ms,
        std::string *response_out,
        bool flush_before_send = true,
        const char *line_ending = "\r\n") const;

    /* Sends an AT command that expects a data prompt and then writes raw bytes. */
    esp_err_t runPromptedAtCommand(
        const char *command,
        const char *payload,
        size_t payload_len,
        int timeout_ms,
        std::string *response_out,
        bool flush_before_send = true,
        const char *line_ending = "\r\n") const;

  private:
    static constexpr const char *kTag = "camper_lte";
    static constexpr uart_port_t kUartPort = UART_NUM_1;
    static constexpr int kUartBaudRate = 57600;
    static constexpr gpio_num_t kPowerEnableGpio = GPIO_NUM_0;
    static constexpr gpio_num_t kPwrKeyGpio = GPIO_NUM_1;
    static constexpr int kTxGpio = 16;
    static constexpr int kRxGpio = 17;
    static constexpr int kUartBufferSize = 2048;
    static constexpr int kDefaultCommandTimeoutMs = 1500;
    static constexpr int kPowerEnableSettleMs = 250;
    static constexpr int kPwrKeyPulseMs = 1200;
    static constexpr int kStartupBootGraceMs = 500;
    static constexpr int kAtProbeTimeoutMs = 700;
    static constexpr int kAtProbeRetryDelayMs = 150;
    static constexpr int kResponsiveWindowMs = 10000;
    static constexpr int kPreferredNetworkTimeoutSec = 30;
    static constexpr int kFallbackNetworkTimeoutSec = 60;
    bool data_connection_active_ = false;

    /* Configures the DFR0535 OUT1 enable GPIO used for modem rail power. */
    esp_err_t configurePowerEnableGpio() const;

    /* Configures the modem PWRKEY control GPIO. */
    esp_err_t configurePwrKeyGpio() const;

    /* Enables the switched modem 5 V rail and waits briefly for it to rise. */
    esp_err_t powerOnModem() const;

    /* Pulses the modem PWRKEY line to request a clean power-on sequence. */
    esp_err_t pulsePwrKey() const;

    /* Makes UART pins high impedance before modem power removal. */
    esp_err_t releaseUartPins() const;

    /* Removes switched modem power after optional AT-level shutdown. */
    esp_err_t powerOffModem() const;

    /* Installs and configures the UART driver for AT commands. */
    esp_err_t configureUart() const;

    /* Switches the live UART driver to a new baud rate for probing. */
    esp_err_t setUartBaudRate(int baud_rate) const;

    /* Clears any stale bytes from the UART RX path. */
    void flushInput() const;

    /* Reads and logs any unsolicited modem UART text that is already pending. */
    void logPendingInput(const char *label, int timeout_ms) const;

    /* Sends an AT command and optionally accepts an alternate success pattern. */
    esp_err_t runAtCommandInternal(
        const char *command,
        int timeout_ms,
        std::string *response_out,
        bool flush_before_send,
        const char *line_ending,
        const char *alternate_success_pattern) const;

    /* Retries a simple AT handshake against an already powered modem. */
    esp_err_t ensureResponsive();

    /* Performs the initial AT-command setup once the modem is awake. */
    esp_err_t initializeModem();

    /* Sets a sane modem RTC from the firmware build timestamp for TLS bring-up. */
    esp_err_t bestEffortSetClockFromBuild();

    /* Waits until the SIM reports READY. */
    esp_err_t ensureSimReady();

    /* Applies packet-data configuration such as APN and full functionality mode. */
    esp_err_t configurePacketData();

    /* Logs an optional modem command response without failing the bring-up flow. */
    void logOptionalCommand(const char *label, const char *command, int timeout_ms) const;

    /* Selects the active LTE-M / NB-IoT preference before registration begins. */
    esp_err_t selectNetworkMode(int cmnb_value, const char *mode_label, bool restart_rf);

    /* Waits for LTE registration using +CEREG polling. */
    esp_err_t waitForNetworkRegistration(int timeout_sec, const char *phase_label);

    /* Requests packet attachment and PDP context activation. */
    esp_err_t activateDataConnection();

    /* Parses the +CEREG registration state from a modem response. */
    static bool parseRegistrationState(const std::string &response, int *state_out);
};

#endif
