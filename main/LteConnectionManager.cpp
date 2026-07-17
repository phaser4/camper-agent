#include "LteConnectionManager.hpp"

#include <cstring>
#include <cstdio>
#include "esp_check.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace {

constexpr int kRegistrationPollIntervalMs = 1000;
constexpr int kUartReadPollMs = 50;

int parseMonthAbbreviation(const char *month_text)
{
    static constexpr const char *kMonths[] = {
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    };

    for (int index = 0; index < static_cast<int>(sizeof(kMonths) / sizeof(kMonths[0])); ++index) {
        if (std::strncmp(month_text, kMonths[index], 3) == 0) {
            return index + 1;
        }
    }

    return -1;
}

bool buildModemClockString(char *clock_text, size_t clock_text_size)
{
    char month_text[4] = {};
    int day = 0;
    int year = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;

    if (std::sscanf(__DATE__, "%3s %d %d", month_text, &day, &year) != 3) {
        return false;
    }

    if (std::sscanf(__TIME__, "%d:%d:%d", &hour, &minute, &second) != 3) {
        return false;
    }

    const int month = parseMonthAbbreviation(month_text);
    if (month < 1 || year < 2000) {
        return false;
    }

    const int written = std::snprintf(
        clock_text,
        clock_text_size,
        "%02d/%02d/%02d,%02d:%02d:%02d+00",
        year % 100,
        month,
        day,
        hour,
        minute,
        second);

    return written > 0 && written < static_cast<int>(clock_text_size);
}

const char *lineEndingLabel(const char *const line_ending)
{
    if (std::strcmp(line_ending, "\r") == 0) {
        return "CR";
    }

    if (std::strcmp(line_ending, "\r\n") == 0) {
        return "CRLF";
    }

    return "custom";
}

bool responseHasOk(const std::string &response)
{
    if (response.size() < 4) {
        return false;
    }

    return response.find("\r\nOK\r\n") != std::string::npos ||
           response.rfind("OK\r\n") == response.size() - 4;
}

bool responseHasError(const std::string &response)
{
    return response.find("\r\nERROR\r\n") != std::string::npos ||
           response.find("+CME ERROR:") != std::string::npos ||
           response.find("+CMS ERROR:") != std::string::npos;
}

bool responseHasPrompt(const std::string &response)
{
    return response.find("\r\n>") != std::string::npos ||
           response == ">" ||
           response.find("> ") != std::string::npos ||
           response.find("DOWNLOAD") != std::string::npos;
}

} // namespace

esp_err_t LteConnectionManager::start()
{
    esp_err_t err = configurePowerEnableGpio();
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "start(%d): failed to configure modem power enable GPIO", __LINE__);
        return err;
    }

    err = configurePwrKeyGpio();
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "start(%d): failed to configure modem PWRKEY GPIO", __LINE__);
        return err;
    }

    err = powerOnModem();
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "start(%d): failed to enable modem power", __LINE__);
        return err;
    }

    err = pulsePwrKey();
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "start(%d): failed to pulse modem PWRKEY", __LINE__);
        powerOffModem();
        return err;
    }

    err = configureUart();
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "start(%d): failed to configure modem UART", __LINE__);
        powerOffModem();
        return err;
    }

    err = ensureResponsive();
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "start(%d): modem did not respond to AT", __LINE__);
        powerOffModem();
        return err;
    }

    err = initializeModem();
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "start(%d): modem initialization failed", __LINE__);
        powerOffModem();
        return err;
    }

    err = ensureSimReady();
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "start(%d): SIM is not ready", __LINE__);
        powerOffModem();
        return err;
    }

    err = configurePacketData();
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "start(%d): packet-data configuration failed", __LINE__);
        powerOffModem();
        return err;
    }

    err = selectNetworkMode(1, "Cat-M1 only", false);
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "start(%d): failed to select Cat-M1 mode", __LINE__);
        powerOffModem();
        return err;
    }

    if (waitForNetworkRegistration(kPreferredNetworkTimeoutSec, "Cat-M1 only") != ESP_OK) {
        ESP_LOGW(kTag, "Cat-M1 registration timed out; falling back to Cat-M1/NB-IoT auto mode");
        err = selectNetworkMode(3, "Cat-M1/NB-IoT auto", true);
        if (err != ESP_OK) {
            ESP_LOGE(kTag, "start(%d): failed to switch to dual-mode registration", __LINE__);
            powerOffModem();
            return err;
        }

        err = waitForNetworkRegistration(kFallbackNetworkTimeoutSec, "Cat-M1/NB-IoT auto");
        if (err != ESP_OK) {
            ESP_LOGE(kTag, "start(%d): network registration timed out", __LINE__);
            powerOffModem();
            return err;
        }
    }

    err = activateDataConnection();
    if (err != ESP_OK) {
        ESP_LOGE(kTag, "start(%d): data activation failed", __LINE__);
        powerOffModem();
        data_connection_active_ = false;
        return err;
    }

    data_connection_active_ = true;
    ESP_LOGI(kTag, "SIM7080G data connection is up");
    return ESP_OK;
}

esp_err_t LteConnectionManager::stop()
{
    std::string response;
    esp_err_t err = ESP_OK;

    if (uart_is_driver_installed(kUartPort)) {
        runAtCommand("AT+CNACT=0,0", 5000, &response);
        runAtCommand("AT+CGATT=0", 5000, &response);
        err = runAtCommandInternal("AT+CPOWD=1", 10000, &response, true, "\r\n", "NORMAL POWER DOWN");
        if (err != ESP_OK && response.find("NORMAL POWER DOWN") == std::string::npos) {
            ESP_LOGW(kTag, "AT+CPOWD=1 did not complete cleanly: %s", response.c_str());
        }
    }

    ESP_RETURN_ON_ERROR(powerOffModem(), kTag, "failed to remove modem power");
    data_connection_active_ = false;
    ESP_LOGI(kTag, "SIM7080G modem power is off");
    return ESP_OK;
}

bool LteConnectionManager::isDataConnectionActive() const
{
    return data_connection_active_;
}

esp_err_t LteConnectionManager::configurePowerEnableGpio() const
{
    ESP_RETURN_ON_ERROR(gpio_reset_pin(kPowerEnableGpio), kTag, "gpio reset failed");
    ESP_RETURN_ON_ERROR(gpio_set_direction(kPowerEnableGpio, GPIO_MODE_OUTPUT), kTag, "gpio direction failed");
    ESP_RETURN_ON_ERROR(gpio_set_level(kPowerEnableGpio, 0), kTag, "gpio initial low failed");
    return ESP_OK;
}

esp_err_t LteConnectionManager::configurePwrKeyGpio() const
{
    ESP_RETURN_ON_ERROR(gpio_reset_pin(kPwrKeyGpio), kTag, "pwrkey gpio reset failed");
    ESP_RETURN_ON_ERROR(gpio_set_direction(kPwrKeyGpio, GPIO_MODE_OUTPUT), kTag, "pwrkey gpio direction failed");
    ESP_RETURN_ON_ERROR(gpio_set_level(kPwrKeyGpio, 0), kTag, "pwrkey initial low failed");
    return ESP_OK;
}

esp_err_t LteConnectionManager::powerOnModem() const
{
    ESP_LOGI(kTag, "enabling modem 5 V rail on GPIO%d", static_cast<int>(kPowerEnableGpio));
    ESP_RETURN_ON_ERROR(gpio_set_level(kPowerEnableGpio, 1), kTag, "failed to enable modem rail");
    vTaskDelay(pdMS_TO_TICKS(kPowerEnableSettleMs));
    return ESP_OK;
}

esp_err_t LteConnectionManager::pulsePwrKey() const
{
    ESP_LOGI(kTag, "pulsing modem PWRKEY on GPIO%d for %d ms", static_cast<int>(kPwrKeyGpio), kPwrKeyPulseMs);
    ESP_RETURN_ON_ERROR(gpio_set_level(kPwrKeyGpio, 1), kTag, "failed to assert pwrkey");
    vTaskDelay(pdMS_TO_TICKS(kPwrKeyPulseMs));
    ESP_RETURN_ON_ERROR(gpio_set_level(kPwrKeyGpio, 0), kTag, "failed to release pwrkey");
    return ESP_OK;
}

esp_err_t LteConnectionManager::releaseUartPins() const
{
    if (uart_is_driver_installed(kUartPort)) {
        ESP_RETURN_ON_ERROR(uart_driver_delete(kUartPort), kTag, "uart driver delete failed");
    }

    ESP_RETURN_ON_ERROR(gpio_reset_pin(static_cast<gpio_num_t>(kTxGpio)), kTag, "tx gpio reset failed");
    ESP_RETURN_ON_ERROR(gpio_reset_pin(static_cast<gpio_num_t>(kRxGpio)), kTag, "rx gpio reset failed");
    ESP_RETURN_ON_ERROR(gpio_set_direction(static_cast<gpio_num_t>(kTxGpio), GPIO_MODE_INPUT), kTag, "tx gpio input failed");
    ESP_RETURN_ON_ERROR(gpio_set_direction(static_cast<gpio_num_t>(kRxGpio), GPIO_MODE_INPUT), kTag, "rx gpio input failed");
    return ESP_OK;
}

esp_err_t LteConnectionManager::powerOffModem() const
{
    ESP_LOGI(kTag, "disabling modem 5 V rail on GPIO%d", static_cast<int>(kPowerEnableGpio));
    ESP_RETURN_ON_ERROR(releaseUartPins(), kTag, "failed to release UART pins");
    ESP_RETURN_ON_ERROR(gpio_set_level(kPwrKeyGpio, 0), kTag, "failed to drive pwrkey low before power-off");
    ESP_RETURN_ON_ERROR(gpio_set_level(kPowerEnableGpio, 0), kTag, "failed to disable modem rail");
    return ESP_OK;
}

esp_err_t LteConnectionManager::configureUart() const
{
    const uart_config_t config = {
        .baud_rate = kUartBaudRate,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .rx_flow_ctrl_thresh = 0,
        .source_clk = UART_SCLK_XTAL,
        .flags = {
            .allow_pd = 0,
            .backup_before_sleep = 0,
        },
    };

    if (!uart_is_driver_installed(kUartPort)) {
        ESP_RETURN_ON_ERROR(
            uart_driver_install(kUartPort, kUartBufferSize, 0, 0, nullptr, 0),
            kTag,
            "uart driver install failed");
    }

    ESP_RETURN_ON_ERROR(uart_param_config(kUartPort, &config), kTag, "uart param config failed");
    ESP_RETURN_ON_ERROR(
        uart_set_pin(kUartPort, kTxGpio, kRxGpio, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE),
        kTag,
        "uart pin config failed");
    ESP_RETURN_ON_ERROR(uart_flush(kUartPort), kTag, "uart flush failed");

    return ESP_OK;
}

esp_err_t LteConnectionManager::setUartBaudRate(const int baud_rate) const
{
    ESP_RETURN_ON_ERROR(uart_set_baudrate(kUartPort, baud_rate), kTag, "uart baud-rate change failed");
    ESP_RETURN_ON_ERROR(uart_flush(kUartPort), kTag, "uart flush failed after baud-rate change");
    return ESP_OK;
}

void LteConnectionManager::flushInput() const
{
    uart_flush_input(kUartPort);
}

void LteConnectionManager::logPendingInput(const char *const label, const int timeout_ms) const
{
    std::string response;
    const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);

    while (xTaskGetTickCount() < deadline) {
        uint8_t buffer[128];
        const TickType_t remaining = deadline - xTaskGetTickCount();
        const int read_timeout = remaining > kUartReadPollMs ? kUartReadPollMs : (remaining > 0 ? remaining : 1);
        const int bytes_read = uart_read_bytes(kUartPort, buffer, sizeof(buffer), read_timeout);

        if (bytes_read > 0) {
            response.append(reinterpret_cast<const char *>(buffer), bytes_read);
        } else {
            break;
        }
    }

    if (!response.empty()) {
        ESP_LOGI(kTag, "%s:\n%s", label, response.c_str());
    }
}

esp_err_t LteConnectionManager::runAtCommand(
    const char *command,
    const int timeout_ms,
    std::string *response_out,
    const bool flush_before_send,
    const char *const line_ending) const
{
    return runAtCommandInternal(command, timeout_ms, response_out, flush_before_send, line_ending, nullptr);
}

esp_err_t LteConnectionManager::runAtCommandInternal(
    const char *command,
    const int timeout_ms,
    std::string *response_out,
    const bool flush_before_send,
    const char *const line_ending,
    const char *const alternate_success_pattern) const
{
    if (!uart_is_driver_installed(kUartPort)) {
        ESP_LOGW(kTag, "cannot run AT command while modem UART is inactive: %s", command);
        return ESP_ERR_INVALID_STATE;
    }

    char command_buffer[160];
    const int written = std::snprintf(command_buffer, sizeof(command_buffer), "%s%s", command, line_ending);

    if (written <= 0 || written >= static_cast<int>(sizeof(command_buffer))) {
        ESP_LOGE(kTag, "AT command too long: %s", command);
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(kTag, "AT >> %s <%s>", command, lineEndingLabel(line_ending));
    if (flush_before_send) {
        flushInput();
    }

    const int tx_bytes = uart_write_bytes(kUartPort, command_buffer, written);
    if (tx_bytes != written) {
        ESP_LOGE(kTag, "short UART write for command: %s", command);
        return ESP_FAIL;
    }

    ESP_ERROR_CHECK(uart_wait_tx_done(kUartPort, pdMS_TO_TICKS(500)));

    std::string response;
    response.reserve(256);
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);
    while (xTaskGetTickCount() < deadline) {
        uint8_t buffer[128];
        const TickType_t remaining = deadline - xTaskGetTickCount();
        const int read_timeout = remaining > kUartReadPollMs ? kUartReadPollMs : (remaining > 0 ? remaining : 1);
        const int bytes_read = uart_read_bytes(kUartPort, buffer, sizeof(buffer), read_timeout);

        if (bytes_read > 0) {
            response.append(reinterpret_cast<const char *>(buffer), bytes_read);

            if (responseHasError(response)) {
                if (response_out != nullptr) {
                    *response_out = response;
                }
                ESP_LOGW(kTag, "AT command failed: %s -> %s", command, response.c_str());
                return ESP_FAIL;
            }

            if (responseHasOk(response)) {
                if (response_out != nullptr) {
                    *response_out = response;
                }
                return ESP_OK;
            }

            if (alternate_success_pattern != nullptr &&
                response.find(alternate_success_pattern) != std::string::npos) {
                if (response_out != nullptr) {
                    *response_out = response;
                }
                return ESP_OK;
            }
        }
    }

    if (response_out != nullptr) {
        *response_out = response;
    }

    ESP_LOGW(kTag, "AT command timed out: %s -> %s", command, response.c_str());
    return ESP_ERR_TIMEOUT;
}

esp_err_t LteConnectionManager::runPromptedAtCommand(
    const char *command,
    const char *payload,
    const size_t payload_len,
    const int timeout_ms,
    std::string *response_out,
    const bool flush_before_send,
    const char *const line_ending) const
{
    if (!uart_is_driver_installed(kUartPort)) {
        ESP_LOGW(kTag, "cannot run prompted AT command while modem UART is inactive: %s", command);
        return ESP_ERR_INVALID_STATE;
    }

    char command_buffer[160];
    const int written = std::snprintf(command_buffer, sizeof(command_buffer), "%s%s", command, line_ending);
    if (written <= 0 || written >= static_cast<int>(sizeof(command_buffer))) {
        ESP_LOGE(kTag, "AT command too long: %s", command);
        return ESP_ERR_INVALID_ARG;
    }

    ESP_LOGI(kTag, "AT >> %s <%s> (%u byte payload)", command, lineEndingLabel(line_ending), static_cast<unsigned>(payload_len));
    if (flush_before_send) {
        flushInput();
    }

    const int tx_bytes = uart_write_bytes(kUartPort, command_buffer, written);
    if (tx_bytes != written) {
        ESP_LOGE(kTag, "short UART write for command: %s", command);
        return ESP_FAIL;
    }

    ESP_ERROR_CHECK(uart_wait_tx_done(kUartPort, pdMS_TO_TICKS(500)));

    std::string response;
    response.reserve(256);
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);

    while (xTaskGetTickCount() < deadline) {
        uint8_t buffer[128];
        const TickType_t remaining = deadline - xTaskGetTickCount();
        const int read_timeout = remaining > kUartReadPollMs ? kUartReadPollMs : (remaining > 0 ? remaining : 1);
        const int bytes_read = uart_read_bytes(kUartPort, buffer, sizeof(buffer), read_timeout);

        if (bytes_read > 0) {
            response.append(reinterpret_cast<const char *>(buffer), bytes_read);

            if (responseHasError(response)) {
                if (response_out != nullptr) {
                    *response_out = response;
                }
                ESP_LOGW(kTag, "AT prompt command failed before payload: %s -> %s", command, response.c_str());
                return ESP_FAIL;
            }

            if (responseHasPrompt(response)) {
                break;
            }
        }
    }

    if (!responseHasPrompt(response)) {
        if (response_out != nullptr) {
            *response_out = response;
        }
        ESP_LOGW(kTag, "AT prompt command timed out waiting for data prompt: %s -> %s", command, response.c_str());
        return ESP_ERR_TIMEOUT;
    }

    if (payload_len > 0) {
        const int payload_tx_bytes = uart_write_bytes(kUartPort, payload, payload_len);
        if (payload_tx_bytes != static_cast<int>(payload_len)) {
            ESP_LOGE(kTag, "short UART write for command payload: %s", command);
            return ESP_FAIL;
        }
    }

    ESP_ERROR_CHECK(uart_wait_tx_done(kUartPort, pdMS_TO_TICKS(500)));

    response.clear();
    deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_ms);

    while (xTaskGetTickCount() < deadline) {
        uint8_t buffer[128];
        const TickType_t remaining = deadline - xTaskGetTickCount();
        const int read_timeout = remaining > kUartReadPollMs ? kUartReadPollMs : (remaining > 0 ? remaining : 1);
        const int bytes_read = uart_read_bytes(kUartPort, buffer, sizeof(buffer), read_timeout);

        if (bytes_read > 0) {
            response.append(reinterpret_cast<const char *>(buffer), bytes_read);

            if (responseHasError(response)) {
                if (response_out != nullptr) {
                    *response_out = response;
                }
                ESP_LOGW(kTag, "AT prompt command failed after payload: %s -> %s", command, response.c_str());
                return ESP_FAIL;
            }

            if (responseHasOk(response)) {
                if (response_out != nullptr) {
                    *response_out = response;
                }
                return ESP_OK;
            }
        }
    }

    if (response_out != nullptr) {
        *response_out = response;
    }

    ESP_LOGW(kTag, "AT prompt command timed out after payload: %s -> %s", command, response.c_str());
    return ESP_ERR_TIMEOUT;
}

esp_err_t LteConnectionManager::ensureResponsive()
{
    std::string response;
    int attempt = 0;
    static constexpr int kProbeBaudRates[] = {57600, 19200, 115200, 9600, 38400};
    static constexpr const char *kProbeLineEndings[] = {"\r", "\r\n"};

    ESP_LOGI(
        kTag,
        "waiting %d ms for modem boot, then probing AT across baud/line-ending combinations for up to %d ms",
        kStartupBootGraceMs,
        kResponsiveWindowMs);
    vTaskDelay(pdMS_TO_TICKS(kStartupBootGraceMs));

    logPendingInput("UART input before AT probe", 200);
    const TickType_t startup_deadline = xTaskGetTickCount() + pdMS_TO_TICKS(kResponsiveWindowMs);

    while (xTaskGetTickCount() < startup_deadline) {
        for (const int baud_rate : kProbeBaudRates) {
            ESP_RETURN_ON_ERROR(setUartBaudRate(baud_rate), kTag, "failed to switch UART baud rate");

            for (const char *line_ending : kProbeLineEndings) {
                if (xTaskGetTickCount() >= startup_deadline) {
                    break;
                }

                ++attempt;
                ESP_LOGI(
                    kTag,
                    "AT probe attempt %d at %d baud using %s",
                    attempt,
                    baud_rate,
                    lineEndingLabel(line_ending));
                if (runAtCommand("AT", kAtProbeTimeoutMs, &response, attempt == 1, line_ending) == ESP_OK) {
                    ESP_LOGI(kTag, "modem answered AT at %d baud using %s", baud_rate, lineEndingLabel(line_ending));
                    return ESP_OK;
                }

                logPendingInput("UART input after AT timeout", 100);
                vTaskDelay(pdMS_TO_TICKS(kAtProbeRetryDelayMs));
            }
        }
    }

    ESP_LOGW(
        kTag,
        "modem did not answer AT on UART1 GPIO16/GPIO17 after %d attempts across baud-rate variants",
        attempt);
    return ESP_ERR_TIMEOUT;
}

esp_err_t LteConnectionManager::initializeModem()
{
    std::string response;

    ESP_RETURN_ON_ERROR(runAtCommand("ATE0", kDefaultCommandTimeoutMs, &response), kTag, "failed to disable echo");
    ESP_RETURN_ON_ERROR(runAtCommand("AT+CMEE=2", kDefaultCommandTimeoutMs, &response), kTag, "failed to enable verbose CME errors");
    if (runAtCommand("AT+CLTS=1", kDefaultCommandTimeoutMs, &response) == ESP_OK) {
        ESP_LOGI(kTag, "enabled modem network time synchronization");
    }
    ESP_RETURN_ON_ERROR(runAtCommand("AT+CFUN=1", 5000, &response), kTag, "failed to enter full functionality");
    bestEffortSetClockFromBuild();

    if (runAtCommand("AT+CSQ", kDefaultCommandTimeoutMs, &response) == ESP_OK) {
        ESP_LOGI(kTag, "signal quality: %s", response.c_str());
    }

    return ESP_OK;
}

esp_err_t LteConnectionManager::bestEffortSetClockFromBuild()
{
    std::string response;
    char clock_text[32];
    char command[64];

    if (!buildModemClockString(clock_text, sizeof(clock_text))) {
        ESP_LOGW(kTag, "unable to derive modem clock from build timestamp %s %s", __DATE__, __TIME__);
        return ESP_FAIL;
    }

    std::snprintf(command, sizeof(command), "AT+CCLK=\"%s\"", clock_text);
    const esp_err_t set_err = runAtCommand(command, kDefaultCommandTimeoutMs, &response);
    if (set_err != ESP_OK) {
        ESP_LOGW(kTag, "failed to seed modem clock from build time %s", clock_text);
        return set_err;
    }

    ESP_LOGI(kTag, "seeded modem clock from build time: %s", clock_text);
    if (runAtCommand("AT+CCLK?", kDefaultCommandTimeoutMs, &response) == ESP_OK) {
        ESP_LOGI(kTag, "modem clock after seeding:\n%s", response.c_str());
    }

    return ESP_OK;
}

esp_err_t LteConnectionManager::ensureSimReady()
{
    TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(10000);

    while (xTaskGetTickCount() < deadline) {
        std::string response;
        const esp_err_t err = runAtCommand("AT+CPIN?", kDefaultCommandTimeoutMs, &response);
        if (err == ESP_OK) {
            if (response.find("READY") != std::string::npos) {
                ESP_LOGI(kTag, "SIM status:\n%s", response.c_str());
                logOptionalCommand("SIM ICCID", "AT+CCID", kDefaultCommandTimeoutMs);
                return ESP_OK;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(500));
    }

    return ESP_ERR_TIMEOUT;
}

esp_err_t LteConnectionManager::configurePacketData()
{
    std::string response;
    const char *apn = CONFIG_CAMPER_MODEM_APN;

    if (apn[0] != '\0') {
        char command[160];
        std::snprintf(command, sizeof(command), "AT+CGDCONT=1,\"IP\",\"%s\"", apn);
        ESP_RETURN_ON_ERROR(runAtCommand(command, kDefaultCommandTimeoutMs, &response), kTag, "failed to configure APN");

        std::snprintf(command, sizeof(command), "AT+CNCFG=0,1,\"%s\"", apn);
        ESP_RETURN_ON_ERROR(
            runAtCommand(command, kDefaultCommandTimeoutMs, &response),
            kTag,
            "failed to configure APP PDP context for CNACT-based clients");
    } else {
        ESP_LOGW(kTag, "CONFIG_CAMPER_MODEM_APN is empty; relying on SIM auto APN");
    }

    logOptionalCommand("network-delivered APN", "AT+CGNAPN", kDefaultCommandTimeoutMs);
    logOptionalCommand("APP PDP config", "AT+CNCFG?", kDefaultCommandTimeoutMs);
    logOptionalCommand("radio system info", "AT+CPSI?", kDefaultCommandTimeoutMs);
    logOptionalCommand("operator selection", "AT+COPS?", kDefaultCommandTimeoutMs);

    return ESP_OK;
}

void LteConnectionManager::logOptionalCommand(const char *label, const char *command, const int timeout_ms) const
{
    std::string response;
    if (runAtCommand(command, timeout_ms, &response) == ESP_OK) {
        ESP_LOGI(kTag, "%s:\n%s", label, response.c_str());
    }
}

esp_err_t LteConnectionManager::selectNetworkMode(
    const int cmnb_value,
    const char *const mode_label,
    const bool restart_rf)
{
    std::string response;
    char command[32];

    ESP_LOGI(kTag, "selecting network mode: %s", mode_label);

    if (restart_rf) {
        ESP_RETURN_ON_ERROR(runAtCommand("AT+CFUN=0", 5000, &response), kTag, "failed to disable RF before mode switch");
    }

    ESP_RETURN_ON_ERROR(runAtCommand("AT+CNMP=38", kDefaultCommandTimeoutMs, &response), kTag, "failed to select LTE network mode");

    std::snprintf(command, sizeof(command), "AT+CMNB=%d", cmnb_value);
    ESP_RETURN_ON_ERROR(runAtCommand(command, kDefaultCommandTimeoutMs, &response), kTag, "failed to select narrowband mode");
    ESP_RETURN_ON_ERROR(runAtCommand("AT+CFUN=1", 5000, &response), kTag, "failed to re-enable RF after mode switch");

    return ESP_OK;
}

esp_err_t LteConnectionManager::waitForNetworkRegistration(const int timeout_sec, const char *const phase_label)
{
    const TickType_t deadline = xTaskGetTickCount() + pdMS_TO_TICKS(timeout_sec * 1000);
    int state = 0;

    while (xTaskGetTickCount() < deadline) {
        std::string response;
        const esp_err_t err = runAtCommand("AT+CEREG?", kDefaultCommandTimeoutMs, &response);
        if (err == ESP_OK && parseRegistrationState(response, &state)) {
            ESP_LOGI(
                kTag,
                "CEREG state during %s: %d (waiting for 1=home or 5=roaming)",
                phase_label,
                state);
            if (state == 1 || state == 5) {
                return ESP_OK;
            }
        } else {
            ESP_LOGW(kTag, "unable to parse CEREG response: %s", response.c_str());
        }

        vTaskDelay(pdMS_TO_TICKS(kRegistrationPollIntervalMs));
    }

    logOptionalCommand("final signal quality", "AT+CSQ", kDefaultCommandTimeoutMs);
    logOptionalCommand("final operator selection", "AT+COPS?", kDefaultCommandTimeoutMs);
    logOptionalCommand("final radio system info", "AT+CPSI?", kDefaultCommandTimeoutMs);
    logOptionalCommand("final registration state", "AT+CEREG?", kDefaultCommandTimeoutMs);
    ESP_LOGW(kTag, "registration phase timed out: %s", phase_label);

    return ESP_ERR_TIMEOUT;
}

esp_err_t LteConnectionManager::activateDataConnection()
{
    std::string response;

    ESP_RETURN_ON_ERROR(runAtCommand("AT+CGATT=1", 10000, &response), kTag, "failed to attach packet service");
    ESP_RETURN_ON_ERROR(runAtCommand("AT+CNACT=0,1", 15000, &response), kTag, "failed to activate data context");
    ESP_RETURN_ON_ERROR(runAtCommand("AT+CNACT?", kDefaultCommandTimeoutMs, &response), kTag, "failed to query data context");

    ESP_LOGI(kTag, "data context: %s", response.c_str());
    return ESP_OK;
}

bool LteConnectionManager::parseRegistrationState(const std::string &response, int *state_out)
{
    const std::string token = "+CEREG:";
    const std::size_t pos = response.find(token);
    if (pos == std::string::npos) {
        return false;
    }

    int n = 0;
    int stat = 0;
    if (std::sscanf(response.c_str() + pos, "+CEREG: %d,%d", &n, &stat) != 2) {
        return false;
    }

    if (state_out != nullptr) {
        *state_out = stat;
    }
    return true;
}
