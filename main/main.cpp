#include "esp_err.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs_flash.h"

#include "BluetoothScanner.hpp"
#include "LteConnectionManager.hpp"
#include "MqttPublisher.hpp"
#include "TelemetryCollector.hpp"
#include "TelemetryQueue.hpp"

namespace {

constexpr const char *kTag = "camper_main";
constexpr uint32_t kCollectionIntervalMs = 2U * 60U * 60U * 1000U;
constexpr uint32_t kPublishIntervalMs = 4U * 60U * 60U * 1000U;

struct CollectionTaskContext {
    TelemetryCollector *collector;
};

struct UploadTaskContext {
    LteConnectionManager *lte_connection_manager;
    MqttPublisher *mqtt_publisher;
    TelemetryQueue *telemetry_queue;
};

const char *resetReasonToString(const esp_reset_reason_t reason)
{
    switch (reason) {
        case ESP_RST_UNKNOWN:
            return "unknown";
        case ESP_RST_POWERON:
            return "poweron";
        case ESP_RST_EXT:
            return "external";
        case ESP_RST_SW:
            return "software";
        case ESP_RST_PANIC:
            return "panic";
        case ESP_RST_INT_WDT:
            return "interrupt_watchdog";
        case ESP_RST_TASK_WDT:
            return "task_watchdog";
        case ESP_RST_WDT:
            return "other_watchdog";
        case ESP_RST_DEEPSLEEP:
            return "deepsleep";
        case ESP_RST_BROWNOUT:
            return "brownout";
        case ESP_RST_SDIO:
            return "sdio";
        case ESP_RST_USB:
            return "usb";
        case ESP_RST_JTAG:
            return "jtag";
        case ESP_RST_EFUSE:
            return "efuse";
        case ESP_RST_PWR_GLITCH:
            return "power_glitch";
        case ESP_RST_CPU_LOCKUP:
            return "cpu_lockup";
        default:
            return "unrecognized";
    }
}

void runCollectionCycle(TelemetryCollector &collector)
{
    collector.collectOnce();
}

void runUploadCycle(
    LteConnectionManager &lte_connection_manager,
    MqttPublisher &mqtt_publisher,
    TelemetryQueue &telemetry_queue)
{
    const TelemetryBatch batch = telemetry_queue.peekAll();
    esp_err_t err;

    if (batch.count == 0) {
        ESP_LOGI(kTag, "telemetry queue is empty; skipping upload cycle");
        return;
    }

    err = lte_connection_manager.start();
    if (err != ESP_OK) {
        ESP_LOGW(kTag, "LTE startup for queued telemetry failed: %s", esp_err_to_name(err));
        return;
    }

    err = mqtt_publisher.publishTelemetryBatch(batch.samples.data(), batch.count);
    if (err != ESP_OK) {
        ESP_LOGW(kTag, "MQTT publish for queued telemetry failed: %s", esp_err_to_name(err));
    } else if (!telemetry_queue.discardOldestIfGenerationMatches(batch.count, batch.generation)) {
        ESP_LOGW(kTag, "telemetry queue changed during upload; leaving queued samples intact for retry");
    } else {
        ESP_LOGI(kTag, "uploaded and removed %u queued telemetry samples", static_cast<unsigned>(batch.count));
    }

    err = lte_connection_manager.stop();
    if (err != ESP_OK) {
        ESP_LOGW(kTag, "LTE modem shutdown after upload failed: %s", esp_err_to_name(err));
    }
}

void periodicCollectionTask(void *param)
{
    CollectionTaskContext *context = static_cast<CollectionTaskContext *>(param);
    const TickType_t collection_interval_ticks = pdMS_TO_TICKS(kCollectionIntervalMs);

    while (context != nullptr) {
        vTaskDelay(collection_interval_ticks);
        runCollectionCycle(*context->collector);
    }

    vTaskDelete(nullptr);
}

void periodicUploadTask(void *param)
{
    UploadTaskContext *context = static_cast<UploadTaskContext *>(param);
    const TickType_t publish_interval_ticks = pdMS_TO_TICKS(kPublishIntervalMs);

    while (context != nullptr) {
        vTaskDelay(publish_interval_ticks);
        runUploadCycle(*context->lte_connection_manager, *context->mqtt_publisher, *context->telemetry_queue);
    }

    vTaskDelete(nullptr);
}

}

/* Initializes NVS, optionally connects the modem, and starts the BLE scanner. */
extern "C" void app_main(void)
{
    static BluetoothScanner scanner;
    static LteConnectionManager lte_connection_manager;
    static MqttPublisher mqtt_publisher(lte_connection_manager);
    static TelemetryQueue telemetry_queue;
    static TelemetryCollector telemetry_collector(scanner, telemetry_queue);
    static CollectionTaskContext collection_task_context;
    static UploadTaskContext upload_task_context;
    esp_err_t err;
    const esp_reset_reason_t reset_reason = esp_reset_reason();

    ESP_LOGI(kTag, "app_main starting");
    ESP_LOGI(kTag, "reset reason: %s (%d)", resetReasonToString(reset_reason), static_cast<int>(reset_reason));

    err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        err = nvs_flash_init();
    }
    ESP_ERROR_CHECK(err);

    scanner.start();
    collection_task_context.collector = &telemetry_collector;
    upload_task_context.lte_connection_manager = &lte_connection_manager;
    upload_task_context.mqtt_publisher = &mqtt_publisher;
    upload_task_context.telemetry_queue = &telemetry_queue;

    runCollectionCycle(telemetry_collector);

    if (xTaskCreate(periodicCollectionTask, "metric_collect", 4096, &collection_task_context, 5, nullptr) != pdPASS) {
        ESP_LOGE(kTag, "failed to create periodic telemetry collection task");
    }

    if (xTaskCreate(periodicUploadTask, "mqtt_upload", 6144, &upload_task_context, 5, nullptr) != pdPASS) {
        ESP_LOGE(kTag, "failed to create periodic MQTT upload task");
    }
}
