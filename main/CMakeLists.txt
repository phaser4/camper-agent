idf_component_register(
    SRCS
        "BluetoothScanner.cpp"
        "LteConnectionManager.cpp"
        "MqttPublisher.cpp"
        "TelemetryCollector.cpp"
        "TelemetryQueue.cpp"
        "main.cpp"
    EMBED_TXTFILES "isrgrootx1.pem"
    REQUIRES bt esp_driver_gpio esp_driver_uart mbedtls nvs_flash)
