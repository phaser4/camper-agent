#ifndef CAMPER_TELEMETRY_QUEUE_HPP
#define CAMPER_TELEMETRY_QUEUE_HPP

#include <array>
#include <cstddef>
#include <cstdint>

#include "TelemetryTypes.hpp"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

class TelemetryQueue {
  public:
    static constexpr size_t kCapacity = TelemetryBatch::kMaxSamples;

    TelemetryQueue();

    /* Appends one sample, discarding the oldest entry when the fixed-capacity buffer is full. */
    void enqueue(const TelemetrySample &sample);

    /* Returns a stable snapshot of the queue contents in oldest-to-newest order. */
    TelemetryBatch peekAll() const;

    /* Removes the oldest samples only if the queue has not changed since the provided snapshot. */
    bool discardOldestIfGenerationMatches(size_t count, uint32_t expected_generation);

    /* Reports the current queue depth. */
    size_t size() const;

  private:
    mutable StaticSemaphore_t mutex_buffer_;
    mutable SemaphoreHandle_t mutex_;
    std::array<TelemetrySample, kCapacity> samples_;
    size_t head_;
    size_t size_;
    uint32_t generation_;
};

#endif
