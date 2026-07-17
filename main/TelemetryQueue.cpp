#include "TelemetryQueue.hpp"

#include "freertos/FreeRTOS.h"

TelemetryQueue::TelemetryQueue()
    : mutex_buffer_{},
      mutex_(xSemaphoreCreateMutexStatic(&mutex_buffer_)),
      samples_{},
      head_(0),
      size_(0),
      generation_(0)
{
}

void TelemetryQueue::enqueue(const TelemetrySample &sample)
{
    size_t insert_index;

    if (mutex_ == nullptr) {
        return;
    }

    if (xSemaphoreTake(mutex_, portMAX_DELAY) != pdTRUE) {
        return;
    }

    insert_index = (head_ + size_) % kCapacity;
    if (size_ == kCapacity) {
        samples_[head_] = sample;
        head_ = (head_ + 1) % kCapacity;
    } else {
        samples_[insert_index] = sample;
        ++size_;
    }

    ++generation_;
    xSemaphoreGive(mutex_);
}

TelemetryBatch TelemetryQueue::peekAll() const
{
    TelemetryBatch batch{};

    if (mutex_ == nullptr) {
        return batch;
    }

    if (xSemaphoreTake(mutex_, portMAX_DELAY) != pdTRUE) {
        return batch;
    }

    batch.count = size_;
    batch.generation = generation_;
    for (size_t index = 0; index < size_; ++index) {
        batch.samples[index] = samples_[(head_ + index) % kCapacity];
    }

    xSemaphoreGive(mutex_);
    return batch;
}

bool TelemetryQueue::discardOldestIfGenerationMatches(size_t count, uint32_t expected_generation)
{
    size_t discard_count;

    if (mutex_ == nullptr) {
        return false;
    }

    if (xSemaphoreTake(mutex_, portMAX_DELAY) != pdTRUE) {
        return false;
    }

    if (generation_ != expected_generation) {
        xSemaphoreGive(mutex_);
        return false;
    }

    discard_count = count;
    if (discard_count > size_) {
        discard_count = size_;
    }

    head_ = (head_ + discard_count) % kCapacity;
    size_ -= discard_count;
    ++generation_;

    xSemaphoreGive(mutex_);
    return true;
}

size_t TelemetryQueue::size() const
{
    size_t current_size = 0;

    if (mutex_ == nullptr) {
        return 0;
    }

    if (xSemaphoreTake(mutex_, portMAX_DELAY) != pdTRUE) {
        return 0;
    }

    current_size = size_;

    xSemaphoreGive(mutex_);
    return current_size;
}
