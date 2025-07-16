#include "yalok/memory.hpp"
#include <iostream>
#include <algorithm>
#include <unordered_set>
#include <cstring>
#include <cassert>

namespace yalok {

MemoryPool::MemoryPool() {
    memory_blocks.reserve(16);
    block_sizes.reserve(16);
    block_used.reserve(16);
    
    allocate_new_block(DEFAULT_BLOCK_SIZE);
}

MemoryPool::~MemoryPool() {
    deallocate_all();
}

size_t MemoryPool::find_suitable_block(size_t size) {
    for (size_t i = 0; i < memory_blocks.size(); ++i) {
        if (!block_used[i] && block_sizes[i] >= size) {
            return i;
        }
    }
    return SIZE_MAX;
}

void MemoryPool::allocate_new_block(size_t size) {
    size_t block_size = std::max(size, DEFAULT_BLOCK_SIZE);
    if (block_size > MAX_BLOCK_SIZE) {
        block_size = MAX_BLOCK_SIZE;
    }
    
    try {
        auto block = std::make_unique<char[]>(block_size);
        memory_blocks.push_back(std::move(block));
        block_sizes.push_back(block_size);
        block_used.push_back(false);
        
        total_allocated.fetch_add(block_size);
    } catch (const std::bad_alloc& e) {
        throw std::runtime_error("Failed to allocate memory block: " + std::string(e.what()));
    }
}

void* MemoryPool::allocate(size_t size) {
    if (size == 0) {
        return nullptr;
    }
    
    std::lock_guard<std::mutex> lock(allocation_mutex);
    
    size_t block_index = find_suitable_block(size);
    if (block_index == SIZE_MAX) {
        allocate_new_block(size);
        block_index = memory_blocks.size() - 1;
    }
    
    if (block_index < memory_blocks.size()) {
        block_used[block_index] = true;
        total_used.fetch_add(size);
        return memory_blocks[block_index].get();
    }
    
    return nullptr;
}

void MemoryPool::deallocate(void* ptr) {
    if (!ptr) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(allocation_mutex);
    
    for (size_t i = 0; i < memory_blocks.size(); ++i) {
        if (memory_blocks[i].get() == ptr) {
            block_used[i] = false;
            total_used.fetch_sub(block_sizes[i]);
            break;
        }
    }
}

void MemoryPool::deallocate_all() {
    std::lock_guard<std::mutex> lock(allocation_mutex);
    
    memory_blocks.clear();
    block_sizes.clear();
    block_used.clear();
    
    total_allocated.store(0);
    total_used.store(0);
}

size_t MemoryPool::get_available_memory() const {
    return total_allocated.load() - total_used.load();
}

void MemoryPool::defragment() {
    std::lock_guard<std::mutex> lock(allocation_mutex);
    
    std::vector<std::unique_ptr<char[]>> new_blocks;
    std::vector<size_t> new_sizes;
    std::vector<bool> new_used;
    
    for (size_t i = 0; i < memory_blocks.size(); ++i) {
        if (block_used[i]) {
            new_blocks.push_back(std::move(memory_blocks[i]));
            new_sizes.push_back(block_sizes[i]);
            new_used.push_back(true);
        }
    }
    
    memory_blocks = std::move(new_blocks);
    block_sizes = std::move(new_sizes);
    block_used = std::move(new_used);
    
    size_t new_total = 0;
    for (size_t size : block_sizes) {
        new_total += size;
    }
    total_allocated.store(new_total);
}

void MemoryPool::shrink_to_fit() {
    std::lock_guard<std::mutex> lock(allocation_mutex);
    
    memory_blocks.shrink_to_fit();
    block_sizes.shrink_to_fit();
    block_used.shrink_to_fit();
}

MemoryPool::MemoryStats MemoryPool::get_stats() const {
    MemoryStats stats;
    stats.total_allocated = total_allocated.load();
    stats.total_used = total_used.load();
    stats.available = get_available_memory();
    stats.block_count = memory_blocks.size();
    
    if (stats.total_allocated > 0) {
        stats.fragmentation_percent = ((stats.total_allocated - stats.total_used) * 100) / stats.total_allocated;
    } else {
        stats.fragmentation_percent = 0;
    }
    
    return stats;
}

GarbageCollector::GarbageCollector() {
    tracked_objects.reserve(1024);
    object_references.reserve(1024);
}

GarbageCollector::~GarbageCollector() {
    force_collection();
}

void GarbageCollector::track_object(void* object, size_t size) {
    if (!object) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(gc_mutex);
    tracked_objects[object] = size;
}

void GarbageCollector::untrack_object(void* object) {
    if (!object) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(gc_mutex);
    
    auto it = tracked_objects.find(object);
    if (it != tracked_objects.end()) {
        tracked_objects.erase(it);
    }
    
    auto ref_it = object_references.find(object);
    if (ref_it != object_references.end()) {
        object_references.erase(ref_it);
    }
    
    for (auto& pair : object_references) {
        auto& refs = pair.second;
        refs.erase(std::remove(refs.begin(), refs.end(), object), refs.end());
    }
}

void GarbageCollector::add_reference(void* from, void* to) {
    if (!from || !to) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(gc_mutex);
    object_references[from].push_back(to);
}

void GarbageCollector::remove_reference(void* from, void* to) {
    if (!from || !to) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(gc_mutex);
    
    auto it = object_references.find(from);
    if (it != object_references.end()) {
        auto& refs = it->second;
        refs.erase(std::remove(refs.begin(), refs.end(), to), refs.end());
        
        if (refs.empty()) {
            object_references.erase(it);
        }
    }
}

bool GarbageCollector::is_reachable(void* object, std::unordered_set<void*>& visited) {
    if (!object || visited.count(object)) {
        return false;
    }
    
    visited.insert(object);
    
    auto it = object_references.find(object);
    if (it != object_references.end()) {
        for (void* ref : it->second) {
            if (is_reachable(ref, visited)) {
                return true;
            }
        }
    }
    
    return false;
}

void GarbageCollector::mark_reachable_objects(std::unordered_set<void*>& reachable) {
    std::unordered_set<void*> visited;
    
    for (const auto& pair : tracked_objects) {
        void* object = pair.first;
        
        if (object_references.find(object) != object_references.end()) {
            reachable.insert(object);
        }
        
        if (is_reachable(object, visited)) {
            reachable.insert(object);
        }
    }
}

void GarbageCollector::sweep_unreachable_objects(const std::unordered_set<void*>& reachable) {
    std::vector<void*> to_remove;
    
    for (const auto& pair : tracked_objects) {
        void* object = pair.first;
        if (reachable.find(object) == reachable.end()) {
            to_remove.push_back(object);
        }
    }
    
    for (void* object : to_remove) {
        MemoryManager::get_instance().deallocate(object);
        untrack_object(object);
    }
}

void GarbageCollector::collect() {
    std::lock_guard<std::mutex> lock(gc_mutex);
    
    if (tracked_objects.empty()) {
        return;
    }
    
    std::unordered_set<void*> reachable;
    mark_reachable_objects(reachable);
    sweep_unreachable_objects(reachable);
}

void GarbageCollector::force_collection() {
    collect();
}

size_t GarbageCollector::get_tracked_memory() const {
    std::lock_guard<std::mutex> lock(gc_mutex);
    
    size_t total = 0;
    for (const auto& pair : tracked_objects) {
        total += pair.second;
    }
    return total;
}

void GarbageCollector::enable_auto_collection(bool enabled) {
    // Demo version - auto collection is always disabled
}

void GarbageCollector::set_collection_threshold(size_t threshold) {
    // Demo version - thresholds are not configurable
}

std::unique_ptr<MemoryManager> MemoryManager::instance = nullptr;
std::once_flag MemoryManager::initialized;

MemoryManager::MemoryManager() {
    memory_pool = std::make_unique<MemoryPool>();
    garbage_collector = std::make_unique<GarbageCollector>();
}

MemoryManager& MemoryManager::get_instance() {
    std::call_once(initialized, []() {
        instance = std::unique_ptr<MemoryManager>(new MemoryManager());
    });
    return *instance;
}

void* MemoryManager::allocate(size_t size) {
    if (size == 0) {
        return nullptr;
    }
    
    void* ptr = memory_pool->allocate(size);
    if (ptr) {
        garbage_collector->track_object(ptr, size);
    }
    return ptr;
}

void MemoryManager::deallocate(void* ptr) {
    if (!ptr) {
        return;
    }
    
    garbage_collector->untrack_object(ptr);
    memory_pool->deallocate(ptr);
}

void MemoryManager::collect_garbage() {
    garbage_collector->collect();
}

MemoryPool::MemoryStats MemoryManager::get_memory_stats() const {
    return memory_pool->get_stats();
}

void MemoryManager::print_memory_stats() const {
    auto stats = get_memory_stats();
    
    std::cout << "\033[36m=== MEMORY STATISTICS ===\033[0m" << std::endl;
    std::cout << "\033[36mTotal allocated: " << stats.total_allocated << " bytes\033[0m" << std::endl;
    std::cout << "\033[36mTotal used: " << stats.total_used << " bytes\033[0m" << std::endl;
    std::cout << "\033[36mAvailable: " << stats.available << " bytes\033[0m" << std::endl;
    std::cout << "\033[36mBlock count: " << stats.block_count << "\033[0m" << std::endl;
    std::cout << "\033[36mFragmentation: " << stats.fragmentation_percent << "%\033[0m" << std::endl;
    std::cout << "\033[36mTracked objects: " << garbage_collector->get_tracked_count() << "\033[0m" << std::endl;
    std::cout << "\033[36mTracked memory: " << garbage_collector->get_tracked_memory() << " bytes\033[0m" << std::endl;
    std::cout << "\033[36m=== END MEMORY STATS ===\033[0m" << std::endl;
}

void MemoryManager::enable_garbage_collection(bool enabled) {
    garbage_collector->enable_auto_collection(enabled);
}

void MemoryManager::set_gc_threshold(size_t threshold) {
    garbage_collector->set_collection_threshold(threshold);
}

void MemoryManager::cleanup() {
    if (garbage_collector) {
        garbage_collector->force_collection();
    }
    
    if (memory_pool) {
        memory_pool->deallocate_all();
    }
}

} 