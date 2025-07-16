#pragma once

#include <memory>
#include <vector>
#include <unordered_map>
#include <atomic>
#include <mutex>

namespace yalok {

class MemoryPool {
private:
    std::vector<std::unique_ptr<char[]>> memory_blocks;
    std::vector<size_t> block_sizes;
    std::vector<bool> block_used;
    std::atomic<size_t> total_allocated{0};
    std::atomic<size_t> total_used{0};
    std::mutex allocation_mutex;
    
    static constexpr size_t DEFAULT_BLOCK_SIZE = 4096;
    static constexpr size_t MAX_BLOCK_SIZE = 1024 * 1024;
    
    size_t find_suitable_block(size_t size);
    void allocate_new_block(size_t size);
    
public:
    MemoryPool();
    ~MemoryPool();
    
    void* allocate(size_t size);
    void deallocate(void* ptr);
    void deallocate_all();
    
    size_t get_total_allocated() const { return total_allocated.load(); }
    size_t get_total_used() const { return total_used.load(); }
    size_t get_available_memory() const;
    
    void defragment();
    void shrink_to_fit();
    
    struct MemoryStats {
        size_t total_allocated;
        size_t total_used;
        size_t available;
        size_t block_count;
        size_t fragmentation_percent;
    };
    
    MemoryStats get_stats() const;
};

class GarbageCollector {
private:
    std::unordered_map<void*, size_t> tracked_objects;
    std::unordered_map<void*, std::vector<void*>> object_references;
    std::mutex gc_mutex;
    
    bool is_reachable(void* object, std::unordered_set<void*>& visited);
    void mark_reachable_objects(std::unordered_set<void*>& reachable);
    void sweep_unreachable_objects(const std::unordered_set<void*>& reachable);
    
public:
    GarbageCollector();
    ~GarbageCollector();
    
    void track_object(void* object, size_t size);
    void untrack_object(void* object);
    void add_reference(void* from, void* to);
    void remove_reference(void* from, void* to);
    
    void collect();
    void force_collection();
    
    size_t get_tracked_count() const { return tracked_objects.size(); }
    size_t get_tracked_memory() const;
    
    void enable_auto_collection(bool enabled);
    void set_collection_threshold(size_t threshold);
};

class MemoryManager {
private:
    std::unique_ptr<MemoryPool> memory_pool;
    std::unique_ptr<GarbageCollector> garbage_collector;
    
    static std::unique_ptr<MemoryManager> instance;
    static std::once_flag initialized;
    
    MemoryManager();
    
public:
    static MemoryManager& get_instance();
    
    void* allocate(size_t size);
    void deallocate(void* ptr);
    void collect_garbage();
    
    MemoryPool::MemoryStats get_memory_stats() const;
    void print_memory_stats() const;
    
    void enable_garbage_collection(bool enabled);
    void set_gc_threshold(size_t threshold);
    
    void cleanup();
};

template<typename T>
class ManagedPtr {
private:
    T* ptr;
    
public:
    ManagedPtr() : ptr(nullptr) {}
    
    explicit ManagedPtr(T* p) : ptr(p) {
        if (ptr) {
            MemoryManager::get_instance().track_object(ptr, sizeof(T));
        }
    }
    
    ~ManagedPtr() {
        if (ptr) {
            MemoryManager::get_instance().untrack_object(ptr);
        }
    }
    
    ManagedPtr(const ManagedPtr& other) : ptr(other.ptr) {
        if (ptr) {
            MemoryManager::get_instance().track_object(ptr, sizeof(T));
        }
    }
    
    ManagedPtr& operator=(const ManagedPtr& other) {
        if (this != &other) {
            if (ptr) {
                MemoryManager::get_instance().untrack_object(ptr);
            }
            ptr = other.ptr;
            if (ptr) {
                MemoryManager::get_instance().track_object(ptr, sizeof(T));
            }
        }
        return *this;
    }
    
    T* get() const { return ptr; }
    T& operator*() const { return *ptr; }
    T* operator->() const { return ptr; }
    
    explicit operator bool() const { return ptr != nullptr; }
    
    void reset(T* new_ptr = nullptr) {
        if (ptr) {
            MemoryManager::get_instance().untrack_object(ptr);
        }
        ptr = new_ptr;
        if (ptr) {
            MemoryManager::get_instance().track_object(ptr, sizeof(T));
        }
    }
};

template<typename T, typename... Args>
ManagedPtr<T> make_managed(Args&&... args) {
    void* memory = MemoryManager::get_instance().allocate(sizeof(T));
    T* object = new(memory) T(std::forward<Args>(args)...);
    return ManagedPtr<T>(object);
}

} 