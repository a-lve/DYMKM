#include <tee_api.h>      
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>
#include "shared_mem_ta.h"

TEE_Result TA_CreateEntryPoint(void) {
    return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void) {
}

// TA 端的会话上下文
struct ta_session_ctx {
    void* shm_buffer;    // 共享内存副本
    size_t shm_size;     // 共享内存大小
};

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
                                   TEE_Param params[4],
                                   void **sess_ctx) 
{
    struct ta_session_ctx *ctx = NULL;
    const uint32_t exp_type = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_MEMREF_INOUT,  // 允许读写
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE
    );

    DMSG("Opening session with shared memory...");

    // 1. 参数类型校验
    if (param_types != exp_type) {
        EMSG("Invalid param types: got 0x%x, expected 0x%x", param_types, exp_type);
        return TEE_ERROR_BAD_PARAMETERS;
    }

    // 2. 检查共享内存是否有效
    if (!params[0].memref.buffer || params[0].memref.size == 0) {
        EMSG("Invalid shared memory reference");
        return TEE_ERROR_BAD_PARAMETERS;
    }

    DMSG("Received shared memory: buffer=%p, size=%zu", params[0].memref.buffer, params[0].memref.size);

    // 3. 创建 TA 端的会话上下文
    ctx = TEE_Malloc(sizeof(*ctx), 0);
    if (!ctx) {
        return TEE_ERROR_OUT_OF_MEMORY;
    }
    memset(ctx, 0, sizeof(*ctx));

    // 4. 分配 TA 侧缓冲区（避免访问 REE 指针）
    ctx->shm_size = params[0].memref.size;
    ctx->shm_buffer = TEE_Malloc(ctx->shm_size, 0);
    if (!ctx->shm_buffer) {
        EMSG("Failed to allocate buffer in TA");
        TEE_Free(ctx);
        return TEE_ERROR_OUT_OF_MEMORY;
    }

    // 5. 复制 REE 端的数据（避免直接访问 `memref.buffer`）
    TEE_MemMove(ctx->shm_buffer, params[0].memref.buffer, ctx->shm_size);

    // 6. 关联上下文到会话
    *sess_ctx = ctx;

    DMSG("Session opened, buffer copied: %p (size: %zu)", ctx->shm_buffer, ctx->shm_size);
    return TEE_SUCCESS;
}

// 关闭会话时清理资源
void TA_CloseSessionEntryPoint(void *sess_ctx) {
    if (!sess_ctx) {
        return;
    }
    struct ta_session_ctx *ctx = (struct ta_session_ctx *)sess_ctx;

    if (ctx->shm_buffer) {
        TEE_Free(ctx->shm_buffer);
    }
    TEE_Free(ctx);

    DMSG("Session closed and memory freed.");
}

// 安全生成哈希链
static TEE_Result generate_hash_chain(struct controlflow_info *entries, 
                                     uint32_t count, 
                                     const uint8_t *initial_hash) {
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint8_t prev_hash[TEE_HASH_SHA256_SIZE];
    TEE_Result res = TEE_SUCCESS;
    
    memcpy(prev_hash, initial_hash, sizeof(prev_hash));
    
    for (uint32_t i = 0; i < count; i++) {
        // 打印条目基本信息
        DMSG("Processing entry %u: source_id=%" PRIu64 " offset=0x%" PRIx64, 
        i, entries[i].source_id, entries[i].addrto_offset);
        uint8_t input[TEE_HASH_SHA256_SIZE + sizeof(uint64_t)*2];
        
        //组装哈希输入数据：prev_hash || source_id || addrto_offset
        memcpy(input, prev_hash, TEE_HASH_SHA256_SIZE);
        memcpy(input + TEE_HASH_SHA256_SIZE, &entries[i].source_id, sizeof(uint64_t));
        memcpy(input + TEE_HASH_SHA256_SIZE + sizeof(uint64_t), &entries[i].addrto_offset, sizeof(uint64_t));
        
        //分配SHA-256计算的操作句柄
        res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
        if (res != TEE_SUCCESS) goto exit;
        
        //输入数据流
        TEE_DigestUpdate(op, input, sizeof(input));
        uint32_t hash_len = TEE_HASH_SHA256_SIZE;

        //计算最终哈希，存入entries[i].hash
        res = TEE_DigestDoFinal(op, NULL, 0, entries[i].hash, &hash_len);
        if (res != TEE_SUCCESS) goto exit;
        
        //更新prev_hash
        memcpy(prev_hash, entries[i].hash, TEE_HASH_SHA256_SIZE);
        TEE_FreeOperation(op);
        op = TEE_HANDLE_NULL;
    }
    
exit:
    if (op != TEE_HANDLE_NULL) TEE_FreeOperation(op);
    return res;
}

//REE写入消息的流程:REE检查队列容量→写入数据→更新head指针→通知TEE
//将controlflow_batch放入共享内存的环形队列
static TEE_Result enqueue_batch(struct shared_mem_ctx *ctx, struct controlflow_batch *batch) {
    DMSG("Enqueuing batch (size:%lu)", batch->batch_size);
    uint32_t head, tail, free_space;
    const uint32_t buffer_size = ctx->ctrl->buffer_size;
    TEE_Result res = TEE_SUCCESS;
    
    //原子加载队列状态
    head = atomic_load_explicit(&ctx->ctrl->head, memory_order_acquire);
    tail = atomic_load_explicit(&ctx->ctrl->tail, memory_order_acquire);
    DMSG("Queue status: head=%u, tail=%u, free=%u", 
        head, tail, (ctx->ctrl->buffer_size + tail - head - 1) % ctx->ctrl->buffer_size);
    //计算队列剩余空间
    free_space = (buffer_size + tail - head - 1) % buffer_size;
    
    if (free_space < batch->batch_size)
        return TEE_ERROR_SHORT_BUFFER;
    
    //获取基线锁,确保baseline在更新时不会被其他线程修改
    while (atomic_exchange_explicit(&ctx->baseline->locked, 1, memory_order_acq_rel) != 0)
        TEE_Wait(10);
    
    //生成哈希链
    uint8_t *initial_hash = ctx->baseline->initial_hash;
    //计算初始哈希值
    if (head != 0) { // 非首条数据，使用前一区块末哈希
        uint32_t last_pos = (head - 1) % buffer_size;
        memcpy(initial_hash, ctx->data_area[last_pos].hash, TEE_HASH_SHA256_SIZE);
    }
    
    res = generate_hash_chain(batch->data, batch->batch_size, initial_hash);
    if (res != TEE_SUCCESS) {
        atomic_store_explicit(&ctx->baseline->locked, 0, memory_order_release);
        return res;
    }
    
    //获取队列锁
    while (atomic_exchange_explicit(&ctx->ctrl->lock, 1, memory_order_acq_rel) != 0)
        TEE_Wait(10);
    
    //写入数据
    for (uint32_t i = 0; i < batch->batch_size; i++) {
        uint32_t pos = (head + i) % buffer_size;
        memcpy(&ctx->data_area[pos], &batch->data[i], sizeof(struct controlflow_info));
    }
    
    // 更新队列头指针
    atomic_store_explicit(&ctx->ctrl->head, (head + batch->batch_size) % buffer_size, memory_order_release);
    atomic_store_explicit(&ctx->ctrl->lock, 0, memory_order_release);
    atomic_store_explicit(&ctx->baseline->locked, 0, memory_order_release);
    
    return TEE_SUCCESS;
}

static TEE_Result verify_chain_hash(struct shared_mem_ctx *ctx,
                                  uint32_t batch_size) {
    DMSG("Verifying chain (size:%u)", batch_size);
    TEE_OperationHandle op = TEE_HANDLE_NULL;
    uint8_t prev_hash[TEE_HASH_SHA256_SIZE];
    uint8_t calc_hash[TEE_HASH_SHA256_SIZE];
    TEE_Result res = TEE_SUCCESS;
    
    // 获取基线初始哈希
    memcpy(prev_hash, ctx->baseline->initial_hash, TEE_HASH_SHA256_SIZE);
    
    //遍历共享内存data_area，每次读取controlflow_info结构体，进行哈希验证
    for (uint32_t i = 0; i < batch_size; i++) {
        struct controlflow_info *info = &ctx->data_area[i];
        DMSG("Verifying entry %u: source_id=%" PRIu64 " hash=", 
            i, info->source_id);
        
        // 打印存储的哈希值
        for (int j = 0; j < TEE_HASH_SHA256_SIZE; j++) {
            DMSG_RAW("%02x", info->hash[j]);
        }
        DMSG_RAW("\n");
        uint8_t input[TEE_HASH_SHA256_SIZE + sizeof(uint64_t)*2];
        
        // 构造输入数据
        memcpy(input, prev_hash, TEE_HASH_SHA256_SIZE);
        memcpy(input + TEE_HASH_SHA256_SIZE, &info->source_id, sizeof(uint64_t));
        memcpy(input + TEE_HASH_SHA256_SIZE + sizeof(uint64_t), &info->addrto_offset, sizeof(uint64_t));
        
        // 计算哈希
        res = TEE_AllocateOperation(&op, TEE_ALG_SHA256, TEE_MODE_DIGEST, 0);
        if (res != TEE_SUCCESS) goto exit;
        
        TEE_DigestUpdate(op, input, sizeof(input));
        
        uint32_t hash_len = sizeof(calc_hash);
        res = TEE_DigestDoFinal(op, NULL, 0, calc_hash, &hash_len);
        if (res != TEE_SUCCESS) goto exit;
        
        // 对比哈希值
        if (memcmp(calc_hash, info->hash, TEE_HASH_SHA256_SIZE) != 0) {
            res = TEE_ERROR_SECURITY;
            goto exit;
        }
        
        memcpy(prev_hash, calc_hash, TEE_HASH_SHA256_SIZE);
        TEE_FreeOperation(op);
        op = TEE_HANDLE_NULL;
    }
    
exit:
    if (op != TEE_HANDLE_NULL) TEE_FreeOperation(op);
    return res;
}

//TEE读取与验证的需求：TEE读取数据→链式哈希验证→更新tail指针→处理验证结果
//从共享内存的环形队列读取controlflow_batch，调用verify_chain_hash进行哈希验证
static TEE_Result process_batch(struct shared_mem_ctx *ctx) {
    uint32_t head, tail, batch_size;
    TEE_Result res = TEE_SUCCESS;
    
    head = atomic_load_explicit(&ctx->ctrl->head, memory_order_acquire);
    tail = atomic_load_explicit(&ctx->ctrl->tail, memory_order_acquire);
    batch_size = (head >= tail) ? (head - tail) : (ctx->ctrl->buffer_size - tail + head);
    
    if (batch_size == 0) return TEE_SUCCESS;
    
    // 获取队列锁，检查lock是否被占用，如果已被其他线程使用，则等待10ms重新尝试。
    while (atomic_exchange_explicit(&ctx->ctrl->lock, 1, memory_order_acq_rel) != 0)
        TEE_Wait(10);
    
    res = verify_chain_hash(ctx, batch_size);

    //如果验证成功，将tail向前移动，表示数据已处理。
    if (res == TEE_SUCCESS) {
        atomic_store_explicit(&ctx->ctrl->tail, (tail + batch_size) % ctx->ctrl->buffer_size, 
                            memory_order_release);
    }
    //释放自旋锁，允许其他进程访问队列
    atomic_store_explicit(&ctx->ctrl->lock, 0, memory_order_release);
    return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx,
                                     uint32_t cmd_id,
                                     uint32_t param_types,
                                     TEE_Param params[4]) {
    struct shared_mem_ctx *ctx = (struct shared_mem_ctx *)sess_ctx;
    
    switch (cmd_id) {
    case TA_CMD_ENQUEUE:
        if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_MEMREF_INPUT)
            return TEE_ERROR_BAD_PARAMETERS;
        return enqueue_batch(ctx, params[0].memref.buffer);
        
    case TA_CMD_PROCESS:
        if (TEE_PARAM_TYPE_GET(param_types, 0) != TEE_PARAM_TYPE_VALUE_INOUT)
            return TEE_ERROR_BAD_PARAMETERS;
        params[0].value.a = process_batch(ctx);
        return TEE_SUCCESS;
        
    default:
        return TEE_ERROR_NOT_IMPLEMENTED;
    }
}