#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <tee_client_api.h>
#include <unistd.h>
#include <stdatomic.h>
#include <stdalign.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "shared_mem_ta.h"
#include "shared_mem_common.h"
#include "agent.h"

#define DEBUG_ENABLE 1

//用于格式化打印调试信息，在日志信息前添加[HOST]前缀，
#define DPRINTF(fmt, ...) \
    do { if (DEBUG_ENABLE) printf("[HOST] " fmt, ##__VA_ARGS__); } while (0)

struct test_ctx {
    TEEC_Context ctx;
    TEEC_Session sess;
    TEEC_SharedMemory shm;
    struct shared_mem_ctx *shm_ctx;  // 合并共享内存上下文管理
};

static void prepare_tee_session(struct test_ctx *ctx) {
    TEEC_UUID uuid = TA_SHARED_MEM_UUID;
    TEEC_Result res;
    uint32_t origin;
    TEEC_Operation op = {0};

    // 初始化 TEE 上下文
    if ((res = TEEC_InitializeContext(NULL, &ctx->ctx)) != TEEC_SUCCESS) {
        errx(1, "TEEC_InitializeContext failed: 0x%x", res);
    }
    DPRINTF("TEE context initialized.\n");

    // 使用共享内存创建者或非创建者模式
    if (!(ctx->shm_ctx = init_shared_mem(0))) {  // 参数0表示非创建者
        errx(1, "Failed to attach to agent's shared memory");
    }

    ctx->shm.buffer = ctx->shm_ctx->ctrl;
    ctx->shm.size = SHM_SIZE;  // 共享内存大小定义
    ctx->shm.flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;  // 设置内存访问权限

    DPRINTF("Registering shared memory at %p (size:%d)...\n", 
          ctx->shm.buffer, ctx->shm.size);
    if ((res = TEEC_RegisterSharedMemory(&ctx->ctx, &ctx->shm)) != TEEC_SUCCESS) {
        errx(1, "TEEC_RegisterSharedMemory failed: 0x%x", res);
    }
    DPRINTF("Shared memory registered successfully.\n");

    // 设置操作参数：传递整个共享内存引用
    //TEEC_MEMREF_WHOLE表示将传递一个完整的内存块memref
    op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE, TEEC_NONE);
    op.params[0].memref.parent = &ctx->shm;
    op.params[0].memref.offset = 0;//设置了内存引用的偏移量
    op.params[0].memref.size = ctx->shm.size;
    DPRINTF("op.paramTypes: 0x%x\n", op.paramTypes);
    DPRINTF("op.params[0].memref.parent: %p\n", op.params[0].memref.parent);
    DPRINTF("op.params[0].memref.size: %zu\n", op.params[0].memref.size);

    // 打开 TEE 会话
    DPRINTF("Opening TEE session...\n");
    if ((res = TEEC_OpenSession(&ctx->ctx, &ctx->sess, &uuid,
                              TEEC_LOGIN_PUBLIC, NULL, &op, &origin)) != TEEC_SUCCESS) {
        errx(1, "TEEC_OpenSession failed: 0x%x (origin 0x%x)", res, origin);
    }
    DPRINTF("TEE session opened.\n");
}


int main() {
    struct test_ctx ctx = {0};
    TEEC_Result res = TEEC_SUCCESS;
    uint32_t err_origin;

    prepare_tee_session(&ctx);
    DPRINTF("TEE session initialized\n");

    // 共享内存状态管理（合并重复初始化）
    struct shared_mem_ctx *shm_ctx = ctx.shm_ctx;
    DPRINTF("Connected to shared memory (Head:%u, Tail:%u)\n",
          atomic_load(&shm_ctx->ctrl->head),
          atomic_load(&shm_ctx->ctrl->tail));

    // 数据处理循环（添加错误处理）
    while (1) {
        uint32_t data_count = atomic_load(&shm_ctx->ctrl->data_count);
        if (data_count == 0) {
            DPRINTF("No more data to process\n");
            break;
        }

        // 原子锁处理（添加超时机制）
        int retries = 0;
        while (atomic_flag_test_and_set(&shm_ctx->ctrl->lock)) {
            if (++retries > 1000) {
                fprintf(stderr, "Lock acquisition timeout\n");
                goto cleanup;
            }
            usleep(100);
        }

        uint32_t head = atomic_load(&shm_ctx->ctrl->head);
        uint32_t tail = atomic_load(&shm_ctx->ctrl->tail);
        uint32_t buf_size = shm_ctx->ctrl->buffer_size;  // 使用非原子访问

        if (head == tail) {
            atomic_flag_clear(&shm_ctx->ctrl->lock);
            DPRINTF("No data after lock acquisition\n");
            break;
        }

        struct controlflow_batch *batch = &shm_ctx->data_area[head];
        DPRINTF("Processing batch with %lu entries\n", batch->batch_size);

        // 命令调用（优化参数传递）
        TEEC_Operation enqueue_op = {
            .paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_WHOLE, TEEC_NONE, TEEC_NONE, TEEC_NONE),
            .params[0].memref.parent = &ctx.shm
        };

        if ((res = TEEC_InvokeCommand(&ctx.sess, TA_CMD_ENQUEUE, &enqueue_op, &err_origin)) != TEEC_SUCCESS) {
            fprintf(stderr, "Enqueue failed: 0x%x (origin 0x%x)\n", res, err_origin);
            atomic_flag_clear(&shm_ctx->ctrl->lock);
            goto cleanup;
        }

        atomic_store(&shm_ctx->ctrl->head, (head + 1) % buf_size);
        atomic_fetch_sub(&shm_ctx->ctrl->data_count, 1);
        atomic_flag_clear(&shm_ctx->ctrl->lock);
    }

    // 最终处理命令
    TEEC_Operation process_op = {
        .paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT, TEEC_NONE, TEEC_NONE, TEEC_NONE)
    };

    DPRINTF("Invoking TA_CMD_PROCESS...\n");
    if ((res = TEEC_InvokeCommand(&ctx.sess, TA_CMD_PROCESS, &process_op, &err_origin)) != TEEC_SUCCESS) {
        fprintf(stderr, "Process failed: 0x%x (TA error: 0x%x)\n", res, process_op.params[0].value.a);
    }

cleanup:
    // 资源释放（优化释放顺序）
    TEEC_ReleaseSharedMemory(&ctx.shm);
    cleanup_shared_mem(ctx.shm_ctx);
    TEEC_CloseSession(&ctx.sess);
    TEEC_FinalizeContext(&ctx.ctx);
    DPRINTF("TEE resources released\n");

    return (res == TEEC_SUCCESS) ? EXIT_SUCCESS : EXIT_FAILURE;
}