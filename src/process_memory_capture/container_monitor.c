#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/crypto.h>
#include <linux/fs.h>
#include <linux/crypto.h>      // 新增
#include <crypto/hash.h>       // 新增
#include <crypto/sha.h>        // 新增

#define TASK_COMM_LEN 16
#define HASH_BUF_SIZE 1024

static struct kprobe docker_kp;

// 完整性度量结构体
struct container_event {
    char event_type[20];
    char container_id[64];
    char image_hash[65];
    char parent_comm[TASK_COMM_LEN];
};

struct sdesc {                 // 新增包装结构体
    struct shash_desc shash;
    char ctx[];
};


// 计算文件SHA256哈希
static void calculate_hash(const char *path, char *output) {
    struct file *file = NULL;
    char buf[HASH_BUF_SIZE] = {0};
    loff_t pos = 0;
    struct crypto_shash *tfm = NULL;
    struct sdesc *desc = NULL;
    int ret = 0;
    
    // 文件操作
    file = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        snprintf(output, SHA256_DIGEST_SIZE, "file_err");
        return;
    }

    // 分配哈希算法（参考网页58）
    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        ret = PTR_ERR(tfm);
        goto cleanup_file;
    }

    // 分配描述符内存（含算法上下文空间）
    int desc_size = sizeof(struct shash_desc) + crypto_shash_descsize(tfm);
    desc = kmalloc(desc_size, GFP_KERNEL);
    if (!desc) {
        ret = -ENOMEM;
        goto cleanup_tfm;
    }
    desc->shash.tfm = tfm;

    ret = crypto_shash_init(&desc->shash);
    if (ret)
        goto cleanup_desc;

    // 分块计算哈希
    while ((ret = kernel_read(file, buf, HASH_BUF_SIZE, &pos)) > 0) {
        ret = crypto_shash_update(&desc->shash, buf, ret);
        if (ret)
            goto cleanup_desc;
        memset(buf, 0, HASH_BUF_SIZE); // 清空缓冲区防止信息泄漏
    }

    // 处理读取错误
    if (ret < 0)
        goto cleanup_desc;

    // 最终哈希计算
    ret = crypto_shash_final(&desc->shash, output);
    if (ret)
        goto cleanup_desc;

cleanup_desc:
    kfree(desc);
cleanup_tfm:
    crypto_free_shash(tfm);
cleanup_file:
    filp_close(file, NULL);
    
    // 错误处理
    if (ret) {
        snprintf(output, SHA256_DIGEST_SIZE, "hash_err%d", abs(ret));
    }
}

// 监控处理函数
static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    struct task_struct *parent = current->real_parent;
    struct container_event event;
    char parent_comm[TASK_COMM_LEN];
    
    get_task_comm(parent_comm, parent);

    // 检测Docker守护进程
    if (strncmp(parent_comm, "dockerd", TASK_COMM_LEN) == 0 ||
        strncmp(parent_comm, "containerd", TASK_COMM_LEN) == 0) {
        
        // 获取容器ID（需根据实际环境调整）
        char *env_ptr = (char *)current->mm->env_start;
        while (env_ptr < (char *)current->mm->env_end) {
            if (strncmp(env_ptr, "CONTAINER_ID=", 13) == 0) {
                strncpy(event.container_id, env_ptr+13, 63);
                break;
            }
            env_ptr += strlen(env_ptr) + 1;
        }

        // 记录事件类型
        strncpy(event.event_type, "container_start", 19);
        strncpy(event.parent_comm, parent_comm, TASK_COMM_LEN-1);
        
        // 计算镜像哈希（示例路径）
        char image_path[256];
        snprintf(image_path, 255, "/var/lib/docker/containers/%s/config.v2.json", event.container_id);
        calculate_hash(image_path, event.image_hash);
        
        // 输出到内核日志
        printk(KERN_INFO "[Container Monitor] Event: %s | Container: %s | Image Hash: %s\n",
               event.event_type, event.container_id, event.image_hash);
    }
    return 0;
}

static int __init monitor_init(void) {
    docker_kp.pre_handler = handler_pre;
    docker_kp.symbol_name = "copy_process";
    
    if (register_kprobe(&docker_kp)) {
        printk(KERN_ERR "Failed to register kprobe\n");
        return -1;
    }
    printk(KERN_INFO "Container Monitor loaded\n");
    return 0;
}

static void __exit monitor_exit(void) {
    unregister_kprobe(&docker_kp);
    printk(KERN_INFO "Container Monitor unloaded\n");
}

module_init(monitor_init);
module_exit(monitor_exit);
MODULE_LICENSE("GPL");