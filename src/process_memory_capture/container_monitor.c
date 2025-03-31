#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/crypto.h>
#include <linux/fs.h>
#include <crypto/hash.h>
#include <linux/uaccess.h>  // 新增用户空间访问头文件
#include <linux/vmalloc.h>

#define TASK_COMM_LEN 16
#define HASH_BUF_SIZE 1024
#define SHA256_DIGEST_SIZE 32

static struct kprobe docker_kp;

// 完整性度量结构体
struct container_event {
    char event_type[20];
    char container_id[64];
    char image_hash[65];      // 调整为64字节+1结束符
    char parent_comm[TASK_COMM_LEN];
};

struct sdesc {
    struct shash_desc shash;
    char ctx[];
};

// 安全获取容器ID函数（新增）
static int safe_get_container_id(char *buf, int size) 
{
    struct mm_struct *mm = current->mm;
    unsigned long env_start = mm->env_start;
    unsigned long env_end = mm->env_end;
    char tmp[64] = {0};
    int ret = -ENOENT;

    // 使用访问用户空间的安全函数
    if (env_start >= env_end)
        return ret;

    long env_len = env_end - env_start;
    char *env = vmalloc(env_len);
    if (!env)
        return -ENOMEM;

    if (copy_from_user(env, (const char __user *)env_start, env_len)) {
        vfree(env);
        return -EFAULT;
    }

    char *cur = env;
    while (cur < env + env_len) {
        if (strncmp(cur, "CONTAINER_ID=", 13) == 0) {
            strscpy(tmp, cur + 13, sizeof(tmp));
            ret = 0;
            break;
        }
        cur += strlen(cur) + 1;
    }

    if (!ret)
        strscpy(buf, tmp, size);

    vfree(env);
    return ret;
}

// 计算文件SHA256哈希（关键修改）
static void calculate_hash(const char *path, char *output) 
{
    struct file *file = NULL;
    char buf[HASH_BUF_SIZE] __aligned(8); // 确保内存对齐
    loff_t pos = 0;
    struct crypto_shash *tfm = NULL;
    struct sdesc *desc = NULL;
    int ret = 0;

    file = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(file)) {
        strscpy(output, "file_err", SHA256_DIGEST_SIZE);
        return;
    }

    tfm = crypto_alloc_shash("sha256", 0, 0);
    if (IS_ERR(tfm)) {
        ret = PTR_ERR(tfm);
        goto cleanup_file;
    }

    int desc_size = sizeof(struct shash_desc) + crypto_shash_descsize(tfm);
    desc = kzalloc(desc_size, GFP_KERNEL);
    if (!desc) {
        ret = -ENOMEM;
        goto cleanup_tfm;
    }
    desc->shash.tfm = tfm;

    ret = crypto_shash_init(&desc->shash);
    if (ret)
        goto cleanup_desc;

    ssize_t read_size;
    while ((read_size = kernel_read(file, buf, HASH_BUF_SIZE, &pos)) > 0) {
        ret = crypto_shash_update(&desc->shash, buf, read_size);
        if (ret)
            goto cleanup_desc;
        memset(buf, 0, HASH_BUF_SIZE);
    }

    if (read_size < 0) {  // 处理读取错误
        ret = read_size;
        goto cleanup_desc;
    }

    ret = crypto_shash_final(&desc->shash, output);
    if (ret)
        goto cleanup_desc;

cleanup_desc:
    kfree(desc);
cleanup_tfm:
    crypto_free_shash(tfm);
cleanup_file:
    filp_close(file, NULL);
    
    if (ret)
        snprintf(output, SHA256_DIGEST_SIZE, "hash_err%d", abs(ret));
}

// 监控处理函数（关键修改）
static int handler_pre(struct kprobe *p, struct pt_regs *regs) 
{
    struct task_struct *parent = current->real_parent;
    struct container_event event = {};  // 显式初始化
    char parent_comm[TASK_COMM_LEN] = {0};
    
    get_task_comm(parent_comm, parent);

    if (strncmp(parent_comm, "dockerd", TASK_COMM_LEN) == 0 ||
        strncmp(parent_comm, "containerd", TASK_COMM_LEN) == 0) {
        
        // 使用安全方法获取容器ID
        if (safe_get_container_id(event.container_id, sizeof(event.container_id))) {
            strscpy(event.container_id, "unknown", sizeof(event.container_id));
        }

        strscpy(event.event_type, "container_start", sizeof(event.event_type));
        strscpy(event.parent_comm, parent_comm, sizeof(event.parent_comm));
        
        char image_path[256];
        snprintf(image_path, sizeof(image_path), 
                "/var/lib/docker/containers/%s/config.v2.json", 
                event.container_id);
        
        calculate_hash(image_path, event.image_hash);
        
        printk(KERN_INFO "[Container Monitor] Event: %s | Container: %s | Image Hash: %64phN\n",
               event.event_type, event.container_id, event.image_hash);
    }
    return 0;
}

static int __init monitor_init(void) 
{
    // 使用正确的系统调用符号（根据内核版本调整）
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,11,0)
    docker_kp.symbol_name = "__x64_sys_execve";
#else
    docker_kp.symbol_name = "sys_execve";
#endif

    docker_kp.pre_handler = handler_pre;
    
    int ret = register_kprobe(&docker_kp);
    if (ret) {
        printk(KERN_ERR "Failed to register kprobe: %d\n", ret);
        return ret;
    }
    printk(KERN_INFO "Container Monitor loaded\n");
    return 0;
}

static void __exit monitor_exit(void) 
{
    unregister_kprobe(&docker_kp);
    printk(KERN_INFO "Container Monitor unloaded\n");
}

module_init(monitor_init);
module_exit(monitor_exit);
MODULE_LICENSE("GPL");