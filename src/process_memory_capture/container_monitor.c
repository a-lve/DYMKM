#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/security.h>
#include <linux/sched.h>
#include <crypto/hash.h>
#include <linux/slab.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>

#define HASH_ALGO "sha256"

static struct crypto_shash *tfm;

struct sdesc {
    struct shash_desc *shash;
    char ctx[];
};

static void hash_task_struct(struct task_struct *task, u8 *output)
{
    struct sdesc *desc;
    char data[128];
    int size;
    int ret;

    size = sizeof(struct shash_desc) + crypto_shash_descsize(tfm);
    desc = kmalloc(size, GFP_KERNEL);
    if (!desc)
        return;
    
    desc->shash = (struct shash_desc *)desc;
    desc->shash->tfm = tfm;
    
    snprintf(data, sizeof(data), "PID: %d PPID: %d Comm: %s", task->pid, task->real_parent->pid, task->comm);
    
    ret = crypto_shash_digest(desc->shash, data, strlen(data), output);
    if (ret)
        pr_err("Failed to compute hash\n");
    
    kfree(desc);
}

static int hook_task_alloc(struct task_struct *task, unsigned long clone_flags)
{
    u8 hash[32];
    hash_task_struct(task, hash);
    pr_info("[Monitor] Task created: PID=%d Comm=%s Hash=%*phN\n", task->pid, task->comm, 32, hash);
    return 0;
}

static void hook_task_free(struct task_struct *task)
{
    pr_info("[Monitor] Task exited: PID=%d Comm=%s\n", task->pid, task->comm);
}

static int hook_bprm_check_security(struct linux_binprm *bprm)
{
    pr_info("[Monitor] Executing: PID=%d Filename=%s\n", current->pid, bprm->filename);
    return 0;
}

static struct security_hook_list hooks[] = {
    LSM_HOOK_INIT(task_alloc, hook_task_alloc),
    LSM_HOOK_INIT(task_free, hook_task_free),
    LSM_HOOK_INIT(bprm_check_security, hook_bprm_check_security),
};

static __init int monitor_init(void)
{
    tfm = crypto_alloc_shash(HASH_ALGO, 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("Failed to allocate hash algorithm\n");
        return PTR_ERR(tfm);
    }

    security_add_hooks(hooks, ARRAY_SIZE(hooks), NULL);
    pr_info("Container lifecycle monitor initialized\n");
    return 0;
}

static __exit void monitor_exit(void)
{
    if (!IS_ERR_OR_NULL(tfm))
        crypto_free_shash(tfm);
    pr_info("Container lifecycle monitor exited\n");
}

DEFINE_LSM(container_monitor) = {
    .name = "container_monitor",
    .init = monitor_init,
};

module_exit(monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("a-lve");
MODULE_DESCRIPTION("Monitor container lifecycle and compute measurements");