#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

#define MAX_CMD_LEN 512

static struct kprobe kp = {
    .symbol_name = "do_execveat_common",
};

static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    char __user *filename = (char *)regs->di;
    char user_cmd[MAX_CMD_LEN] = {0};
    int len;

    len = strncpy_from_user(user_cmd, filename, MAX_CMD_LEN - 1);
    if (len > 0 && strstr(user_cmd, "docker")) {
        printk(KERN_INFO "[Monitor] Detected container command: %s\n", user_cmd);
        // 这里可以加入度量值生成逻辑
    }
    return 0;
}

static int __init container_monitor_init(void)
{
    int ret;
    kp.pre_handler = handler_pre;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_ERR "Failed to register kprobe\n");
        return ret;
    }
    printk(KERN_INFO "Container Lifecycle Monitor Loaded\n");
    return 0;
}

static void __exit container_monitor_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "Container Lifecycle Monitor Unloaded\n");
}

module_init(container_monitor_init);
module_exit(container_monitor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Monitor container lifecycle and generate measurements");
