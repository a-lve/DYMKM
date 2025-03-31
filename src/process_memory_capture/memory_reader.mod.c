#include <linux/module.h>
#define INCLUDE_VERMAGIC
#include <linux/build-salt.h>
#include <linux/elfnote-lto.h>
#include <linux/vermagic.h>
#include <linux/compiler.h>

BUILD_SALT;
BUILD_LTO_INFO;

MODULE_INFO(vermagic, VERMAGIC_STRING);
MODULE_INFO(name, KBUILD_MODNAME);

__visible struct module __this_module
__section(".gnu.linkonce.this_module") = {
	.name = KBUILD_MODNAME,
	.init = init_module,
#ifdef CONFIG_MODULE_UNLOAD
	.exit = cleanup_module,
#endif
	.arch = MODULE_ARCH_INIT,
};

#ifdef CONFIG_RETPOLINE
MODULE_INFO(retpoline, "Y");
#endif

static const struct modversion_info ____versions[]
__used __section("__versions") = {
	{ 0xcd6bb128, "module_layout" },
	{ 0x97bbd22c, "param_ops_int" },
	{ 0x67471419, "get_pid_task" },
	{ 0x279e157d, "find_get_pid" },
	{ 0xc22521c7, "filp_open" },
	{ 0xd0da656b, "__stack_chk_fail" },
	{ 0x67d729f5, "kernel_write" },
	{ 0xcbd4898c, "fortify_panic" },
	{ 0xa916b694, "strnlen" },
	{ 0x87a21cb3, "__ubsan_handle_out_of_bounds" },
	{ 0x656e4a6e, "snprintf" },
	{ 0x37a0cba, "kfree" },
	{ 0x2782e7c5, "crypto_shash_digest" },
	{ 0x356d8995, "crypto_destroy_tfm" },
	{ 0xeb233a45, "__kmalloc" },
	{ 0x3e358609, "crypto_alloc_shash" },
	{ 0x97651e6c, "vmemmap_base" },
	{ 0x800473f, "__cond_resched" },
	{ 0x3a0533f3, "get_user_pages_remote" },
	{ 0x7cd8d75e, "page_offset_base" },
	{ 0x905fbf70, "pv_ops" },
	{ 0xdad13544, "ptrs_per_p4d" },
	{ 0x8a35b432, "sme_me_mask" },
	{ 0x1d19f77b, "physical_mask" },
	{ 0xa648e561, "__ubsan_handle_shift_out_of_bounds" },
	{ 0x72d79d83, "pgdir_shift" },
	{ 0xcb2f2b52, "boot_cpu_data" },
	{ 0x92997ed8, "_printk" },
	{ 0x2fd729f4, "filp_close" },
	{ 0xbdfb6dbb, "__fentry__" },
	{ 0x5b8239ca, "__x86_return_thunk" },
	{ 0x560215d4, "__put_page" },
	{ 0xd96ade86, "put_devmap_managed_page" },
	{ 0x587f22d7, "devmap_managed_key" },
};

MODULE_INFO(depends, "");


MODULE_INFO(srcversion, "2C53F43CA70C887B2F3C066");
