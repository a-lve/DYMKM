static asmlinkage long my_execve(const struct pt_regs *regs)
{
    char __user *filename = (char *)regs->di;
    char user_filename[MAX_FILE_NAME_LEN] = {0};
    int len = 0, flag = 1;
    long copied = 0;
    char **argv = (char **)regs->si;
    int i = 0, j = 0;
    char file[BUF_SIZE] = {'\0'};
    char *image_names = NULL;
    char cmp_str[image_name_size] = {'\0'};
    char dirn[PATH_LEN] = {'\0'};
    int num = 0;

    mm_segment_t fs;
    loff_t pos;
    struct file *fp;
    int fsize;
    int kernel_read_num;
    char single_image[image_name_size] = {'\0'};
    char new_name[image_name_size] = {'\0'};
    int image_flag;
    int flag_vtpm = 0;

    copied = strncpy_from_user(user_filename, filename, len);

    strncpy(file, Project_path, BUF_SIZE);
    strcat(file, "images.log");

    len = strnlen_user(filename, MAX_FILE_NAME_LEN);
    if (unlikely(len >= MAX_FILE_NAME_LEN))
    {
        len = MAX_FILE_NAME_LEN - 1;
    }

    get_user_cmdline(argv, user_filename, MAX_FILE_NAME_LEN);

    if (strstr(user_filename, "docker pull"))
    {
        if (strstr(user_filename, "logger"))
        {
            docker_images(file);

            fp = filp_open(file, O_RDONLY, 0);
            if (IS_ERR(fp))
            {
                printk("create file error/n");
                return -1;
            }

            fsize = fp->f_inode->i_size;
            fs = get_fs();
            set_fs(KERNEL_DS);
            pos = 0;

            image_names = (char *)kmalloc(fsize, GFP_KERNEL);
            kernel_read_num = kernel_read(fp, image_names, BUF_SIZE, &pos);

            for (i = 0; i < kernel_read_num; i++)
            {
                if (image_names[i] != '\n')
                {
                    single_image[j] = image_names[i];
                    j++;
                    continue;
                }

                strcpy(new_name, single_image);
                name_change(new_name);
                image_flag = file_exist(Base_value_path, new_name);

                if (image_flag == 0 && (strstr(user_filename, single_image) != NULL))
                {
                    query_loc(Base_value_path, single_image, new_name);
                    base_generate(Base_value_path, new_name);
                }

                memset(single_image, 0x00, sizeof(single_image));
                memset(new_name, 0x00, sizeof(single_image));
                j = 0;
            }

            filp_close(fp, NULL);
            set_fs(fs);

            kfree(image_names);
            image_names = NULL;
            printk("Complete the base value calculation!");
            printk("OK!");
        }
    }

    if (strstr(user_filename, "docker run") || strstr(user_filename, "docker create"))
    {
        if (!strstr(user_filename, "logger"))
        {
            parse(cmp_str, image_record_path, user_filename);

            if (strcmp(cmp_str, "none") != 0)
            {
                flag = measure(Project_path, Base_value_path, cmp_str);

                if (flag == 1)
                {
                    printk("measure complete,It's ok! Create a new secure container ^_^ !");
                    printString("Measure OK !\n");
                    return old_execve(regs);
                }
                else if (flag == -2)
                {
                    printk("measure complete,It's wrong! Can't crate a new secure container!");
                    printString("The base value is attacked.\n");
                    return -1;
                }
                else
                {
                    printk("measure complete,It's wrong! Can't crate a new secure container! ");
                    printString("Measure error, images may have been attacked.\n");
                    return -1;
                }
            }
            else
            {
                printString("Please use docker pull to download the image firstly.");
                return -1;
            }
        }
    }

    if (strstr(user_filename, "/var/run/docker/runtime-runc/moby"))
    {
        if (strstr(user_filename, "start"))
        {
            j = 0;
            for (i = 0; i < strlen(user_filename); i++)
            {
                if (user_filename[i] == ' ' && user_filename[i - 1] == 'g' && user_filename[i - 2] == 'o' && user_filename[i - 3] == 'l' && user_filename[i - 4] == '-')
                {
                    num = 1;
                }
                if (num == 1 && (user_filename[i + 1] != ' '))
                {
                    dirn[j] = user_filename[i + 1];
                    j++;
                }
                if (user_filename[i + 1] == ' ')
                {
                    num = 0;
                }
            }
            if (j == 0)
            {
                printk(KERN_DEBUG "create vtpm error!");
                return -1;
            }
            flag_vtpm = end_replace(dirn, "/config.json");
            if (flag_vtpm == -1)
            {
                printk(KERN_DEBUG "create vtpm error!");
                return -1;
            }

            // 使用内核哈希算法替代TPM加密
            char hash[SHA256_DIGEST_SIZE] = {0};
            struct crypto_shash *tfm;
            struct shash_desc *desc;
            int ret;

            tfm = crypto_alloc_shash("sha256", 0, 0);
            if (IS_ERR(tfm)) {
                printk(KERN_ERR "Failed to allocate SHA-256 algorithm\n");
                return -1;
            }

            desc = kmalloc(sizeof(*desc) + crypto_shash_descsize(tfm), GFP_KERNEL);
            if (!desc) {
                crypto_free_shash(tfm);
                printk(KERN_ERR "Failed to allocate memory for shash_desc\n");
                return -1;
            }

            desc->tfm = tfm;

            ret = crypto_shash_digest(desc, dirn, strlen(dirn), hash);
            if (ret) {
                printk(KERN_ERR "Failed to compute SHA-256 hash\n");
                kfree(desc);
                crypto_free_shash(tfm);
                return -1;
            }

            kfree(desc);
            crypto_free_shash(tfm);

            // 将哈希值存储到文件中
            char hash_file[BUF_SIZE] = {'\0'};
            strncpy(hash_file, dirn, strlen(dirn));
            strcat(hash_file, "/hash.txt");

            struct file *f;
            mm_segment_t old_fs = get_fs();
            set_fs(KERNEL_DS);
            f = filp_open(hash_file, O_CREAT | O_WRONLY, 0644);
            if (IS_ERR(f)) {
                printk(KERN_ERR "Failed to open file for writing hash\n");
                set_fs(old_fs);
                return -1;
            }

            loff_t pos = 0;
            kernel_write(f, hash, SHA256_DIGEST_SIZE, &pos);
            filp_close(f, NULL);
            set_fs(old_fs);

            printk(KERN_INFO "SHA-256 hash computed and stored successfully\n");
        }
    }

    return old_execve(regs);
}