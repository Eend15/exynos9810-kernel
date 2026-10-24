// SPDX-License-Identifier: GPL-2.0
/* Read-only KernelSU Next v3.4.2 status ABI for built-in SuSFS v1.5.5.
 * Keep the original prctl control ABI and report the real version/features.
 */
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/susfs.h>

static const char ksu_susfs_legacy_features[] =
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
 "CONFIG_KSU_SUSFS_SUS_PATH\n"
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
 "CONFIG_KSU_SUSFS_SUS_MOUNT\n"
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT
 "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_KSU_DEFAULT_MOUNT\n"
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT
 "CONFIG_KSU_SUSFS_AUTO_ADD_SUS_BIND_MOUNT\n"
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
 "CONFIG_KSU_SUSFS_SUS_KSTAT\n"
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_OVERLAYFS
 "CONFIG_KSU_SUSFS_SUS_OVERLAYFS\n"
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
 "CONFIG_KSU_SUSFS_TRY_UMOUNT\n"
#endif
#ifdef CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT
 "CONFIG_KSU_SUSFS_AUTO_ADD_TRY_UMOUNT_FOR_BIND_MOUNT\n"
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
 "CONFIG_KSU_SUSFS_SPOOF_UNAME\n"
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
 "CONFIG_KSU_SUSFS_ENABLE_LOG\n"
#endif
#ifdef CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS
 "CONFIG_KSU_SUSFS_HIDE_KSU_SUSFS_SYMBOLS\n"
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
 "CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG\n"
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
 "CONFIG_KSU_SUSFS_OPEN_REDIRECT\n"
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_SU
 "CONFIG_KSU_SUSFS_SUS_SU\n"
#endif
#ifdef CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT
 "CONFIG_KSU_SUSFS_HAS_MAGIC_MOUNT\n"
#endif
 "";

static int ksu_susfs_copy_status(void __user *arg, const char *value,
                                size_t capacity)
{
 size_t length = strlen(value) + 1;
 int error = 0;

 if (length > capacity)
  return -E2BIG;
 if (copy_to_user(arg, value, length))
  return -EFAULT;
 if (copy_to_user((char __user *)arg + capacity, &error, sizeof(error)))
  return -EFAULT;
 return 0;
}

int ksu_susfs_legacy_status(unsigned int cmd, void __user *arg)
{
 /* The manager invokes ksud from its root shell. Never expose a new
  * unprivileged query surface or allow any state-changing command here.
  */
 if (current_uid().val != 0)
  return -EPERM;
 switch (cmd) {
 case 0x555e1:
  return ksu_susfs_copy_status(arg, SUSFS_VERSION, 16);
 case 0x555e2:
  return ksu_susfs_copy_status(arg, ksu_susfs_legacy_features, 8192);
 case 0x555e3:
  return ksu_susfs_copy_status(arg, SUSFS_VARIANT, 16);
 default:
  return -EOPNOTSUPP;
 }
}
