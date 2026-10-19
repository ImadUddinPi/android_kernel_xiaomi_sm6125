#!/usr/bin/env python3
"""Apply KernelSU-Next manual hooks to a 4.14 kernel tree (run from the kernel root).

Anchored text replacement instead of a diff, so it survives line-number drift.
Idempotent: files that already contain the hook are skipped. Fails loudly if an anchor is missing.
"""
import os
import sys

HOOKS = [
    ("fs/exec.c", [
        ("int do_execve(struct filename *filename,\n",
         "#ifdef CONFIG_KSU\n"
         "__attribute__((hot))\n"
         "extern int ksu_handle_execveat(int *fd, struct filename **filename_ptr,\n"
         "\t\t\t\tvoid *argv, void *envp, int *flags);\n"
         "#endif\n\n"
         "int do_execve(struct filename *filename,\n"),
        ("\tstruct user_arg_ptr envp = { .ptr.native = __envp };\n\treturn do_execveat_common(AT_FDCWD, filename, argv, envp, 0);\n",
         "\tstruct user_arg_ptr envp = { .ptr.native = __envp };\n"
         "#ifdef CONFIG_KSU\n"
         "\tksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);\n"
         "#endif\n"
         "\treturn do_execveat_common(AT_FDCWD, filename, argv, envp, 0);\n"),
        ("\t\t.ptr.compat = __envp,\n\t};\n\treturn do_execveat_common(AT_FDCWD, filename, argv, envp, 0);\n",
         "\t\t.ptr.compat = __envp,\n\t};\n"
         "#ifdef CONFIG_KSU // 32-bit ksud and 32-on-64 support\n"
         "\tksu_handle_execveat((int *)AT_FDCWD, &filename, &argv, &envp, 0);\n"
         "#endif\n"
         "\treturn do_execveat_common(AT_FDCWD, filename, argv, envp, 0);\n"),
    ]),
    ("fs/open.c", [
        ("SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n{\n",
         "#ifdef CONFIG_KSU\n"
         "__attribute__((hot))\n"
         "extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,\n"
         "\t\t\t\tint *mode, int *flags);\n"
         "#endif\n\n"
         "SYSCALL_DEFINE3(faccessat, int, dfd, const char __user *, filename, int, mode)\n{\n"),
        ("\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n\n\tif (mode & ~S_IRWXO)",
         "\tunsigned int lookup_flags = LOOKUP_FOLLOW;\n\n"
         "#ifdef CONFIG_KSU\n"
         "\tksu_handle_faccessat(&dfd, &filename, &mode, NULL);\n"
         "#endif\n\n"
         "\tif (mode & ~S_IRWXO)"),
    ]),
    ("fs/read_write.c", [
        ("SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)\n{\n\tstruct fd f = fdget_pos(fd);\n\tssize_t ret = -EBADF;\n",
         "#ifdef CONFIG_KSU\n"
         "extern bool ksu_vfs_read_hook __read_mostly;\n"
         "extern __attribute__((cold)) int ksu_handle_sys_read(unsigned int fd,\n"
         "\t\t\t\tchar __user **buf_ptr, size_t *count_ptr);\n"
         "#endif\n\n"
         "SYSCALL_DEFINE3(read, unsigned int, fd, char __user *, buf, size_t, count)\n{\n"
         "\tstruct fd f = fdget_pos(fd);\n\tssize_t ret = -EBADF;\n\n"
         "#ifdef CONFIG_KSU\n"
         "\tif (unlikely(ksu_vfs_read_hook))\n"
         "\t\tksu_handle_sys_read(fd, &buf, &count);\n"
         "#endif\n"),
    ]),
    ("fs/stat.c", [
        ("SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,\n\t\tstruct stat __user *, statbuf, int, flag)\n{\n\tstruct kstat stat;\n\tint error;\n",
         "#ifdef CONFIG_KSU\n"
         "__attribute__((hot))\n"
         "extern int ksu_handle_stat(int *dfd, const char __user **filename_user,\n"
         "\t\t\t\tint *flags);\n"
         "#endif\n\n"
         "SYSCALL_DEFINE4(newfstatat, int, dfd, const char __user *, filename,\n\t\tstruct stat __user *, statbuf, int, flag)\n{\n\tstruct kstat stat;\n\tint error;\n\n"
         "#ifdef CONFIG_KSU\n"
         "\tksu_handle_stat(&dfd, &filename, &flag);\n"
         "#endif\n"),
    ]),
    ("kernel/reboot.c", [
        ("SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,\n\t\tvoid __user *, arg)\n{\n\tstruct pid_namespace *pid_ns = task_active_pid_ns(current);\n\tchar buffer[256];\n\tint ret = 0;\n",
         "#ifdef CONFIG_KSU\n"
         "extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);\n"
         "#endif\n\n"
         "SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int, cmd,\n\t\tvoid __user *, arg)\n{\n\tstruct pid_namespace *pid_ns = task_active_pid_ns(current);\n\tchar buffer[256];\n\tint ret = 0;\n\n"
         "#ifdef CONFIG_KSU\n"
         "\tksu_handle_sys_reboot(magic1, magic2, cmd, &arg);\n"
         "#endif\n"),
    ]),
]

def main():
    bad = 0
    for path, edits in HOOKS:
        if not os.path.exists(path):
            print(f"[x] missing {path}"); bad += 1; continue
        text = open(path, encoding="utf-8", errors="surrogateescape").read()
        if "CONFIG_KSU" in text:
            print(f"[=] {path}: already patched"); continue
        for old, new in edits:
            if text.count(old) != 1:
                print(f"[x] {path}: anchor matched {text.count(old)}x:\n{old}"); bad += 1; break
            text = text.replace(old, new)
        else:
            open(path, "w", encoding="utf-8", errors="surrogateescape").write(text)
            print(f"[+] {path}: patched ({len(edits)} edits)")
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()
