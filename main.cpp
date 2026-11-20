#include <iostream>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <linux/ptrace.h>
#include <sys/user.h>
#include <cstdio>

typedef unsigned long long Page;

int main(int argc, char* argv[]) {
    long refCount = 0;
    pid_t ch_pid = fork();
    if (ch_pid == 0) {
        // Tell parent to trace this process
        ptrace(static_cast<__ptrace_request>(PTRACE_TRACEME), getpid(), nullptr, nullptr);
        raise(SIGSTOP); // stop myself so the parent can start tracing
        char *args[] = {(char *) "./short-loop", nullptr};
        execvp(args[0], args);
    } else {
        long page_size = sysconf(_SC_PAGE_SIZE);
        int status;
        // Wait for the child to stop before starting to trace its instructions
        wait(nullptr);
        // Start tracing at the (first) instruction of the child process
        ptrace((__ptrace_request) PTRACE_SINGLESTEP, ch_pid, nullptr, nullptr);
        while (true) {
            wait(&status);
            if (WIFEXITED(status) || WIFSIGNALED(status)) break;
            // Get the address of the current instruction (rip register)
            user_regs_struct regs;
            ptrace((__ptrace_request) PTRACE_GETREGS, ch_pid, nullptr, &regs);
            Page mem_addr = regs.rip;
            Page page_num = mem_addr / page_size;

            refCount++;
            printf("[%ld] at %llx Page %llx\n", refCount, mem_addr, page_num);
            // Continue tracing to the next instruction of the child process
            ptrace((__ptrace_request) PTRACE_SINGLESTEP, ch_pid, nullptr, nullptr);
        }
        printf("\nRefCount: %ld\n", refCount);
    }
    return 0;
}