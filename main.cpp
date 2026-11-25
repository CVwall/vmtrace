#include <iostream>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/errno.h>
#include <linux/ptrace.h>
#include <sys/user.h>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

typedef unsigned long long Page;

int maxFrames = 10;          // -n: number of pages allocated to the process
std::vector<Page> frames;    // pages currently in memory
int hand = 0;                // next victim for FIFO

// Returns the frame holding the page, or -1 if not in memory
int findPage(Page page) {
    for (size_t i = 0; i < frames.size(); i++)
        if (frames[i] == page) return i;
    return -1;
}

// Each policy returns true on a page fault

// FIFO: replace the page that has been in memory the longest
bool fifo(Page page) {
    if (findPage(page) != -1) return false;
    if ((int) frames.size() < maxFrames) {
        frames.push_back(page);
    } else {
        frames[hand] = page;
        hand = (hand + 1) % maxFrames;
    }
    return true;
}

void usage() {
    fprintf(stderr, "Usage: vmtrace -p fifo|lru|clock|lfu [-n pages] command [args...]\n");
    exit(1);
}

int main(int argc, char* argv[]) {
    std::string policy;

    // '+' stops parsing at the command name, so its flags go to the tracee
    int opt;
    while ((opt = getopt(argc, argv, "+p:n:")) != -1) {
        switch (opt) {
            case 'p': policy = optarg; break;
            case 'n': maxFrames = atoi(optarg); break;
            default: usage();
        }
    }

    bool (*reference)(Page);
    if (policy == "fifo") reference = fifo;
    else usage();

    if (maxFrames < 1 || optind >= argc) usage();

    long refCount = 0;
    pid_t ch_pid = fork();
    if (ch_pid == 0) {
        // Tell parent to trace this process
        ptrace(static_cast<__ptrace_request>(PTRACE_TRACEME), getpid(), nullptr, nullptr);
        raise(SIGSTOP); // stop myself so the parent can start tracing
        execvp(argv[optind], &argv[optind]);
        perror("execvp");
        exit(1);
    } else {
        long page_size = sysconf(_SC_PAGE_SIZE);
        long pageFaults = 0;
        Page lastPage = 0;
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
            bool fault = reference(page_num);
            if (fault) pageFaults++;

            if (page_num != lastPage)
                printf("[%ld/%ld] at %llx Page %llx\n", refCount, pageFaults, mem_addr, page_num);
            lastPage = page_num;
            // Continue tracing to the next instruction of the child process
            ptrace((__ptrace_request) PTRACE_SINGLESTEP, ch_pid, nullptr, nullptr);
        }
        printf("\nPage Allocation: %d, RefCount: %ld, Page Faults: %ld (%.4f%%)\n",
               maxFrames, refCount, pageFaults, 100.0 * pageFaults / refCount);
    }
    return 0;
}