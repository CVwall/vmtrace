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
std::vector<long> info;      // extra value per frame, used differently by each policy
long refCount = 0;           // number of memory references so far
int hand = 0;                // next victim for FIFO / clock hand for Clock

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

// LRU: info[] holds the time of the last reference to each page
bool lru(Page page) {
    int i = findPage(page);
    if (i != -1) {
        info[i] = refCount;
        return false;
    }
    if ((int) frames.size() < maxFrames) {
        frames.push_back(page);
        info.push_back(refCount);
    } else {
        int victim = 0;
        for (int k = 1; k < maxFrames; k++)
            if (info[k] < info[victim]) victim = k;
        frames[victim] = page;
        info[victim] = refCount;
    }
    return true;
}

// Clock (second chance): info[] holds the 1-bit reference bit of each page
bool clockPolicy(Page page) {
    int i = findPage(page);
    if (i != -1) {
        info[i] = 1;
        return false;
    }
    if ((int) frames.size() < maxFrames) {
        frames.push_back(page);
        info.push_back(1);
    } else {
        // Skip (and clear) pages whose reference bit is set
        while (info[hand] == 1) {
            info[hand] = 0;
            hand = (hand + 1) % maxFrames;
        }
        frames[hand] = page;
        info[hand] = 1;
        hand = (hand + 1) % maxFrames;
    }
    return true;
}

// LFU: info[] holds how many times each page has been referenced
bool lfu(Page page) {
    int i = findPage(page);
    if (i != -1) {
        info[i]++;
        return false;
    }
    if ((int) frames.size() < maxFrames) {
        frames.push_back(page);
        info.push_back(1);
    } else {
        int victim = 0;
        for (int k = 1; k < maxFrames; k++)
            if (info[k] < info[victim]) victim = k;
        frames[victim] = page;
        info[victim] = 1;
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
    else if (policy == "lru") reference = lru;
    else if (policy == "clock") reference = clockPolicy;
    else if (policy == "lfu") reference = lfu;
    else usage();

    if (maxFrames < 1 || optind >= argc) usage();

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