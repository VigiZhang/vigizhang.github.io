---
layout: article
title:  "Honggfuzz Usage"
tags: fuzz
---

## Feedback-driven Fuzzing

Honggfuzz实现了如下feedback-guided fuzzing方法：
<!--more-->

1. (Linux) Hardware-based counter (instructions, branches)
2. (Linux) Intel BTS code coverage (kernel >= 4.2)
3. (Linux) Intel PT code coverage (kernel >= 4.2)
4. Sanitizer-coverage instrumentation (`-fsanitize-coverage=bb`)
5. Compile-time instrumentation (`-finstrument-functions`or`-fsanitize-coverage=trace-pc[-guard],indirect-calls,trace-cmp`or both)

hfuzz-clang会使用本机clang，所以本机clang的版本会对编译产生影响。

- `-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp` - clang >= 4.0
- `-fsanitize-coverage=bb` - clang >= 3.7
- `-finstrument-functions` - gcc or clang
- \[older, slower variant\] `-fsanitize-coverage=trace-pc,indirect-calls` - clang >= 3.9

使用hfuzz-clang时会默认添加编译选项`-fsanitize-coverage=trace-pc-guard,indirect-calls,trace-cmp`，所以确保本机clang大于等于4.0版本就没问题。并且，当使用hfuzz-clang时也会自动链接libhfuzz.a。

### Persistent Mode

**-P**选项将使用持久化模式进行fuzz。需要代码支持，两种可用持久化的代码如下：

1. LLVM-style LLVMFuzzerTestOneInput

```c
#include <inttypes.h>
#include <testlib.h>  // Our API to test

extern int LLVMFuzzerTestOneInput(uint8_t **buf, size_t *len);

int LLVMFuzzerTestOneInput(uint8_t *buf, size_t len) {
  _FuncFromFuzzedLib_(buf, len);
  return 0;
}
```

2. Fetching input with HF_ITER()

```c
#include <inttypes.h>
#include <testlib.h>  // Our API to test

// Get input from the fuzzer
extern void HF_ITER(uint8_t **buf, size_t *len);

int main(void) {
  for (;;) {
    uint8_t *buf;
    size_t len;
    HF_ITER(&buf, &len);
    _FuncFromFuzzedLib_(buf, len);
  }
  return 0;
}
```

使用命令类似于：

```shell
$ honggfuzz -P -z -f in -W out -- ./fuzz-target
```

其中，**-z**选项为使用Compile-time instrumentation，为默认项，可以不用加。

[Not Done Yet] 其余硬件辅助Fuzzing（Hardware-based counters / Intel BTS / Intel PT）见[Feedback-driven Fuzzing](<https://github.com/google/honggfuzz/blob/master/docs/FeedbackDrivenFuzzing.md>)

### Usage

根据以上，总结honggfuzz的使用方法为：

1. 使用hfuzz-clang编译目标程序

```shell
$ hfuzz-clang -O1 -fno-omit-frame-pointer -g -fsanitize=address fuzz-target.c -o fuzz-target
```

2. 使用honggfuzz进行fuzz

```shell
$ honggfuzz -P -S -f in -W out -- ./fuzz-target
```

其他一些重要的选项：

**\-\-sanitizers\|\-S** 启用sanitizers

**\-\-threads\|\-n VALUE** 线程数 (default: number of CPUs / 2)

**\-\-dict\|\-w** 字典

**\-\-noinst\|\-x** 不使用任何插桩反馈（包括软硬件方式）

**\-\-monitor\_sigabrt VALUE** 监控SIGABRT (default: false for Android, true for other platforms)

**\-\-mutate\_cmd\|\-c VALUE** 使用外部命令产生fuzz files (instead of internal mutators)

其他的选项见honggfuzz -h。

此外，输入数据可从标准输入**-s**`read(0, buf, sizeof(buf))`或者文件`___FILE___`中读取。

## Use External Fuzzer

Honggfuzz提供**-c**选项调用外部Fuzzer。

1. 从input files中随机选取一个文件，保存为.honggfuzz文件。
2. 执行外部指定程序对.honggfuzz文件进行变异处理。
3. honggfuzz会等待外部程序运行结束。
4. honggfuzz执行fuzz target，使用外部程序处理过的文件。

[Not Done Yet] 能否结合libprotobuf-mutator?

## Honggfuzz NetDriver

Honggfuzz提供了netdriver库可以fuzz socket类程序。只需要将程序main改成HFND_FUZZING_ENTRY_FUNCTION即可。

例子程序见Appendix A。Honggfuzz会自动根据二进制签名使用libhfnetdriver，或者可以指定**-netdriver**选项，或者编译链接时带上libhfnetdriver.a。

例子程序中默认开启5001端口，fuzz时需要指定环境变量HFND_TCP_PORT=5001。

编译：

```shell
$ hfuzz-clang -O1 -fno-omit-frame-pointer -g -fsanitize=address vuln.c -o vuln
```

运行：

```shell
$ HFND_TCP_PORT=5001 ../../honggfuzz -f in -W out -- ./vuln
```



## Appendix

### A

```c
#include <crypt.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* Do nothing with first message */
void handleData0(char *data, int len) {
    printf("Auth success\n");
}

/* Second message is stack based buffer overflow */
void handleData1(char *data, int len) {
    char buff[8];
    bzero(buff, 8);
    memcpy(buff, data, len);
    printf("Handledata1: %s\n", buff);
}

/* Third message is heap overflow */
void handleData2(char *data, int len) {
    char *buff = malloc(8);
    bzero(buff, 8);
    memcpy(buff, data, len);
    printf("Handledata2: %s\n", buff);
    free(buff);
}

void handleData3(char *data, int len) {
    printf("Meh: %i\n", len);
}

void handleData4(char *data, int len) {
    printf("Blah: %i\n", len);
}

void doprocessing(int sock) {
    char data[1024];
    int n = 0;
    int len = 0;

    while (1) {
        bzero(data, sizeof(data));
        len = read(sock, data, 1024);

        if (len == 0 || len <= 1) {
            return;
        }

        printf("Received data with len: %i on state: %i\n", len, n);
        switch (data[0]) {
            case 'A':
                handleData0(data, len);
                write(sock, "ok", 2);
                break;
            case 'B':
                handleData1(data, len);
                write(sock, "ok", 2);
                break;
            case 'C':
                handleData2(data, len);
                write(sock, "ok", 2);
                break;
            case 'D':
                handleData3(data, len);
                write(sock, "ok", 2);
                break;
            case 'E':
                handleData4(data, len);
                write(sock, "ok", 2);
                break;
            default:
                return;
        }

        n++;
    }
}

HFND_FUZZING_ENTRY_FUNCTION(int argc, char *argv[]) {
    int sockfd, newsockfd, portno, clilen;
    char buffer[256];
    struct sockaddr_in serv_addr, cli_addr;
    int n, pid;

    if (argc == 2) {
        portno = atoi(argv[1]);
    } else {
        portno = 5001;
    }

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("ERROR opening socket");
        exit(1);
    }

    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEPORT, (const char *)&reuse, sizeof(reuse)) < 0)
        perror("setsockopt(SO_REUSEPORT) failed");

    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(portno);

    printf("Listening on port: %i\n", portno);

    /* Now bind the host address using bind() call.*/
    if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("ERROR on binding");
        exit(1);
    }

    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    while (1) {
        newsockfd = accept(sockfd, (struct sockaddr *)&cli_addr, &clilen);
        if (newsockfd < 0) {
            perror("ERROR on accept");
            exit(1);
        }
        printf("New client connected\n");
        doprocessing(newsockfd);
        printf("Closing...\n");
        shutdown(newsockfd, 2);
        close(newsockfd);
    }
}
```
