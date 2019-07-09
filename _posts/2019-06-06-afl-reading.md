---
layout: article
title:  "AFL源码阅读笔记"
tags: fuzzing
---

## afl-gcc.c

在使用AFL进行fuzz的整个生命周期中，第一环节就是使用afl-gcc这一编译入口进行源码编译插桩。

<!--more-->

其由如下3步组成：

```c
  /* [analysis] 1. afl-gcc主要进行了如下3步：
                   find_as查找可用as
                   edit_params处理参数
                   execvp执行
  */
  find_as(argv[0]);

  edit_params(argc, argv);

  execvp(cc_params[0], (char**)cc_params);
```

第一步查找可用afl-as，之后会分析afl-as插桩代码。

第二步调整运行参数，比如clang-mode会使用clang/clang++：

```c
    /* [analysis] 4. 如程序名为afl-clang++则尝试以AFL_CXX作为程序或使用clang++；
                     其余尝试以AFL_CC作为程序或使用clang
    */
    if (!strcmp(name, "afl-clang++")) {
      u8* alt_cxx = getenv("AFL_CXX");
      cc_params[0] = alt_cxx ? alt_cxx : (u8*)"clang++";
    } else {
      u8* alt_cc = getenv("AFL_CC");
      cc_params[0] = alt_cc ? alt_cc : (u8*)"clang";
    }
```

-B指定编译器as路径：

```c
  cc_params[cc_par_cnt++] = "-B"; // [analysis] 7. 指定编译器as路径
  cc_params[cc_par_cnt++] = as_path;
```

还有根据环境变量处理各种待运行参数等：

```c
  if (getenv("AFL_NO_BUILTIN")) {

    cc_params[cc_par_cnt++] = "-fno-builtin-strcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strncasecmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-memcmp";
    cc_params[cc_par_cnt++] = "-fno-builtin-strstr";
    cc_params[cc_par_cnt++] = "-fno-builtin-strcasestr";

  }
```

第三步执行编译器开始编译插桩。

## afl-as.c

afl-as用于对目标程序插桩，其获得目标编译架构：

```c
  /* [analysis] 2. 设定64位/32位 */
  for (i = 1; i < argc - 1; i++) {

    if (!strcmp(argv[i], "--64")) use_64bit = 1;
    else if (!strcmp(argv[i], "--32")) use_64bit = 0;
```

之后使用相应版本插桩代码进行插桩。

插桩时只插桩.text段：

```c
      /* [analysis] 6. 只插桩.text部分内容，设置instr_ok = 1，满足插桩条件 */
      if (!strncmp(line + 2, "text\n", 5) ||
          !strncmp(line + 2, "section\t.text", 13) ||
          !strncmp(line + 2, "section\t__TEXT,__text", 21) ||
          !strncmp(line + 2, "section __TEXT,__text", 21)) {
        instr_ok = 1;
        continue; 
      }
```

不对与设定插桩架构相反目标插桩：

```c
    /* [analysis] 7. 当.code所示的架构和真实架构相反时，设置skip_csect = 1，不满足插桩条件 */
    if (strstr(line, ".code")) {

      if (strstr(line, ".code32")) skip_csect = use_64bit;
      if (strstr(line, ".code64")) skip_csect = !use_64bit;

    }
```

不插桩intel syntax汇编：

```c
    /* [analysis] 8. 不对intel syntax汇编代码插桩。
                     当汇编代码为intel syntax时，设置skip_intel = 1，不满足插桩条件 
    */
    if (strstr(line, ".intel_syntax")) skip_intel = 1;
    if (strstr(line, ".att_syntax")) skip_intel = 0;
```

对非jmp的跳转（如ja），在下一行（即跳转失败分支）插桩：

```c
      /* [analysis] 10. 对jmp以外的跳转，在下一行插桩 */
      if (line[1] == 'j' && line[2] != 'm' && R(100) < inst_ratio) {

        fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
                R(MAP_SIZE));

        ins_lines++;

      }
```

跳转的目的地址（即跳转成功分支）和函数开头延迟插桩：

```c
    /* [analysis] 12. 延迟插桩 */
    if (!pass_thru && !skip_intel && !skip_app && !skip_csect && instr_ok &&
        instrument_next && line[0] == '\t' && isalpha(line[1])) {

      fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
              R(MAP_SIZE));

      instrument_next = 0;
      ins_lines++;

    }
```

## afl-as.h

afl-as.h头文件中包含了插桩代码，分为64和32两个版本，每个版本包含两部分：

1. 插桩代码trampoline
2. 插桩代码函数定义main payload

所涉及的函数有：

`__afl_maybe_log`

`__afl_store`

`__afl_return`

`__afl_setup`

`__afl_forkserver`

`__afl_fork_wait_loop`

`__afl_fork_resume`

`__afl_die`

`__afl_setup_abort`

64位和32位插桩代码功能相同，只是寄存器和指令格式不同，拿32位作例。

### trampoline

trampoline插桩到代码的分支点，用于路径覆盖率跟踪：

```c
  "\n"
  "/* --- AFL TRAMPOLINE (32-BIT) --- */\n"
  "\n"
  ".align 4\n"
  "\n"
  "leal -16(%%esp), %%esp\n"
  "movl %%edi,  0(%%esp)\n"
  "movl %%edx,  4(%%esp)\n"
  "movl %%ecx,  8(%%esp)\n"
  "movl %%eax, 12(%%esp)\n"
  "movl $0x%08x, %%ecx\n" /* [analysis] 1. 此处为fprintf参数R(MAP_SIZE)
                                           即0 ~ MAP_SIZE之间的随机数
                                           此随机数是用于标识此代码块的key
                          */
  "call __afl_maybe_log\n"
  "movl 12(%%esp), %%eax\n"
  "movl  8(%%esp), %%ecx\n"
  "movl  4(%%esp), %%edx\n"
  "movl  0(%%esp), %%edi\n"
  "leal 16(%%esp), %%esp\n"
  "\n"
  "/* --- END --- */\n"
  "\n";
```

可以看到，在程序运行到每一分支时，其实都会调用`__afl_maybe_log`函数。

需要注意的是，在使用`fprintf`插桩时，会将`R(MAP_SIZE)`写在`movl $0x%08x, %%ecx\n`处：

```c
      fprintf(outf, use_64bit ? trampoline_fmt_64 : trampoline_fmt_32,
              R(MAP_SIZE));
```

此`R(MAP_SIZE)`实际上会产生0 ~ MAP\_SIZE之间的随机数，作为此代码块的key值，传递给ecx寄存器。该key值标识区分了每个分支路径的区别。

### main payload

main payload则相对复杂，可以看到在`__afl_maybe_log`定义中，首先检查`__afl_area_ptr`所指共享内存区域是否已映射：

```c
  "__afl_maybe_log:\n"
  "\n"
  "  lahf\n"
  "  seto %al\n"
  "\n"
  "  /* Check if SHM region is already mapped. */\n"
  "\n"
  "  movl  __afl_area_ptr, %edx\n"  /* [analysis] 3. __afl_area_ptr所指共享内存区域是否已映射 */
  "  testl %edx, %edx\n"
  "  je    __afl_setup\n"
  "\n"
```

如果已映射，执行`__afl_store`覆盖率跟踪代码；如果未映射，则执行`__afl_setup`映射SHM及创建fork server。

1. 如果已映射便开始`__afl_store`，通过从ecx中获得代码块的key，与`__afl_prev_loc`异或作为index，对SHM作处理，来标记路径命中。

```c
  /* [analysis] 12. 此为计算存储代码块命中算法
                    利用ecx即代码块的key，与__afl_prev_loc异或作为index，对SHM作处理
                    伪代码由technical_details.txt中得：
                    cur_location = <COMPILE_TIME_RANDOM>;
                    shared_mem[cur_location ^ prev_location]++; 
                    prev_location = cur_location >> 1;
  */
#ifndef COVERAGE_ONLY
  "  movl __afl_prev_loc, %edi\n"
  "  xorl %ecx, %edi\n"
  "  shrl $1, %ecx\n"
  "  movl %ecx, __afl_prev_loc\n"
#else
  "  movl %ecx, %edi\n"
#endif /* ^!COVERAGE_ONLY */
  "\n"
#ifdef SKIP_COUNTS
  "  orb  $1, (%edx, %edi, 1)\n"
#else
  "  incb (%edx, %edi, 1)\n"
```

2. 如果SHM未映射，则进行`__afl_setup`。

`__afl_setup`首先映射SHM：

```c
  "  pushl $0          /* shmat flags    */\n"
  "  pushl $0          /* requested addr */\n"
  "  pushl %eax        /* SHM ID         */\n"
  "  call  shmat\n" /* [analysis] 5. 映射SHM，将指针保存到__afl_area_ptr和edx */
  "  addl  $12, %esp\n"
  "\n"
  "  cmpl $-1, %eax\n"
  "  je   __afl_setup_abort\n"
  "\n"
  "  /* Store the address of the SHM region. */\n"
  "\n"
  "  movl %eax, __afl_area_ptr\n"
  "  movl %eax, %edx\n"
```

然后进入fork server模式，fork server的代码需要和afl-fuzz.c代码一起阅读才能理解，这里先阐述代码功能，不理解等看到afl-fuzz.c该功能处再返回来看便能理解。

fork server向状态管道写4字节，通知fuzzer已准备完毕，可以开始fork进程执行程序：

```c
  "  pushl $4          /* length    */\n"
  "  pushl $__afl_temp /* data      */\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "  /* file desc */\n"
  "  call  write\n" /* [analysis] 6. 通知fuzzer准备完毕，可以开始fork */
  "  addl  $12, %esp\n"
```

然后开始循环等待读取控制管道命令，开始fork：

```c
  "  pushl $4          /* length    */\n"
  "  pushl $__afl_temp /* data      */\n"
  "  pushl $" STRINGIFY(FORKSRV_FD) "        /* file desc */\n"
  "  call  read\n"  /* [analysis] 7. 读取控制管道命令，fuzzer通知fork server开始fork */
  "  addl  $12, %esp\n"
```

fork后，fork server将fork出的子进程pid传递给fuzzer：

```c
  "  pushl $4              /* length    */\n"
  "  pushl $__afl_fork_pid /* data      */\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "      /* file desc */\n"
  "  call  write\n" /* [analysis] 8. 父进程将fork出的子进程pid传递给fuzzer */
  "  addl  $12, %esp\n"
```

等待子进程运行结束将子进程的结束状态传递给fuzzer：

```c
  "  pushl $0             /* no flags  */\n"
  "  pushl $__afl_temp    /* status    */\n"
  "  pushl __afl_fork_pid /* PID       */\n"
  "  call  waitpid\n" /* [analysis] 9. 等待子进程运行完毕 */
  "  addl  $12, %esp\n"
  "\n"
  "  cmpl  $0, %eax\n"
  "  jle   __afl_die\n"
  "\n"
  "  /* Relay wait status to pipe, then loop back. */\n"
  "\n"
  "  pushl $4          /* length    */\n"
  "  pushl $__afl_temp /* data      */\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "  /* file desc */\n"
  "  call  write\n" /* [analysis] 10. 将子进程运行结束状态传递给fuzzer */
  "  addl  $12, %esp\n"
```

而子进程将关闭其不需要使用的管道，继续执行程序，运行`__afl_store`，完成覆盖率跟踪执行：

```c
  "  pushl $" STRINGIFY(FORKSRV_FD) "\n"
  "  call  close\n" /* [analysis] 11. 子进程关闭不需要的管道并继续运行 */
  "\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "\n"
  "  call  close\n"
  "\n"
  "  addl  $8, %esp\n"
  "\n"
  "  popl %edx\n"
  "  popl %ecx\n"
  "  popl %eax\n"
  "  jmp  __afl_store\n"
```

上述fork server与fuzzer通信过程会在afl-fuzz.c代码阅读中对应体现。

## afl-fuzz.c

afl-fuzz.c是AFL的主要功能代码。其主要包括功能有（太多，列表并不详细，见下述代码阅读）：

- 处理输入输出目录
- 并行执行fuzz
- 设定fuzz资源参数（内存，字典等）
- 恢复继续执行fuzz
- 使用Qemu模式
- 变异文件
- 跟踪覆盖率
- 产生字典项
- favored & redundant优化
- 等等

AFL包括盲fuzz（dumb mode），覆盖率指导fuzz（instrument mode），Qemu辅助二进制文件fuzz（qemu mode）等多种fuzz方式。以下主要以阅读覆盖率指导fuzz为主视角。

### 准备部分

#### 参数及优化

首先处理参数部分不再详述，主要功能就是根据参数和环境变量标记功能是否开启，检查互斥参数。

然后进行一些优化准备工作，见注释：

```c
  /* [analysis] 13. 处理banner */
  fix_up_banner(argv[optind]);

  /* [analysis] 14. 检测是否在tty
                    可设置AFL_NO_UI强制设置not_on_tty
  */
  check_if_tty();

  /* [analysis] 15. 获取CPU核心数 */
  get_core_count();

#ifdef HAVE_AFFINITY
  /* [analysis] 16. 在Linux下，未设置AFL_NO_AFFINITY的情况下，尝试绑定fuzz进程到固定空闲CPU */
  bind_to_free_cpu();
#endif /* HAVE_AFFINITY */

  /* [analysis] 17. 检查确保crash dump不会自动使用其他程序打开
                    Linux下需临时设置 echo core > /proc/sys/kernel/core_pattern
  */
  check_crash_handling();
  /* [analysis] 18. 检查CPU调速器是否为ondemand，如果是，需设置为performance
                    原因是afl-fuzz会产生生命周期很短的进程，而内核调度算法并不能够很好感知
                    导致ondemand变频失效
                    需开启performance使CPU运行于最大频率
  */
  check_cpu_governor();

  /* [analysis] 19. 如存在AFL_POST_LIBRARY，尝试设置后置处理器 */
  setup_post();
  /* [analysis] 20. 初始化virgin_bits, virgin_tmout, virgin_crash
                    同时设置共享内存trace_bits
  */
  setup_shm();
  /* [analysis] 21. 设置count_class_lookup16[65536] */
  init_count_class16();
```

#### 输出目录

创建所需输出目录，子目录.state下将会在fuzz时保存所需要的信息：

```c
  /* [analysis] 35. 创建queue目录及子目录保存任何新发现的路径相关文件：
                    out_dir/queue
                    out_dir/queue/.state/ (保存任务元数据)
                    out_dir/queue/.state/deterministic_done/ (已标记跑完确定性变异的条目)
                    out_dir/queue/.state/auto_extras/ (自动选择产生的字典条目)
                    out_dir/queue/.state/redundant_edges/ (目前认为冗余的路径集)
                    out_dir/queue/.state/variable_behavior/ (多行为的路径集)
  */
  tmp = alloc_printf("%s/queue", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);
```

同步fuzz时，还会创建.synced子目录：

```c
  if (sync_id) {
    /* [analysis] 36. 多进程同步fuzz时，尝试创建out_dir/.synced/，可存在 */
    tmp = alloc_printf("%s/.synced/", out_dir);
```

此外还将创建用于保存crash和hang的子目录：

```c
  /* [analysis] 37. 创建out_dir/crashes和out_dir/hangs目录 */
  tmp = alloc_printf("%s/crashes", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);

  /* All recorded hangs. */

  tmp = alloc_printf("%s/hangs", out_dir);
  if (mkdir(tmp, 0700)) PFATAL("Unable to create '%s'", tmp);
  ck_free(tmp);
```

#### 输入目录

接着，开始处理输入目录。输入目录其中必须存在至少一个文件：

```c
  nl_cnt = scandir(in_dir, &nl, NULL, alphasort);
  /* [analysis] 41. in_dir中必须存在至少一个文件 */
  if (nl_cnt < 0) {

    if (errno == ENOENT || errno == ENOTDIR)
```

根据`AFL_SHUFFLE_QUEUE`环境变量对queue进行shuffle：

```c
  /* [analysis] 42. 若开启shuffle_queue，则shuffle输入queue文件 */
  if (shuffle_queue && nl_cnt > 1) {

    ACTF("Shuffling queue...");
    shuffle_ptrs((void**)nl, nl_cnt);
```

检查文件属性，并排除dot文件和README.txt：

```c
    /* [analysis] 43. 循环检查in_dir/[FILE]文件是否可访问，文件大小以及排除. ..和README.txt */
    if (lstat(fn, &st) || access(fn, R_OK))
      PFATAL("Unable to access '%s'", fn);

    /* This also takes care of . and .. */

    if (!S_ISREG(st.st_mode) || !st.st_size || strstr(fn, "/README.txt")) {
```

如果对应文件存在in_dir/.state/deterministic_done/[FILE]，则设置该文件项passed_det属性为1，在之后fuzz时将跳过deterministic变异阶段：

```c
    /* [analysis] 44. 如果存在对应in_dir/.state/deterministic_done/[FILE]，则passed_det = 1 */
    if (!access(dfn, F_OK)) passed_det = 1;
```

处理过的文件项加入queue中等待fuzz：

```c
    /* [analysis] 45. 将文件加入输入队列中 */
    add_to_queue(fn, st.st_size, passed_det);
```

#### 加载字典

加载字典分为加载“自动生成的字典”和“用户-x指定的字典”两种。

##### 自动生成的字典

读取in_dir/.state/auto_extras/auto_xxx，若长度合适，尝试加入自动生成的字典a_extras中。

```c
    /* [analysis] 47. 读取in_dir/.state/auto_extras/auto_xxx，如果长度合适，尝试加入字典 */
    if (len >= MIN_AUTO_EXTRA && len <= MAX_AUTO_EXTRA)
      maybe_add_auto(tmp, len);
```

之所以是尝试加入，是因为还会对其进行诸多检查。

如果其内容全部一样，忽略加入字典：

```c
  /* [analysis] 48. 若全部一样，则不予作为字典项 */
  for (i = 1; i < len; i++)
    if (mem[0] ^ mem[i]) break;
```

如果其与内置的interesting值（即一些内置的边界值和特殊值）相同，忽略加入字典：

```c
  /* [analysis] 49. 若与内置的interesting值相同，也不予作为字典项 */
  if (len == 2) {

    i = sizeof(interesting_16) >> 1;

    while (i--) 
      if (*((u16*)mem) == interesting_16[i] ||
          *((u16*)mem) == SWAP16(interesting_16[i])) return;
```

如果存在相同的用户自定义字典项，忽略加入字典：

```c
  /* [analysis] 50. 若已存在相同字典项，跳过（因为字典项已按大小排序(见60)，此处有优化） */
  for (i = 0; i < extras_cnt; i++)
    if (extras[i].len >= len) break;

  for (; i < extras_cnt && extras[i].len == len; i++)
    if (!memcmp_nocase(extras[i].data, mem, len)) return;
```

同理如果存在相同的已加入自动生成字典的字典项，忽略加入字典：

```c
  /* [analysis] 51. 同理检查自动生成字典a_extras中是否已存在相同条目 */
  auto_changed = 1;

  for (i = 0; i < a_extras_cnt; i++) {

    if (a_extras[i].len == len && !memcmp_nocase(a_extras[i].data, mem, len)) {

      a_extras[i].hit_cnt++;
      goto sort_a_extras;

    }

  }
```

检查通过会加入a_extras。

##### 用户-x指定的字典

用户-x指定的字典又分为“以文件格式”和“以目录格式”两种。

- “以文件格式”字典即-x指定字典文件，字典文件中包含各种name=value格式的字典项。加载这种格式的字典可以指定@level，每个字典项也可以指定@level，这样如果当字典项的@level大于所指定加载的@level时，会跳过加载。这是一种过滤字典项的方式：

```c
      /* [analysis] 58. file模式可以指定@level
                        如果字典项中的@level大于所指定@level时，会跳过，不予添加字典项
      */
      load_extras_file(dir, &min_len, &max_len, dict_level);
```

- “以目录格式”字典则是-x指定一个目录，其中包含每个字典项文件，文件中的内容即为字典项。

需要注意的是，加载完字典项后，用户自定义字典会进行大小排序，这有两点好处：

1. 在加载自动生成的字典项时会检测其是否存在在用户指定的字典项中，排序的字典可以根据大小快速过滤掉长度较小的字典项，而不做内存比较，这是一种优化。
2. 变异时，在依次使用字典项进行替换原文时，长度大的字典项可以覆盖掉长度小的字典项，而不用每次替换都作恢复原文操作，提高了性能。

用户自定义字典加载到extras中。

#### 其他准备工作

输入queue中的初始文件，会直接移至out_dir/queue/中（硬链接或拷贝）：

```c
      nfn = alloc_printf("%s/queue/id:%06u,orig:%s", out_dir, id, use_name);

#else

      nfn = alloc_printf("%s/queue/id_%06u", out_dir, id);

#endif /* ^!SIMPLE_FILES */

    }

    /* Pivot to the new queue entry. */
    /* [analysis] 54. 硬链接或拷贝输入queue中文件到out_dir/queue/ */
    link_or_copy(q->fname, nfn);
```

之前passed_det属性标记为1的文件会同样保存在out_dir/queue/.state/deterministic_done/中：

```c
    /* [analysis] 55. 已完成确定性变异的文件，同样保存到out_dir/queue/.state/deterministic_done/ */
    if (q->passed_det) mark_as_det_done(q);
```

resume模式下清理掉之前输出目录中的resume子目录：

```c
  /* [analysis] 56. resume模式下清理resume目录：
                    out_dir/_resume/.state/deterministic_done
                    out_dir/_resume/.state/auto_extras
                    out_dir/_resume/.state/redundant_edges
                    out_dir/_resume/.state/variable_behavior
                    out_dir/_resume/.state
                    out_dir/_resume
  */
  if (in_place_resume) nuke_resume_dir();
```

其他的一些准备工作见注释：

```c
  /* [analysis] 61. 当未设定timeout时，如果是resume模式，从fuzzer_stats中获取exec_timeout */
  if (!timeout_given) find_timeout();

  /* [analysis] 62. 检测文件输入标记@@ */
  detect_file_args(argv + optind + 1);

  /* [analysis] 63. 未指定-f选项情况下，创建out_dir/.cur_input */
  if (!out_file) setup_stdio_file();

  /* [analysis] 64. 检查目标程序格式是否满足fuzz条件 */
  check_binary(argv[optind]);

  start_time = get_cur_time();

  if (qemu_mode)
    /* [analysis] 72. qemu模式下，查找afl-qemu-trace */
    use_argv = get_qemu_argv(argv[0], argv + optind, argc - optind);
  else
    use_argv = argv + optind;
```

需要注意的是`check_binary`函数，它对目标fuzz程序进行了执行前最后的check工作。

目标fuzz程序不能在/tmp或/var/tmp目录中：

```c
  /* [analysis] 65. 程序不应该在/tmp或/var/tmp目录中 */
  if ((!strncmp(target_path, "/tmp/", 5) && !strchr(target_path + 5, '/')) ||
      (!strncmp(target_path, "/var/tmp/", 9) && !strchr(target_path + 9, '/')))
     FATAL("Please don't keep binaries in /tmp or /var/tmp");
```

目标fuzz程序不应该是shell script：

```c
  /* [analysis] 66. 排除shell script */
  if (f_data[0] == '#' && f_data[1] == '!') {
```

检查目标程序ELF或Mach-O格式头：

```c
/* [analysis] 67. 检查ELF或Mach-O格式头Magic */
#ifndef __APPLE__

  if (f_data[0] != 0x7f || memcmp(f_data + 1, "ELF", 3))
    FATAL("Program '%s' is not an ELF binary", target_path);

#else

  if (f_data[0] != 0xCF || f_data[1] != 0xFA || f_data[2] != 0xED)
    FATAL("Program '%s' is not a 64-bit Mach-O binary", target_path);
```

以及检查程序是否插桩，是否使用ASAN等。

到此，准备工作就绪。

### dry run

dry run就是依次使用最初的输入文件对目标程序执行一次，不对输入文件作变异，用以检查目标程序可执行性，创建fork server，生成初始路径bitmap以及寻找favorable的输入。

这一步骤主要功能叫做`calibrate_case`，即目的是使用新的输入queue entry执行程序以期提早发现问题，以及发现新的执行路径。

对每一queue entry，calibrate会执行多次，次数会受到`AFL_FAST_CAL`环境变量的影响：

```c
  /* [analysis] 75. AFL_FAST_CAL环境变量影响到stage_max是3还是8 */
  stage_name = "calibration";
  stage_max  = fast_cal ? 3 : CAL_CYCLES;
```

非盲fuzz（dumb mode）下，未设置`AFL_NO_FORKSRV`环境变量且fork server未初始化的情况下，会创建初始化fork server：

```c
  if (dumb_mode != 1 && !no_forkserver && !forksrv_pid)
    /* [analysis] 76. 插桩模式下，未设置AFL_NO_FORKSRV且fork server未初始化的情况下
                      初始化fork server
    */
    init_forkserver(argv);
```

#### fork server

这里就和afl-as.h插桩代码里的fork server代码对应起来。

`init_forkserver`首先创建两个管道用于进程间通信：状态管道 和 控制管道，然后fork：

```c
  /* [analysis] 77. 创建状态管道和控制管道 */
  if (pipe(st_pipe) || pipe(ctl_pipe)) PFATAL("pipe() failed");

  forksrv_pid = fork();
```

接着开始初始化fork server进程，即这里fork的子进程，包括：

```c
    /* [analysis] 78. (fork server进程) 设置进程可打开的最大文件描述符 */
    if (!getrlimit(RLIMIT_NOFILE, &r) && r.rlim_cur < FORKSRV_FD + 2) {

      r.rlim_cur = FORKSRV_FD + 2;
      setrlimit(RLIMIT_NOFILE, &r); /* Ignore errors */
```

```c
    /* [analysis] 79. (fork server进程) 设置进程最大虚拟内存空间 */
    if (mem_limit) {

      r.rlim_max = r.rlim_cur = ((rlim_t)mem_limit) << 20;

#ifdef RLIMIT_AS

      setrlimit(RLIMIT_AS, &r); /* Ignore errors */
```

```c
    /* [analysis] 80. (fork server进程) 设置内核不转存dump */
    r.rlim_max = r.rlim_cur = 0;

    setrlimit(RLIMIT_CORE, &r); /* Ignore errors */
```

```c
    /* [analysis] 81. (fork server进程) 设置fork server进程脱离终端 */
    setsid();

    /* [analysis] 82. (fork server进程) 重定向stdout和stderr到/dev/null */
    dup2(dev_null_fd, 1);
    dup2(dev_null_fd, 2);

    /* [analysis] 83. (fork server进程) 如果指定了out_file，将stdout重定向到/dev/null
                      否则克隆out_fd并将stdout重定向到它
    */
    if (out_file) {

      dup2(dev_null_fd, 0);

    } else {

      dup2(out_fd, 0);
      close(out_fd);

    }
```

fork server进程使用控制管道读，用于读取fuzzer传递的命令；状态管道写，用于将子进程退出状态传递给fuzzer：

```c
    /* [analysis] 84. (fork server进程) fork server进程使用控制管道读，状态管道写 */
    if (dup2(ctl_pipe[0], FORKSRV_FD) < 0) PFATAL("dup2() failed");
    if (dup2(st_pipe[1], FORKSRV_FD + 1) < 0) PFATAL("dup2() failed");

    close(ctl_pipe[0]);
    close(ctl_pipe[1]);
    close(st_pipe[0]);
    close(st_pipe[1]);
```

启用即时引用重定位提升性能，并设置ASAN|MSAN选项，执行程序：

```c
    /* [analysis] 85. (fork server进程) 启用即时引用重定位提升性能 */
    if (!getenv("LD_BIND_LAZY")) setenv("LD_BIND_NOW", "1", 0);

    /* Set sane defaults for ASAN if nothing else specified. */
    /* [analysis] 86. (fork server进程) 设置ASAN和MSAN options */
    setenv("ASAN_OPTIONS", "abort_on_error=1:"
                           "detect_leaks=0:"
                           "symbolize=0:"
                           "allocator_may_return_null=1", 0);

    /* MSAN is tricky, because it doesn't support abort_on_error=1 at this
       point. So, we do this in a very hacky way. */

    setenv("MSAN_OPTIONS", "exit_code=" STRINGIFY(MSAN_ERROR) ":"
                           "symbolize=0:"
                           "abort_on_error=1:"
                           "allocator_may_return_null=1:"
                           "msan_track_origins=0", 0);

    /* [analysis] 87. (fork server进程) 执行目标程序 */
    execv(target_path, argv);
```

fuzzer进程，即父进程会使用控制管道写，状态管道读，与fork server进行通信：

```c
  /* [analysis] 88. fuzzer进程使用控制管道写，状态管道读 */
  close(ctl_pipe[0]);
  close(st_pipe[1]);

  fsrv_ctl_fd = ctl_pipe[1];
  fsrv_st_fd  = st_pipe[0];
```

尝试读取状态管道信息，如果正常读出4个字节则说明fork server创建完成。这里与afl-as.h中的插桩代码相对应

。插桩代码中fork server会向状态管道写4个字节以说明fork server准备完毕：

```c
  "  pushl $4          /* length    */\n"
  "  pushl $__afl_temp /* data      */\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "  /* file desc */\n"
  "  call  write\n"		/* [analysis] 6. 通知fuzzer准备完毕，可以开始fork */
  "  addl  $12, %esp\n"
```

这里fuzzer接收这4个字节：

```c
  /* [analysis] 89. 读取状态管道信息，正常则说明fork server创建完成 */
  rlen = read(fsrv_st_fd, &status, 4);

  it.it_value.tv_sec = 0;
  it.it_value.tv_usec = 0;

  setitimer(ITIMER_REAL, &it, NULL);

  /* If we have a four-byte "hello" message from the server, we're all set.
     Otherwise, try to figure out what went wrong. */

  if (rlen == 4) {
    OKF("All right - fork server is up.");
    return;
  }
```

#### 执行程序记录路径

完成了fork server的初始化后，开始使用输入case进行目标程序执行。先进行`write_to_testcase`，将内存中修改好的data（后面进行变异时一样）保存成testcase，然后`run_target`：

```c
    write_to_testcase(use_mem, q->len);

    /* [analysis] 91. 执行目标程序 */
    fault = run_target(argv, use_tmout);
```

dumb mode或是设定了`AFL_NO_FORKSRV`的情况下，直接执行。

有fork server的情况下，fuzzer进程会往控制管道写命令，通知fork server开始fork子进程运行程序：

```c
    /* [analysis] 93. 发出命令使fork server开始fork子进程 */
    if ((res = write(fsrv_ctl_fd, &prev_timed_out, 4)) != 4) {
```

这里和afl-as.h中的插桩代码相对应，插桩代码读取了这个命令：

```c
  "  pushl $4          /* length    */\n"
  "  pushl $__afl_temp /* data      */\n"
  "  pushl $" STRINGIFY(FORKSRV_FD) "        /* file desc */\n"
  "  call  read\n"  /* [analysis] 7. 读取控制管道命令，fuzzer通知fork server开始fork */
  "  addl  $12, %esp\n"
```

开始fork，fork后将子进程pid通过状态管道传递给fuzzer：

```c
  "  pushl $4              /* length    */\n"
  "  pushl $__afl_fork_pid /* data      */\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "      /* file desc */\n"
  "  call  write\n" /* [analysis] 8. 父进程将fork出的子进程pid传递给fuzzer */
  "  addl  $12, %esp\n"
```

fuzzer获取pid等待进程执行完成：

```c
    /* [analysis] 94. 获取fork出的子进程pid */
    if ((res = read(fsrv_st_fd, &child_pid, 4)) != 4) {
```

子进程运行完成后将结束状态传递给fuzzer：

```c
  "  pushl $4          /* length    */\n"
  "  pushl $__afl_temp /* data      */\n"
  "  pushl $" STRINGIFY((FORKSRV_FD + 1)) "  /* file desc */\n"
  "  call  write\n" /* [analysis] 10. 将子进程运行结束状态传递给fuzzer */
  "  addl  $12, %esp\n"
```

fuzzer获取子进程结束状态：

```c
    /* [analysis] 95. 获取子进程退出状态 */
    if ((res = read(fsrv_st_fd, &status, 4)) != 4) {
```

至此，fuzzer与fork server的一次互相通信流程完成。

此次执行的程序路径，即`trace_bits`即为插桩代码中的SHM。执行完成后会根据一个算法来分类整理路径命中信息：

```c
  /* [analysis] 96. 重新按照count_class_lookup计算trace_bits bitmaps */
  tb4 = *(u32*)trace_bits;

#ifdef __x86_64__
  classify_counts((u64*)trace_bits);
#else
  classify_counts((u32*)trace_bits);
#endif /* ^__x86_64__ */
```

此算法实际上是分类整理了路径命中的次数，以免诸如代码每次循环都被认为是不同的路径问题。该算法原理见[AFL technical_details.txt](<https://github.com/mirrorer/afl/blob/master/docs/technical_details.txt>)的2) Detecting new behaviors。

算法使用了一张命中数分类对照表：

```c
static const u8 count_class_lookup8[256] = {

  [0]           = 0,
  [1]           = 1,
  [2]           = 2,
  [3]           = 4,
  [4 ... 7]     = 8,
  [8 ... 15]    = 16,
  [16 ... 31]   = 32,
  [32 ... 127]  = 64,
  [128 ... 255] = 128

};
```

即将同一路径的命中数分为多个档：0, 1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+。举例来说一个代码块命中了4次到7次都认为是同一路径，当命中8次就认为和命中4次的路径不同。这就可以排除大量冗余的路径重复问题。

整理完路径bitmap后，计算hash值，以比较发现是否走过了新的路径，命中数的改变返回1，新的代码块返回2：

```c
    /* [analysis] 98. 计算trace_bits hash，以发现是否有新的路径 */
    cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

    if (q->exec_cksum != cksum) {

      /* [analysis] 99. hit-count改变返回1，新的代码块路径返回2 */
      u8 hnb = has_new_bits(virgin_bits);
```

#### favorable

bitmap计算完，保存执行的各种状态到该testcase的各属性，之后会用于计算分数。然后AFL对此次执行的testcase做了`update_bitmap_score`，该函数会判断此testcase是否favorable，favorable的testcase会在之后的fuzz中被使用到：

```c
  q->exec_us     = (stop_us - start_us) / stage_max;
  q->bitmap_size = count_bytes(trace_bits);
  q->handicap    = handicap;
  q->cal_failed  = 0;

  total_bitmap_size += q->bitmap_size;
  total_bitmap_entries++;

  /* [analysis] 100. 判断是否more favorable，并更新top_rated bitmap */
  update_bitmap_score(q);
```

此函数`update_bitmap_score`和之后的`cull_queue`是一块功能，一起提出来分析。该部分技术原理可见[AFL technical_details.txt](<https://github.com/mirrorer/afl/blob/master/docs/technical_details.txt>)的4) Culling the corpus。

此块功能设置了一个名为`top_rated`的指针数组，其大小与SHM的大小相同，用于保存每一路径（即每一index）所对应的最小最快执行testcase指针。也就是说，`top_rated`里保存testcase指针，指向的每个testcase就是能达到该index路径的最小最快case。

##### update_bitmap_score

`update_bitmap_score`便是记录`top_rated`的函数，执行testcase过后，如果是新路径，则在`top_rated`中相应index直接保存该testcase，如果`top_rated`中已有该路径case，便使用执行速度和大小相乘结果来与原case比较，如果更小则替换到`top_rated`中：

```c
static void update_bitmap_score(struct queue_entry* q) {
/* [analysis] technical_details.txt 4) Culling the corpus [part 1]
              trace_bits[i]与top_rated[i]比较：
              如果还没有top_rated[i]，直接将q加入top_rated[i]
              如果已存在top_rated[i]，比较exec_us * len，将更快更小的q替换top_rated[i]
*/

  u32 i;
  u64 fav_factor = q->exec_us * q->len;

  /* For every byte set in trace_bits[], see if there is a previous winner,
     and how it compares to us. */

  for (i = 0; i < MAP_SIZE; i++)

    if (trace_bits[i]) {

       if (top_rated[i]) {

         /* Faster-executing or smaller test cases are favored. */

         if (fav_factor > top_rated[i]->exec_us * top_rated[i]->len) continue;
```

##### cull_queue

而之后会用到的`cull_queue`将从`top_rated`中取出case标记为favored，并为其他queue中的case建立reduntant标记文件。此功能类似于跑完一轮输入后，queue中保存了之前的testcase和新发现路径的testcase，通过`top_rated`选择出favored的testcase，其余的被“筛选”掉的便置为reduntant。favored的testcase将会更大概率被优先fuzz。

```c
static void cull_queue(void) {
/* [analysis] technical_details.txt 4) Culling the corpus [part 2]
              从top_rated[i]中取q标记为favored
              并为其他q创建out_dir/queue/.state/redundant_edges/[FILE]文件
*/
...
      while (j--) 
        if (top_rated[i]->trace_mini[j])
          temp_v[j] &= ~top_rated[i]->trace_mini[j];

      top_rated[i]->favored = 1;
      queued_favored++;

      if (!top_rated[i]->was_fuzzed) pending_favored++;

    }

  q = queue;

  while (q) {
    mark_as_redundant(q, !q->favored);
    q = q->next;
  }
```

在输入文件经过`calibrate_case`执行完后，dry run根据初始化输入文件的退出状态来“提早发现问题”，如果给予AFL的初始输入即造成timeout或crash等问题的话，AFL会提早退出并显示改进输入文件建议信息。

至此，dry run结束。

### fuzz

dry run结束后，AFL开始进行fuzz前的一些准备工作。

先使用上面提到的cull_queue清理queue，标记favored和redundant testcase：

```c
  /* [analysis] 103. 标记favored和redundant */
  cull_queue();
```

显示dry run运行结果，resume模式会从fuzzer_stats中找到继续开始的位置，保存fuzzer_stats文件和自动生成的字典项。

```c
  /* [analysis] 104. 显示初始化queue运行状态结果 */
  show_init_stats();

  /* [analysis] 105. 如果是resume模式，从fuzzer_stats中找到继续开始的位置 */
  seek_to = find_start_position();

  /* [analysis] 106. 保存fuzzer_stats文件和自动生成的字典项 */
  write_stats_file(0, 0, 0);
  save_auto();
```

睡眠暂停4秒就开始真正的fuzz阶段，fuzz阶段理论上是个无限循环，`queue_cur`（指向`queue`中的当前testcase）会每次循环指向next：

```c
    queue_cur = queue_cur->next;
```

每当`queue_cur`为空时，就相当于进行了一轮（cycle++），`queue_cur`重新指向`queue`：

```c
  if (!not_on_tty) {
    sleep(4);
    start_time += 4000;
    if (stop_soon) goto stop_fuzzing;
  }

  while (1) {

    u8 skipped_fuzz;

    /* [analysis] 107. 循环每次运行前先标记favored和redundant */
    cull_queue();

    if (!queue_cur) {

      /* [analysis] 147. 完成整个queue的fuzz后，queue_cycle++ */
      queue_cycle++;
      current_entry     = 0;
      cur_skipped_paths = 0;
      queue_cur         = queue;
```

之所以说是理论上，除了手动ctrl-c外，如果一次循环没有发现新的路径，尝试使用剪接策略变异fuzz，如果已使用，则`cycles_wo_finds++`，当`cycles_wo_finds`超过100时且设置了`AFL_EXIT_WHEN_DONE`环境变量则AFL会退出。

如果在同步进行fuzz，会同步其他fuzz的interesting case：

```c
        /* [analysis] 109. 同步其他fuzzer的interesting test cases */
        sync_fuzzers(use_argv);
```

完成了上述准备后，进入对当前testcase即`queue_cur`作fuzz的流程：

```c
    /* [analysis] 115. fuzz!!! */
    skipped_fuzz = fuzz_one(use_argv);
```

当存在未fuzz过的favored的testcase（`pending_favored`），且当前testcase已经被fuzz过，或者它并不是favored，那么将有99%的概率被跳过，这大大提高了新的favored的testcase的被fuzz率：

```c
  if (pending_favored) {

    /* If we have any favored, non-fuzzed new arrivals in the queue,
       possibly skip to them at the expense of already-fuzzed or non-favored
       cases. */
    /* [analysis] 116. 如果有新的favored的case，可能会跳过一些已fuzz过或非favored的case */
    if ((queue_cur->was_fuzzed || !queue_cur->favored) &&
        UR(100) < SKIP_TO_NEW_PROB) return 1;
```

而在非dumb mode下，即使没有新的favored的testcase，也会有可能跳过该testcase的fuzz。已fuzz过的有95%的概率被跳过，尚未fuzz过的有75%的概率被跳过：

```c
  /* [analysis] 117. 非dumb_mode下，非favored的case，也有可能被跳过
                     没有fuzz过的case跳过可能性比fuzz过的case跳过可能性低
  */
    if (queue_cycle > 1 && !queue_cur->was_fuzzed) {

      if (UR(100) < SKIP_NFAV_NEW_PROB) return 1;

    } else {

      if (UR(100) < SKIP_NFAV_OLD_PROB) return 1;

    }
```

如果之前calibration失败了，会重新进行calibration，以确保提早发现问题：

```c
  /* [analysis] 118. 之前calibration失败，重新calibrate */
  if (queue_cur->cal_failed) {

    u8 res = FAULT_TMOUT;

    if (queue_cur->cal_failed < CAL_CHANCES) {

      res = calibrate_case(argv, queue_cur, in_buf, queue_cycle - 1, 0);
```

尝试对当前testcase在不改变路径覆盖率的情况下裁剪大小：

```c
  /* [analysis] 119. trim case，尝试将待变异queue文件在不影响覆盖率的前提下裁剪大小 */
  if (!dumb_mode && !queue_cur->trim_done) {

    u8 res = trim_case(argv, queue_cur, in_buf);
```

这里的裁剪大小算法原理可见[AFL technical_details.txt](<https://github.com/mirrorer/afl/blob/master/docs/technical_details.txt>)的5) Trimming input files。

它将按序递增使用2的n次方作为长度删除块，并观察路径覆盖率有无收到影响来得到较小的testcase文件。

还记得之前favorable一节中执行完程序后记录的各种状态信息吗？AFL会使用这些信息来做一个分值计算用于优化fuzz。该分值称为**performance socre**，它由执行程序的exec_us，bitmap_size，handicap，depth来综合加权累计。

```c
  /* [analysis] 120. 根据queue_cur的exec_us，bitmap_size，handicap和depth计算分值 */
  orig_perf = perf_score = calculate_score(queue_cur);
```

计算出的`perf_socre`之后会用于fuzz变异时havoc变异阶段的循环次数计算。

开始真正的变异，变异大体上分为deterministic，havoc和splicing三个阶段。

如果指定了-d参数，即跳过deterministic变异阶段。如果在resume模式下，该testcase的passed_det属性为1，也会跳过deterministic变异阶段，直接开始havoc变异：

```c
  /* [analysis] 121. 指定了-d，或运行完确定性fuzzing，或在resume模式下passed_det为1，直接开始havoc */
  if (skip_deterministic || queue_cur->was_fuzzed || queue_cur->passed_det)
    goto havoc_stage;
```

如果进行的是同步fuzz，指定了-M参数，但其路径checksum与总master数相模，与masterid-1不符，也会直接开始havoc变异：

```c
  /* [analysis] 122.指定了-M，但其路径checksum和总master数相模，与masterid-1不符，直接开始havoc */
  if (master_max && (queue_cur->exec_cksum % master_max) != master_id - 1)
    goto havoc_stage;
```

这行代码不太明白，只知道-S的进程不会进行deterministic，直接havoc，而指定多个-M的功能也是实验功能（见[AFL parallel_fuzzing.txt](<https://github.com/mirrorer/afl/blob/master/docs/parallel_fuzzing.txt>)），这里可能也是使得即使使用多个-M的实验功能，也只让一个master进行deterministic变异吧。

#### determinisitc

deterministic变异阶段包含下列算法：

- bitflip 按位翻转
- arithmetic 算术加减
- interesting 特殊值替换
- dictionary 字典项替换/插入

##### bitflip

bitflip按位翻转变异会依次对testcase作如下操作：

- bitflip 1/1 每次翻转1bit，按照每1bit的步长进行

- bitflip 2/1 每次翻转2bits，按照每1bit的步长进行

- bitflip 4/1 每次翻转4bits，按照每1bit的步长进行

- bitflip 8/8 每次翻转1byte，按照每1byte的步长进行

- bitflip 16/8 每次翻转2bytes，按照每1byte的步长进行

- bitflip 32/8 每次翻转4bytes，按照每1byte的步长进行

其中值得注意的是在进行bitflip 1/1时，使用到了一个trick，使得AFL可能会找到可用作一段特定bits的magic token。原理是在一位一位翻转的过程中，每次会check路径checksum是否与上次一致，如果找到一段bits在它之前的checksum和之后的checksum都与其不同，而其本身每1bit的翻转得到的checksum都相同时，就判定为其可能为一段magic token，并加入自动生成字典a_extras：

```c
  /* [analysis] 124. 这里使用了一个trick来寻找可能的magic token，并将其加入字典
                     在按位翻转的过程中，会发现一段bits，其路径checksum与开头和结尾位翻转的checksum不一样
                     但是其自身内部翻转的路径checksum相同，就判定其可能是一个magic token
                     如：xxxxxxxxIHDRxxxxxxxx ，经过此trick可以找到IHDR可能为magic token
  */
    if (!dumb_mode && (stage_cur & 7) == 7) {

      u32 cksum = hash32(trace_bits, MAP_SIZE, HASH_CONST);

      if (stage_cur == stage_max - 1 && cksum == prev_cksum) {
```

而在进行bitflip 8/8时，又用到一个trick来判定每1byte是否为“有效”byte，即在翻转每个byte时，如果造成路径checksum变化，则标记该byte为“有效”，加入`eff_map`中，该`eff_map`会在之后的变异中多次被使用，来用于跳过“无效”的byte，提升fuzz性能：

```c
    /* [analysis] 125. 在bitflip 8/8时，使用了一个trick来标记每一byte是否“有效”
                       在每一byte进行翻转时，如果造成路径checksum不一致，则标记byte“有效”
                       “无效”的byte在之后的变异中会被跳过，提升性能，节省执行资源
    */
    if (!eff_map[EFF_APOS(stage_cur)]) {
```

注意，如果文件大小小于128字节则都标记为“有效”；且如果文件中90%以上的bytes都为“有效”的话，也会将所有bytes标记为“有效”。因为这两种情况利用`eff_map`过滤掉“无效”bytes也不会提升太多性能。

##### arithmetic

arithmetic算术加减变异会依次对testcase作如下操作：

- arith 8/8 每次对1byte算术运算，按照每1byte的步长进行
- arith 16/8 每次对2bytes算术运算，按照每1byte的步长进行
- arith 32/8 每次对4bytes算术运算，按照每1byte的步长进行

算术加减比较简单，需要注意的几点有：

1. 加减的值受`ARITH_MAX`影响，默认值为35。
2. 会跳过bitflip变异时已进行过的testcase：

```c
      /* [analysis] 129. 跳过bitflip进行过变异的fuzz */
      if (!could_be_bitflip(r)) {
```

3. 多字节会分别进行大顶端及小顶端处理。

##### interesting

interesting使用特殊值替换变异会依次对testcase作如下操作：

- interest 8/8 每次对1byte进行替换，按照每1byte的步长进行
- interest 16/8 每次对2bytes进行替换，按照每1byte的步长进行
- interest 32/8 每次对4bytes进行替换，按照每1byte的步长进行

interesting的值是AFL预设的一些边缘值和特殊值：

```c
#define INTERESTING_8 \
  -128,          /* Overflow signed 8-bit when decremented  */ \
  -1,            /*                                         */ \
   0,            /*                                         */ \
   1,            /*                                         */ \
   16,           /* One-off with common buffer size         */ \
   32,           /* One-off with common buffer size         */ \
   64,           /* One-off with common buffer size         */ \
   100,          /* One-off with common buffer size         */ \
   127           /* Overflow signed 8-bit when incremented  */

#define INTERESTING_16 \
  -32768,        /* Overflow signed 16-bit when decremented */ \
  -129,          /* Overflow signed 8-bit                   */ \
   128,          /* Overflow signed 8-bit                   */ \
   255,          /* Overflow unsig 8-bit when incremented   */ \
   256,          /* Overflow unsig 8-bit                    */ \
   512,          /* One-off with common buffer size         */ \
   1000,         /* One-off with common buffer size         */ \
   1024,         /* One-off with common buffer size         */ \
   4096,         /* One-off with common buffer size         */ \
   32767         /* Overflow signed 16-bit when incremented */

#define INTERESTING_32 \
  -2147483648LL, /* Overflow signed 32-bit when decremented */ \
  -100663046,    /* Large negative number (endian-agnostic) */ \
  -32769,        /* Overflow signed 16-bit                  */ \
   32768,        /* Overflow signed 16-bit                  */ \
   65535,        /* Overflow unsig 16-bit when incremented  */ \
   65536,        /* Overflow unsig 16 bit                   */ \
   100663045,    /* Large positive number (endian-agnostic) */ \
   2147483647    /* Overflow signed 32-bit when incremented */
```

也会跳过之前bitflip和arithmetic进行过的testcase。

##### dictionary

dictionary使用字典项替换/插入变异会依次对testcase作如下操作：

- user extras (over) 使用用户自定义字典项替换
- user extras (insert) 使用用户自定义字典项插入
- auto extras (over) 使用自动生成字典项替换

在user extras (over) 使用用户自定义字典项替换时，之前所述对字典项按大小排序的优化就使用到了。由于字典项由小到大排序，依次使用字典项替换原文时就可以对同一位置覆盖而不需要每次替换后恢复原文，这提高了fuzz性能。此外，当字典项超出`MAX_DET_EXTRAS`时，会有概率跳过此次覆盖；且当无空间覆盖，覆盖值与原文相同或替换字段“无效”时，则会跳过该次覆盖：

```c
    /* [analysis] 132. 由于字典项大小是从小到大排序的，这就省去了每次替换fuzz后恢复原文的操作
                       因为之后大的字典项会覆盖掉小的字典项
    */
    for (j = 0; j < extras_cnt; j++) {

      /* Skip extras probabilistically if extras_cnt > MAX_DET_EXTRAS. Also
         skip them if there's no room to insert the payload, if the token
         is redundant, or if its entire span has no bytes set in the effector
         map. */

      /* [analysis] 133. 当字典项超出MAX_DET_EXTRAS时，会有概率跳过该次覆盖
                         并且当无空间，覆盖值与原文相同或替换字段“无效”时，跳过该次覆盖
      */
      if ((extras_cnt > MAX_DET_EXTRAS && UR(extras_cnt) >= MAX_DET_EXTRAS) ||
          extras[j].len > len - i ||
          !memcmp(extras[j].data, out_buf + i, extras[j].len) ||
          !memchr(eff_map + EFF_APOS(i), 1, EFF_SPAN_ALEN(i, extras[j].len))) {

        stage_max--;
        continue;

      }
```

在user extras (insert) 使用用户自定义字典项插入时，使用的方法是拼接head+extra+tail，并没有对原文作改变，这样就省去了每次恢复原文的开销：

```c
      /* [analysis] 134. insert时其实是拼接head+extra+tail，不用还原case，token多时开销大 */
      /* Insert token */
      memcpy(ex_tmp + i, extras[j].data, extras[j].len);

      /* Copy tail */
      memcpy(ex_tmp + i + extras[j].len, out_buf + i, len - i);
```

使用自动生成的字典项时只有替换，没有插入，且最多使用`USE_AUTO_EXTRAS`个，默认为50：

```c
    /* [analysis] 135. 自动生成的字典项最多使用USE_AUTO_EXTRAS个，默认50 */
    for (j = 0; j < MIN(a_extras_cnt, USE_AUTO_EXTRAS); j++) {
```

至此，deterministic变异完成。会创建当前testcase到out_dir/queue/.state/deterministic_done/目录下，且设置passed_det属性为1：

```c
  fn = alloc_printf("%s/queue/.state/deterministic_done/%s", out_dir, fn + 1);

  fd = open(fn, O_WRONLY | O_CREAT | O_EXCL, 0600);
  if (fd < 0) PFATAL("Unable to create '%s'", fn);
  close(fd);

  ck_free(fn);

  q->passed_det = 1;
```

#### havoc

havoc的变异次数受到之前所说计算的`perf_score`的影响产生：

```c
    stage_max   = (doing_det ? HAVOC_CYCLES_INIT : HAVOC_CYCLES) *
                  perf_score / havoc_div / 100;
...
  /* [analysis] 138. 根据120计算的perf_score产生循环执行havoc变异的次数，进行变异fuzz */
  for (stage_cur = 0; stage_cur < stage_max; stage_cur++) {
```

每次变异随机选取一种变异方式，如果使用-x指定了字典，将有17种变异方式；如果没有指定字典，则只有15种变异方式：

-  0 => 随机翻转1bit
-  1 => 随机替换1byte为interest值
-  2 => 随机替换1word为interest值
-  3 => 随机替换1dword为interest值
-  4 => 随机1byte减随机值
-  5 => 随机1byte加随机值
-  6 => 随机1word减随机值，且随机字节序
-  7 => 随机1word加随机值，且随机字节序
-  8 => 随机1dword减随机值，且随机字节序
-  9 => 随机1dword加随机值，且随机字节序
- 10 => 随机设置1byte为随机值
- 11...12 => 随机删除随机个数bytes，设置2个case的目的是提高概率，保持文件不会因插入bytes变得太大
- 13 => 75%概率拷贝原文随机一段bytes到随机位置；25%概率插入随机bytes个相同随机值到随机位置
- 14 => 75%概率使用原文随机一段bytes替换原文随机位置；25%概率使用随机bytes个相同随机值替换原文随机位置
- 15 => 随机使用字典项替换原文bytes
- 16 => 随机插入字典项到原文随机位置

#### splicing

最后当使用splicing，且splicing的次数小于`SPLICE_CYCELS`（默认15），queue中testcase不止1个且当前testcase长度大于1时，会进行splicing剪接变异阶段。剪接算法如下：

随机从queue中选取不为自身的另一项：

```c
    /* [analysis] 140. 随机从queue中选取另一项剪接，不能剪接自身到自身 */
    do { tid = UR(queued_paths); } while (tid == current_entry);
```

从自身和选取的另一项文件中找寻首个不同位置和最后的不同位置。计算两文件的相似度，如果非常相似，则重新选取一个：

```c
    /* [analysis] 141. 对比两个文件，找到两文件首个不同的字节位置和最后一个不同的字节位置 */
    locate_diffs(in_buf, new_buf, MIN(len, target->len), &f_diff, &l_diff);

    /* [analysis] 142. 如果两文件非常相似，重新选取target进行剪接 */
    if (f_diff < 0 || l_diff < 2 || f_diff == l_diff) {
      ck_free(new_buf);
      goto retry_splicing;
    }
```

在首个不同位置和最后的不同位置之间随机选一个位置，作为分割点，拼接两个文件：

```c
    /* [analysis] 143. 随机从首个不同点到最后不同点中选取一个位置，作为分割点 */
    split_at = f_diff + UR(l_diff - f_diff);

    /* Do the thing. */

    /* [analysis] 144. 拼接 */
    len = target->len;
    memcpy(new_buf, in_buf, split_at);
    in_buf = new_buf;
```

使用拼接好的文件继续进行havoc变异fuzz：

```c
    /* [analysis] 145. 拼接后的case继续进行havoc变异fuzz */
    goto havoc_stage;
```

在进行完15次splicing后，此testcase的此轮fuzz过程就结束了，将其标记为fuzz过的，如果此testcase是favored，将`pending_favored--`：

```c
  /* [analysis] 146. 完成queue中1个case的fuzz过程 */
  if (!stop_soon && !queue_cur->cal_failed && !queue_cur->was_fuzzed) {
    queue_cur->was_fuzzed = 1;
    pending_not_fuzzed--;
    if (queue_cur->favored) pending_favored--;
  }
```

完成当前testcase的fuzz后，如上所述`queue_cur`指向`queue_cur->next`，循环对下一个testcase进行fuzz。

#### common_fuzz_stuff

上述进行的每一项变异方法，在对testcase进行变异后，都会执行`common_fuzz_stuff`函数来执行程序和保存得到的crash，hang等。

`common_fuzz_stuff`首先还是执行程序：

```c
  write_to_testcase(out_buf, len);

  fault = run_target(argv, exec_tmout);
```

然后会调用`save_if_interesting`来保存使得目标程序crash或hang的testcase。

如果程序结束状态为`FAULT_TMOUT`，`total_tmouts++`，但是只有达到新路径的testcase才会`unique_tmouts++`：

```c
      total_tmouts++;

      if (unique_hangs >= KEEP_UNIQUE_HANG) return keeping;

      if (!dumb_mode) {

#ifdef __x86_64__
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^__x86_64__ */

        /* [analysis] 是否有新路径来决定是否unique */
        if (!has_new_bits(virgin_tmout)) return keeping;

      }

      unique_tmouts++;
```

然后在判断此次timeout是否为hang时，会使用`hang_tmout`而非`exec_tmout`再次执行一遍程序以确认，通常`hang_tmout`比`exec_tmout`更长一些，如果执行结果还是`FAULT_TMOUT`，则将其认定为`unique_hangs++`，并保存out_dir/hangs/id:xxx文件：

```c
      if (exec_tmout < hang_tmout) {

        u8 new_fault;
        write_to_testcase(mem, len);
        /* [analysis] 使用hang_tmout来重新执行程序以判断是否为hang */
        new_fault = run_target(argv, hang_tmout);

        /* A corner case that one user reported bumping into: increasing the
           timeout actually uncovers a crash. Make sure we don't discard it if
           so. */

        if (!stop_soon && new_fault == FAULT_CRASH) goto keep_as_crash;

        if (stop_soon || new_fault != FAULT_TMOUT) return keeping;

      }
```

而如果程序结束状态为`FAULT_CRASH`，则原理与上相同，只不过不用再重新执行程序，且保存unique crash为out_dir/crashes/id:xxx：

```c
      /* [analysis] crash同理，只不过不用再重新执行程序了 */
      total_crashes++;

      if (unique_crashes >= KEEP_UNIQUE_CRASH) return keeping;

      if (!dumb_mode) {

#ifdef __x86_64__
        simplify_trace((u64*)trace_bits);
#else
        simplify_trace((u32*)trace_bits);
#endif /* ^__x86_64__ */

        if (!has_new_bits(virgin_crash)) return keeping;

      }

      if (!unique_crashes) write_crash_readme();

#ifndef SIMPLE_FILES

      fn = alloc_printf("%s/crashes/id:%06llu,sig:%02u,%s", out_dir,
                        unique_crashes, kill_signal, describe_op(0));

#else

      fn = alloc_printf("%s/crashes/id_%06llu_%02u", out_dir, unique_crashes,
```

