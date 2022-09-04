# Kernel runtime security instrumentation

原文地址： https://lwn.net/Articles/798157/


Finding ways to make it easier and faster to mitigate an ongoing attack against a Linux system at runtime is part of the motivation behind the kernel runtime security instrumentation (KRSI) project. Its developer, KP Singh, gave a presentation about the project at the [2019 Linux Security Summit North America](https://events.linuxfoundation.org/events/linux-security-summit-north-america-2019/) (LSS-NA), which was held in late August in San Diego. A prototype of KRSI is implemented as a Linux security module (LSM) that allows eBPF programs to be attached to the kernel's security hooks.

内核运行时安全检测(KRSI)项目背后的动机之一是寻找更容易、更快地减轻Linux系统在运行时受到的持续攻击的方法。其开发者KP Singh在8月底于圣地亚哥举行的[2019北美Linux安全峰会](https://events.linuxfoundation.org/events/linux-security-summit-north-america-2019/) (LSS-NA)上介绍了该项目。KRSI的一个原型被实现为一个Linux安全模块(LSM)，它允许eBPF程序附加到内核的安全钩子上。

Singh began by laying out the motivation for KRSI. When looking at the security of a system, there are two sides to the coin: signals and mitigations. The signals are events that might, but do not always, indicate some kind of malicious activity is taking place; the mitigations are what is done to thwart the malicious activity once it has been detected. The two "go hand in hand", he said.

辛格首先阐述了KRSI的动机。当观察系统的安全性时，这个问题有两个方面:信号和缓解。这些信号可能(但不总是)表明某种恶意活动正在发生;缓解措施是指一旦检测到恶意活动就采取的阻止措施。他表示，这两者“密不可分”。

For example, the audit subsystem can provide signals of activity that might be malicious. If you have a program that determines that the activity actually is problematic, then you might want it to update the policy for an LSM to restrict or prevent that behavior. Audit may also need to be configured to log the events in question. He would like to see a unified mechanism for specifying both the signals and mitigations so that the two work better together. That is what KRSI is meant to provide.

例如，审计子系统可以提供可能是恶意活动的信号。如果您有一个程序确定该活动实际上有问题，那么您可能希望它更新LSM的策略，以限制或防止该行为。可能还需要配置审计以记录有问题的事件。他希望看到一个统一的机制来明确信号和缓解措施，以便两者更好地协同工作。这正是KRSI所要提供的。

He gave a few examples of different types of signals. For one, a process that executes and then deletes its executable might well be malicious. A kernel module that loads and then hides itself is also suspect. A process that executes with suspicious environment variables (e.g. `LD_PRELOAD`) might indicate something has gone awry as well.

他举了几个不同类型信号的例子。首先，执行然后删除其可执行文件的进程很可能是恶意的。加载然后隐藏自身的内核模块也是可疑的。使用可疑的环境变量(例如:' LD_PRELOAD ')也可能表明出错了。

On the mitigation side, an administrator might want to prevent mounting USB drives on a server, perhaps after a certain point during the startup. There could be dynamic whitelists or blacklists of various sorts, for kernel modules that can be loaded, for instance, to prevent known vulnerable binaries from executing, or stopping binaries from loading a core library that is vulnerable to ensure that updates are done. Adding any of these signals or mitigations requires reconfiguration of various parts of the kernel, which takes time and/or operator intervention. He wondered if there was a way to make it easy to add them in a unified way.
在缓解方面，管理员可能希望阻止在服务器上挂载USB驱动器，可能是在启动期间的某个时间点之后。对于可以加载的内核模块，可能存在各种动态白名单或黑名单，例如，防止已知的易受攻击的二进制文件执行，或阻止二进制文件加载易受攻击的核心库，以确保完成更新。添加任何这些信号或缓解措施都需要重新配置内核的各个部分，这需要时间和/或操作人员的干预。他想知道是否有一种方法可以使它们以一种统一的方式容易地添加。

#### eBPF + LSM

He has created a new eBPF program type that can be used by the KRSI LSM. There is a set of eBPF helpers that provide a "unified policy API" for signals and mitigations. They are security-focused helpers that can be built up to create the behavior required.

他创建了一种新的eBPF程序类型，可被KRSI LSM使用。有一组eBPF helper程序，它们为信号和缓解措施提供了“统一的策略API”。它们是专注于安全的助手，可以通过构建来创建所需的行为。

Singh is frequently asked why he chose to use an LSM, rather than other options. Security behaviors map better to LSMs, he said, than to things like seccomp filters, which are based on system call interception. Various security-relevant behaviors can be accomplished via multiple system calls, so it would be easy to miss one or more, whereas the LSM hooks intercept the behaviors of interest. He also hopes this work will benefit the overall LSM ecosystem, he said.

Singh经常被问到为什么他选择使用LSM，而不是其他选择。他说，与基于系统调用拦截的seccomp过滤器相比，安全行为更适合于LSMs。各种与安全相关的行为可以通过多个系统调用来完成，因此很容易遗漏一个或多个，而LSM钩子则拦截感兴趣的行为。他还希望这项工作将有利于整个LSM生态系统，他说。

He talked with some security engineers about their needs and one mentioned logging `LD_PRELOAD` values on process execution. The way that could be done with KRSI would be to add a BPF program to to the [`bprm_check_security()`](https://elixir.bootlin.com/linux/v5.2.11/source/include/linux/lsm_hooks.h#L51) LSM hook that gets executed when a process is run. So KRSI registers a function for that hook, which gets called along with any other LSM's hooks for `bprm_check_security()`. When the KRSI hook is run, it calls out to the BPF program, which will communicate to user space (e.g. a daemon that makes decisions to add further restrictions) via an output buffer.

他与一些安全工程师讨论了他们的需求，其中一位提到了在进程执行时记录“LD_PRELOAD”值。使用KRSI的方法是在[' bprm_check_security() '](https://elixir.bootlin.com/linux/v5.2.11/source/include/linux/lsm_hooks.h#L51) LSM钩子中添加一个BPF程序，该钩子在进程运行时执行。因此，KRSI为该钩子注册了一个函数，该函数与任何其他LSM钩子一起被调用，用于' bprm_check_security() '。当KRSI钩子运行时，它调用BPF程序，BPF程序将通过输出缓冲区与用户空间通信(例如，决定添加进一步限制的守护进程)。

The intent is that the helpers are "precise and granular". Unlike the BPF tracing API, they will not have general access to internal kernel data structures. His [slides [PDF\]](https://static.sched.com/hosted_files/lssna19/03/Kernel Runtime Security Instrumentation.pdf) had [`bpf_probe_read()`](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-bpf_probe_read) in a circle with a slash through it as an indication of what he was trying to avoid. The idea is to maintain backward compatibility by not tying the helpers to the internals of a given kernel.

这样做的目的是让helpers “精确而细致”。与BPF跟踪API不同，它们不能访问内部内核数据结构。他的[幻灯片[PDF\]](https://static.sched.com/hosted_files/lssna19/03/Kernel Runtime Security Instrumentation.pdf)有[' bpf_probe_read() '](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#1-bpf_probe_read)在一个圆圈中，并有一个斜杠穿过它，表示他试图避免什么。其思想是通过不将helper绑定到给定内核的内部来保持向后兼容性。





He then went through various alternatives for implementing this scheme and described the problems he saw with them. To start with, why not use audit? One problem is that the mitigations have to be handled separately. But there is also a fair amount of performance overhead when adding more things to be audited; he would back that up with some numbers later in the presentation. Also, audit messages have rigid formatting that must be parsed, which might delay how quickly a daemon could react.

然后，他介绍了实现这个方案的各种备选方案，并描述了他看到的这些方案的问题。首先，为什么不使用审计?一个问题是mitigations措施必须分开处理。但是当添加更多需要审计的内容时，也会产生相当数量的性能开销;在随后的演讲中，他会用一些数字来支持这一点。此外，审计消息具有必须进行解析的严格格式，这可能会延迟守护进程的反应速度。

Seccomp with BPF was up next. As he said earlier, security behaviors map more directly into LSM hooks than to system-call interception. He is also concerned about time-of-check-to-time-of-use (TOCTTOU) races when handling the system call parameters from user space, though he said he is not sure that problem actually exists.

其次是BPF旗下的Seccomp。正如他之前所说，安全行为更直接地映射到LSM挂钩，而不是系统调用拦截。在处理来自用户空间的系统调用参数时，他还关心检查到使用时间(TOCTTOU)的竞争，尽管他说他不确定这个问题是否真的存在。

Using kernel probes (kprobes) and eBPF was another possibility. It is a "very flexible" solution, but it depends on the layout of internal kernel data structures. That makes deployment hard as things need to be recompiled for each kernel that is targeted. In addition, kprobes is not a stable API; functions can be added and removed from the kernel, which may necessitate changes.

使用内核探针(kprobes)和eBPF是另一种可能。这是一个“非常灵活”的解决方案，但它取决于内部内核数据结构的布局。这使得部署变得困难，因为每个目标内核都需要重新编译。此外，kprobes不是一个稳定的API;函数可以从内核中添加或删除，这可能需要进行更改。

The final alternative was the [Landlock LSM](https://lwn.net/Articles/703876/). It is geared toward providing a security sandbox for unprivileged processes, Singh said. KRSI, on the other hand, is focused on detecting and reacting to security-relevant behaviors. While Landlock is meant to be used by unprivileged processes, KRSI requires `CAP_SYS_ADMIN` to do its job.

最后的选择是[Landlock LSM](https://lwn.net/Articles/703876/)。辛格说，它旨在为非特权进程提供一个安全沙盒。而KRSI则专注于检测与安全相关的行为并对其做出反应。虽然Landlock是由非特权进程使用的，但KRSI需要' CAP_SYS_ADMIN '来完成它的工作。

#### Case study

He then described a case study: auditing the environment variables set when executing programs on a system. It sounds like something that should be easy to do, but it turns out not to be. For one thing, there can be up to 32 pages of environment variables, which he found surprising.

然后，他描述了一个案例研究:审计在系统上执行程序时设置的环境变量。这听起来像是很容易做到的事情，但事实证明并非如此。首先，书中关于环境变量的内容多达32页，这让他感到惊讶。

He looked at two different designs for an eBPF helper, one that would return all of the environment variables or one that just returned the variable of interest. The latter has less overhead, so it might be better, especially if there is a small set of variables to be audited. But either of those helpers could end up sleeping because of a page fault, which is something that eBPF programs are not allowed to do.

他研究了eBPF helper的两种不同设计，一种将返回所有环境变量，另一种只返回感兴趣的变量。后者的开销较小，因此可能更好，特别是在需要审计一小部分变量的情况下。但是这些帮助程序中的任何一个都可能因为页面错误而睡着，这是eBPF程序不允许做的事情。

Singh did some rough performance testing in order to ensure that KRSI was not completely unworkable, but the actual numbers need to be taken with a few grains of salt, he said. He ran a no-op binary 100 times and compared the average execution time (over N iterations of the test) of that on a few different systems: a kernel with audit configured out, a kernel with audit but no audit rules, one where audit was used to record `execve()` calls, and one where KRSI recorded the value of `LD_PRELOAD`. The first two were measured at a bit over 500µs (518 and 522), while the audit test with rules came in at 663µs (with a much wider distribution of values than any of the other tests). The rudimentary KRSI test clocked in at 543µs, which gave him reason to continue on; had it been a lot higher, he would have shelved the whole idea.

Singh说，为了确保KRSI不是完全不可用，他做了一些粗略的性能测试，但需要对实际数据有所保留。他运行了100次无操作二进制，并比较了在几个不同的系统上的平均执行时间(测试的N次迭代):一个配置了审计的内核，一个有审计但没有审计规则的内核，一个使用审计来记录' execve() '调用，以及一个使用KRSI记录' LD_PRELOAD '的值。前两个测试的测试值略高于500个µs(518和522)，而带有规则的审计测试的测试值为663个(比其他任何测试的值分布都要广泛得多)。基本的KRSI检测结果为543份，这给了他继续工作的理由。如果价格高得多，他就会搁置整个想法。

There are plenty of things that are up for discussion, he said. Right now, KRSI uses the perf ring buffer to communicate with user space; it is fast and eBPF already has a helper to access it. But that ring buffer is a per-CPU buffer, so it uses more memory than required, especially for systems with a lot of CPUs. There is already talk of allowing eBPF programs to sleep, which would simplify KRSI and allow it to use less memory. Right now, the LSM hook needs to pin the memory for use by the eBPF program. He is hopeful that discussions in the [BPF microconference](https://linuxplumbersconf.org/event/4/sessions/62/#20190911) at the [Linux Plumbers Conference](https://linuxplumbersconf.org/) will make some progress on that.

他说，有很多事情需要讨论。目前，KRSI使用perf环缓冲区与用户空间通信;它是快速的，eBPF已经有一个助手来访问它。但是这个循环缓冲区是一个per-CPU的缓冲区，所以它使用的内存比需要的更多，特别是对于有很多cpu的系统。目前已经在讨论允许eBPF程序休眠，这将简化KRSI，并允许它使用更少的内存。现在，LSM钩子需要固定内存以供eBPF程序使用。他希望在[Linux Plumbers Conference](https://linuxplumbersconf.org/event/4/sessions/62/#20190911)(https://linuxplumbersconf.org/)上的[BPF microconference](https://linuxplumbersconf.org/event/4/sessions/62/#20190911)的讨论将在这方面取得一些进展。

As part of the Q&A, Landlock developer Mickaël Salaün spoke up to suggest working together. He went through the same thinking about alternative kernel facilities that Singh presented and believes that Landlock would integrate well with KRSI. Singh said that he was not fully up-to-speed on Landlock but was amenable to joining forces if the two are headed toward the same goals.

作为问答的一部分，Landlock的开发者Mickaël Salaün提出了合作的建议。他也考虑了Singh提出的替代内核设施，并相信Landlock能够很好地与KRSI集成。辛格说，他还没有完全跟上Landlock的速度，但如果两者朝着相同的目标前进，他愿意联合起来。
