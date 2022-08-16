# Impedance matching for BPF and LSM

原文地址: https://lwn.net/Articles/813261/

The "kernel runtime security instrumentation" (KRSI) patch set has been making the rounds over the past few months; the idea is to use the Linux security module (LSM) hooks as a way to detect, and potentially deflect, active attacks against a running system. It does so by allowing BPF programs to be attached to the LSM hooks. That has caused [some concern](https://lwn.net/Articles/808048/) in the past about exposing the security hooks as external kernel APIs, which makes them potentially subject to the "don't break user space" edict. But there has been no real objection to the goals of KRSI. The fourth version of the patch set was [posted](https://lwn.net/ml/linux-kernel/20200220175250.10795-1-kpsingh@chromium.org/) by KP Singh on February 20; the concerns raised this time are about its impact on the LSM infrastructure.

“内核运行时安全工具”(KRSI)补丁集在过去的几个月里一直在进行;其思想是使用Linux安全模块(LSM)钩子作为一种方法来检测并潜在地转移针对正在运行的系统的主动攻击。它通过允许BPF程序附加到LSM挂钩来实现这一点。这在过去引起了[一些关注](https://lwn.net/Articles/808048/)，关于将安全钩子暴露为外部内核api，这使得它们可能受制于“不要破坏用户空间”的命令。但是对KRSI的目标并没有真正的反对意见。该补丁集的第四个版本是由KP Singh于2月20日发布的(https://lwn.net/ml/linux-kernel/20200220175250.10795-1-kpsingh@chromium.org/);这次提出的担忧是它对LSM基础设施的影响。

The main change Singh made from the previous version effectively removed KRSI from the standard LSM calling mechanisms by using [BPF "fexit" (for function exit) trampolines](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fec56f5890d9) on the LSM hooks. That trampoline can efficiently call any BPF programs that have been placed on the hook without the overhead associated with the normal LSM path; in particular, it avoids the cost of the [retpoline](https://support.google.com/faqs/answer/7625886) mitigation for the Spectre hardware vulnerability. The KRSI hooks are enabled by [static keys](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/static-keys.txt), which means they have zero cost when they are not being used. But it does mean that KRSI looks less like a normal LSM as Singh acknowledged: "Since the code does not deal with security_hook_heads anymore, it goes from 'being a BPF LSM' to 'BPF program attachment to LSM hooks'."

Singh对上一个版本所做的主要改变是，通过在LSM钩子上使用[BPF "fexit"(用于函数退出)trampolines](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=fec56f5890d9)，有效地将KRSI从标准LSM调用机制中移除。这个trampoline可以有效地调用任何放置在钩子上的BPF程序，而不需要与普通LSM路径相关的开销;特别是，它避免了[retpoline](https://support.google.com/faqs/answer/7625886)缓解Spectre硬件漏洞的成本。KRSI钩子是通过[静态键](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/Documentation/static-keys.txt)启用的，这意味着当它们不被使用时，它们的成本为零。但正如Singh所承认的那样，这确实意味着KRSI看起来不太像一个正常的LSM:“由于代码不再处理security_hook_heads，它从‘作为一个BPF LSM’变成了‘BPF程序附加到LSM钩子’。”

Casey Schaufler, who has done a lot of work on the LSM infrastructure over the last few years, [objected](https://lwn.net/ml/linux-kernel/0ef26943-9619-3736-4452-fec536a8d169@schaufler-ca.com/) to making KRSI a special case, however: "You aren't doing anything so special that the general mechanism won't work." Singh [agreed](https://lwn.net/ml/linux-kernel/20200221114458.GA56944@google.com/) that the standard LSM approach would work for KRSI, "but the cost of an indirect call for all the hooks, even those that are completely unused is not really acceptable for KRSI’s use cases".

在过去几年里，Casey Schaufler在LSM基础架构上做了大量的工作，他反对将KRSI作为一个特例，但是:“你并没有做任何特殊到一般机制无法工作的事情。”Singh[同意](https://lwn.net/ml/linux-kernel/20200221114458.GA56944@google.com/)标准的LSM方法对KRSI来说是可行的，“但是间接调用所有钩子的成本，即使是那些完全没有使用的钩子，对于KRSI的用例来说是无法接受的”。

Kees Cook [focused](https://lwn.net/ml/linux-kernel/202002211946.A23A987@keescook/) on the performance issue, noting that making calls for each of the hooks, even when there is nothing to do, is common for LSMs. Of the 230 hooks defined in the LSM interface, only SELinux uses more than half (202), Smack is next (108), and the rest use less than a hundred—several use four or less. He would like to see some numbers on the performance gain from using static keys to disable hooks that are not required. It might make sense to use that mechanism for all of LSM, he said. Singh [agreed](https://lwn.net/ml/linux-kernel/20200224172309.GB21886@chromium.org/) that it would be useful to have some performance numbers; "I will do some analysis and come back with the numbers." It is, after all, a bit difficult to have a discussion about improving performance without some data to guide the decision-making.

Kees Cook[关注](https://lwn.net/ml/linux-kernel/202002211946.A23A987@keescook/)性能问题，注意到调用每个钩子，即使在无事可做的情况下，在LSMs中也是常见的。在LSM接口中定义的230个钩子中，只有SELinux使用了一半以上(202个)，Smack次之(108个)，其余的使用不到100个——有几个使用4个或更少。他希望看到使用静态键禁用不需要的钩子所带来的性能提升。他说，在所有LSM中使用这种机制可能是有意义的。Singh[同意](https://lwn.net/ml/linux-kernel/20200224172309.GB21886@chromium.org/)，有一些性能数据是有用的;“我会做一些分析，然后得出数据。”毕竟，在没有一些数据来指导决策的情况下，讨论提高绩效是有点困难的。

There are several intertwined pieces to the disagreement. The LSM infrastructure has generally not been seen as a performance bottleneck, at least until the advent of KRSI; instead, over recent years, the focus has been on generalizing that infrastructure to support [arbitrary stacking of multiple LSMs](https://lwn.net/Articles/804906/) in a running system. That has improved the performance of handling calls into multiple hooks (when more than one LSM defines one for a given operation) over the previous mechanism, but it was not geared to the high-performance requirements that KRSI is trying to bring to the LSM world.

这个分歧有几个相互交织的部分。LSM基础设施通常不被视为性能瓶颈，至少在KRSI出现之前是这样;相反，近年来，重点是将基础设施一般化，以便在运行的系统中支持[任意堆叠多个LSMs](https://lwn.net/Articles/804906/)。与之前的机制相比，这改进了在多个钩子中处理调用的性能(当多个LSM为给定的操作定义一个钩子时)，但它没有适应KRSI试图为LSM世界带来的高性能需求。

In addition, the stacking work has made it so that LSMs can be stacked in any order; each defined hook for a given operation is called in order, the first that denies the operation "wins" and the operation fails without calling any others. That infrastructure is in place, but KRSI upends it to a certain extent. KRSI comes from the BPF world, so the list traversal and indirect calls used by the LSM infrastructure are seen as performance bottlenecks. KRSI always places itself (conceptually) last on the list and uses the BPF trampoline to avoid that overhead. That makes it a special case, unlike the other "normal" stackable LSMs, but that may be a case of a premature optimization, as Cook noted.

此外，堆叠工作使LSMs可以以任何顺序堆叠;每个为给定操作定义的钩子都是按顺序调用的，第一个拒绝该操作的钩子将“获胜”，而该操作将在不调用其他钩子的情况下失败。基础设施已经到位，但KRSI在一定程度上颠覆了它。KRSI来自BPF领域，因此LSM基础设施使用的列表遍历和间接调用被视为性能瓶颈。KRSI总是(在概念上)将自己放在列表的最后，并使用BPF蹦床来避免这种开销。这使它成为一种特殊的情况，不像其他“正常”的堆叠lsm，但这可能是一个过早的优化的情况，如库克指出。

BPF developer Alexei Starovoitov [does not see it as "premature"](https://lwn.net/ml/linux-kernel/20200223220833.wdhonzvven7payaw@ast-mbp/) at all, however. "I'm convinced that avoiding the cost of retpoline in critical path is a requirement for any new infrastructure in the kernel." He thought that the LSM infrastructure should consider using static keys to enable its hooks, and that the mechanism employed by KRSI should be used there:

BPF开发者Alexei Starovoitov (https://lwn.net/ml/linux-kernel/20200223220833.wdhonzvven7payaw@ast-mbp/)完全不认为这是“过早的”。“我确信，避免在关键路径上重新布线的成本是任何新的内核基础设施的要求。”他认为LSM基础架构应该考虑使用静态键来启用它的钩子，而KRSI所采用的机制也应该在那里使用:

Just compiling with CONFIG_SECURITY adds "if (hlist_empty)" check for every hook. Some of those hooks are in critical path. This load+cmp can be avoided with static_key optimization. I think it's worth doing.

只用CONFIG_SECURITY编译就会为每个钩子添加"if (hlist_empty)"检查。有些钩子在关键路径上。这种load+cmp可以通过static_key优化来避免。我认为这值得一做。

I really like that KRSI costs absolutely zero when it's not enabled. Attaching BPF prog to one hook preserves zero cost for all other hooks. And when one hook is BPF powered it's using direct call instead of super expensive retpoline.

我真的很喜欢KRSI不启用时的成本绝对为零。将BPF prog连接到一个钩子可以为所有其他钩子节省零成本。当一个钩子是BPF支持时，它使用的是直接调用，而不是超级昂贵的 retpoline（Google开发的针对Spectre变种2漏洞缓解利用技术）。

But the insistence on treating KRSI differently than the other LSMs means that perhaps KRSI should go its own way—or work on improving the LSM infrastructure as a whole. Schaufler [said](https://lwn.net/ml/linux-kernel/c5c67ece-e5c1-9e8f-3a2b-60d8d002c894@schaufler-ca.com/) that he had not "gotten that memo" on avoiding retpolines and that the LSM infrastructure is not new. He is interested in looking at using static keys, but is concerned that the mechanism is too specific to use in the general case, where multiple LSMs can register hooks to be called:

但是坚持将KRSI与其他LSM区别对待意味着KRSI也许应该走自己的路——或者作为一个整体来改进LSM的基础设施。Schaufler[说](https://lwn.net/ml/linux-kernel/c5c67ece-e5c1-9e8f-3a2b-60d8d002c894@schaufler-ca.com/)他没有“收到备忘录”关于避免路由，并且LSM的基础设施并不是新的。他对使用静态键感兴趣，但他担心这种机制过于特定，不能用于一般情况，在一般情况下，多个LSMs可以注册要调用的钩子:

I admit to being unfamiliar with the static_key implementation, but if it would work for a list of hooks rather than a singe hook, I'm all ears.

我承认我不熟悉static_key实现，但是如果它适用于一列钩子而不是一个钩子，我将认真听取。

The new piece is not KRSI per se, Singh [said](https://lwn.net/ml/linux-kernel/20200224171305.GA21886@chromium.org/), but the ability to attach BPF programs to the security hooks *is* new. There are techniques available to make that have zero cost, so it makes sense to use them:

Singh说:“这个新的部件本身并不是KRSI，但是将BPF程序附加到安全钩子上的能力是新的。”有一些技术可以实现零成本，所以使用它们是有意义的:

There are other tracing / attachment [mechanisms] in the kernel which provide similar [guarantees] (using static keys and direct calls) and it seems regressive for KRSI to not leverage these known patterns and sacrifice performance [especially] in hotpaths. This provides users to use KRSI alongside other LSMs without paying extra cost for all the possible hooks.

在内核中还有其他的跟踪/附加[机制]提供了类似的[保证](使用静态键和直接调用)，对于KRSI来说，不利用这些已知的模式并牺牲性能(尤其是)在热路径中似乎是一种退化。这使得用户可以在使用其他LSMs的同时使用KRSI，而无需为所有可能的钩子支付额外的费用。

 My analogy here is that if every tracepoint in the kernel were of the type:

我在这里的类比是，如果内核中的每个跟踪点都是这样的类型:

```
if (trace_foo_enabled) // <-- Overhead here, solved with static key
   trace_foo(a);  // <-- retpoline overhead, solved with fexit trampolines
```

It would be very hard to justify enabling them on a production system, and the same can be said for BPF and KRSI.

在生产系统中启用它们是非常困难的，对于BPF和KRSI也是如此。

The difficulty is that the LSM interface came about under a different set of constraints, Schaufler [said](https://lwn.net/ml/linux-kernel/00c216e1-bcfd-b7b1-5444-2a2dfa69190b@schaufler-ca.com/). Those constraints have changed over time and the infrastructure is being worked on to improve its performance, but it still needs to work with the existing LSMs:

Schaufler[认为](https://lwn.net/ml/linux-kernel/00c216e1-bcfd-b7b1-5444-2a2dfa69190b@schaufler-ca.com/)，困难在于LSM接口是在一组不同的约束下产生的随着时间的推移，这些限制已经发生了变化，基础设施正在改进其性能，但仍然需要与现有的LSMs一起工作:

The LSM mechanism is not zero overhead. It never has been. That's why you can compile it out. You get added value at a price. You get the ability to use SELinux and KRSI together at a price. If that's unacceptable you can go the route of seccomp, which doesn't use LSM for many of the same reasons you're on about.

LSM机制的开销不是零。从来都不是。这就是为什么可以编译出来。你以一定的价格获得了附加值。您可以以一定的价格同时使用SELinux和KRSI。如果这是不可接受的，你可以走seccomp的路线，它不使用LSM的许多相同的原因，你说。

When LSM was introduced it was expected to be used by the lunatic fringe people with government mandated security requirements. Today it has a much greater general application. That's why I'm in the process of bringing it up to modern use case requirements. Performance is much more important now than it was before the use of LSM became popular.

当LSM被引入的时候，它被认为是被政府强制要求安全的极端分子使用的。今天，它有更广泛的普遍应用。这就是为什么我正在将它提升到现代用例需求的原因。性能现在比LSM流行之前重要得多。

 If BPF and KRSI are that performance critical you shouldn't be tying them to LSM, which is known to have overhead. If you can't accept the LSM overhead, get out of the LSM. Or, help us fix the LSM infrastructure to make its overhead closer to zero. Whether you believe it or not, a lot of work has gone into keeping the LSM overhead as small as possible while remaining sufficiently general to perform its function.

如果BPF和KRSI对性能至关重要，你就不应该将它们与LSM捆绑在一起，因为众所周知LSM会带来开销。如果不能接受LSM开销，就退出LSM。或者，帮助我们修复LSM基础设施，使其开销接近于零。不管您信不信，我们已经做了大量的工作来保持LSM开销尽可能小，同时保持其功能足够通用。

The goal of eliminating the retpoline overhead is reasonable, Cook [said](https://lwn.net/ml/linux-kernel/202002241136.C4F9F7DFF@keescook/), but the LSM world has not yet needed to do so. "I think it's a desirable goal, to be sure, but this does appear to be an early optimization." He noted there is something of an impedance mismatch; the BPF developers do not want to see any performance hit associated with BPF, but the LSM developers "do not want any new special cases in LSM stacking". So he suggested adding a "slow" KRSI that used the LSM stacking infrastructure as it is today, followed by work to optimize that calling path.

Cook[认为](https://lwn.net/ml/linux-kernel/202002241136.C4F9F7DFF@keescook/)，消除retpoline开销的目标是合理的，但LSM世界还不需要这样做。“我认为这是一个理想的目标，这是肯定的，但这似乎是一个早期优化。”他指出，存在阻抗不匹配的情况;BPF开发人员不希望看到与BPF相关的任何性能下降，但LSM开发人员“不希望LSM堆叠中出现任何新的特殊情况”。因此，他建议添加一个“慢”的KRSI，使用今天的LSM堆叠基础设施，然后进行优化调用路径的工作。

But Starovoitov [thought](https://lwn.net/ml/linux-kernel/20200225054125.dttrc3fvllzu4mx5@ast-mbp/) that KRSI should perhaps just go its own way. He proposed changing the BPF program type from `BPF_PROG_TYPE_LSM` to `BPF_PROG_TYPE_OVERRIDE_RETURN` and moving KRSI completely out of the LSM world: "I don't see anything in LSM infra that KRSI can reuse." He does not see a slow KRSI as an option and suggested that perhaps the LSM interface and the new BPF program type should be made mutually exclusive at kernel build time:

但是Starovoitov[认为](https://lwn.net/ml/linux-kernel/20200225054125.dttrc3fvllzu4mx5@ast-mbp/)， KRSI或许应该走自己的路。他建议将BPF程序类型从‘BPF_PROG_TYPE_LSM’更改为‘BPF_PROG_TYPE_OVERRIDE_RETURN’，并将KRSI完全移出LSM的世界:“我在LSM基础架构中看不到KRSI可以重用的任何东西。”他不认为缓慢的KRSI是一个选项，并建议也许LSM接口和新的BPF程序类型应该在内核构建时互斥:

It may seem as a downside that it will force a choice on kernel users. Either they build the kernel with CONFIG_SECURITY and their choice of LSMs or build the kernel with CONFIG_BPF_OVERRIDE_RETURN and use BPF_PROG_TYPE_OVERRIDE_RETURN programs to enforce any kind of policy. I think it's a pro not a con.

这似乎是一个缺点，它将迫使内核用户做出选择。他们要么用CONFIG_SECURITY和他们选择的lsm构建内核，要么用CONFIG_BPF_OVERRIDE_RETURN构建内核，然后使用BPF_PROG_TYPE_OVERRIDE_RETURN程序强制任何类型的策略。我觉得这是好事，不是坏事。

The goal of eliminating the retpoline overhead is reasonable, Cook [said](https://lwn.net/ml/linux-kernel/202002241136.C4F9F7DFF@keescook/), but the LSM world has not yet needed to do so. "I think it's a desirable goal, to be sure, but this does appear to be an early optimization." He noted there is something of an impedance mismatch; the BPF developers do not want to see any performance hit associated with BPF, but the LSM developers "do not want any new special cases in LSM stacking". So he suggested adding a "slow" KRSI that used the LSM stacking infrastructure as it is today, followed by work to optimize that calling path. But Starovoitov [thought](https://lwn.net/ml/linux-kernel/20200225054125.dttrc3fvllzu4mx5@ast-mbp/) that KRSI should perhaps just go its own way. He proposed changing the BPF program type from `BPF_PROG_TYPE_LSM` to `BPF_PROG_TYPE_OVERRIDE_RETURN` and moving KRSI completely out of the LSM world: "I don't see anything in LSM infra that KRSI can reuse." He does not see a slow KRSI as an option and suggested that perhaps the LSM interface and the new BPF program type should be made mutually exclusive at kernel build time: It may seem as a downside that it will force a choice on kernel users. Either they build the kernel with CONFIG_SECURITY and their choice of LSMs or build the kernel with CONFIG_BPF_OVERRIDE_RETURN and use BPF_PROG_TYPE_OVERRIDE_RETURN programs to enforce any kind of policy. I think it's a pro not a con.

Cook[认为](https://lwn.net/ml/linux-kernel/202002241136.C4F9F7DFF@keescook/)，消除retpoline开销的目标是合理的，但LSM世界还不需要这样做。“我认为这是一个理想的目标，这是肯定的，但这似乎是一个早期优化。”他指出，存在阻抗不匹配的情况;BPF开发人员不希望看到与BPF相关的任何性能下降，但LSM开发人员“不希望LSM堆叠中出现任何新的特殊情况”。因此，他建议添加一个“慢”的KRSI，使用今天的LSM堆叠基础设施，然后进行优化调用路径的工作。但是Starovoitov[认为](https://lwn.net/ml/linux-kernel/20200225054125.dttrc3fvllzu4mx5@ast-mbp/)， KRSI或许应该走自己的路。他建议将BPF程序类型从‘BPF_PROG_TYPE_LSM’更改为‘BPF_PROG_TYPE_OVERRIDE_RETURN’，并将KRSI完全移出LSM的世界:“我在LSM基础架构中看不到KRSI可以重用的任何东西。”他不认为缓慢的KRSI是一种选择，并建议也许LSM接口和新的BPF程序类型应该在内核构建时互斥:这似乎是一个缺点，它将迫使内核用户做出选择。他们要么用CONFIG_SECURITY和他们选择的lsm构建内核，要么用CONFIG_BPF_OVERRIDE_RETURN构建内核，然后使用BPF_PROG_TYPE_OVERRIDE_RETURN程序强制任何类型的策略。我觉得这是好事，不是坏事。

There are, of course, lots of users of the LSM interface, including most distributions, so it might difficult to go that route, Schaufler [said](https://lwn.net/ml/linux-kernel/4b56177f-8148-177b-e1e5-c98da86b3b01@schaufler-ca.com/). But Singh [noted](https://lwn.net/ml/linux-kernel/20200226051535.GA17117@chromium.org/) that the users of a `BPF_PROG_TYPE_OVERRIDE_RETURN` feature may be highly performance-sensitive such that they already disable LSMs "because of the current performance characteristics". But Singh did [think](https://lwn.net/ml/linux-kernel/20200225193108.GB22391@chromium.org/) that `BPF_PROG_TYPE_OVERRIDE_RETURN` might be useful on its own, separate from the KRSI work; he plans to split that out into its own patch set. He [agreed](https://lwn.net/ml/linux-kernel/20200225192913.GA22391@chromium.org/) with Cook's approach, as well, and plans to re-spin the KRSI patches to use the standard LSM approach as a starting point; "we can follow-up on performance".

Schaufler[认为](https://lwn.net/ml/linux-kernel/4b56177f-8148-177b-e1e5-c98da86b3b01@schaufler-ca.com/)，当然，LSM界面有很多用户，包括大多数发行版，所以走这条路可能会很困难但是Singh[指出](https://lwn.net/ml/linux-kernel/20200226051535.GA17117@chromium.org/)使用“BPF_PROG_TYPE_OVERRIDE_RETURN”功能的用户可能对性能非常敏感，以至于他们已经“因为当前的性能特征”禁用了LSMs。但是Singh确实[认为](https://lwn.net/ml/linux-kernel/20200225193108.GB22391@chromium.org/)“BPF_PROG_TYPE_OVERRIDE_RETURN”本身可能是有用的，独立于KRSI工作;他计划把它分成自己的补丁集。他[同意](https://lwn.net/ml/linux-kernel/20200225192913.GA22391@chromium.org/)库克的方法，并计划重新调整KRSI补丁，以使用标准的LSM方法为起点;“我们可以跟进业绩”。

The clash here was the classic speed versus generality tradeoff that pops up in the kernel (and elsewhere) with some frequency. The BPF developers are laser-focused on their "baby"—and squeezing every last drop of performance out of it—but there is a wider world in kernel-land, some parts of which have different requirements. It would seem that a reasonable compromise has been found here. Preserving the generality of the LSM approach while gaining the performance improvements that the BPF developers have been working on would be a win for both, really—taking the kernel and its users along for the ride.

这里的冲突是典型的速度与通用性之间的权衡，这在内核(和其他地方)中以一定的频率出现。BPF的开发人员专注于他们的“宝贝”，并榨干每一滴性能，但内核领域还有更广阔的世界，其中一些部分有不同的需求。在这方面似乎已经找到了一个合理的妥协。保持LSM方法的通用性，同时获得BPF开发人员一直在努力的性能改进，这对双方都是一种胜利，真正让内核和它的用户一起前行。
