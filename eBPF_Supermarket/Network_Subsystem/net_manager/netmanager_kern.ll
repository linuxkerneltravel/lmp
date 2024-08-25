; ModuleID = 'netmanager_kern.c'
source_filename = "netmanager_kern.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%struct.anon.11 = type { [14 x i32]*, i32*, i32*, [256 x i32]* }
%struct.anon.15 = type { [1 x i32]*, %struct.conn_ipv4_key*, %struct.conn_ipv4_val*, [256 x i32]* }
%struct.conn_ipv4_key = type { i32, i32, i16, i16, i16 }
%struct.conn_ipv4_val = type { i32, i32 }
%struct.anon.16 = type { [1 x i32]*, i16*, i16*, [1 x i32]* }
%struct.anon.17 = type { [6 x i32]*, i32*, %struct.datarec*, [5 x i32]* }
%struct.datarec = type { i64, i64 }
%struct.anon.18 = type { [1 x i32]*, i16*, %struct.rules_ipv4*, [256 x i32]* }
%struct.rules_ipv4 = type { i32, i32, i8, i8, i16, i16, i16, i16, i16, i16 }
%struct.anon.19 = type { [1 x i32]*, i16*, %struct.rules_mac*, [256 x i32]* }
%struct.rules_mac = type { [6 x i8], [6 x i8], i16, i16, i16 }
%struct.anon.20 = type { [1 x i32]*, i32*, %struct.rt_item*, [256 x i32]* }
%struct.rt_item = type { i32, [6 x i8], [6 x i8] }
%struct.xdp_md = type { i32, i32, i32, i32, i32, i32 }
%struct.ethhdr = type { [6 x i8], [6 x i8], i16 }
%struct.hdr_cursor = type { i8* }
%struct.collect_vlans = type { [2 x i16] }
%struct.vlan_hdr = type { i16, i16 }
%struct.iphdr = type { i8, i8, i16, i16, i16, i8, i8, i16, %union.anon }
%union.anon = type { %struct.anon }
%struct.anon = type { i32, i32 }
%struct.tcphdr = type { i16, i16, i32, i32, i16, i16, i16, i16 }
%struct.udphdr = type { i16, i16, i16, i16 }
%struct.conn_ipv4 = type { i32, i32, i16, i16, i16 }
%struct.bpf_fib_lookup = type { i8, i8, i16, i16, %union.anon.1, i32, %union.anon.2, %union.anon.3, %union.anon.4, %union.anon.5, [6 x i8], [6 x i8] }
%union.anon.1 = type { i16 }
%union.anon.2 = type { i32 }
%union.anon.3 = type { [4 x i32] }
%union.anon.4 = type { [4 x i32] }
%union.anon.5 = type { i32 }
%struct.ipv6hdr = type { i8, [3 x i8], i16, i8, i8, %union.anon.7 }
%union.anon.7 = type { %struct.anon.8 }
%struct.anon.8 = type { %struct.in6_addr, %struct.in6_addr }
%struct.in6_addr = type { %union.anon.9 }
%union.anon.9 = type { [4 x i32] }
%struct.conn_mac = type { [6 x i8], [6 x i8] }
%struct.icmphdr = type { i8, i8, i16, %union.anon.12 }
%union.anon.12 = type { i32 }

@tx_port = dso_local global %struct.anon.11 zeroinitializer, section ".maps", align 8, !dbg !0
@conn_ipv4_map = dso_local global %struct.anon.15 zeroinitializer, section ".maps", align 8, !dbg !517
@xdp_entry_state.___fmt = internal constant [56 x i8] c"tcp(%lu.%lu.%lu.%lu:%u->%lu.%lu.%lu.%lu:%u),state:%s,%s\00", align 1, !dbg !210
@.str = private unnamed_addr constant [12 x i8] c"ESTABLISHED\00", align 1
@.str.1 = private unnamed_addr constant [7 x i8] c"client\00", align 1
@.str.2 = private unnamed_addr constant [8 x i8] c"service\00", align 1
@xdp_entry_state.___fmt.4 = internal constant [56 x i8] c"tcp(%lu.%lu.%lu.%lu:%u->%lu.%lu.%lu.%lu:%u),state:%s,%s\00", align 1, !dbg !396
@.str.5 = private unnamed_addr constant [9 x i8] c"SYN-RECV\00", align 1
@xdp_entry_state.___fmt.6 = internal constant [56 x i8] c"tcp(%lu.%lu.%lu.%lu:%u->%lu.%lu.%lu.%lu:%u),state:%s,%s\00", align 1, !dbg !404
@.str.7 = private unnamed_addr constant [4 x i8] c"RST\00", align 1
@.str.8 = private unnamed_addr constant [9 x i8] c"SYN_SENT\00", align 1
@.str.9 = private unnamed_addr constant [9 x i8] c"SYN_RECV\00", align 1
@.str.10 = private unnamed_addr constant [10 x i8] c"FIN_WAIT1\00", align 1
@.str.11 = private unnamed_addr constant [10 x i8] c"FIN_WAIT2\00", align 1
@.str.12 = private unnamed_addr constant [11 x i8] c"CLOSE_WAIT\00", align 1
@.str.13 = private unnamed_addr constant [6 x i8] c"CLOSE\00", align 1
@.str.14 = private unnamed_addr constant [1 x i8] zeroinitializer, align 1
@xdp_entry_state.___fmt.15 = internal constant [56 x i8] c"tcp(%lu.%lu.%lu.%lu:%u->%lu.%lu.%lu.%lu:%u),state:%s,%s\00", align 1, !dbg !406
@xdp_entry_state.___fmt.16 = internal constant [52 x i8] c"udp(%lu.%lu.%lu.%lu:%u->%lu.%lu.%lu.%lu:%u),len=%lu\00", align 1, !dbg !408
@xdp_entry_state.___fmt.17 = internal constant [55 x i8] c"icmp(%lu.%lu.%lu.%lu->%lu.%lu.%lu.%lu),type=%u,code=%u\00", align 1, !dbg !413
@test.____fmt = internal constant [17 x i8] c"1111111111 test\0A\00", align 1, !dbg !418
@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1, !dbg !432
@print_info_map = dso_local global %struct.anon.16 zeroinitializer, section ".maps", align 8, !dbg !435
@xdp_stats_map = dso_local global %struct.anon.17 zeroinitializer, section ".maps", align 8, !dbg !448
@rules_ipv4_map = dso_local global %struct.anon.18 zeroinitializer, section ".maps", align 8, !dbg !468
@rules_mac_map = dso_local global %struct.anon.19 zeroinitializer, section ".maps", align 8, !dbg !493
@rtcache_map4 = dso_local global %struct.anon.20 zeroinitializer, section ".maps", align 8, !dbg !509
@match_rules_ipv4_loop.____fmt = internal constant [25 x i8] c"match_rules_ipv4_loop %d\00", align 1, !dbg !526
@match_rules_ipv4_loop.___fmt = internal constant [24 x i8] c"src: %lu.%lu.%lu.%lu:%d\00", align 1, !dbg !553
@match_rules_ipv4_loop.___fmt.18 = internal constant [24 x i8] c"dst: %lu.%lu.%lu.%lu:%d\00", align 1, !dbg !558
@match_rules_ipv4_loop.____fmt.19 = internal constant [29 x i8] c"prot:%d ,action:%d ,index:%d\00", align 1, !dbg !560
@match_rules_ipv4_loop.____fmt.20 = internal constant [36 x i8] c"-----------------------------------\00", align 1, !dbg !565
@llvm.compiler.used = appending global [13 x i8*] [i8* getelementptr inbounds ([4 x i8], [4 x i8]* @_license, i32 0, i32 0), i8* bitcast (%struct.anon.15* @conn_ipv4_map to i8*), i8* bitcast (%struct.anon.16* @print_info_map to i8*), i8* bitcast (%struct.anon.20* @rtcache_map4 to i8*), i8* bitcast (%struct.anon.18* @rules_ipv4_map to i8*), i8* bitcast (%struct.anon.19* @rules_mac_map to i8*), i8* bitcast (i32 (%struct.xdp_md*)* @test to i8*), i8* bitcast (%struct.anon.11* @tx_port to i8*), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_entry_ipv4 to i8*), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_entry_mac to i8*), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_entry_router to i8*), i8* bitcast (i32 (%struct.xdp_md*)* @xdp_entry_state to i8*), i8* bitcast (%struct.anon.17* @xdp_stats_map to i8*)], section "llvm.metadata"

; Function Attrs: nounwind
define dso_local i32 @xdp_entry_ipv4(%struct.xdp_md* nocapture noundef readonly %0) #0 section "xdp" !dbg !592 {
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  %4 = alloca i32, align 4
  %5 = alloca [5 x i64], align 8
  %6 = alloca [5 x i64], align 8
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !594, metadata !DIExpression()), !dbg !607
  call void @llvm.dbg.value(metadata i32 2, metadata !595, metadata !DIExpression()), !dbg !607
  %7 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1, !dbg !608
  %8 = load i32, i32* %7, align 4, !dbg !608, !tbaa !609
  %9 = zext i32 %8 to i64, !dbg !614
  %10 = inttoptr i64 %9 to i8*, !dbg !615
  call void @llvm.dbg.value(metadata i8* %10, metadata !597, metadata !DIExpression()), !dbg !607
  %11 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0, !dbg !616
  %12 = load i32, i32* %11, align 4, !dbg !616, !tbaa !617
  %13 = zext i32 %12 to i64, !dbg !618
  %14 = inttoptr i64 %13 to i8*, !dbg !619
  call void @llvm.dbg.value(metadata i8* %14, metadata !598, metadata !DIExpression()), !dbg !607
  call void @llvm.dbg.value(metadata i8 0, metadata !605, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 8)), !dbg !607
  call void @llvm.dbg.value(metadata i8 0, metadata !605, metadata !DIExpression(DW_OP_LLVM_fragment, 8, 8)), !dbg !607
  call void @llvm.dbg.value(metadata i8 0, metadata !605, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 8)), !dbg !607
  call void @llvm.dbg.value(metadata i8 0, metadata !605, metadata !DIExpression(DW_OP_LLVM_fragment, 24, 8)), !dbg !607
  call void @llvm.dbg.value(metadata i8 0, metadata !605, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 8)), !dbg !607
  call void @llvm.dbg.value(metadata i8 0, metadata !605, metadata !DIExpression(DW_OP_LLVM_fragment, 40, 8)), !dbg !607
  call void @llvm.dbg.value(metadata i8 0, metadata !605, metadata !DIExpression(DW_OP_LLVM_fragment, 48, 8)), !dbg !607
  call void @llvm.dbg.value(metadata i8 0, metadata !605, metadata !DIExpression(DW_OP_LLVM_fragment, 56, 8)), !dbg !607
  call void @llvm.dbg.value(metadata i16 0, metadata !605, metadata !DIExpression(DW_OP_LLVM_fragment, 64, 16)), !dbg !607
  call void @llvm.dbg.value(metadata i16 0, metadata !605, metadata !DIExpression(DW_OP_LLVM_fragment, 80, 16)), !dbg !607
  call void @llvm.dbg.value(metadata i16 0, metadata !605, metadata !DIExpression(DW_OP_LLVM_fragment, 96, 16)), !dbg !607
  call void @llvm.dbg.value(metadata i8* %14, metadata !599, metadata !DIExpression()), !dbg !607
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !601, metadata !DIExpression(DW_OP_deref)), !dbg !607
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !620, metadata !DIExpression()) #7, !dbg !629
  call void @llvm.dbg.value(metadata i8* %10, metadata !627, metadata !DIExpression()) #7, !dbg !629
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !628, metadata !DIExpression()) #7, !dbg !629
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !631, metadata !DIExpression()) #7, !dbg !656
  call void @llvm.dbg.value(metadata i8* %10, metadata !643, metadata !DIExpression()) #7, !dbg !656
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !644, metadata !DIExpression()) #7, !dbg !656
  call void @llvm.dbg.value(metadata %struct.collect_vlans* null, metadata !645, metadata !DIExpression()) #7, !dbg !656
  call void @llvm.dbg.value(metadata i8* %14, metadata !646, metadata !DIExpression()) #7, !dbg !656
  call void @llvm.dbg.value(metadata i32 14, metadata !647, metadata !DIExpression()) #7, !dbg !656
  %15 = getelementptr i8, i8* %14, i64 14, !dbg !658
  %16 = icmp ugt i8* %15, %10, !dbg !660
  br i1 %16, label %243, label %17, !dbg !661

17:                                               ; preds = %1
  call void @llvm.dbg.value(metadata i8* %14, metadata !646, metadata !DIExpression()) #7, !dbg !656
  call void @llvm.dbg.value(metadata i8* %15, metadata !599, metadata !DIExpression()), !dbg !607
  call void @llvm.dbg.value(metadata i8* %15, metadata !648, metadata !DIExpression()) #7, !dbg !656
  %18 = getelementptr inbounds i8, i8* %14, i64 12, !dbg !662
  %19 = bitcast i8* %18 to i16*, !dbg !662
  call void @llvm.dbg.value(metadata i16 undef, metadata !654, metadata !DIExpression()) #7, !dbg !656
  call void @llvm.dbg.value(metadata i32 0, metadata !655, metadata !DIExpression()) #7, !dbg !656
  %20 = load i16, i16* %19, align 1, !dbg !656, !tbaa !663
  call void @llvm.dbg.value(metadata i16 %20, metadata !654, metadata !DIExpression()) #7, !dbg !656
  %21 = inttoptr i64 %9 to %struct.vlan_hdr*
  call void @llvm.dbg.value(metadata i16 %20, metadata !665, metadata !DIExpression()) #7, !dbg !670
  %22 = icmp eq i16 %20, 129, !dbg !676
  %23 = icmp eq i16 %20, -22392, !dbg !677
  %24 = tail call i1 @llvm.bpf.passthrough.i1.i1(i32 0, i1 %22) #7
  %25 = or i1 %23, %24, !dbg !677
  %26 = xor i1 %25, true, !dbg !678
  %27 = getelementptr i8, i8* %14, i64 18
  %28 = bitcast i8* %27 to %struct.vlan_hdr*
  %29 = icmp ugt %struct.vlan_hdr* %28, %21
  %30 = select i1 %26, i1 true, i1 %29, !dbg !679
  br i1 %30, label %48, label %31, !dbg !679

31:                                               ; preds = %17
  call void @llvm.dbg.value(metadata i16 undef, metadata !654, metadata !DIExpression()) #7, !dbg !656
  %32 = getelementptr i8, i8* %14, i64 16, !dbg !680
  %33 = bitcast i8* %32 to i16*, !dbg !680
  call void @llvm.dbg.value(metadata %struct.vlan_hdr* %28, metadata !648, metadata !DIExpression()) #7, !dbg !656
  call void @llvm.dbg.value(metadata i32 1, metadata !655, metadata !DIExpression()) #7, !dbg !656
  %34 = load i16, i16* %33, align 1, !dbg !656, !tbaa !663
  call void @llvm.dbg.value(metadata i16 %34, metadata !654, metadata !DIExpression()) #7, !dbg !656
  call void @llvm.dbg.value(metadata i16 %34, metadata !665, metadata !DIExpression()) #7, !dbg !670
  %35 = icmp eq i16 %34, 129, !dbg !676
  %36 = icmp eq i16 %34, -22392, !dbg !677
  %37 = tail call i1 @llvm.bpf.passthrough.i1.i1(i32 0, i1 %35) #7
  %38 = or i1 %36, %37, !dbg !677
  %39 = xor i1 %38, true, !dbg !678
  %40 = getelementptr i8, i8* %14, i64 22
  %41 = bitcast i8* %40 to %struct.vlan_hdr*
  %42 = icmp ugt %struct.vlan_hdr* %41, %21
  %43 = select i1 %39, i1 true, i1 %42, !dbg !679
  br i1 %43, label %48, label %44, !dbg !679

44:                                               ; preds = %31
  call void @llvm.dbg.value(metadata i16 undef, metadata !654, metadata !DIExpression()) #7, !dbg !656
  %45 = getelementptr i8, i8* %14, i64 20, !dbg !680
  %46 = bitcast i8* %45 to i16*, !dbg !680
  call void @llvm.dbg.value(metadata %struct.vlan_hdr* %41, metadata !648, metadata !DIExpression()) #7, !dbg !656
  call void @llvm.dbg.value(metadata i32 2, metadata !655, metadata !DIExpression()) #7, !dbg !656
  %47 = load i16, i16* %46, align 1, !dbg !656, !tbaa !663
  call void @llvm.dbg.value(metadata i16 %47, metadata !654, metadata !DIExpression()) #7, !dbg !656
  br label %48

48:                                               ; preds = %17, %31, %44
  %49 = phi i8* [ %15, %17 ], [ %27, %31 ], [ %40, %44 ], !dbg !656
  %50 = phi i16 [ %20, %17 ], [ %34, %31 ], [ %47, %44 ], !dbg !656
  call void @llvm.dbg.value(metadata i8* %49, metadata !599, metadata !DIExpression()), !dbg !607
  call void @llvm.dbg.value(metadata i16 %50, metadata !600, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !607
  %51 = icmp ne i16 %50, 8
  %52 = getelementptr inbounds i8, i8* %49, i64 20
  %53 = icmp ugt i8* %52, %10
  %54 = select i1 %51, i1 true, i1 %53, !dbg !681
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !682, metadata !DIExpression()), !dbg !692
  call void @llvm.dbg.value(metadata i8* %10, metadata !688, metadata !DIExpression()), !dbg !692
  call void @llvm.dbg.value(metadata %struct.iphdr** undef, metadata !689, metadata !DIExpression()), !dbg !692
  call void @llvm.dbg.value(metadata i8* %49, metadata !690, metadata !DIExpression()), !dbg !692
  br i1 %54, label %243, label %55, !dbg !681

55:                                               ; preds = %48
  %56 = load i8, i8* %49, align 4, !dbg !696
  %57 = shl i8 %56, 2, !dbg !697
  %58 = and i8 %57, 60, !dbg !697
  call void @llvm.dbg.value(metadata i8 %58, metadata !691, metadata !DIExpression(DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !692
  %59 = icmp ult i8 %58, 20, !dbg !698
  br i1 %59, label %243, label %60, !dbg !700

60:                                               ; preds = %55
  %61 = zext i8 %58 to i64
  call void @llvm.dbg.value(metadata i64 %61, metadata !691, metadata !DIExpression()), !dbg !692
  %62 = getelementptr i8, i8* %49, i64 %61, !dbg !701
  %63 = icmp ugt i8* %62, %10, !dbg !703
  br i1 %63, label %243, label %64, !dbg !704

64:                                               ; preds = %60
  call void @llvm.dbg.value(metadata i8* %62, metadata !599, metadata !DIExpression()), !dbg !607
  %65 = getelementptr inbounds i8, i8* %49, i64 9, !dbg !705
  %66 = load i8, i8* %65, align 1, !dbg !705, !tbaa !706
  call void @llvm.dbg.value(metadata i8 %66, metadata !600, metadata !DIExpression(DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !607
  switch i8 %66, label %100 [
    i8 6, label %67
    i8 17, label %81
  ], !dbg !708

67:                                               ; preds = %64
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !709, metadata !DIExpression()), !dbg !719
  call void @llvm.dbg.value(metadata i8* %10, metadata !715, metadata !DIExpression()), !dbg !719
  call void @llvm.dbg.value(metadata %struct.tcphdr** undef, metadata !716, metadata !DIExpression()), !dbg !719
  call void @llvm.dbg.value(metadata i8* %62, metadata !718, metadata !DIExpression()), !dbg !719
  %68 = getelementptr inbounds i8, i8* %62, i64 20, !dbg !724
  %69 = icmp ugt i8* %68, %10, !dbg !726
  br i1 %69, label %243, label %70, !dbg !727

70:                                               ; preds = %67
  %71 = getelementptr inbounds i8, i8* %62, i64 12, !dbg !728
  %72 = bitcast i8* %71 to i16*, !dbg !728
  %73 = load i16, i16* %72, align 4, !dbg !728
  %74 = lshr i16 %73, 2, !dbg !729
  %75 = and i16 %74, 60, !dbg !729
  call void @llvm.dbg.value(metadata i16 %75, metadata !717, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !719
  %76 = icmp ult i16 %75, 20, !dbg !730
  br i1 %76, label %243, label %77, !dbg !732

77:                                               ; preds = %70
  %78 = zext i16 %75 to i64
  %79 = getelementptr i8, i8* %62, i64 %78, !dbg !733
  %80 = icmp ugt i8* %79, %10, !dbg !735
  br i1 %80, label %243, label %92, !dbg !736

81:                                               ; preds = %64
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !737, metadata !DIExpression()) #7, !dbg !747
  call void @llvm.dbg.value(metadata i8* %10, metadata !743, metadata !DIExpression()) #7, !dbg !747
  call void @llvm.dbg.value(metadata %struct.udphdr** undef, metadata !744, metadata !DIExpression()) #7, !dbg !747
  call void @llvm.dbg.value(metadata i8* %62, metadata !746, metadata !DIExpression()) #7, !dbg !747
  %82 = getelementptr inbounds i8, i8* %62, i64 8, !dbg !752
  %83 = bitcast i8* %82 to %struct.udphdr*, !dbg !752
  %84 = inttoptr i64 %9 to %struct.udphdr*, !dbg !754
  %85 = icmp ugt %struct.udphdr* %83, %84, !dbg !755
  br i1 %85, label %243, label %86, !dbg !756

86:                                               ; preds = %81
  call void @llvm.dbg.value(metadata %struct.udphdr* %83, metadata !599, metadata !DIExpression()), !dbg !607
  %87 = getelementptr inbounds i8, i8* %62, i64 4, !dbg !757
  %88 = bitcast i8* %87 to i16*, !dbg !757
  %89 = load i16, i16* %88, align 2, !dbg !757, !tbaa !758
  %90 = tail call i16 @llvm.bswap.i16(i16 %89) #7, !dbg !757
  call void @llvm.dbg.value(metadata i16 %90, metadata !745, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_constu, 8, DW_OP_minus, DW_OP_stack_value)) #7, !dbg !747
  %91 = icmp ult i16 %90, 8, !dbg !760
  br i1 %91, label %243, label %92, !dbg !762

92:                                               ; preds = %86, %77
  %93 = bitcast i8* %62 to i16*, !dbg !763
  %94 = load i16, i16* %93, align 2, !dbg !763, !tbaa !663
  %95 = tail call i16 @llvm.bswap.i16(i16 %94), !dbg !763
  %96 = getelementptr inbounds i8, i8* %62, i64 2, !dbg !763
  %97 = bitcast i8* %96 to i16*, !dbg !763
  %98 = load i16, i16* %97, align 2, !dbg !763, !tbaa !663
  %99 = tail call i16 @llvm.bswap.i16(i16 %98), !dbg !763
  br label %100, !dbg !764

100:                                              ; preds = %92, %64
  %101 = phi i16 [ 0, %64 ], [ %95, %92 ], !dbg !607
  %102 = phi i16 [ 0, %64 ], [ %99, %92 ], !dbg !607
  call void @llvm.dbg.value(metadata i16 %102, metadata !605, metadata !DIExpression(DW_OP_LLVM_fragment, 80, 16)), !dbg !607
  call void @llvm.dbg.value(metadata i16 %101, metadata !605, metadata !DIExpression(DW_OP_LLVM_fragment, 64, 16)), !dbg !607
  call void @llvm.dbg.value(metadata i8* %49, metadata !602, metadata !DIExpression()), !dbg !607
  %103 = getelementptr inbounds i8, i8* %49, i64 12, !dbg !764
  %104 = bitcast i8* %103 to i32*, !dbg !764
  %105 = load i32, i32* %104, align 4, !dbg !764, !tbaa !765
  %106 = tail call i32 @llvm.bswap.i32(i32 %105), !dbg !764
  call void @llvm.dbg.value(metadata i32 %106, metadata !605, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value, DW_OP_LLVM_fragment, 0, 8)), !dbg !607
  %107 = lshr i32 %106, 8, !dbg !766
  call void @llvm.dbg.value(metadata i32 %107, metadata !605, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value, DW_OP_LLVM_fragment, 8, 8)), !dbg !607
  %108 = lshr i32 %106, 16, !dbg !766
  call void @llvm.dbg.value(metadata i32 %108, metadata !605, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value, DW_OP_LLVM_fragment, 16, 8)), !dbg !607
  %109 = lshr i32 %106, 24, !dbg !766
  %110 = zext i32 %109 to i64, !dbg !766
  call void @llvm.dbg.value(metadata i32 %109, metadata !605, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value, DW_OP_LLVM_fragment, 24, 8)), !dbg !607
  %111 = getelementptr inbounds i8, i8* %49, i64 16, !dbg !767
  %112 = bitcast i8* %111 to i32*, !dbg !767
  %113 = load i32, i32* %112, align 4, !dbg !767, !tbaa !765
  %114 = tail call i32 @llvm.bswap.i32(i32 %113), !dbg !767
  call void @llvm.dbg.value(metadata i32 %114, metadata !605, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value, DW_OP_LLVM_fragment, 32, 8)), !dbg !607
  %115 = lshr i32 %114, 8, !dbg !768
  call void @llvm.dbg.value(metadata i32 %115, metadata !605, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value, DW_OP_LLVM_fragment, 40, 8)), !dbg !607
  %116 = lshr i32 %114, 16, !dbg !768
  call void @llvm.dbg.value(metadata i32 %116, metadata !605, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value, DW_OP_LLVM_fragment, 48, 8)), !dbg !607
  %117 = lshr i32 %114, 24, !dbg !768
  %118 = zext i32 %117 to i64, !dbg !768
  call void @llvm.dbg.value(metadata i32 %117, metadata !605, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_stack_value, DW_OP_LLVM_fragment, 56, 8)), !dbg !607
  %119 = zext i8 %66 to i16, !dbg !769
  call void @llvm.dbg.value(metadata i16 %119, metadata !605, metadata !DIExpression(DW_OP_LLVM_fragment, 96, 16)), !dbg !607
  call void @llvm.dbg.declare(metadata i32* undef, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 32)) #7, !dbg !778
  call void @llvm.dbg.value(metadata %struct.conn_ipv4* undef, metadata !775, metadata !DIExpression()) #7, !dbg !780
  call void @llvm.dbg.value(metadata i16 2, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !780
  call void @llvm.dbg.value(metadata i16 0, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !780
  call void @llvm.dbg.value(metadata %struct.conn_ipv4* undef, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 64, 64)) #7, !dbg !780
  call void @llvm.dbg.value(metadata i32 0, metadata !776, metadata !DIExpression()) #7, !dbg !781
  %120 = bitcast i32* %3 to i8*
  %121 = bitcast i32* %4 to i8*
  br label %122, !dbg !782

122:                                              ; preds = %239, %100
  %123 = phi i32 [ 0, %100 ], [ %241, %239 ]
  %124 = phi i16 [ 0, %100 ], [ %240, %239 ]
  call void @llvm.dbg.value(metadata i32 %123, metadata !776, metadata !DIExpression()) #7, !dbg !781
  call void @llvm.dbg.value(metadata i16 %124, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !780
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %120) #7, !dbg !783
  call void @llvm.dbg.value(metadata i32 %123, metadata !532, metadata !DIExpression()) #7, !dbg !783
  store i32 %123, i32* %3, align 4, !tbaa !788
  call void @llvm.dbg.value(metadata i8* undef, metadata !533, metadata !DIExpression()) #7, !dbg !783
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %121) #7, !dbg !789
  call void @llvm.dbg.value(metadata i32 0, metadata !534, metadata !DIExpression()) #7, !dbg !783
  store i32 0, i32* %4, align 4, !dbg !790, !tbaa !788
  call void @llvm.dbg.value(metadata i8* undef, metadata !537, metadata !DIExpression()) #7, !dbg !783
  %125 = zext i16 %124 to i32, !dbg !791
  %126 = icmp eq i32 %123, %125, !dbg !793
  br i1 %126, label %128, label %127, !dbg !794

127:                                              ; preds = %122
  call void @llvm.dbg.value(metadata i16 2, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !780
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %121) #7, !dbg !795
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %120) #7, !dbg !795
  br label %239, !dbg !796

128:                                              ; preds = %122
  call void @llvm.dbg.value(metadata i32* %3, metadata !532, metadata !DIExpression(DW_OP_deref)) #7, !dbg !783
  %129 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* noundef bitcast (%struct.anon.18* @rules_ipv4_map to i8*), i8* noundef nonnull %120) #7, !dbg !797
  call void @llvm.dbg.value(metadata i8* %129, metadata !538, metadata !DIExpression()) #7, !dbg !783
  %130 = icmp eq i8* %129, null, !dbg !798
  br i1 %130, label %131, label %133, !dbg !800

131:                                              ; preds = %128
  call void @llvm.dbg.value(metadata i16 2, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !780
  call void @llvm.dbg.value(metadata i16 %136, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !780
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %121) #7, !dbg !795
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %120) #7, !dbg !795
  call void @llvm.dbg.value(metadata i16 %195, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !780
  call void @llvm.dbg.value(metadata i32 %248, metadata !595, metadata !DIExpression()), !dbg !607
  call void @llvm.dbg.label(metadata !606), !dbg !801
  %132 = bitcast i32* %2 to i8*, !dbg !802
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %132), !dbg !802
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !807, metadata !DIExpression()) #7, !dbg !802
  call void @llvm.dbg.value(metadata i32 %248, metadata !808, metadata !DIExpression()) #7, !dbg !802
  store i32 2, i32* %2, align 4, !tbaa !788
  call void @llvm.dbg.value(metadata i32 undef, metadata !809, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !802
  call void @llvm.dbg.value(metadata i32 undef, metadata !810, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !802
  br label %251, !dbg !814

133:                                              ; preds = %128
  %134 = getelementptr inbounds i8, i8* %129, i64 20, !dbg !815
  %135 = bitcast i8* %134 to i16*, !dbg !815
  %136 = load i16, i16* %135, align 4, !dbg !815, !tbaa !816
  call void @llvm.dbg.value(metadata i16 %136, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !780
  %137 = load i32, i32* %3, align 4, !dbg !818, !tbaa !788
  call void @llvm.dbg.value(metadata i32 %137, metadata !532, metadata !DIExpression()) #7, !dbg !783
  %138 = icmp eq i32 %137, 0, !dbg !820
  br i1 %138, label %236, label %139, !dbg !821

139:                                              ; preds = %133
  %140 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef getelementptr inbounds ([25 x i8], [25 x i8]* @match_rules_ipv4_loop.____fmt, i64 0, i64 0), i32 noundef 25, i32 noundef %137) #7, !dbg !822
  %141 = bitcast i8* %129 to i32*, !dbg !824
  %142 = load i32, i32* %141, align 4, !dbg !824, !tbaa !825
  %143 = getelementptr inbounds i8, i8* %129, i64 8, !dbg !826
  %144 = load i8, i8* %143, align 4, !dbg !826, !tbaa !827
  call void @llvm.dbg.value(metadata i32 undef, metadata !828, metadata !DIExpression()) #7, !dbg !838
  call void @llvm.dbg.value(metadata i32 %142, metadata !833, metadata !DIExpression()) #7, !dbg !838
  call void @llvm.dbg.value(metadata i8 %144, metadata !834, metadata !DIExpression()) #7, !dbg !838
  %145 = icmp eq i32 %142, 0, !dbg !840
  %146 = icmp eq i8 %144, 0
  %147 = and i1 %145, %146, !dbg !842
  br i1 %147, label %155, label %148, !dbg !842

148:                                              ; preds = %139
  call void @llvm.dbg.value(metadata i32 %106, metadata !828, metadata !DIExpression()) #7, !dbg !838
  %149 = zext i8 %144 to i32
  %150 = sub nsw i32 32, %149, !dbg !843
  %151 = shl nsw i32 -1, %150, !dbg !844
  call void @llvm.dbg.value(metadata i32 %151, metadata !835, metadata !DIExpression()) #7, !dbg !838
  call void @llvm.dbg.value(metadata !DIArgList(i32 %151, i32 undef), metadata !836, metadata !DIExpression(DW_OP_LLVM_arg, 0, DW_OP_LLVM_arg, 1, DW_OP_and, DW_OP_stack_value)) #7, !dbg !838
  call void @llvm.dbg.value(metadata !DIArgList(i32 %151, i32 %142), metadata !837, metadata !DIExpression(DW_OP_LLVM_arg, 0, DW_OP_LLVM_arg, 1, DW_OP_and, DW_OP_stack_value)) #7, !dbg !838
  %152 = xor i32 %142, %106, !dbg !845
  %153 = and i32 %151, %152, !dbg !845
  %154 = icmp eq i32 %153, 0, !dbg !845
  br i1 %154, label %155, label %234, !dbg !846

155:                                              ; preds = %148, %139
  %156 = getelementptr inbounds i8, i8* %129, i64 4, !dbg !847
  %157 = bitcast i8* %156 to i32*, !dbg !847
  %158 = load i32, i32* %157, align 4, !dbg !847, !tbaa !848
  %159 = getelementptr inbounds i8, i8* %129, i64 9, !dbg !849
  %160 = load i8, i8* %159, align 1, !dbg !849, !tbaa !850
  call void @llvm.dbg.value(metadata i32 undef, metadata !828, metadata !DIExpression()) #7, !dbg !851
  call void @llvm.dbg.value(metadata i32 %158, metadata !833, metadata !DIExpression()) #7, !dbg !851
  call void @llvm.dbg.value(metadata i8 %160, metadata !834, metadata !DIExpression()) #7, !dbg !851
  %161 = icmp eq i32 %158, 0, !dbg !853
  %162 = icmp eq i8 %160, 0
  %163 = and i1 %161, %162, !dbg !854
  br i1 %163, label %171, label %164, !dbg !854

164:                                              ; preds = %155
  call void @llvm.dbg.value(metadata i32 %114, metadata !828, metadata !DIExpression()) #7, !dbg !851
  %165 = zext i8 %160 to i32
  %166 = sub nsw i32 32, %165, !dbg !855
  %167 = shl nsw i32 -1, %166, !dbg !856
  call void @llvm.dbg.value(metadata i32 %167, metadata !835, metadata !DIExpression()) #7, !dbg !851
  call void @llvm.dbg.value(metadata !DIArgList(i32 %167, i32 undef), metadata !836, metadata !DIExpression(DW_OP_LLVM_arg, 0, DW_OP_LLVM_arg, 1, DW_OP_and, DW_OP_stack_value)) #7, !dbg !851
  call void @llvm.dbg.value(metadata !DIArgList(i32 %167, i32 %158), metadata !837, metadata !DIExpression(DW_OP_LLVM_arg, 0, DW_OP_LLVM_arg, 1, DW_OP_and, DW_OP_stack_value)) #7, !dbg !851
  %168 = xor i32 %158, %114, !dbg !857
  %169 = and i32 %167, %168, !dbg !857
  %170 = icmp eq i32 %169, 0, !dbg !857
  br i1 %170, label %171, label %234, !dbg !858

171:                                              ; preds = %164, %155
  %172 = getelementptr inbounds i8, i8* %129, i64 10, !dbg !859
  %173 = bitcast i8* %172 to i16*, !dbg !859
  %174 = load i16, i16* %173, align 2, !dbg !859, !tbaa !860
  call void @llvm.dbg.value(metadata i16 %101, metadata !861, metadata !DIExpression()) #7, !dbg !867
  call void @llvm.dbg.value(metadata i16 %174, metadata !866, metadata !DIExpression()) #7, !dbg !867
  %175 = icmp ne i16 %174, 0, !dbg !869
  %176 = icmp ne i16 %174, %101
  %177 = and i1 %175, %176, !dbg !871
  br i1 %177, label %234, label %178, !dbg !872

178:                                              ; preds = %171
  %179 = getelementptr inbounds i8, i8* %129, i64 12, !dbg !873
  %180 = bitcast i8* %179 to i16*, !dbg !873
  %181 = load i16, i16* %180, align 4, !dbg !873, !tbaa !874
  call void @llvm.dbg.value(metadata i16 %102, metadata !861, metadata !DIExpression()) #7, !dbg !875
  call void @llvm.dbg.value(metadata i16 %181, metadata !866, metadata !DIExpression()) #7, !dbg !875
  %182 = icmp ne i16 %181, 0, !dbg !877
  %183 = icmp ne i16 %181, %102
  %184 = and i1 %182, %183, !dbg !878
  br i1 %184, label %234, label %185, !dbg !879

185:                                              ; preds = %178
  %186 = getelementptr inbounds i8, i8* %129, i64 14, !dbg !880
  %187 = bitcast i8* %186 to i16*, !dbg !880
  %188 = load i16, i16* %187, align 2, !dbg !880, !tbaa !881
  call void @llvm.dbg.value(metadata i16 %119, metadata !861, metadata !DIExpression()) #7, !dbg !882
  call void @llvm.dbg.value(metadata i16 %188, metadata !866, metadata !DIExpression()) #7, !dbg !882
  %189 = icmp ne i16 %188, 0, !dbg !884
  %190 = icmp ne i16 %188, %119
  %191 = and i1 %189, %190, !dbg !885
  br i1 %191, label %234, label %192, !dbg !886

192:                                              ; preds = %185
  %193 = getelementptr inbounds i8, i8* %129, i64 16, !dbg !887
  %194 = bitcast i8* %193 to i16*, !dbg !887
  %195 = load i16, i16* %194, align 4, !dbg !887, !tbaa !888
  call void @llvm.dbg.value(metadata i16 %195, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !780
  call void @llvm.dbg.value(metadata i32* %4, metadata !534, metadata !DIExpression(DW_OP_deref)) #7, !dbg !783
  %196 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* noundef bitcast (%struct.anon.16* @print_info_map to i8*), i8* noundef nonnull %121) #7, !dbg !889
  call void @llvm.dbg.value(metadata i8* %196, metadata !539, metadata !DIExpression()) #7, !dbg !890
  %197 = icmp eq i8* %196, null, !dbg !891
  br i1 %197, label %198, label %200, !dbg !893

198:                                              ; preds = %192
  %199 = zext i16 %195 to i32, !dbg !894
  br label %247, !dbg !893

200:                                              ; preds = %192
  call void @llvm.dbg.value(metadata i8* undef, metadata !535, metadata !DIExpression()) #7, !dbg !783
  call void @llvm.dbg.value(metadata i8* undef, metadata !536, metadata !DIExpression()) #7, !dbg !783
  %201 = bitcast [5 x i64]* %5 to i8*, !dbg !895
  call void @llvm.lifetime.start.p0i8(i64 40, i8* nonnull %201) #7, !dbg !895
  call void @llvm.dbg.declare(metadata [5 x i64]* %5, metadata !542, metadata !DIExpression()) #7, !dbg !895
  %202 = getelementptr inbounds [5 x i64], [5 x i64]* %5, i64 0, i64 0, !dbg !895
  store i64 %110, i64* %202, align 8, !dbg !895, !tbaa !896
  %203 = and i32 %108, 255, !dbg !895
  %204 = zext i32 %203 to i64, !dbg !895
  %205 = getelementptr inbounds [5 x i64], [5 x i64]* %5, i64 0, i64 1, !dbg !895
  store i64 %204, i64* %205, align 8, !dbg !895, !tbaa !896
  %206 = and i32 %107, 255, !dbg !895
  %207 = zext i32 %206 to i64, !dbg !895
  %208 = getelementptr inbounds [5 x i64], [5 x i64]* %5, i64 0, i64 2, !dbg !895
  store i64 %207, i64* %208, align 8, !dbg !895, !tbaa !896
  %209 = and i32 %106, 255, !dbg !895
  %210 = zext i32 %209 to i64, !dbg !895
  %211 = getelementptr inbounds [5 x i64], [5 x i64]* %5, i64 0, i64 3, !dbg !895
  store i64 %210, i64* %211, align 8, !dbg !895, !tbaa !896
  %212 = zext i16 %101 to i64, !dbg !895
  %213 = getelementptr inbounds [5 x i64], [5 x i64]* %5, i64 0, i64 4, !dbg !895
  store i64 %212, i64* %213, align 8, !dbg !895, !tbaa !896
  %214 = call i64 inttoptr (i64 177 to i64 (i8*, i32, i8*, i32)*)(i8* noundef getelementptr inbounds ([24 x i8], [24 x i8]* @match_rules_ipv4_loop.___fmt, i64 0, i64 0), i32 noundef 24, i8* noundef nonnull %201, i32 noundef 40) #7, !dbg !895
  call void @llvm.lifetime.end.p0i8(i64 40, i8* nonnull %201) #7, !dbg !898
  %215 = bitcast [5 x i64]* %6 to i8*, !dbg !899
  call void @llvm.lifetime.start.p0i8(i64 40, i8* nonnull %215) #7, !dbg !899
  call void @llvm.dbg.declare(metadata [5 x i64]* %6, metadata !547, metadata !DIExpression()) #7, !dbg !899
  %216 = getelementptr inbounds [5 x i64], [5 x i64]* %6, i64 0, i64 0, !dbg !899
  store i64 %118, i64* %216, align 8, !dbg !899, !tbaa !896
  %217 = and i32 %116, 255, !dbg !899
  %218 = zext i32 %217 to i64, !dbg !899
  %219 = getelementptr inbounds [5 x i64], [5 x i64]* %6, i64 0, i64 1, !dbg !899
  store i64 %218, i64* %219, align 8, !dbg !899, !tbaa !896
  %220 = and i32 %115, 255, !dbg !899
  %221 = zext i32 %220 to i64, !dbg !899
  %222 = getelementptr inbounds [5 x i64], [5 x i64]* %6, i64 0, i64 2, !dbg !899
  store i64 %221, i64* %222, align 8, !dbg !899, !tbaa !896
  %223 = and i32 %114, 255, !dbg !899
  %224 = zext i32 %223 to i64, !dbg !899
  %225 = getelementptr inbounds [5 x i64], [5 x i64]* %6, i64 0, i64 3, !dbg !899
  store i64 %224, i64* %225, align 8, !dbg !899, !tbaa !896
  %226 = zext i16 %102 to i64, !dbg !899
  %227 = getelementptr inbounds [5 x i64], [5 x i64]* %6, i64 0, i64 4, !dbg !899
  store i64 %226, i64* %227, align 8, !dbg !899, !tbaa !896
  %228 = call i64 inttoptr (i64 177 to i64 (i8*, i32, i8*, i32)*)(i8* noundef getelementptr inbounds ([24 x i8], [24 x i8]* @match_rules_ipv4_loop.___fmt.18, i64 0, i64 0), i32 noundef 24, i8* noundef nonnull %215, i32 noundef 40) #7, !dbg !899
  call void @llvm.lifetime.end.p0i8(i64 40, i8* nonnull %215) #7, !dbg !900
  %229 = zext i8 %66 to i32, !dbg !901
  %230 = zext i16 %195 to i32, !dbg !901
  %231 = load i32, i32* %3, align 4, !dbg !901, !tbaa !788
  call void @llvm.dbg.value(metadata i32 %231, metadata !532, metadata !DIExpression()) #7, !dbg !783
  %232 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef getelementptr inbounds ([29 x i8], [29 x i8]* @match_rules_ipv4_loop.____fmt.19, i64 0, i64 0), i32 noundef 29, i32 noundef %229, i32 noundef %230, i32 noundef %231) #7, !dbg !901
  %233 = call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef getelementptr inbounds ([36 x i8], [36 x i8]* @match_rules_ipv4_loop.____fmt.20, i64 0, i64 0), i32 noundef 36) #7, !dbg !903
  br label %247, !dbg !905

234:                                              ; preds = %185, %178, %171, %164, %148
  %235 = load i16, i16* %135, align 4, !dbg !906, !tbaa !816
  br label %236, !dbg !906

236:                                              ; preds = %234, %133
  %237 = phi i16 [ %235, %234 ], [ %136, %133 ], !dbg !906
  call void @llvm.dbg.label(metadata !549) #7, !dbg !908
  %238 = icmp eq i16 %237, 0, !dbg !909
  call void @llvm.dbg.value(metadata i16 2, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !780
  call void @llvm.dbg.value(metadata i16 %136, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !780
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %121) #7, !dbg !795
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %120) #7, !dbg !795
  br i1 %238, label %245, label %239, !dbg !796

239:                                              ; preds = %236, %127
  %240 = phi i16 [ %124, %127 ], [ %136, %236 ]
  %241 = add nuw nsw i32 %123, 1, !dbg !910
  call void @llvm.dbg.value(metadata i16 2, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !780
  call void @llvm.dbg.value(metadata i16 %240, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !780
  call void @llvm.dbg.value(metadata i32 %241, metadata !776, metadata !DIExpression()) #7, !dbg !781
  %242 = icmp eq i32 %241, 256, !dbg !911
  br i1 %242, label %245, label %122, !dbg !782, !llvm.loop !912

243:                                              ; preds = %48, %1, %55, %60, %67, %70, %77, %81, %86
  call void @llvm.dbg.value(metadata i32 %248, metadata !595, metadata !DIExpression()), !dbg !607
  call void @llvm.dbg.label(metadata !606), !dbg !801
  %244 = bitcast i32* %2 to i8*, !dbg !802
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %244), !dbg !802
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !807, metadata !DIExpression()) #7, !dbg !802
  call void @llvm.dbg.value(metadata i32 %248, metadata !808, metadata !DIExpression()) #7, !dbg !802
  store i32 2, i32* %2, align 4, !tbaa !788
  call void @llvm.dbg.value(metadata i32 undef, metadata !809, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !802
  call void @llvm.dbg.value(metadata i32 undef, metadata !810, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !802
  br label %251, !dbg !814

245:                                              ; preds = %239, %236
  call void @llvm.dbg.value(metadata i16 %195, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !780
  call void @llvm.dbg.value(metadata i32 %248, metadata !595, metadata !DIExpression()), !dbg !607
  call void @llvm.dbg.label(metadata !606), !dbg !801
  %246 = bitcast i32* %2 to i8*, !dbg !802
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %246), !dbg !802
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !807, metadata !DIExpression()) #7, !dbg !802
  call void @llvm.dbg.value(metadata i32 %248, metadata !808, metadata !DIExpression()) #7, !dbg !802
  store i32 2, i32* %2, align 4, !tbaa !788
  call void @llvm.dbg.value(metadata i32 undef, metadata !809, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !802
  call void @llvm.dbg.value(metadata i32 undef, metadata !810, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !802
  br label %251, !dbg !814

247:                                              ; preds = %198, %200
  %248 = phi i32 [ %199, %198 ], [ %230, %200 ], !dbg !894
  call void @llvm.dbg.value(metadata i16 2, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !780
  call void @llvm.dbg.value(metadata i16 %136, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !780
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %121) #7, !dbg !795
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %120) #7, !dbg !795
  call void @llvm.dbg.value(metadata i16 %195, metadata !770, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !780
  call void @llvm.dbg.value(metadata i32 %248, metadata !595, metadata !DIExpression()), !dbg !607
  call void @llvm.dbg.label(metadata !606), !dbg !801
  %249 = bitcast i32* %2 to i8*, !dbg !802
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %249), !dbg !802
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !807, metadata !DIExpression()) #7, !dbg !802
  call void @llvm.dbg.value(metadata i32 %248, metadata !808, metadata !DIExpression()) #7, !dbg !802
  store i32 %248, i32* %2, align 4, !tbaa !788
  call void @llvm.dbg.value(metadata i32 undef, metadata !809, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !802
  call void @llvm.dbg.value(metadata i32 undef, metadata !810, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !802
  %250 = icmp ugt i16 %195, 4, !dbg !915
  br i1 %250, label %269, label %251, !dbg !814

251:                                              ; preds = %131, %245, %243, %247
  %252 = bitcast i32* %2 to i8*
  %253 = load i32, i32* %7, align 4, !dbg !917, !tbaa !609
  %254 = load i32, i32* %11, align 4, !dbg !918, !tbaa !617
  call void @llvm.dbg.value(metadata i32* %2, metadata !808, metadata !DIExpression(DW_OP_deref)) #7, !dbg !802
  %255 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* noundef bitcast (%struct.anon.17* @xdp_stats_map to i8*), i8* noundef nonnull %252) #7, !dbg !919
  call void @llvm.dbg.value(metadata i8* %255, metadata !811, metadata !DIExpression()) #7, !dbg !802
  %256 = icmp eq i8* %255, null, !dbg !920
  br i1 %256, label %269, label %257, !dbg !922

257:                                              ; preds = %251
  %258 = zext i32 %253 to i64, !dbg !923
  %259 = zext i32 %254 to i64, !dbg !924
  call void @llvm.dbg.value(metadata i8* %255, metadata !811, metadata !DIExpression()) #7, !dbg !802
  %260 = sub nsw i64 %258, %259, !dbg !925
  call void @llvm.dbg.value(metadata i64 %260, metadata !812, metadata !DIExpression()) #7, !dbg !802
  %261 = bitcast i8* %255 to i64*, !dbg !926
  %262 = load i64, i64* %261, align 8, !dbg !927, !tbaa !928
  %263 = add i64 %262, 1, !dbg !927
  store i64 %263, i64* %261, align 8, !dbg !927, !tbaa !928
  %264 = getelementptr inbounds i8, i8* %255, i64 8, !dbg !930
  %265 = bitcast i8* %264 to i64*, !dbg !930
  %266 = load i64, i64* %265, align 8, !dbg !931, !tbaa !932
  %267 = add i64 %260, %266, !dbg !931
  store i64 %267, i64* %265, align 8, !dbg !931, !tbaa !932
  %268 = load i32, i32* %2, align 4, !dbg !933, !tbaa !788
  call void @llvm.dbg.value(metadata i32 %268, metadata !808, metadata !DIExpression()) #7, !dbg !802
  br label %269

269:                                              ; preds = %247, %251, %257
  %270 = phi i32 [ 0, %247 ], [ %268, %257 ], [ 0, %251 ], !dbg !802
  %271 = bitcast i32* %2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %271), !dbg !934
  ret i32 %270, !dbg !935
}

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.declare(metadata, metadata, metadata) #1

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.start.p0i8(i64 immarg, i8* nocapture) #2

; Function Attrs: argmemonly mustprogress nofree nounwind willreturn writeonly
declare void @llvm.memset.p0i8.i64(i8* nocapture writeonly, i8, i64, i1 immarg) #3

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare i16 @llvm.bswap.i16(i16) #1

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare i32 @llvm.bswap.i32(i32) #1

; Function Attrs: mustprogress nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.label(metadata) #1

; Function Attrs: argmemonly mustprogress nofree nosync nounwind willreturn
declare void @llvm.lifetime.end.p0i8(i64 immarg, i8* nocapture) #2

; Function Attrs: nounwind
define dso_local i32 @xdp_entry_router(%struct.xdp_md* noundef %0) #0 section "xdp" !dbg !936 {
  %2 = alloca i32, align 4
  %3 = alloca %struct.bpf_fib_lookup, align 4
  %4 = alloca %struct.rt_item, align 4
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !938, metadata !DIExpression()), !dbg !983
  call void @llvm.dbg.value(metadata i32 2, metadata !939, metadata !DIExpression()), !dbg !983
  %5 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1, !dbg !984
  %6 = load i32, i32* %5, align 4, !dbg !984, !tbaa !609
  %7 = zext i32 %6 to i64, !dbg !985
  %8 = inttoptr i64 %7 to i8*, !dbg !986
  call void @llvm.dbg.value(metadata i8* %8, metadata !940, metadata !DIExpression()), !dbg !983
  %9 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0, !dbg !987
  %10 = load i32, i32* %9, align 4, !dbg !987, !tbaa !617
  %11 = zext i32 %10 to i64, !dbg !988
  %12 = inttoptr i64 %11 to i8*, !dbg !989
  call void @llvm.dbg.value(metadata i8* %12, metadata !941, metadata !DIExpression()), !dbg !983
  %13 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 0, !dbg !990
  call void @llvm.lifetime.start.p0i8(i64 64, i8* nonnull %13) #7, !dbg !990
  call void @llvm.dbg.declare(metadata %struct.bpf_fib_lookup* %3, metadata !942, metadata !DIExpression()), !dbg !991
  call void @llvm.memset.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(64) %13, i8 0, i64 64, i1 false), !dbg !991
  call void @llvm.dbg.value(metadata i64 %11, metadata !945, metadata !DIExpression()), !dbg !983
  call void @llvm.dbg.value(metadata i32 0, metadata !974, metadata !DIExpression()), !dbg !983
  %14 = bitcast %struct.rt_item* %4 to i8*, !dbg !992
  call void @llvm.lifetime.start.p0i8(i64 16, i8* nonnull %14) #7, !dbg !992
  call void @llvm.dbg.declare(metadata %struct.rt_item* %4, metadata !976, metadata !DIExpression()), !dbg !993
  call void @llvm.memset.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(16) %14, i8 0, i64 16, i1 false), !dbg !993
  call void @llvm.dbg.value(metadata i8* %12, metadata !943, metadata !DIExpression()), !dbg !983
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !620, metadata !DIExpression()) #7, !dbg !994
  call void @llvm.dbg.value(metadata i8* %8, metadata !627, metadata !DIExpression()) #7, !dbg !994
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !628, metadata !DIExpression()) #7, !dbg !994
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !631, metadata !DIExpression()) #7, !dbg !996
  call void @llvm.dbg.value(metadata i8* %8, metadata !643, metadata !DIExpression()) #7, !dbg !996
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !644, metadata !DIExpression()) #7, !dbg !996
  call void @llvm.dbg.value(metadata %struct.collect_vlans* null, metadata !645, metadata !DIExpression()) #7, !dbg !996
  call void @llvm.dbg.value(metadata i8* %12, metadata !646, metadata !DIExpression()) #7, !dbg !996
  call void @llvm.dbg.value(metadata i32 14, metadata !647, metadata !DIExpression()) #7, !dbg !996
  %15 = getelementptr i8, i8* %12, i64 14, !dbg !998
  %16 = icmp ugt i8* %15, %8, !dbg !999
  br i1 %16, label %201, label %17, !dbg !1000

17:                                               ; preds = %1
  call void @llvm.dbg.value(metadata i8* %12, metadata !646, metadata !DIExpression()) #7, !dbg !996
  call void @llvm.dbg.value(metadata i8* %15, metadata !943, metadata !DIExpression()), !dbg !983
  %18 = inttoptr i64 %11 to %struct.ethhdr*, !dbg !1001
  call void @llvm.dbg.value(metadata i8* %15, metadata !648, metadata !DIExpression()) #7, !dbg !996
  %19 = getelementptr inbounds i8, i8* %12, i64 12, !dbg !1002
  %20 = bitcast i8* %19 to i16*, !dbg !1002
  call void @llvm.dbg.value(metadata i16 undef, metadata !654, metadata !DIExpression()) #7, !dbg !996
  call void @llvm.dbg.value(metadata i32 0, metadata !655, metadata !DIExpression()) #7, !dbg !996
  %21 = load i16, i16* %20, align 1, !dbg !996, !tbaa !663
  call void @llvm.dbg.value(metadata i16 %21, metadata !654, metadata !DIExpression()) #7, !dbg !996
  %22 = inttoptr i64 %7 to %struct.vlan_hdr*
  call void @llvm.dbg.value(metadata i16 %21, metadata !665, metadata !DIExpression()) #7, !dbg !1003
  %23 = icmp eq i16 %21, 129, !dbg !1005
  %24 = icmp eq i16 %21, -22392, !dbg !1006
  %25 = tail call i1 @llvm.bpf.passthrough.i1.i1(i32 0, i1 %23) #7
  %26 = or i1 %24, %25, !dbg !1006
  %27 = xor i1 %26, true, !dbg !1007
  %28 = getelementptr i8, i8* %12, i64 18
  %29 = bitcast i8* %28 to %struct.vlan_hdr*
  %30 = icmp ugt %struct.vlan_hdr* %29, %22
  %31 = select i1 %27, i1 true, i1 %30, !dbg !1008
  br i1 %31, label %49, label %32, !dbg !1008

32:                                               ; preds = %17
  call void @llvm.dbg.value(metadata i16 undef, metadata !654, metadata !DIExpression()) #7, !dbg !996
  %33 = getelementptr i8, i8* %12, i64 16, !dbg !1009
  %34 = bitcast i8* %33 to i16*, !dbg !1009
  call void @llvm.dbg.value(metadata %struct.vlan_hdr* %29, metadata !648, metadata !DIExpression()) #7, !dbg !996
  call void @llvm.dbg.value(metadata i32 1, metadata !655, metadata !DIExpression()) #7, !dbg !996
  %35 = load i16, i16* %34, align 1, !dbg !996, !tbaa !663
  call void @llvm.dbg.value(metadata i16 %35, metadata !654, metadata !DIExpression()) #7, !dbg !996
  call void @llvm.dbg.value(metadata i16 %35, metadata !665, metadata !DIExpression()) #7, !dbg !1003
  %36 = icmp eq i16 %35, 129, !dbg !1005
  %37 = icmp eq i16 %35, -22392, !dbg !1006
  %38 = tail call i1 @llvm.bpf.passthrough.i1.i1(i32 0, i1 %36) #7
  %39 = or i1 %37, %38, !dbg !1006
  %40 = xor i1 %39, true, !dbg !1007
  %41 = getelementptr i8, i8* %12, i64 22
  %42 = bitcast i8* %41 to %struct.vlan_hdr*
  %43 = icmp ugt %struct.vlan_hdr* %42, %22
  %44 = select i1 %40, i1 true, i1 %43, !dbg !1008
  br i1 %44, label %49, label %45, !dbg !1008

45:                                               ; preds = %32
  call void @llvm.dbg.value(metadata i16 undef, metadata !654, metadata !DIExpression()) #7, !dbg !996
  %46 = getelementptr i8, i8* %12, i64 20, !dbg !1009
  %47 = bitcast i8* %46 to i16*, !dbg !1009
  call void @llvm.dbg.value(metadata %struct.vlan_hdr* %42, metadata !648, metadata !DIExpression()) #7, !dbg !996
  call void @llvm.dbg.value(metadata i32 2, metadata !655, metadata !DIExpression()) #7, !dbg !996
  %48 = load i16, i16* %47, align 1, !dbg !996, !tbaa !663
  call void @llvm.dbg.value(metadata i16 %48, metadata !654, metadata !DIExpression()) #7, !dbg !996
  br label %49

49:                                               ; preds = %17, %32, %45
  %50 = phi i8* [ %15, %17 ], [ %28, %32 ], [ %41, %45 ], !dbg !996
  %51 = phi i16 [ %21, %17 ], [ %35, %32 ], [ %48, %45 ], !dbg !996
  call void @llvm.dbg.value(metadata i8* %50, metadata !943, metadata !DIExpression()), !dbg !983
  call void @llvm.dbg.value(metadata i16 %51, metadata !944, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_signed, DW_OP_LLVM_convert, 32, DW_ATE_signed, DW_OP_stack_value)), !dbg !983
  switch i16 %51, label %201 [
    i16 8, label %52
    i16 -8826, label %155
  ], !dbg !1010

52:                                               ; preds = %49
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !682, metadata !DIExpression()), !dbg !1011
  call void @llvm.dbg.value(metadata i8* %8, metadata !688, metadata !DIExpression()), !dbg !1011
  call void @llvm.dbg.value(metadata %struct.iphdr** undef, metadata !689, metadata !DIExpression()), !dbg !1011
  call void @llvm.dbg.value(metadata i8* %50, metadata !690, metadata !DIExpression()), !dbg !1011
  %53 = getelementptr inbounds i8, i8* %50, i64 20, !dbg !1014
  %54 = icmp ugt i8* %53, %8, !dbg !1016
  br i1 %54, label %201, label %55, !dbg !1017

55:                                               ; preds = %52
  %56 = load i8, i8* %50, align 4, !dbg !1018
  %57 = shl i8 %56, 2, !dbg !1019
  %58 = and i8 %57, 60, !dbg !1019
  call void @llvm.dbg.value(metadata i8 %58, metadata !691, metadata !DIExpression(DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1011
  %59 = icmp ult i8 %58, 20, !dbg !1020
  br i1 %59, label %201, label %60, !dbg !1021

60:                                               ; preds = %55
  %61 = zext i8 %58 to i64
  call void @llvm.dbg.value(metadata i64 %61, metadata !691, metadata !DIExpression()), !dbg !1011
  %62 = getelementptr i8, i8* %50, i64 %61, !dbg !1022
  %63 = icmp ugt i8* %62, %8, !dbg !1023
  br i1 %63, label %201, label %64, !dbg !1024

64:                                               ; preds = %60
  call void @llvm.dbg.value(metadata i8* %62, metadata !943, metadata !DIExpression()), !dbg !983
  call void @llvm.dbg.value(metadata i8 undef, metadata !944, metadata !DIExpression(DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !983
  call void @llvm.dbg.value(metadata i8* %50, metadata !973, metadata !DIExpression()), !dbg !983
  %65 = getelementptr inbounds i8, i8* %50, i64 8, !dbg !1025
  %66 = load i8, i8* %65, align 4, !dbg !1025, !tbaa !1027
  %67 = icmp ult i8 %66, 2, !dbg !1028
  br i1 %67, label %201, label %68, !dbg !1029

68:                                               ; preds = %64
  %69 = getelementptr inbounds i8, i8* %50, i64 12, !dbg !1030
  %70 = bitcast i8* %69 to i32*, !dbg !1030
  %71 = load i32, i32* %70, align 4, !dbg !1030, !tbaa !765
  call void @llvm.dbg.value(metadata i32 %71, metadata !974, metadata !DIExpression()), !dbg !983
  %72 = getelementptr inbounds %struct.rt_item, %struct.rt_item* %4, i64 0, i32 0, !dbg !1031
  store i32 %71, i32* %72, align 4, !dbg !1032, !tbaa !1033
  call void @llvm.dbg.value(metadata %struct.rt_item* %4, metadata !1035, metadata !DIExpression()) #7, !dbg !1041
  call void @llvm.dbg.value(metadata %struct.rt_item* %4, metadata !1040, metadata !DIExpression()) #7, !dbg !1041
  %73 = call i64 inttoptr (i64 181 to i64 (i32, i8*, i8*, i64)*)(i32 noundef 256, i8* noundef bitcast (i32 (i32, i8*)* @match_rules_loop to i8*), i8* noundef nonnull %14, i64 noundef 0) #7, !dbg !1043
  %74 = getelementptr inbounds %struct.rt_item, %struct.rt_item* %4, i64 0, i32 2, i64 0, !dbg !1044
  call void @llvm.dbg.value(metadata i8* %74, metadata !1046, metadata !DIExpression()), !dbg !1055
  call void @llvm.dbg.value(metadata i64 0, metadata !1053, metadata !DIExpression()), !dbg !1057
  %75 = load i8, i8* %74, align 2, !dbg !1058, !tbaa !765
  %76 = icmp eq i8 %75, 0, !dbg !1062
  call void @llvm.dbg.value(metadata i64 0, metadata !1053, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !1057
  %77 = getelementptr inbounds %struct.rt_item, %struct.rt_item* %4, i64 0, i32 2, i64 1
  %78 = load i8, i8* %77, align 1
  %79 = icmp eq i8 %78, 0
  %80 = select i1 %76, i1 %79, i1 false, !dbg !1063
  call void @llvm.dbg.value(metadata i64 1, metadata !1053, metadata !DIExpression()), !dbg !1057
  call void @llvm.dbg.value(metadata i64 1, metadata !1053, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !1057
  %81 = getelementptr inbounds %struct.rt_item, %struct.rt_item* %4, i64 0, i32 2, i64 2
  %82 = load i8, i8* %81, align 4
  %83 = icmp eq i8 %82, 0
  %84 = select i1 %80, i1 %83, i1 false, !dbg !1063
  call void @llvm.dbg.value(metadata i64 2, metadata !1053, metadata !DIExpression()), !dbg !1057
  call void @llvm.dbg.value(metadata i64 2, metadata !1053, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !1057
  %85 = getelementptr inbounds %struct.rt_item, %struct.rt_item* %4, i64 0, i32 2, i64 3
  %86 = load i8, i8* %85, align 1
  %87 = icmp eq i8 %86, 0
  %88 = select i1 %84, i1 %87, i1 false, !dbg !1063
  call void @llvm.dbg.value(metadata i64 3, metadata !1053, metadata !DIExpression()), !dbg !1057
  call void @llvm.dbg.value(metadata i64 3, metadata !1053, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !1057
  %89 = getelementptr inbounds %struct.rt_item, %struct.rt_item* %4, i64 0, i32 2, i64 4
  %90 = load i8, i8* %89, align 2
  %91 = icmp eq i8 %90, 0
  %92 = select i1 %88, i1 %91, i1 false, !dbg !1063
  call void @llvm.dbg.value(metadata i64 4, metadata !1053, metadata !DIExpression()), !dbg !1057
  call void @llvm.dbg.value(metadata i64 4, metadata !1053, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !1057
  %93 = getelementptr inbounds %struct.rt_item, %struct.rt_item* %4, i64 0, i32 2, i64 5
  %94 = load i8, i8* %93, align 1
  %95 = icmp eq i8 %94, 0
  %96 = select i1 %92, i1 %95, i1 false, !dbg !1063
  call void @llvm.dbg.value(metadata i64 5, metadata !1053, metadata !DIExpression()), !dbg !1057
  call void @llvm.dbg.value(metadata i64 5, metadata !1053, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !1057
  br i1 %96, label %111, label %97, !dbg !1063

97:                                               ; preds = %68
  call void @llvm.dbg.value(metadata i8* %50, metadata !973, metadata !DIExpression()), !dbg !983
  call void @llvm.dbg.value(metadata i8* %50, metadata !1064, metadata !DIExpression()), !dbg !1070
  %98 = getelementptr inbounds i8, i8* %50, i64 10, !dbg !1073
  %99 = bitcast i8* %98 to i16*, !dbg !1073
  %100 = load i16, i16* %99, align 2, !dbg !1073, !tbaa !1074
  call void @llvm.dbg.value(metadata i16 %100, metadata !1069, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1070
  %101 = add i16 %100, 1, !dbg !1075
  call void @llvm.dbg.value(metadata i16 %100, metadata !1069, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !1070
  %102 = icmp ugt i16 %100, -3, !dbg !1076
  %103 = zext i1 %102 to i16, !dbg !1076
  %104 = add i16 %101, %103, !dbg !1077
  store i16 %104, i16* %99, align 2, !dbg !1078, !tbaa !1074
  %105 = load i8, i8* %65, align 4, !dbg !1079, !tbaa !1027
  %106 = add i8 %105, -1, !dbg !1079
  store i8 %106, i8* %65, align 4, !dbg !1079, !tbaa !1027
  call void @llvm.dbg.value(metadata %struct.ethhdr* %18, metadata !945, metadata !DIExpression()), !dbg !983
  %107 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %18, i64 0, i32 0, i64 0, !dbg !1080
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(6) %107, i8* noundef nonnull align 2 dereferenceable(6) %74, i64 6, i1 false), !dbg !1080
  %108 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %18, i64 0, i32 1, i64 0, !dbg !1081
  %109 = getelementptr inbounds %struct.rt_item, %struct.rt_item* %4, i64 0, i32 1, i64 0, !dbg !1081
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(6) %108, i8* noundef nonnull align 4 dereferenceable(6) %109, i64 6, i1 false), !dbg !1081
  %110 = call i64 inttoptr (i64 51 to i64 (i8*, i64, i64)*)(i8* noundef bitcast (%struct.anon.11* @tx_port to i8*), i64 noundef 0, i64 noundef 0) #7, !dbg !1082
  call void @llvm.dbg.value(metadata i64 %110, metadata !939, metadata !DIExpression(DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !983
  br label %204, !dbg !1083

111:                                              ; preds = %68
  call void @llvm.dbg.value(metadata i64 5, metadata !1053, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !1057
  store i8 2, i8* %13, align 4, !dbg !1084, !tbaa !1085
  call void @llvm.dbg.value(metadata i8* %50, metadata !973, metadata !DIExpression()), !dbg !983
  %112 = getelementptr inbounds i8, i8* %50, i64 1, !dbg !1087
  %113 = load i8, i8* %112, align 1, !dbg !1087, !tbaa !1088
  %114 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 6, !dbg !1089
  %115 = bitcast %union.anon.2* %114 to i8*, !dbg !1089
  store i8 %113, i8* %115, align 4, !dbg !1090, !tbaa !765
  %116 = getelementptr inbounds i8, i8* %50, i64 9, !dbg !1091
  %117 = load i8, i8* %116, align 1, !dbg !1091, !tbaa !706
  %118 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 1, !dbg !1092
  store i8 %117, i8* %118, align 1, !dbg !1093, !tbaa !1094
  %119 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 2, !dbg !1095
  store i16 0, i16* %119, align 2, !dbg !1096, !tbaa !1097
  %120 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 3, !dbg !1098
  store i16 0, i16* %120, align 4, !dbg !1099, !tbaa !1100
  %121 = getelementptr inbounds i8, i8* %50, i64 2, !dbg !1101
  %122 = bitcast i8* %121 to i16*, !dbg !1101
  %123 = load i16, i16* %122, align 2, !dbg !1101, !tbaa !1102
  %124 = call i16 @llvm.bswap.i16(i16 %123), !dbg !1101
  %125 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 4, i32 0, !dbg !1103
  store i16 %124, i16* %125, align 2, !dbg !1104, !tbaa !765
  %126 = load i32, i32* %70, align 4, !dbg !1105, !tbaa !765
  %127 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 7, i32 0, i64 0, !dbg !1106
  store i32 %126, i32* %127, align 4, !dbg !1107, !tbaa !765
  %128 = getelementptr inbounds i8, i8* %50, i64 16, !dbg !1108
  %129 = bitcast i8* %128 to i32*, !dbg !1108
  %130 = load i32, i32* %129, align 4, !dbg !1108, !tbaa !765
  %131 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 8, i32 0, i64 0, !dbg !1109
  store i32 %130, i32* %131, align 4, !dbg !1110, !tbaa !765
  %132 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 3, !dbg !1111
  %133 = load i32, i32* %132, align 4, !dbg !1111, !tbaa !1112
  %134 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 5, !dbg !1113
  store i32 %133, i32* %134, align 4, !dbg !1114, !tbaa !1115
  %135 = bitcast %struct.xdp_md* %0 to i8*, !dbg !1116
  %136 = call i64 inttoptr (i64 69 to i64 (i8*, %struct.bpf_fib_lookup*, i32, i32)*)(i8* noundef %135, %struct.bpf_fib_lookup* noundef nonnull %3, i32 noundef 64, i32 noundef 0) #7, !dbg !1117
  %137 = trunc i64 %136 to i32, !dbg !1117
  call void @llvm.dbg.value(metadata i32 %137, metadata !975, metadata !DIExpression()), !dbg !983
  switch i32 %137, label %201 [
    i32 0, label %138
    i32 1, label %154
    i32 2, label %154
    i32 3, label %154
  ], !dbg !1118

138:                                              ; preds = %111
  call void @llvm.dbg.value(metadata i8* %50, metadata !973, metadata !DIExpression()), !dbg !983
  call void @llvm.dbg.value(metadata i8* %50, metadata !1064, metadata !DIExpression()), !dbg !1119
  %139 = getelementptr inbounds i8, i8* %50, i64 10, !dbg !1122
  %140 = bitcast i8* %139 to i16*, !dbg !1122
  %141 = load i16, i16* %140, align 2, !dbg !1122, !tbaa !1074
  call void @llvm.dbg.value(metadata i16 %141, metadata !1069, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1119
  %142 = add i16 %141, 1, !dbg !1123
  call void @llvm.dbg.value(metadata i16 %141, metadata !1069, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_plus_uconst, 1, DW_OP_stack_value)), !dbg !1119
  %143 = icmp ugt i16 %141, -3, !dbg !1124
  %144 = zext i1 %143 to i16, !dbg !1124
  %145 = add i16 %142, %144, !dbg !1125
  store i16 %145, i16* %140, align 2, !dbg !1126, !tbaa !1074
  %146 = load i8, i8* %65, align 4, !dbg !1127, !tbaa !1027
  %147 = add i8 %146, -1, !dbg !1127
  store i8 %147, i8* %65, align 4, !dbg !1127, !tbaa !1027
  call void @llvm.dbg.value(metadata %struct.ethhdr* %18, metadata !945, metadata !DIExpression()), !dbg !983
  %148 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %18, i64 0, i32 0, i64 0, !dbg !1128
  %149 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 11, i64 0, !dbg !1128
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(6) %148, i8* noundef nonnull align 2 dereferenceable(6) %149, i64 6, i1 false), !dbg !1128
  %150 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %18, i64 0, i32 1, i64 0, !dbg !1129
  %151 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 10, i64 0, !dbg !1129
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(6) %150, i8* noundef nonnull align 4 dereferenceable(6) %151, i64 6, i1 false), !dbg !1129
  %152 = load i32, i32* %134, align 4, !dbg !1130, !tbaa !1115
  %153 = call i64 inttoptr (i64 23 to i64 (i32, i64)*)(i32 noundef %152, i64 noundef 0) #7, !dbg !1131
  call void @llvm.dbg.value(metadata i64 %153, metadata !939, metadata !DIExpression(DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !983
  br label %204, !dbg !1132

154:                                              ; preds = %111, %111, %111
  call void @llvm.dbg.value(metadata i32 1, metadata !939, metadata !DIExpression()), !dbg !983
  br label %201, !dbg !1133

155:                                              ; preds = %49
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !1134, metadata !DIExpression()), !dbg !1143
  call void @llvm.dbg.value(metadata i8* %8, metadata !1140, metadata !DIExpression()), !dbg !1143
  call void @llvm.dbg.value(metadata %struct.ipv6hdr** undef, metadata !1141, metadata !DIExpression()), !dbg !1143
  call void @llvm.dbg.value(metadata i8* %50, metadata !1142, metadata !DIExpression()), !dbg !1143
  %156 = getelementptr inbounds i8, i8* %50, i64 40, !dbg !1145
  %157 = bitcast i8* %156 to %struct.ipv6hdr*, !dbg !1145
  %158 = inttoptr i64 %7 to %struct.ipv6hdr*, !dbg !1147
  %159 = icmp ugt %struct.ipv6hdr* %157, %158, !dbg !1148
  br i1 %159, label %201, label %160, !dbg !1149

160:                                              ; preds = %155
  call void @llvm.dbg.value(metadata %struct.ipv6hdr* %157, metadata !943, metadata !DIExpression()), !dbg !983
  call void @llvm.dbg.value(metadata i8 undef, metadata !944, metadata !DIExpression(DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !983
  call void @llvm.dbg.value(metadata %struct.bpf_fib_lookup* %3, metadata !977, metadata !DIExpression(DW_OP_plus_uconst, 16, DW_OP_stack_value)), !dbg !1150
  call void @llvm.dbg.value(metadata %struct.bpf_fib_lookup* %3, metadata !981, metadata !DIExpression(DW_OP_plus_uconst, 32, DW_OP_stack_value)), !dbg !1150
  call void @llvm.dbg.value(metadata i8* %50, metadata !946, metadata !DIExpression()), !dbg !983
  %161 = getelementptr inbounds i8, i8* %50, i64 7, !dbg !1151
  %162 = load i8, i8* %161, align 1, !dbg !1151, !tbaa !1153
  %163 = icmp ult i8 %162, 2, !dbg !1155
  br i1 %163, label %201, label %164, !dbg !1156

164:                                              ; preds = %160
  %165 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 8, i32 0, i64 0, !dbg !1157
  call void @llvm.dbg.value(metadata i32* %165, metadata !981, metadata !DIExpression()), !dbg !1150
  %166 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 7, i32 0, i64 0, !dbg !1158
  call void @llvm.dbg.value(metadata i32* %166, metadata !977, metadata !DIExpression()), !dbg !1150
  store i8 10, i8* %13, align 4, !dbg !1159, !tbaa !1085
  %167 = bitcast i8* %50 to i32*, !dbg !1160
  call void @llvm.dbg.value(metadata %struct.ipv6hdr* undef, metadata !946, metadata !DIExpression()), !dbg !983
  %168 = load i32, i32* %167, align 4, !dbg !1161, !tbaa !788
  %169 = and i32 %168, -241, !dbg !1162
  %170 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 6, i32 0, !dbg !1163
  store i32 %169, i32* %170, align 4, !dbg !1164, !tbaa !765
  call void @llvm.dbg.value(metadata i8* %50, metadata !946, metadata !DIExpression()), !dbg !983
  %171 = getelementptr inbounds i8, i8* %50, i64 6, !dbg !1165
  %172 = load i8, i8* %171, align 2, !dbg !1165, !tbaa !1166
  %173 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 1, !dbg !1167
  store i8 %172, i8* %173, align 1, !dbg !1168, !tbaa !1094
  %174 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 2, !dbg !1169
  store i16 0, i16* %174, align 2, !dbg !1170, !tbaa !1097
  %175 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 3, !dbg !1171
  store i16 0, i16* %175, align 4, !dbg !1172, !tbaa !1100
  %176 = getelementptr inbounds i8, i8* %50, i64 4, !dbg !1173
  %177 = bitcast i8* %176 to i16*, !dbg !1173
  %178 = load i16, i16* %177, align 4, !dbg !1173, !tbaa !1174
  %179 = tail call i16 @llvm.bswap.i16(i16 %178), !dbg !1173
  %180 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 4, i32 0, !dbg !1175
  store i16 %179, i16* %180, align 2, !dbg !1176, !tbaa !765
  %181 = getelementptr inbounds i8, i8* %50, i64 8, !dbg !1177
  %182 = bitcast i32* %166 to i8*, !dbg !1177
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(16) %182, i8* noundef nonnull align 4 dereferenceable(16) %181, i64 16, i1 false), !dbg !1177, !tbaa.struct !1178
  %183 = getelementptr inbounds i8, i8* %50, i64 24, !dbg !1179
  %184 = bitcast i32* %165 to i8*, !dbg !1179
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(16) %184, i8* noundef nonnull align 4 dereferenceable(16) %183, i64 16, i1 false), !dbg !1179, !tbaa.struct !1178
  %185 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 3, !dbg !1180
  %186 = load i32, i32* %185, align 4, !dbg !1180, !tbaa !1112
  %187 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 5, !dbg !1181
  store i32 %186, i32* %187, align 4, !dbg !1182, !tbaa !1115
  %188 = bitcast %struct.xdp_md* %0 to i8*, !dbg !1183
  %189 = call i64 inttoptr (i64 69 to i64 (i8*, %struct.bpf_fib_lookup*, i32, i32)*)(i8* noundef %188, %struct.bpf_fib_lookup* noundef nonnull %3, i32 noundef 64, i32 noundef 0) #7, !dbg !1184
  %190 = trunc i64 %189 to i32, !dbg !1184
  call void @llvm.dbg.value(metadata i32 %190, metadata !975, metadata !DIExpression()), !dbg !983
  switch i32 %190, label %201 [
    i32 0, label %191
    i32 1, label %200
    i32 2, label %200
    i32 3, label %200
  ], !dbg !1185

191:                                              ; preds = %164
  call void @llvm.dbg.value(metadata i8* %50, metadata !946, metadata !DIExpression()), !dbg !983
  %192 = load i8, i8* %161, align 1, !dbg !1186, !tbaa !1153
  %193 = add i8 %192, -1, !dbg !1186
  store i8 %193, i8* %161, align 1, !dbg !1186, !tbaa !1153
  call void @llvm.dbg.value(metadata %struct.ethhdr* %18, metadata !945, metadata !DIExpression()), !dbg !983
  %194 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %18, i64 0, i32 0, i64 0, !dbg !1188
  %195 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 11, i64 0, !dbg !1188
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(6) %194, i8* noundef nonnull align 2 dereferenceable(6) %195, i64 6, i1 false), !dbg !1188
  %196 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %18, i64 0, i32 1, i64 0, !dbg !1189
  %197 = getelementptr inbounds %struct.bpf_fib_lookup, %struct.bpf_fib_lookup* %3, i64 0, i32 10, i64 0, !dbg !1189
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 1 dereferenceable(6) %196, i8* noundef nonnull align 4 dereferenceable(6) %197, i64 6, i1 false), !dbg !1189
  %198 = load i32, i32* %187, align 4, !dbg !1190, !tbaa !1115
  %199 = call i64 inttoptr (i64 23 to i64 (i32, i64)*)(i32 noundef %198, i64 noundef 0) #7, !dbg !1191
  call void @llvm.dbg.value(metadata i64 %199, metadata !939, metadata !DIExpression(DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !983
  br label %204, !dbg !1192

200:                                              ; preds = %164, %164, %164
  call void @llvm.dbg.value(metadata i32 1, metadata !939, metadata !DIExpression()), !dbg !983
  br label %201, !dbg !1193

201:                                              ; preds = %64, %111, %154, %49, %160, %164, %200, %1, %52, %55, %60, %155
  %202 = phi i32 [ 1, %200 ], [ 2, %164 ], [ 2, %160 ], [ 2, %49 ], [ 1, %154 ], [ 2, %111 ], [ 2, %64 ], [ 2, %1 ], [ 2, %52 ], [ 2, %55 ], [ 2, %60 ], [ 2, %155 ]
  call void @llvm.dbg.value(metadata i32 %206, metadata !939, metadata !DIExpression()), !dbg !983
  call void @llvm.dbg.label(metadata !982), !dbg !1194
  %203 = bitcast i32* %2 to i8*, !dbg !1195
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %203), !dbg !1195
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !807, metadata !DIExpression()) #7, !dbg !1195
  call void @llvm.dbg.value(metadata i32 %206, metadata !808, metadata !DIExpression()) #7, !dbg !1195
  store i32 %202, i32* %2, align 4, !tbaa !788
  call void @llvm.dbg.value(metadata i32 undef, metadata !809, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !1195
  call void @llvm.dbg.value(metadata i32 undef, metadata !810, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !1195
  br label %209, !dbg !1197

204:                                              ; preds = %191, %138, %97
  %205 = phi i64 [ %110, %97 ], [ %153, %138 ], [ %199, %191 ]
  %206 = trunc i64 %205 to i32, !dbg !983
  call void @llvm.dbg.value(metadata i32 %206, metadata !939, metadata !DIExpression()), !dbg !983
  call void @llvm.dbg.label(metadata !982), !dbg !1194
  %207 = bitcast i32* %2 to i8*, !dbg !1195
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %207), !dbg !1195
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !807, metadata !DIExpression()) #7, !dbg !1195
  call void @llvm.dbg.value(metadata i32 %206, metadata !808, metadata !DIExpression()) #7, !dbg !1195
  store i32 %206, i32* %2, align 4, !tbaa !788
  call void @llvm.dbg.value(metadata i32 undef, metadata !809, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !1195
  call void @llvm.dbg.value(metadata i32 undef, metadata !810, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !1195
  %208 = icmp ugt i32 %206, 4, !dbg !1198
  br i1 %208, label %227, label %209, !dbg !1197

209:                                              ; preds = %201, %204
  %210 = bitcast i32* %2 to i8*
  %211 = load i32, i32* %5, align 4, !dbg !1199, !tbaa !609
  %212 = load i32, i32* %9, align 4, !dbg !1200, !tbaa !617
  call void @llvm.dbg.value(metadata i32* %2, metadata !808, metadata !DIExpression(DW_OP_deref)) #7, !dbg !1195
  %213 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* noundef bitcast (%struct.anon.17* @xdp_stats_map to i8*), i8* noundef nonnull %210) #7, !dbg !1201
  call void @llvm.dbg.value(metadata i8* %213, metadata !811, metadata !DIExpression()) #7, !dbg !1195
  %214 = icmp eq i8* %213, null, !dbg !1202
  br i1 %214, label %227, label %215, !dbg !1203

215:                                              ; preds = %209
  %216 = zext i32 %211 to i64, !dbg !1204
  %217 = zext i32 %212 to i64, !dbg !1205
  call void @llvm.dbg.value(metadata i8* %213, metadata !811, metadata !DIExpression()) #7, !dbg !1195
  %218 = sub nsw i64 %216, %217, !dbg !1206
  call void @llvm.dbg.value(metadata i64 %218, metadata !812, metadata !DIExpression()) #7, !dbg !1195
  %219 = bitcast i8* %213 to i64*, !dbg !1207
  %220 = load i64, i64* %219, align 8, !dbg !1208, !tbaa !928
  %221 = add i64 %220, 1, !dbg !1208
  store i64 %221, i64* %219, align 8, !dbg !1208, !tbaa !928
  %222 = getelementptr inbounds i8, i8* %213, i64 8, !dbg !1209
  %223 = bitcast i8* %222 to i64*, !dbg !1209
  %224 = load i64, i64* %223, align 8, !dbg !1210, !tbaa !932
  %225 = add i64 %218, %224, !dbg !1210
  store i64 %225, i64* %223, align 8, !dbg !1210, !tbaa !932
  %226 = load i32, i32* %2, align 4, !dbg !1211, !tbaa !788
  call void @llvm.dbg.value(metadata i32 %226, metadata !808, metadata !DIExpression()) #7, !dbg !1195
  br label %227

227:                                              ; preds = %204, %209, %215
  %228 = phi i32 [ 0, %204 ], [ %226, %215 ], [ 0, %209 ], !dbg !1195
  %229 = bitcast i32* %2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %229), !dbg !1212
  call void @llvm.lifetime.end.p0i8(i64 16, i8* nonnull %14) #7, !dbg !1213
  call void @llvm.lifetime.end.p0i8(i64 64, i8* nonnull %13) #7, !dbg !1213
  ret i32 %228, !dbg !1213
}

; Function Attrs: argmemonly mustprogress nofree nounwind willreturn
declare void @llvm.memcpy.p0i8.p0i8.i64(i8* noalias nocapture writeonly, i8* noalias nocapture readonly, i64, i1 immarg) #4

; Function Attrs: nounwind
define dso_local i32 @xdp_entry_mac(%struct.xdp_md* nocapture noundef readonly %0) #0 section "xdp" !dbg !1214 {
  %2 = alloca i32, align 4
  %3 = alloca i32, align 4
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !1216, metadata !DIExpression()), !dbg !1227
  call void @llvm.dbg.value(metadata i32 2, metadata !1217, metadata !DIExpression()), !dbg !1227
  %4 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1, !dbg !1228
  %5 = load i32, i32* %4, align 4, !dbg !1228, !tbaa !609
  %6 = zext i32 %5 to i64, !dbg !1229
  %7 = inttoptr i64 %6 to i8*, !dbg !1230
  call void @llvm.dbg.value(metadata i8* %7, metadata !1218, metadata !DIExpression()), !dbg !1227
  %8 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0, !dbg !1231
  %9 = load i32, i32* %8, align 4, !dbg !1231, !tbaa !617
  %10 = zext i32 %9 to i64, !dbg !1232
  %11 = inttoptr i64 %10 to i8*, !dbg !1233
  call void @llvm.dbg.value(metadata i8* %11, metadata !1219, metadata !DIExpression()), !dbg !1227
  call void @llvm.dbg.value(metadata i8 0, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i8 0, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 8, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i8 0, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i8 0, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 24, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i8 0, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i8 0, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 40, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i8 0, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 48, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i8 0, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 56, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i8 0, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 64, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i8 0, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 72, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i8 0, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 80, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i8 0, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 88, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i8* %11, metadata !1220, metadata !DIExpression()), !dbg !1227
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !620, metadata !DIExpression()) #7, !dbg !1234
  call void @llvm.dbg.value(metadata i8* %7, metadata !627, metadata !DIExpression()) #7, !dbg !1234
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !628, metadata !DIExpression()) #7, !dbg !1234
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !631, metadata !DIExpression()) #7, !dbg !1236
  call void @llvm.dbg.value(metadata i8* %7, metadata !643, metadata !DIExpression()) #7, !dbg !1236
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !644, metadata !DIExpression()) #7, !dbg !1236
  call void @llvm.dbg.value(metadata %struct.collect_vlans* null, metadata !645, metadata !DIExpression()) #7, !dbg !1236
  call void @llvm.dbg.value(metadata i8* %11, metadata !646, metadata !DIExpression()) #7, !dbg !1236
  call void @llvm.dbg.value(metadata i32 14, metadata !647, metadata !DIExpression()) #7, !dbg !1236
  %12 = getelementptr i8, i8* %11, i64 14, !dbg !1238
  %13 = icmp ugt i8* %12, %7, !dbg !1239
  br i1 %13, label %203, label %14, !dbg !1240

14:                                               ; preds = %1
  call void @llvm.dbg.value(metadata i8* %11, metadata !646, metadata !DIExpression()) #7, !dbg !1236
  call void @llvm.dbg.value(metadata i8* %12, metadata !1220, metadata !DIExpression()), !dbg !1227
  %15 = inttoptr i64 %10 to %struct.ethhdr*, !dbg !1241
  call void @llvm.dbg.value(metadata i8* %12, metadata !648, metadata !DIExpression()) #7, !dbg !1236
  call void @llvm.dbg.value(metadata i16 undef, metadata !654, metadata !DIExpression()) #7, !dbg !1236
  call void @llvm.dbg.value(metadata i32 0, metadata !655, metadata !DIExpression()) #7, !dbg !1236
  call void @llvm.dbg.value(metadata i16 undef, metadata !654, metadata !DIExpression()) #7, !dbg !1236
  call void @llvm.dbg.value(metadata %struct.vlan_hdr* undef, metadata !1220, metadata !DIExpression()), !dbg !1227
  call void @llvm.dbg.value(metadata i16 undef, metadata !1221, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1227
  call void @llvm.dbg.value(metadata i32 0, metadata !1224, metadata !DIExpression()), !dbg !1242
  %16 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %15, i64 0, i32 0, i64 0, !dbg !1243
  %17 = load i8, i8* %16, align 1, !dbg !1243, !tbaa !765
  call void @llvm.dbg.value(metadata i8 %17, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 8)), !dbg !1227
  %18 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %15, i64 0, i32 0, i64 1, !dbg !1243
  %19 = load i8, i8* %18, align 1, !dbg !1243, !tbaa !765
  call void @llvm.dbg.value(metadata i8 %19, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 8, 8)), !dbg !1227
  %20 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %15, i64 0, i32 0, i64 2, !dbg !1243
  %21 = load i8, i8* %20, align 1, !dbg !1243, !tbaa !765
  call void @llvm.dbg.value(metadata i8 %21, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 8)), !dbg !1227
  %22 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %15, i64 0, i32 0, i64 3, !dbg !1243
  %23 = load i8, i8* %22, align 1, !dbg !1243, !tbaa !765
  call void @llvm.dbg.value(metadata i8 %23, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 24, 8)), !dbg !1227
  %24 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %15, i64 0, i32 0, i64 4, !dbg !1243
  %25 = load i8, i8* %24, align 1, !dbg !1243, !tbaa !765
  call void @llvm.dbg.value(metadata i8 %25, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 8)), !dbg !1227
  %26 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %15, i64 0, i32 0, i64 5, !dbg !1243
  %27 = load i8, i8* %26, align 1, !dbg !1243, !tbaa !765
  call void @llvm.dbg.value(metadata i8 %27, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 40, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i64 0, metadata !1224, metadata !DIExpression()), !dbg !1242
  call void @llvm.dbg.value(metadata %struct.ethhdr* %15, metadata !1222, metadata !DIExpression()), !dbg !1227
  %28 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %15, i64 0, i32 1, i64 0, !dbg !1246
  %29 = load i8, i8* %28, align 1, !dbg !1246, !tbaa !765
  call void @llvm.dbg.value(metadata i8 %29, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 48, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i64 1, metadata !1224, metadata !DIExpression()), !dbg !1242
  call void @llvm.dbg.value(metadata i64 1, metadata !1224, metadata !DIExpression()), !dbg !1242
  call void @llvm.dbg.value(metadata %struct.ethhdr* %15, metadata !1222, metadata !DIExpression()), !dbg !1227
  %30 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %15, i64 0, i32 1, i64 1, !dbg !1246
  %31 = load i8, i8* %30, align 1, !dbg !1246, !tbaa !765
  call void @llvm.dbg.value(metadata i8 %31, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 56, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i64 2, metadata !1224, metadata !DIExpression()), !dbg !1242
  call void @llvm.dbg.value(metadata i64 2, metadata !1224, metadata !DIExpression()), !dbg !1242
  call void @llvm.dbg.value(metadata %struct.ethhdr* %15, metadata !1222, metadata !DIExpression()), !dbg !1227
  %32 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %15, i64 0, i32 1, i64 2, !dbg !1246
  %33 = load i8, i8* %32, align 1, !dbg !1246, !tbaa !765
  call void @llvm.dbg.value(metadata i8 %33, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 64, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i64 3, metadata !1224, metadata !DIExpression()), !dbg !1242
  call void @llvm.dbg.value(metadata i64 3, metadata !1224, metadata !DIExpression()), !dbg !1242
  call void @llvm.dbg.value(metadata %struct.ethhdr* %15, metadata !1222, metadata !DIExpression()), !dbg !1227
  %34 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %15, i64 0, i32 1, i64 3, !dbg !1246
  %35 = load i8, i8* %34, align 1, !dbg !1246, !tbaa !765
  call void @llvm.dbg.value(metadata i8 %35, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 72, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i64 4, metadata !1224, metadata !DIExpression()), !dbg !1242
  call void @llvm.dbg.value(metadata i64 4, metadata !1224, metadata !DIExpression()), !dbg !1242
  call void @llvm.dbg.value(metadata %struct.ethhdr* %15, metadata !1222, metadata !DIExpression()), !dbg !1227
  %36 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %15, i64 0, i32 1, i64 4, !dbg !1246
  %37 = load i8, i8* %36, align 1, !dbg !1246, !tbaa !765
  call void @llvm.dbg.value(metadata i8 %37, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 80, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i64 5, metadata !1224, metadata !DIExpression()), !dbg !1242
  call void @llvm.dbg.value(metadata i64 5, metadata !1224, metadata !DIExpression()), !dbg !1242
  call void @llvm.dbg.value(metadata %struct.ethhdr* %15, metadata !1222, metadata !DIExpression()), !dbg !1227
  %38 = getelementptr inbounds %struct.ethhdr, %struct.ethhdr* %15, i64 0, i32 1, i64 5, !dbg !1246
  %39 = load i8, i8* %38, align 1, !dbg !1246, !tbaa !765
  call void @llvm.dbg.value(metadata i8 %39, metadata !1223, metadata !DIExpression(DW_OP_LLVM_fragment, 88, 8)), !dbg !1227
  call void @llvm.dbg.value(metadata i64 6, metadata !1224, metadata !DIExpression()), !dbg !1242
  call void @llvm.dbg.declare(metadata i32* undef, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 32)) #7, !dbg !1255
  call void @llvm.dbg.value(metadata %struct.conn_mac* undef, metadata !1252, metadata !DIExpression()) #7, !dbg !1257
  call void @llvm.dbg.value(metadata i16 2, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !1257
  call void @llvm.dbg.value(metadata i16 0, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !1257
  call void @llvm.dbg.value(metadata %struct.conn_mac* undef, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 64, 64)) #7, !dbg !1257
  call void @llvm.dbg.value(metadata i32 0, metadata !1253, metadata !DIExpression()) #7, !dbg !1258
  %40 = bitcast i32* %3 to i8*
  br label %41, !dbg !1259

41:                                               ; preds = %199, %14
  %42 = phi i32 [ 0, %14 ], [ %201, %199 ]
  %43 = phi i16 [ 0, %14 ], [ %200, %199 ]
  call void @llvm.dbg.value(metadata i32 %42, metadata !1253, metadata !DIExpression()) #7, !dbg !1258
  call void @llvm.dbg.value(metadata i16 %43, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !1257
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %40) #7, !dbg !1260
  call void @llvm.dbg.value(metadata i32 %42, metadata !1263, metadata !DIExpression()) #7, !dbg !1260
  store i32 %42, i32* %3, align 4, !tbaa !788
  call void @llvm.dbg.value(metadata i8* undef, metadata !1264, metadata !DIExpression()) #7, !dbg !1260
  call void @llvm.dbg.value(metadata i8* undef, metadata !1265, metadata !DIExpression()) #7, !dbg !1260
  %44 = zext i16 %43 to i32, !dbg !1272
  %45 = icmp eq i32 %42, %44, !dbg !1274
  br i1 %45, label %47, label %46, !dbg !1275

46:                                               ; preds = %41
  call void @llvm.dbg.value(metadata i16 2, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !1257
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %40) #7, !dbg !1276
  br label %199, !dbg !1277

47:                                               ; preds = %41
  call void @llvm.dbg.value(metadata i32* %3, metadata !1263, metadata !DIExpression(DW_OP_deref)) #7, !dbg !1260
  %48 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* noundef bitcast (%struct.anon.19* @rules_mac_map to i8*), i8* noundef nonnull %40) #7, !dbg !1278
  call void @llvm.dbg.value(metadata i8* %48, metadata !1266, metadata !DIExpression()) #7, !dbg !1260
  %49 = icmp eq i8* %48, null, !dbg !1279
  br i1 %49, label %50, label %52, !dbg !1281

50:                                               ; preds = %47
  call void @llvm.dbg.value(metadata i16 2, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !1257
  call void @llvm.dbg.value(metadata i16 %55, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !1257
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %40) #7, !dbg !1276
  call void @llvm.dbg.value(metadata i16 %210, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !1257
  call void @llvm.dbg.value(metadata i32 %211, metadata !1217, metadata !DIExpression()), !dbg !1227
  call void @llvm.dbg.label(metadata !1226), !dbg !1282
  %51 = bitcast i32* %2 to i8*, !dbg !1283
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %51), !dbg !1283
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !807, metadata !DIExpression()) #7, !dbg !1283
  call void @llvm.dbg.value(metadata i32 %211, metadata !808, metadata !DIExpression()) #7, !dbg !1283
  store i32 2, i32* %2, align 4, !tbaa !788
  call void @llvm.dbg.value(metadata i32 undef, metadata !809, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !1283
  call void @llvm.dbg.value(metadata i32 undef, metadata !810, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !1283
  br label %214, !dbg !1285

52:                                               ; preds = %47
  %53 = getelementptr inbounds i8, i8* %48, i64 16, !dbg !1286
  %54 = bitcast i8* %53 to i16*, !dbg !1286
  %55 = load i16, i16* %54, align 2, !dbg !1286, !tbaa !1287
  call void @llvm.dbg.value(metadata i16 %55, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !1257
  %56 = load i32, i32* %3, align 4, !dbg !1289, !tbaa !788
  call void @llvm.dbg.value(metadata i32 %56, metadata !1263, metadata !DIExpression()) #7, !dbg !1260
  %57 = icmp eq i32 %56, 0, !dbg !1291
  br i1 %57, label %197, label %58, !dbg !1292

58:                                               ; preds = %52
  call void @llvm.dbg.value(metadata i8* undef, metadata !1293, metadata !DIExpression()) #7, !dbg !1300
  call void @llvm.dbg.value(metadata i8* %48, metadata !1298, metadata !DIExpression()) #7, !dbg !1300
  call void @llvm.dbg.value(metadata i8 0, metadata !1299, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 8)) #7, !dbg !1300
  call void @llvm.dbg.value(metadata i8 0, metadata !1299, metadata !DIExpression(DW_OP_LLVM_fragment, 8, 8)) #7, !dbg !1300
  call void @llvm.dbg.value(metadata i8 0, metadata !1299, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 8)) #7, !dbg !1300
  call void @llvm.dbg.value(metadata i8 0, metadata !1299, metadata !DIExpression(DW_OP_LLVM_fragment, 24, 8)) #7, !dbg !1300
  call void @llvm.dbg.value(metadata i8 0, metadata !1299, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 8)) #7, !dbg !1300
  call void @llvm.dbg.value(metadata i8 0, metadata !1299, metadata !DIExpression(DW_OP_LLVM_fragment, 40, 8)) #7, !dbg !1300
  call void @llvm.dbg.value(metadata i8* %48, metadata !1303, metadata !DIExpression()) #7, !dbg !1317
  call void @llvm.dbg.value(metadata i8* undef, metadata !1310, metadata !DIExpression()) #7, !dbg !1317
  call void @llvm.dbg.value(metadata i64 6, metadata !1311, metadata !DIExpression()) #7, !dbg !1317
  call void @llvm.dbg.value(metadata i8* %48, metadata !1312, metadata !DIExpression()) #7, !dbg !1317
  call void @llvm.dbg.value(metadata i8* undef, metadata !1315, metadata !DIExpression()) #7, !dbg !1317
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression()) #7, !dbg !1317
  %59 = load i8, i8* %48, align 1, !dbg !1320, !tbaa !765
  %60 = icmp eq i8 %59, 0, !dbg !1325
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1317
  br i1 %60, label %61, label %81, !dbg !1326

61:                                               ; preds = %58
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression()) #7, !dbg !1317
  %62 = getelementptr inbounds i8, i8* %48, i64 1, !dbg !1320
  %63 = load i8, i8* %62, align 1, !dbg !1320, !tbaa !765
  %64 = icmp eq i8 %63, 0, !dbg !1325
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1317
  br i1 %64, label %65, label %81, !dbg !1326

65:                                               ; preds = %61
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression()) #7, !dbg !1317
  %66 = getelementptr inbounds i8, i8* %48, i64 2, !dbg !1320
  %67 = load i8, i8* %66, align 1, !dbg !1320, !tbaa !765
  %68 = icmp eq i8 %67, 0, !dbg !1325
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1317
  br i1 %68, label %69, label %81, !dbg !1326

69:                                               ; preds = %65
  call void @llvm.dbg.value(metadata i64 3, metadata !1316, metadata !DIExpression()) #7, !dbg !1317
  %70 = getelementptr inbounds i8, i8* %48, i64 3, !dbg !1320
  %71 = load i8, i8* %70, align 1, !dbg !1320, !tbaa !765
  %72 = icmp eq i8 %71, 0, !dbg !1325
  call void @llvm.dbg.value(metadata i64 3, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1317
  br i1 %72, label %73, label %81, !dbg !1326

73:                                               ; preds = %69
  call void @llvm.dbg.value(metadata i64 4, metadata !1316, metadata !DIExpression()) #7, !dbg !1317
  %74 = getelementptr inbounds i8, i8* %48, i64 4, !dbg !1320
  %75 = load i8, i8* %74, align 1, !dbg !1320, !tbaa !765
  %76 = icmp eq i8 %75, 0, !dbg !1325
  call void @llvm.dbg.value(metadata i64 4, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1317
  br i1 %76, label %77, label %81, !dbg !1326

77:                                               ; preds = %73
  call void @llvm.dbg.value(metadata i64 5, metadata !1316, metadata !DIExpression()) #7, !dbg !1317
  %78 = getelementptr inbounds i8, i8* %48, i64 5, !dbg !1320
  %79 = load i8, i8* %78, align 1, !dbg !1320, !tbaa !765
  %80 = icmp eq i8 %79, 0, !dbg !1325
  call void @llvm.dbg.value(metadata i64 5, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1317
  br i1 %80, label %127, label %81, !dbg !1326

81:                                               ; preds = %77, %73, %69, %65, %61, %58
  %82 = getelementptr inbounds i8, i8* %48, i64 3, !dbg !1327
  call void @llvm.dbg.value(metadata i8* %82, metadata !1303, metadata !DIExpression()) #7, !dbg !1329
  call void @llvm.dbg.value(metadata i8* undef, metadata !1310, metadata !DIExpression()) #7, !dbg !1329
  call void @llvm.dbg.value(metadata i64 3, metadata !1311, metadata !DIExpression()) #7, !dbg !1329
  call void @llvm.dbg.value(metadata i8* %82, metadata !1312, metadata !DIExpression()) #7, !dbg !1329
  call void @llvm.dbg.value(metadata i8* undef, metadata !1315, metadata !DIExpression()) #7, !dbg !1329
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression()) #7, !dbg !1329
  %83 = load i8, i8* %82, align 1, !dbg !1331, !tbaa !765
  %84 = icmp eq i8 %83, 0, !dbg !1332
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1329
  br i1 %84, label %85, label %103, !dbg !1333

85:                                               ; preds = %81
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression()) #7, !dbg !1329
  %86 = getelementptr inbounds i8, i8* %48, i64 4, !dbg !1331
  %87 = load i8, i8* %86, align 1, !dbg !1331, !tbaa !765
  %88 = icmp eq i8 %87, 0, !dbg !1332
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1329
  br i1 %88, label %89, label %103, !dbg !1333

89:                                               ; preds = %85
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression()) #7, !dbg !1329
  %90 = getelementptr inbounds i8, i8* %48, i64 5, !dbg !1331
  %91 = load i8, i8* %90, align 1, !dbg !1331, !tbaa !765
  %92 = icmp eq i8 %91, 0, !dbg !1332
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1329
  %93 = icmp eq i8 %17, %59
  %94 = select i1 %92, i1 %93, i1 false, !dbg !1333
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1329
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression()) #7, !dbg !1334
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1334
  br i1 %94, label %95, label %103, !dbg !1333

95:                                               ; preds = %89
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression()) #7, !dbg !1334
  %96 = getelementptr inbounds i8, i8* %48, i64 1, !dbg !1338
  %97 = load i8, i8* %96, align 1, !dbg !1338, !tbaa !765
  %98 = icmp eq i8 %19, %97, !dbg !1339
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1334
  br i1 %98, label %99, label %108, !dbg !1340

99:                                               ; preds = %95
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression()) #7, !dbg !1334
  %100 = getelementptr inbounds i8, i8* %48, i64 2, !dbg !1338
  %101 = load i8, i8* %100, align 1, !dbg !1338, !tbaa !765
  %102 = icmp eq i8 %21, %101, !dbg !1339
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1334
  br i1 %102, label %127, label %114, !dbg !1340

103:                                              ; preds = %81, %85, %89
  call void @llvm.dbg.value(metadata i8* %48, metadata !1303, metadata !DIExpression()) #7, !dbg !1341
  call void @llvm.dbg.value(metadata i8* undef, metadata !1310, metadata !DIExpression()) #7, !dbg !1341
  call void @llvm.dbg.value(metadata i64 6, metadata !1311, metadata !DIExpression()) #7, !dbg !1341
  call void @llvm.dbg.value(metadata i8* %48, metadata !1312, metadata !DIExpression()) #7, !dbg !1341
  call void @llvm.dbg.value(metadata i8* undef, metadata !1315, metadata !DIExpression()) #7, !dbg !1341
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression()) #7, !dbg !1341
  %104 = icmp eq i8 %59, %17, !dbg !1344
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1341
  br i1 %104, label %105, label %197, !dbg !1345

105:                                              ; preds = %103
  %106 = getelementptr inbounds i8, i8* %48, i64 1
  %107 = load i8, i8* %106, align 1, !dbg !1346, !tbaa !765
  br label %108, !dbg !1345

108:                                              ; preds = %105, %95
  %109 = phi i8 [ %107, %105 ], [ %97, %95 ], !dbg !1346
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression()) #7, !dbg !1341
  %110 = icmp eq i8 %109, %19, !dbg !1344
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1341
  br i1 %110, label %111, label %197, !dbg !1345

111:                                              ; preds = %108
  %112 = getelementptr inbounds i8, i8* %48, i64 2
  %113 = load i8, i8* %112, align 1, !dbg !1346, !tbaa !765
  br label %114, !dbg !1345

114:                                              ; preds = %111, %99
  %115 = phi i8 [ %113, %111 ], [ %101, %99 ], !dbg !1346
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression()) #7, !dbg !1341
  %116 = icmp eq i8 %115, %21, !dbg !1344
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1341
  %117 = icmp eq i8 %83, %23
  %118 = select i1 %116, i1 %117, i1 false, !dbg !1345
  call void @llvm.dbg.value(metadata i64 3, metadata !1316, metadata !DIExpression()) #7, !dbg !1341
  call void @llvm.dbg.value(metadata i64 3, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1341
  br i1 %118, label %119, label %197, !dbg !1345

119:                                              ; preds = %114
  call void @llvm.dbg.value(metadata i64 4, metadata !1316, metadata !DIExpression()) #7, !dbg !1341
  %120 = getelementptr inbounds i8, i8* %48, i64 4, !dbg !1346
  %121 = load i8, i8* %120, align 1, !dbg !1346, !tbaa !765
  %122 = icmp eq i8 %121, %25, !dbg !1344
  call void @llvm.dbg.value(metadata i64 4, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1341
  br i1 %122, label %123, label %197, !dbg !1345

123:                                              ; preds = %119
  call void @llvm.dbg.value(metadata i64 5, metadata !1316, metadata !DIExpression()) #7, !dbg !1341
  %124 = getelementptr inbounds i8, i8* %48, i64 5, !dbg !1346
  %125 = load i8, i8* %124, align 1, !dbg !1346, !tbaa !765
  %126 = icmp eq i8 %125, %27, !dbg !1344
  call void @llvm.dbg.value(metadata i64 5, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1341
  br i1 %126, label %127, label %197, !dbg !1345

127:                                              ; preds = %123, %99, %77
  %128 = getelementptr inbounds i8, i8* %48, i64 6, !dbg !1347
  call void @llvm.dbg.value(metadata i8* undef, metadata !1293, metadata !DIExpression()) #7, !dbg !1348
  call void @llvm.dbg.value(metadata i8* %128, metadata !1298, metadata !DIExpression()) #7, !dbg !1348
  call void @llvm.dbg.value(metadata i8 0, metadata !1299, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 8)) #7, !dbg !1348
  call void @llvm.dbg.value(metadata i8 0, metadata !1299, metadata !DIExpression(DW_OP_LLVM_fragment, 8, 8)) #7, !dbg !1348
  call void @llvm.dbg.value(metadata i8 0, metadata !1299, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 8)) #7, !dbg !1348
  call void @llvm.dbg.value(metadata i8 0, metadata !1299, metadata !DIExpression(DW_OP_LLVM_fragment, 24, 8)) #7, !dbg !1348
  call void @llvm.dbg.value(metadata i8 0, metadata !1299, metadata !DIExpression(DW_OP_LLVM_fragment, 32, 8)) #7, !dbg !1348
  call void @llvm.dbg.value(metadata i8 0, metadata !1299, metadata !DIExpression(DW_OP_LLVM_fragment, 40, 8)) #7, !dbg !1348
  call void @llvm.dbg.value(metadata i8* %128, metadata !1303, metadata !DIExpression()) #7, !dbg !1350
  call void @llvm.dbg.value(metadata i8* undef, metadata !1310, metadata !DIExpression()) #7, !dbg !1350
  call void @llvm.dbg.value(metadata i64 6, metadata !1311, metadata !DIExpression()) #7, !dbg !1350
  call void @llvm.dbg.value(metadata i8* %128, metadata !1312, metadata !DIExpression()) #7, !dbg !1350
  call void @llvm.dbg.value(metadata i8* undef, metadata !1315, metadata !DIExpression()) #7, !dbg !1350
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression()) #7, !dbg !1350
  %129 = load i8, i8* %128, align 1, !dbg !1352, !tbaa !765
  %130 = icmp eq i8 %129, 0, !dbg !1353
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1350
  br i1 %130, label %131, label %151, !dbg !1354

131:                                              ; preds = %127
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression()) #7, !dbg !1350
  %132 = getelementptr inbounds i8, i8* %48, i64 7, !dbg !1352
  %133 = load i8, i8* %132, align 1, !dbg !1352, !tbaa !765
  %134 = icmp eq i8 %133, 0, !dbg !1353
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1350
  br i1 %134, label %135, label %151, !dbg !1354

135:                                              ; preds = %131
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression()) #7, !dbg !1350
  %136 = getelementptr inbounds i8, i8* %48, i64 8, !dbg !1352
  %137 = load i8, i8* %136, align 1, !dbg !1352, !tbaa !765
  %138 = icmp eq i8 %137, 0, !dbg !1353
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1350
  br i1 %138, label %139, label %151, !dbg !1354

139:                                              ; preds = %135
  call void @llvm.dbg.value(metadata i64 3, metadata !1316, metadata !DIExpression()) #7, !dbg !1350
  %140 = getelementptr inbounds i8, i8* %48, i64 9, !dbg !1352
  %141 = load i8, i8* %140, align 1, !dbg !1352, !tbaa !765
  %142 = icmp eq i8 %141, 0, !dbg !1353
  call void @llvm.dbg.value(metadata i64 3, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1350
  br i1 %142, label %143, label %151, !dbg !1354

143:                                              ; preds = %139
  call void @llvm.dbg.value(metadata i64 4, metadata !1316, metadata !DIExpression()) #7, !dbg !1350
  %144 = getelementptr inbounds i8, i8* %48, i64 10, !dbg !1352
  %145 = load i8, i8* %144, align 1, !dbg !1352, !tbaa !765
  %146 = icmp eq i8 %145, 0, !dbg !1353
  call void @llvm.dbg.value(metadata i64 4, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1350
  br i1 %146, label %147, label %151, !dbg !1354

147:                                              ; preds = %143
  call void @llvm.dbg.value(metadata i64 5, metadata !1316, metadata !DIExpression()) #7, !dbg !1350
  %148 = getelementptr inbounds i8, i8* %48, i64 11, !dbg !1352
  %149 = load i8, i8* %148, align 1, !dbg !1352, !tbaa !765
  %150 = icmp eq i8 %149, 0, !dbg !1353
  call void @llvm.dbg.value(metadata i64 5, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1350
  br i1 %150, label %207, label %151, !dbg !1354

151:                                              ; preds = %147, %143, %139, %135, %131, %127
  %152 = getelementptr inbounds i8, i8* %48, i64 9, !dbg !1355
  call void @llvm.dbg.value(metadata i8* %152, metadata !1303, metadata !DIExpression()) #7, !dbg !1356
  call void @llvm.dbg.value(metadata i8* undef, metadata !1310, metadata !DIExpression()) #7, !dbg !1356
  call void @llvm.dbg.value(metadata i64 3, metadata !1311, metadata !DIExpression()) #7, !dbg !1356
  call void @llvm.dbg.value(metadata i8* %152, metadata !1312, metadata !DIExpression()) #7, !dbg !1356
  call void @llvm.dbg.value(metadata i8* undef, metadata !1315, metadata !DIExpression()) #7, !dbg !1356
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression()) #7, !dbg !1356
  %153 = load i8, i8* %152, align 1, !dbg !1358, !tbaa !765
  %154 = icmp eq i8 %153, 0, !dbg !1359
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1356
  br i1 %154, label %155, label %173, !dbg !1360

155:                                              ; preds = %151
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression()) #7, !dbg !1356
  %156 = getelementptr inbounds i8, i8* %48, i64 10, !dbg !1358
  %157 = load i8, i8* %156, align 1, !dbg !1358, !tbaa !765
  %158 = icmp eq i8 %157, 0, !dbg !1359
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1356
  br i1 %158, label %159, label %173, !dbg !1360

159:                                              ; preds = %155
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression()) #7, !dbg !1356
  %160 = getelementptr inbounds i8, i8* %48, i64 11, !dbg !1358
  %161 = load i8, i8* %160, align 1, !dbg !1358, !tbaa !765
  %162 = icmp eq i8 %161, 0, !dbg !1359
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1356
  %163 = icmp eq i8 %29, %129
  %164 = select i1 %162, i1 %163, i1 false, !dbg !1360
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1356
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression()) #7, !dbg !1361
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1361
  br i1 %164, label %165, label %173, !dbg !1360

165:                                              ; preds = %159
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression()) #7, !dbg !1361
  %166 = getelementptr inbounds i8, i8* %48, i64 7, !dbg !1363
  %167 = load i8, i8* %166, align 1, !dbg !1363, !tbaa !765
  %168 = icmp eq i8 %31, %167, !dbg !1364
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1361
  br i1 %168, label %169, label %178, !dbg !1365

169:                                              ; preds = %165
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression()) #7, !dbg !1361
  %170 = getelementptr inbounds i8, i8* %48, i64 8, !dbg !1363
  %171 = load i8, i8* %170, align 1, !dbg !1363, !tbaa !765
  %172 = icmp eq i8 %33, %171, !dbg !1364
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1361
  br i1 %172, label %207, label %184, !dbg !1365

173:                                              ; preds = %151, %155, %159
  call void @llvm.dbg.value(metadata i8* %128, metadata !1303, metadata !DIExpression()) #7, !dbg !1366
  call void @llvm.dbg.value(metadata i8* undef, metadata !1310, metadata !DIExpression()) #7, !dbg !1366
  call void @llvm.dbg.value(metadata i64 6, metadata !1311, metadata !DIExpression()) #7, !dbg !1366
  call void @llvm.dbg.value(metadata i8* %128, metadata !1312, metadata !DIExpression()) #7, !dbg !1366
  call void @llvm.dbg.value(metadata i8* undef, metadata !1315, metadata !DIExpression()) #7, !dbg !1366
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression()) #7, !dbg !1366
  %174 = icmp eq i8 %129, %29, !dbg !1368
  call void @llvm.dbg.value(metadata i64 0, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1366
  br i1 %174, label %175, label %197, !dbg !1369

175:                                              ; preds = %173
  %176 = getelementptr inbounds i8, i8* %48, i64 7
  %177 = load i8, i8* %176, align 1, !dbg !1370, !tbaa !765
  br label %178, !dbg !1369

178:                                              ; preds = %175, %165
  %179 = phi i8 [ %177, %175 ], [ %167, %165 ], !dbg !1370
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression()) #7, !dbg !1366
  %180 = icmp eq i8 %179, %31, !dbg !1368
  call void @llvm.dbg.value(metadata i64 1, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1366
  br i1 %180, label %181, label %197, !dbg !1369

181:                                              ; preds = %178
  %182 = getelementptr inbounds i8, i8* %48, i64 8
  %183 = load i8, i8* %182, align 1, !dbg !1370, !tbaa !765
  br label %184, !dbg !1369

184:                                              ; preds = %181, %169
  %185 = phi i8 [ %183, %181 ], [ %171, %169 ], !dbg !1370
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression()) #7, !dbg !1366
  %186 = icmp eq i8 %185, %33, !dbg !1368
  call void @llvm.dbg.value(metadata i64 2, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1366
  %187 = icmp eq i8 %153, %35
  %188 = select i1 %186, i1 %187, i1 false, !dbg !1369
  call void @llvm.dbg.value(metadata i64 3, metadata !1316, metadata !DIExpression()) #7, !dbg !1366
  call void @llvm.dbg.value(metadata i64 3, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1366
  br i1 %188, label %189, label %197, !dbg !1369

189:                                              ; preds = %184
  call void @llvm.dbg.value(metadata i64 4, metadata !1316, metadata !DIExpression()) #7, !dbg !1366
  %190 = getelementptr inbounds i8, i8* %48, i64 10, !dbg !1370
  %191 = load i8, i8* %190, align 1, !dbg !1370, !tbaa !765
  %192 = icmp eq i8 %191, %37, !dbg !1368
  call void @llvm.dbg.value(metadata i64 4, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1366
  br i1 %192, label %193, label %197, !dbg !1369

193:                                              ; preds = %189
  call void @llvm.dbg.value(metadata i64 5, metadata !1316, metadata !DIExpression()) #7, !dbg !1366
  %194 = getelementptr inbounds i8, i8* %48, i64 11, !dbg !1370
  %195 = load i8, i8* %194, align 1, !dbg !1370, !tbaa !765
  %196 = icmp eq i8 %195, %39, !dbg !1368
  call void @llvm.dbg.value(metadata i64 5, metadata !1316, metadata !DIExpression(DW_OP_plus_uconst, 1, DW_OP_stack_value)) #7, !dbg !1366
  br i1 %196, label %207, label %197, !dbg !1369

197:                                              ; preds = %193, %189, %184, %178, %173, %123, %119, %114, %108, %103, %52
  call void @llvm.dbg.label(metadata !1267) #7, !dbg !1371
  %198 = icmp eq i16 %55, 0, !dbg !1372
  call void @llvm.dbg.value(metadata i16 2, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !1257
  call void @llvm.dbg.value(metadata i16 %55, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !1257
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %40) #7, !dbg !1276
  br i1 %198, label %205, label %199, !dbg !1277

199:                                              ; preds = %197, %46
  %200 = phi i16 [ %43, %46 ], [ %55, %197 ]
  %201 = add nuw nsw i32 %42, 1, !dbg !1374
  call void @llvm.dbg.value(metadata i16 2, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !1257
  call void @llvm.dbg.value(metadata i16 %200, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !1257
  call void @llvm.dbg.value(metadata i32 %201, metadata !1253, metadata !DIExpression()) #7, !dbg !1258
  %202 = icmp eq i32 %201, 256, !dbg !1375
  br i1 %202, label %205, label %41, !dbg !1259, !llvm.loop !1376

203:                                              ; preds = %1
  call void @llvm.dbg.value(metadata i32 %211, metadata !1217, metadata !DIExpression()), !dbg !1227
  call void @llvm.dbg.label(metadata !1226), !dbg !1282
  %204 = bitcast i32* %2 to i8*, !dbg !1283
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %204), !dbg !1283
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !807, metadata !DIExpression()) #7, !dbg !1283
  call void @llvm.dbg.value(metadata i32 %211, metadata !808, metadata !DIExpression()) #7, !dbg !1283
  store i32 2, i32* %2, align 4, !tbaa !788
  call void @llvm.dbg.value(metadata i32 undef, metadata !809, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !1283
  call void @llvm.dbg.value(metadata i32 undef, metadata !810, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !1283
  br label %214, !dbg !1285

205:                                              ; preds = %199, %197
  call void @llvm.dbg.value(metadata i16 %210, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !1257
  call void @llvm.dbg.value(metadata i32 %211, metadata !1217, metadata !DIExpression()), !dbg !1227
  call void @llvm.dbg.label(metadata !1226), !dbg !1282
  %206 = bitcast i32* %2 to i8*, !dbg !1283
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %206), !dbg !1283
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !807, metadata !DIExpression()) #7, !dbg !1283
  call void @llvm.dbg.value(metadata i32 %211, metadata !808, metadata !DIExpression()) #7, !dbg !1283
  store i32 2, i32* %2, align 4, !tbaa !788
  call void @llvm.dbg.value(metadata i32 undef, metadata !809, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !1283
  call void @llvm.dbg.value(metadata i32 undef, metadata !810, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !1283
  br label %214, !dbg !1285

207:                                              ; preds = %147, %169, %193
  %208 = getelementptr inbounds i8, i8* %48, i64 12, !dbg !1378
  %209 = bitcast i8* %208 to i16*, !dbg !1378
  %210 = load i16, i16* %209, align 2, !dbg !1378, !tbaa !1380
  call void @llvm.dbg.value(metadata i16 2, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !1257
  call void @llvm.dbg.value(metadata i16 %55, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 16, 16)) #7, !dbg !1257
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %40) #7, !dbg !1276
  call void @llvm.dbg.value(metadata i16 %210, metadata !1247, metadata !DIExpression(DW_OP_LLVM_fragment, 0, 16)) #7, !dbg !1257
  %211 = zext i16 %210 to i32, !dbg !1381
  call void @llvm.dbg.value(metadata i32 %211, metadata !1217, metadata !DIExpression()), !dbg !1227
  call void @llvm.dbg.label(metadata !1226), !dbg !1282
  %212 = bitcast i32* %2 to i8*, !dbg !1283
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %212), !dbg !1283
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !807, metadata !DIExpression()) #7, !dbg !1283
  call void @llvm.dbg.value(metadata i32 %211, metadata !808, metadata !DIExpression()) #7, !dbg !1283
  store i32 %211, i32* %2, align 4, !tbaa !788
  call void @llvm.dbg.value(metadata i32 undef, metadata !809, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !1283
  call void @llvm.dbg.value(metadata i32 undef, metadata !810, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !1283
  %213 = icmp ugt i16 %210, 4, !dbg !1382
  br i1 %213, label %232, label %214, !dbg !1285

214:                                              ; preds = %50, %205, %203, %207
  %215 = bitcast i32* %2 to i8*
  %216 = load i32, i32* %4, align 4, !dbg !1383, !tbaa !609
  %217 = load i32, i32* %8, align 4, !dbg !1384, !tbaa !617
  call void @llvm.dbg.value(metadata i32* %2, metadata !808, metadata !DIExpression(DW_OP_deref)) #7, !dbg !1283
  %218 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* noundef bitcast (%struct.anon.17* @xdp_stats_map to i8*), i8* noundef nonnull %215) #7, !dbg !1385
  call void @llvm.dbg.value(metadata i8* %218, metadata !811, metadata !DIExpression()) #7, !dbg !1283
  %219 = icmp eq i8* %218, null, !dbg !1386
  br i1 %219, label %232, label %220, !dbg !1387

220:                                              ; preds = %214
  %221 = zext i32 %216 to i64, !dbg !1388
  %222 = zext i32 %217 to i64, !dbg !1389
  call void @llvm.dbg.value(metadata i8* %218, metadata !811, metadata !DIExpression()) #7, !dbg !1283
  %223 = sub nsw i64 %221, %222, !dbg !1390
  call void @llvm.dbg.value(metadata i64 %223, metadata !812, metadata !DIExpression()) #7, !dbg !1283
  %224 = bitcast i8* %218 to i64*, !dbg !1391
  %225 = load i64, i64* %224, align 8, !dbg !1392, !tbaa !928
  %226 = add i64 %225, 1, !dbg !1392
  store i64 %226, i64* %224, align 8, !dbg !1392, !tbaa !928
  %227 = getelementptr inbounds i8, i8* %218, i64 8, !dbg !1393
  %228 = bitcast i8* %227 to i64*, !dbg !1393
  %229 = load i64, i64* %228, align 8, !dbg !1394, !tbaa !932
  %230 = add i64 %223, %229, !dbg !1394
  store i64 %230, i64* %228, align 8, !dbg !1394, !tbaa !932
  %231 = load i32, i32* %2, align 4, !dbg !1395, !tbaa !788
  call void @llvm.dbg.value(metadata i32 %231, metadata !808, metadata !DIExpression()) #7, !dbg !1283
  br label %232

232:                                              ; preds = %207, %214, %220
  %233 = phi i32 [ 0, %207 ], [ %231, %220 ], [ 0, %214 ], !dbg !1283
  %234 = bitcast i32* %2 to i8*
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %234), !dbg !1396
  ret i32 %233, !dbg !1397
}

; Function Attrs: nounwind
define dso_local i32 @xdp_entry_state(%struct.xdp_md* nocapture noundef readonly %0) #0 section "xdp" !dbg !212 {
  %2 = alloca i32, align 4
  %3 = alloca %struct.conn_ipv4_key, align 4
  %4 = alloca i64, align 8
  %5 = bitcast i64* %4 to %struct.conn_ipv4_val*
  %6 = alloca [12 x i64], align 8
  %7 = alloca i64, align 8
  %8 = bitcast i64* %7 to %struct.conn_ipv4_val*
  %9 = alloca [12 x i64], align 8
  %10 = alloca [12 x i64], align 8
  %11 = alloca [12 x i64], align 8
  %12 = alloca [11 x i64], align 8
  %13 = alloca [10 x i64], align 8
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !225, metadata !DIExpression()), !dbg !1398
  call void @llvm.dbg.value(metadata i32 2, metadata !226, metadata !DIExpression()), !dbg !1398
  %14 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 1, !dbg !1399
  %15 = load i32, i32* %14, align 4, !dbg !1399, !tbaa !609
  %16 = zext i32 %15 to i64, !dbg !1400
  %17 = inttoptr i64 %16 to i8*, !dbg !1401
  call void @llvm.dbg.value(metadata i8* %17, metadata !227, metadata !DIExpression()), !dbg !1398
  %18 = getelementptr inbounds %struct.xdp_md, %struct.xdp_md* %0, i64 0, i32 0, !dbg !1402
  %19 = load i32, i32* %18, align 4, !dbg !1402, !tbaa !617
  %20 = zext i32 %19 to i64, !dbg !1403
  %21 = inttoptr i64 %20 to i8*, !dbg !1404
  call void @llvm.dbg.value(metadata i8* %21, metadata !228, metadata !DIExpression()), !dbg !1398
  %22 = bitcast %struct.conn_ipv4_key* %3 to i8*, !dbg !1405
  call void @llvm.lifetime.start.p0i8(i64 16, i8* nonnull %22) #7, !dbg !1405
  call void @llvm.dbg.declare(metadata %struct.conn_ipv4_key* %3, metadata !328, metadata !DIExpression()), !dbg !1406
  call void @llvm.memset.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(16) %22, i8 0, i64 16, i1 false), !dbg !1406
  call void @llvm.dbg.value(metadata i8* %21, metadata !229, metadata !DIExpression()), !dbg !1398
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !235, metadata !DIExpression(DW_OP_deref)), !dbg !1398
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !620, metadata !DIExpression()) #7, !dbg !1407
  call void @llvm.dbg.value(metadata i8* %17, metadata !627, metadata !DIExpression()) #7, !dbg !1407
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !628, metadata !DIExpression()) #7, !dbg !1407
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !631, metadata !DIExpression()) #7, !dbg !1409
  call void @llvm.dbg.value(metadata i8* %17, metadata !643, metadata !DIExpression()) #7, !dbg !1409
  call void @llvm.dbg.value(metadata %struct.ethhdr** undef, metadata !644, metadata !DIExpression()) #7, !dbg !1409
  call void @llvm.dbg.value(metadata %struct.collect_vlans* null, metadata !645, metadata !DIExpression()) #7, !dbg !1409
  call void @llvm.dbg.value(metadata i8* %21, metadata !646, metadata !DIExpression()) #7, !dbg !1409
  call void @llvm.dbg.value(metadata i32 14, metadata !647, metadata !DIExpression()) #7, !dbg !1409
  %23 = getelementptr i8, i8* %21, i64 14, !dbg !1411
  %24 = icmp ugt i8* %23, %17, !dbg !1412
  br i1 %24, label %445, label %25, !dbg !1413

25:                                               ; preds = %1
  call void @llvm.dbg.value(metadata i8* %21, metadata !646, metadata !DIExpression()) #7, !dbg !1409
  call void @llvm.dbg.value(metadata i8* %23, metadata !229, metadata !DIExpression()), !dbg !1398
  call void @llvm.dbg.value(metadata i8* %23, metadata !648, metadata !DIExpression()) #7, !dbg !1409
  %26 = getelementptr inbounds i8, i8* %21, i64 12, !dbg !1414
  %27 = bitcast i8* %26 to i16*, !dbg !1414
  call void @llvm.dbg.value(metadata i16 undef, metadata !654, metadata !DIExpression()) #7, !dbg !1409
  call void @llvm.dbg.value(metadata i32 0, metadata !655, metadata !DIExpression()) #7, !dbg !1409
  %28 = load i16, i16* %27, align 1, !dbg !1409, !tbaa !663
  call void @llvm.dbg.value(metadata i16 %28, metadata !654, metadata !DIExpression()) #7, !dbg !1409
  %29 = inttoptr i64 %16 to %struct.vlan_hdr*
  call void @llvm.dbg.value(metadata i16 %28, metadata !665, metadata !DIExpression()) #7, !dbg !1415
  %30 = icmp eq i16 %28, 129, !dbg !1417
  %31 = icmp eq i16 %28, -22392, !dbg !1418
  %32 = tail call i1 @llvm.bpf.passthrough.i1.i1(i32 0, i1 %30) #7
  %33 = or i1 %31, %32, !dbg !1418
  %34 = xor i1 %33, true, !dbg !1419
  %35 = getelementptr i8, i8* %21, i64 18
  %36 = bitcast i8* %35 to %struct.vlan_hdr*
  %37 = icmp ugt %struct.vlan_hdr* %36, %29
  %38 = select i1 %34, i1 true, i1 %37, !dbg !1420
  br i1 %38, label %56, label %39, !dbg !1420

39:                                               ; preds = %25
  call void @llvm.dbg.value(metadata i16 undef, metadata !654, metadata !DIExpression()) #7, !dbg !1409
  %40 = getelementptr i8, i8* %21, i64 16, !dbg !1421
  %41 = bitcast i8* %40 to i16*, !dbg !1421
  call void @llvm.dbg.value(metadata %struct.vlan_hdr* %36, metadata !648, metadata !DIExpression()) #7, !dbg !1409
  call void @llvm.dbg.value(metadata i32 1, metadata !655, metadata !DIExpression()) #7, !dbg !1409
  %42 = load i16, i16* %41, align 1, !dbg !1409, !tbaa !663
  call void @llvm.dbg.value(metadata i16 %42, metadata !654, metadata !DIExpression()) #7, !dbg !1409
  call void @llvm.dbg.value(metadata i16 %42, metadata !665, metadata !DIExpression()) #7, !dbg !1415
  %43 = icmp eq i16 %42, 129, !dbg !1417
  %44 = icmp eq i16 %42, -22392, !dbg !1418
  %45 = tail call i1 @llvm.bpf.passthrough.i1.i1(i32 0, i1 %43) #7
  %46 = or i1 %44, %45, !dbg !1418
  %47 = xor i1 %46, true, !dbg !1419
  %48 = getelementptr i8, i8* %21, i64 22
  %49 = bitcast i8* %48 to %struct.vlan_hdr*
  %50 = icmp ugt %struct.vlan_hdr* %49, %29
  %51 = select i1 %47, i1 true, i1 %50, !dbg !1420
  br i1 %51, label %56, label %52, !dbg !1420

52:                                               ; preds = %39
  call void @llvm.dbg.value(metadata i16 undef, metadata !654, metadata !DIExpression()) #7, !dbg !1409
  %53 = getelementptr i8, i8* %21, i64 20, !dbg !1421
  %54 = bitcast i8* %53 to i16*, !dbg !1421
  call void @llvm.dbg.value(metadata %struct.vlan_hdr* %49, metadata !648, metadata !DIExpression()) #7, !dbg !1409
  call void @llvm.dbg.value(metadata i32 2, metadata !655, metadata !DIExpression()) #7, !dbg !1409
  %55 = load i16, i16* %54, align 1, !dbg !1409, !tbaa !663
  call void @llvm.dbg.value(metadata i16 %55, metadata !654, metadata !DIExpression()) #7, !dbg !1409
  br label %56

56:                                               ; preds = %25, %39, %52
  %57 = phi i8* [ %23, %25 ], [ %35, %39 ], [ %48, %52 ], !dbg !1409
  %58 = phi i16 [ %28, %25 ], [ %42, %39 ], [ %55, %52 ], !dbg !1409
  call void @llvm.dbg.value(metadata i8* %57, metadata !229, metadata !DIExpression()), !dbg !1398
  call void @llvm.dbg.value(metadata i16 %58, metadata !234, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1398
  %59 = icmp ne i16 %58, 8
  %60 = getelementptr inbounds i8, i8* %57, i64 20
  %61 = icmp ugt i8* %60, %17
  %62 = select i1 %59, i1 true, i1 %61, !dbg !1422
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !682, metadata !DIExpression()), !dbg !1423
  call void @llvm.dbg.value(metadata i8* %17, metadata !688, metadata !DIExpression()), !dbg !1423
  call void @llvm.dbg.value(metadata %struct.iphdr** undef, metadata !689, metadata !DIExpression()), !dbg !1423
  call void @llvm.dbg.value(metadata i8* %57, metadata !690, metadata !DIExpression()), !dbg !1423
  br i1 %62, label %445, label %63, !dbg !1422

63:                                               ; preds = %56
  %64 = load i8, i8* %57, align 4, !dbg !1425
  %65 = shl i8 %64, 2, !dbg !1426
  %66 = and i8 %65, 60, !dbg !1426
  call void @llvm.dbg.value(metadata i8 %66, metadata !691, metadata !DIExpression(DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1423
  %67 = icmp ult i8 %66, 20, !dbg !1427
  br i1 %67, label %445, label %68, !dbg !1428

68:                                               ; preds = %63
  %69 = zext i8 %66 to i64
  call void @llvm.dbg.value(metadata i64 %69, metadata !691, metadata !DIExpression()), !dbg !1423
  %70 = getelementptr i8, i8* %57, i64 %69, !dbg !1429
  %71 = icmp ugt i8* %70, %17, !dbg !1430
  br i1 %71, label %445, label %72, !dbg !1431

72:                                               ; preds = %68
  call void @llvm.dbg.value(metadata i8* %70, metadata !229, metadata !DIExpression()), !dbg !1398
  %73 = getelementptr inbounds i8, i8* %57, i64 9, !dbg !1432
  %74 = load i8, i8* %73, align 1, !dbg !1432, !tbaa !706
  call void @llvm.dbg.value(metadata i8 %74, metadata !234, metadata !DIExpression(DW_OP_LLVM_convert, 8, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1398
  call void @llvm.dbg.value(metadata i8* %57, metadata !243, metadata !DIExpression()), !dbg !1398
  %75 = getelementptr inbounds i8, i8* %57, i64 12, !dbg !1433
  %76 = bitcast i8* %75 to i32*, !dbg !1433
  %77 = load i32, i32* %76, align 4, !dbg !1433, !tbaa !765
  %78 = tail call i32 @llvm.bswap.i32(i32 %77), !dbg !1433
  %79 = getelementptr inbounds %struct.conn_ipv4_key, %struct.conn_ipv4_key* %3, i64 0, i32 0, !dbg !1434
  store i32 %78, i32* %79, align 4, !dbg !1435, !tbaa !1436
  %80 = getelementptr inbounds i8, i8* %57, i64 16, !dbg !1438
  %81 = bitcast i8* %80 to i32*, !dbg !1438
  %82 = load i32, i32* %81, align 4, !dbg !1438, !tbaa !765
  %83 = tail call i32 @llvm.bswap.i32(i32 %82), !dbg !1438
  %84 = getelementptr inbounds %struct.conn_ipv4_key, %struct.conn_ipv4_key* %3, i64 0, i32 1, !dbg !1439
  store i32 %83, i32* %84, align 4, !dbg !1440, !tbaa !1441
  %85 = zext i8 %74 to i16, !dbg !1442
  %86 = getelementptr inbounds %struct.conn_ipv4_key, %struct.conn_ipv4_key* %3, i64 0, i32 4, !dbg !1443
  store i16 %85, i16* %86, align 4, !dbg !1444, !tbaa !1445
  call void @llvm.dbg.value(metadata i8* %22, metadata !326, metadata !DIExpression()), !dbg !1398
  %87 = bitcast i32* %84 to i8*, !dbg !1446
  call void @llvm.dbg.value(metadata i8* %87, metadata !327, metadata !DIExpression()), !dbg !1398
  %88 = lshr i32 %78, 24, !dbg !1447
  %89 = zext i32 %88 to i64, !dbg !1447
  %90 = lshr i32 %78, 16, !dbg !1447
  %91 = lshr i32 %78, 8, !dbg !1447
  %92 = lshr i32 %83, 24, !dbg !1447
  %93 = zext i32 %92 to i64, !dbg !1447
  %94 = lshr i32 %83, 16, !dbg !1447
  %95 = lshr i32 %83, 8, !dbg !1447
  switch i8 %74, label %445 [
    i8 6, label %96
    i8 17, label %359
    i8 1, label %408
  ], !dbg !1447

96:                                               ; preds = %72
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !709, metadata !DIExpression()), !dbg !1448
  call void @llvm.dbg.value(metadata i8* %17, metadata !715, metadata !DIExpression()), !dbg !1448
  call void @llvm.dbg.value(metadata %struct.tcphdr** undef, metadata !716, metadata !DIExpression()), !dbg !1448
  call void @llvm.dbg.value(metadata i8* %70, metadata !718, metadata !DIExpression()), !dbg !1448
  %97 = getelementptr inbounds i8, i8* %70, i64 20, !dbg !1451
  %98 = icmp ugt i8* %97, %17, !dbg !1452
  br i1 %98, label %445, label %99, !dbg !1453

99:                                               ; preds = %96
  %100 = getelementptr inbounds i8, i8* %70, i64 12, !dbg !1454
  %101 = bitcast i8* %100 to i16*, !dbg !1454
  %102 = load i16, i16* %101, align 4, !dbg !1454
  %103 = lshr i16 %102, 2, !dbg !1455
  %104 = and i16 %103, 60, !dbg !1455
  call void @llvm.dbg.value(metadata i16 %104, metadata !717, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !1448
  %105 = icmp ult i16 %104, 20, !dbg !1456
  br i1 %105, label %445, label %106, !dbg !1457

106:                                              ; preds = %99
  %107 = zext i16 %104 to i64
  %108 = getelementptr i8, i8* %70, i64 %107, !dbg !1458
  %109 = icmp ugt i8* %108, %17, !dbg !1459
  br i1 %109, label %445, label %110, !dbg !1460

110:                                              ; preds = %106
  call void @llvm.dbg.value(metadata i8* %108, metadata !229, metadata !DIExpression()), !dbg !1398
  call void @llvm.dbg.value(metadata i8* %70, metadata !271, metadata !DIExpression()), !dbg !1398
  %111 = bitcast i8* %70 to i16*, !dbg !1461
  %112 = load i16, i16* %111, align 4, !dbg !1461, !tbaa !1462
  %113 = tail call i16 @llvm.bswap.i16(i16 %112), !dbg !1461
  %114 = getelementptr inbounds %struct.conn_ipv4_key, %struct.conn_ipv4_key* %3, i64 0, i32 2, !dbg !1464
  store i16 %113, i16* %114, align 4, !dbg !1465, !tbaa !1466
  %115 = getelementptr inbounds i8, i8* %70, i64 2, !dbg !1467
  %116 = bitcast i8* %115 to i16*, !dbg !1467
  %117 = load i16, i16* %116, align 2, !dbg !1467, !tbaa !1468
  %118 = tail call i16 @llvm.bswap.i16(i16 %117), !dbg !1467
  %119 = getelementptr inbounds %struct.conn_ipv4_key, %struct.conn_ipv4_key* %3, i64 0, i32 3, !dbg !1469
  store i16 %118, i16* %119, align 2, !dbg !1470, !tbaa !1471
  %120 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* noundef bitcast (%struct.anon.15* @conn_ipv4_map to i8*), i8* noundef nonnull %22) #7, !dbg !1472
  call void @llvm.dbg.value(metadata i8* %120, metadata !336, metadata !DIExpression()), !dbg !1473
  %121 = icmp eq i8* %120, null, !dbg !1474
  %122 = load i16, i16* %101, align 4, !dbg !1473
  br i1 %121, label %123, label %223, !dbg !1475

123:                                              ; preds = %110
  %124 = and i16 %122, 4608, !dbg !1476
  %125 = icmp eq i16 %124, 4608, !dbg !1476
  br i1 %125, label %126, label %173, !dbg !1476

126:                                              ; preds = %123
  %127 = bitcast i64* %4 to i8*, !dbg !1477
  call void @llvm.lifetime.start.p0i8(i64 8, i8* nonnull %127) #7, !dbg !1477
  call void @llvm.dbg.declare(metadata %struct.conn_ipv4_val* %5, metadata !346, metadata !DIExpression()), !dbg !1478
  store i64 4294967297, i64* %4, align 8, !dbg !1478
  %128 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i8* noundef bitcast (%struct.anon.15* @conn_ipv4_map to i8*), i8* noundef nonnull %22, i8* noundef nonnull %127, i64 noundef 0) #7, !dbg !1479
  %129 = bitcast [12 x i64]* %6 to i8*, !dbg !1480
  call void @llvm.lifetime.start.p0i8(i64 96, i8* nonnull %129) #7, !dbg !1480
  call void @llvm.dbg.declare(metadata [12 x i64]* %6, metadata !351, metadata !DIExpression()), !dbg !1480
  %130 = load i8, i8* %22, align 4, !dbg !1480, !tbaa !765
  %131 = zext i8 %130 to i64, !dbg !1480
  %132 = getelementptr inbounds [12 x i64], [12 x i64]* %6, i64 0, i64 0, !dbg !1480
  store i64 %131, i64* %132, align 8, !dbg !1480, !tbaa !896
  %133 = getelementptr inbounds i8, i8* %22, i64 1, !dbg !1480
  %134 = load i8, i8* %133, align 1, !dbg !1480, !tbaa !765
  %135 = zext i8 %134 to i64, !dbg !1480
  %136 = getelementptr inbounds [12 x i64], [12 x i64]* %6, i64 0, i64 1, !dbg !1480
  store i64 %135, i64* %136, align 8, !dbg !1480, !tbaa !896
  %137 = getelementptr inbounds i8, i8* %22, i64 2, !dbg !1480
  %138 = load i8, i8* %137, align 2, !dbg !1480, !tbaa !765
  %139 = zext i8 %138 to i64, !dbg !1480
  %140 = getelementptr inbounds [12 x i64], [12 x i64]* %6, i64 0, i64 2, !dbg !1480
  store i64 %139, i64* %140, align 8, !dbg !1480, !tbaa !896
  %141 = getelementptr inbounds i8, i8* %22, i64 3, !dbg !1480
  %142 = load i8, i8* %141, align 1, !dbg !1480, !tbaa !765
  %143 = zext i8 %142 to i64, !dbg !1480
  %144 = getelementptr inbounds [12 x i64], [12 x i64]* %6, i64 0, i64 3, !dbg !1480
  store i64 %143, i64* %144, align 8, !dbg !1480, !tbaa !896
  %145 = load i16, i16* %114, align 4, !dbg !1480, !tbaa !1466
  %146 = zext i16 %145 to i64, !dbg !1480
  %147 = getelementptr inbounds [12 x i64], [12 x i64]* %6, i64 0, i64 4, !dbg !1480
  store i64 %146, i64* %147, align 8, !dbg !1480, !tbaa !896
  %148 = load i8, i8* %87, align 4, !dbg !1480, !tbaa !765
  %149 = zext i8 %148 to i64, !dbg !1480
  %150 = getelementptr inbounds [12 x i64], [12 x i64]* %6, i64 0, i64 5, !dbg !1480
  store i64 %149, i64* %150, align 8, !dbg !1480, !tbaa !896
  %151 = getelementptr inbounds i8, i8* %87, i64 1, !dbg !1480
  %152 = load i8, i8* %151, align 1, !dbg !1480, !tbaa !765
  %153 = zext i8 %152 to i64, !dbg !1480
  %154 = getelementptr inbounds [12 x i64], [12 x i64]* %6, i64 0, i64 6, !dbg !1480
  store i64 %153, i64* %154, align 8, !dbg !1480, !tbaa !896
  %155 = getelementptr inbounds i8, i8* %87, i64 2, !dbg !1480
  %156 = load i8, i8* %155, align 2, !dbg !1480, !tbaa !765
  %157 = zext i8 %156 to i64, !dbg !1480
  %158 = getelementptr inbounds [12 x i64], [12 x i64]* %6, i64 0, i64 7, !dbg !1480
  store i64 %157, i64* %158, align 8, !dbg !1480, !tbaa !896
  %159 = getelementptr inbounds i8, i8* %87, i64 3, !dbg !1480
  %160 = load i8, i8* %159, align 1, !dbg !1480, !tbaa !765
  %161 = zext i8 %160 to i64, !dbg !1480
  %162 = getelementptr inbounds [12 x i64], [12 x i64]* %6, i64 0, i64 8, !dbg !1480
  store i64 %161, i64* %162, align 8, !dbg !1480, !tbaa !896
  %163 = load i16, i16* %119, align 2, !dbg !1480, !tbaa !1471
  %164 = zext i16 %163 to i64, !dbg !1480
  %165 = getelementptr inbounds [12 x i64], [12 x i64]* %6, i64 0, i64 9, !dbg !1480
  store i64 %164, i64* %165, align 8, !dbg !1480, !tbaa !896
  %166 = getelementptr inbounds [12 x i64], [12 x i64]* %6, i64 0, i64 10, !dbg !1480
  store i64 ptrtoint ([12 x i8]* @.str to i64), i64* %166, align 8, !dbg !1480, !tbaa !896
  %167 = getelementptr inbounds %struct.conn_ipv4_val, %struct.conn_ipv4_val* %5, i64 0, i32 1, !dbg !1480
  %168 = load i32, i32* %167, align 4, !dbg !1480, !tbaa !1481
  %169 = icmp eq i32 %168, 0, !dbg !1480
  %170 = select i1 %169, i64 ptrtoint ([8 x i8]* @.str.2 to i64), i64 ptrtoint ([7 x i8]* @.str.1 to i64), !dbg !1480
  %171 = getelementptr inbounds [12 x i64], [12 x i64]* %6, i64 0, i64 11, !dbg !1480
  store i64 %170, i64* %171, align 8, !dbg !1480, !tbaa !896
  %172 = call i64 inttoptr (i64 177 to i64 (i8*, i32, i8*, i32)*)(i8* noundef getelementptr inbounds ([56 x i8], [56 x i8]* @xdp_entry_state.___fmt, i64 0, i64 0), i32 noundef 56, i8* noundef nonnull %129, i32 noundef 96) #7, !dbg !1480
  call void @llvm.lifetime.end.p0i8(i64 96, i8* nonnull %129) #7, !dbg !1483
  call void @llvm.lifetime.end.p0i8(i64 8, i8* nonnull %127) #7, !dbg !1484
  br label %445, !dbg !1485

173:                                              ; preds = %123
  %174 = and i16 %122, 512, !dbg !1486
  %175 = icmp eq i16 %174, 0, !dbg !1486
  call void @llvm.dbg.value(metadata i8* %70, metadata !271, metadata !DIExpression()), !dbg !1398
  br i1 %175, label %445, label %176, !dbg !1487

176:                                              ; preds = %173
  %177 = bitcast i64* %7 to i8*, !dbg !1488
  call void @llvm.lifetime.start.p0i8(i64 8, i8* nonnull %177) #7, !dbg !1488
  call void @llvm.dbg.declare(metadata %struct.conn_ipv4_val* %8, metadata !356, metadata !DIExpression()), !dbg !1489
  store i64 3, i64* %7, align 8, !dbg !1489
  %178 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i8* noundef bitcast (%struct.anon.15* @conn_ipv4_map to i8*), i8* noundef nonnull %22, i8* noundef nonnull %177, i64 noundef 0) #7, !dbg !1490
  %179 = bitcast [12 x i64]* %9 to i8*, !dbg !1491
  call void @llvm.lifetime.start.p0i8(i64 96, i8* nonnull %179) #7, !dbg !1491
  call void @llvm.dbg.declare(metadata [12 x i64]* %9, metadata !359, metadata !DIExpression()), !dbg !1491
  %180 = load i8, i8* %22, align 4, !dbg !1491, !tbaa !765
  %181 = zext i8 %180 to i64, !dbg !1491
  %182 = getelementptr inbounds [12 x i64], [12 x i64]* %9, i64 0, i64 0, !dbg !1491
  store i64 %181, i64* %182, align 8, !dbg !1491, !tbaa !896
  %183 = getelementptr inbounds i8, i8* %22, i64 1, !dbg !1491
  %184 = load i8, i8* %183, align 1, !dbg !1491, !tbaa !765
  %185 = zext i8 %184 to i64, !dbg !1491
  %186 = getelementptr inbounds [12 x i64], [12 x i64]* %9, i64 0, i64 1, !dbg !1491
  store i64 %185, i64* %186, align 8, !dbg !1491, !tbaa !896
  %187 = getelementptr inbounds i8, i8* %22, i64 2, !dbg !1491
  %188 = load i8, i8* %187, align 2, !dbg !1491, !tbaa !765
  %189 = zext i8 %188 to i64, !dbg !1491
  %190 = getelementptr inbounds [12 x i64], [12 x i64]* %9, i64 0, i64 2, !dbg !1491
  store i64 %189, i64* %190, align 8, !dbg !1491, !tbaa !896
  %191 = getelementptr inbounds i8, i8* %22, i64 3, !dbg !1491
  %192 = load i8, i8* %191, align 1, !dbg !1491, !tbaa !765
  %193 = zext i8 %192 to i64, !dbg !1491
  %194 = getelementptr inbounds [12 x i64], [12 x i64]* %9, i64 0, i64 3, !dbg !1491
  store i64 %193, i64* %194, align 8, !dbg !1491, !tbaa !896
  %195 = load i16, i16* %114, align 4, !dbg !1491, !tbaa !1466
  %196 = zext i16 %195 to i64, !dbg !1491
  %197 = getelementptr inbounds [12 x i64], [12 x i64]* %9, i64 0, i64 4, !dbg !1491
  store i64 %196, i64* %197, align 8, !dbg !1491, !tbaa !896
  %198 = load i8, i8* %87, align 4, !dbg !1491, !tbaa !765
  %199 = zext i8 %198 to i64, !dbg !1491
  %200 = getelementptr inbounds [12 x i64], [12 x i64]* %9, i64 0, i64 5, !dbg !1491
  store i64 %199, i64* %200, align 8, !dbg !1491, !tbaa !896
  %201 = getelementptr inbounds i8, i8* %87, i64 1, !dbg !1491
  %202 = load i8, i8* %201, align 1, !dbg !1491, !tbaa !765
  %203 = zext i8 %202 to i64, !dbg !1491
  %204 = getelementptr inbounds [12 x i64], [12 x i64]* %9, i64 0, i64 6, !dbg !1491
  store i64 %203, i64* %204, align 8, !dbg !1491, !tbaa !896
  %205 = getelementptr inbounds i8, i8* %87, i64 2, !dbg !1491
  %206 = load i8, i8* %205, align 2, !dbg !1491, !tbaa !765
  %207 = zext i8 %206 to i64, !dbg !1491
  %208 = getelementptr inbounds [12 x i64], [12 x i64]* %9, i64 0, i64 7, !dbg !1491
  store i64 %207, i64* %208, align 8, !dbg !1491, !tbaa !896
  %209 = getelementptr inbounds i8, i8* %87, i64 3, !dbg !1491
  %210 = load i8, i8* %209, align 1, !dbg !1491, !tbaa !765
  %211 = zext i8 %210 to i64, !dbg !1491
  %212 = getelementptr inbounds [12 x i64], [12 x i64]* %9, i64 0, i64 8, !dbg !1491
  store i64 %211, i64* %212, align 8, !dbg !1491, !tbaa !896
  %213 = load i16, i16* %119, align 2, !dbg !1491, !tbaa !1471
  %214 = zext i16 %213 to i64, !dbg !1491
  %215 = getelementptr inbounds [12 x i64], [12 x i64]* %9, i64 0, i64 9, !dbg !1491
  store i64 %214, i64* %215, align 8, !dbg !1491, !tbaa !896
  %216 = getelementptr inbounds [12 x i64], [12 x i64]* %9, i64 0, i64 10, !dbg !1491
  store i64 ptrtoint ([9 x i8]* @.str.5 to i64), i64* %216, align 8, !dbg !1491, !tbaa !896
  %217 = getelementptr inbounds %struct.conn_ipv4_val, %struct.conn_ipv4_val* %8, i64 0, i32 1, !dbg !1491
  %218 = load i32, i32* %217, align 4, !dbg !1491, !tbaa !1481
  %219 = icmp eq i32 %218, 0, !dbg !1491
  %220 = select i1 %219, i64 ptrtoint ([8 x i8]* @.str.2 to i64), i64 ptrtoint ([7 x i8]* @.str.1 to i64), !dbg !1491
  %221 = getelementptr inbounds [12 x i64], [12 x i64]* %9, i64 0, i64 11, !dbg !1491
  store i64 %220, i64* %221, align 8, !dbg !1491, !tbaa !896
  %222 = call i64 inttoptr (i64 177 to i64 (i8*, i32, i8*, i32)*)(i8* noundef getelementptr inbounds ([56 x i8], [56 x i8]* @xdp_entry_state.___fmt.4, i64 0, i64 0), i32 noundef 56, i8* noundef nonnull %179, i32 noundef 96) #7, !dbg !1491
  call void @llvm.lifetime.end.p0i8(i64 96, i8* nonnull %179) #7, !dbg !1492
  call void @llvm.lifetime.end.p0i8(i64 8, i8* nonnull %177) #7, !dbg !1493
  br label %445, !dbg !1494

223:                                              ; preds = %110
  %224 = and i16 %122, 1024, !dbg !1495
  %225 = icmp eq i16 %224, 0, !dbg !1495
  br i1 %225, label %273, label %226, !dbg !1496

226:                                              ; preds = %223
  %227 = call i64 inttoptr (i64 3 to i64 (i8*, i8*)*)(i8* noundef bitcast (%struct.anon.15* @conn_ipv4_map to i8*), i8* noundef nonnull %22) #7, !dbg !1497
  %228 = bitcast [12 x i64]* %10 to i8*, !dbg !1498
  call void @llvm.lifetime.start.p0i8(i64 96, i8* nonnull %228) #7, !dbg !1498
  call void @llvm.dbg.declare(metadata [12 x i64]* %10, metadata !361, metadata !DIExpression()), !dbg !1498
  %229 = load i8, i8* %22, align 4, !dbg !1498, !tbaa !765
  %230 = zext i8 %229 to i64, !dbg !1498
  %231 = getelementptr inbounds [12 x i64], [12 x i64]* %10, i64 0, i64 0, !dbg !1498
  store i64 %230, i64* %231, align 8, !dbg !1498, !tbaa !896
  %232 = getelementptr inbounds i8, i8* %22, i64 1, !dbg !1498
  %233 = load i8, i8* %232, align 1, !dbg !1498, !tbaa !765
  %234 = zext i8 %233 to i64, !dbg !1498
  %235 = getelementptr inbounds [12 x i64], [12 x i64]* %10, i64 0, i64 1, !dbg !1498
  store i64 %234, i64* %235, align 8, !dbg !1498, !tbaa !896
  %236 = getelementptr inbounds i8, i8* %22, i64 2, !dbg !1498
  %237 = load i8, i8* %236, align 2, !dbg !1498, !tbaa !765
  %238 = zext i8 %237 to i64, !dbg !1498
  %239 = getelementptr inbounds [12 x i64], [12 x i64]* %10, i64 0, i64 2, !dbg !1498
  store i64 %238, i64* %239, align 8, !dbg !1498, !tbaa !896
  %240 = getelementptr inbounds i8, i8* %22, i64 3, !dbg !1498
  %241 = load i8, i8* %240, align 1, !dbg !1498, !tbaa !765
  %242 = zext i8 %241 to i64, !dbg !1498
  %243 = getelementptr inbounds [12 x i64], [12 x i64]* %10, i64 0, i64 3, !dbg !1498
  store i64 %242, i64* %243, align 8, !dbg !1498, !tbaa !896
  %244 = load i16, i16* %114, align 4, !dbg !1498, !tbaa !1466
  %245 = zext i16 %244 to i64, !dbg !1498
  %246 = getelementptr inbounds [12 x i64], [12 x i64]* %10, i64 0, i64 4, !dbg !1498
  store i64 %245, i64* %246, align 8, !dbg !1498, !tbaa !896
  %247 = load i8, i8* %87, align 4, !dbg !1498, !tbaa !765
  %248 = zext i8 %247 to i64, !dbg !1498
  %249 = getelementptr inbounds [12 x i64], [12 x i64]* %10, i64 0, i64 5, !dbg !1498
  store i64 %248, i64* %249, align 8, !dbg !1498, !tbaa !896
  %250 = getelementptr inbounds i8, i8* %87, i64 1, !dbg !1498
  %251 = load i8, i8* %250, align 1, !dbg !1498, !tbaa !765
  %252 = zext i8 %251 to i64, !dbg !1498
  %253 = getelementptr inbounds [12 x i64], [12 x i64]* %10, i64 0, i64 6, !dbg !1498
  store i64 %252, i64* %253, align 8, !dbg !1498, !tbaa !896
  %254 = getelementptr inbounds i8, i8* %87, i64 2, !dbg !1498
  %255 = load i8, i8* %254, align 2, !dbg !1498, !tbaa !765
  %256 = zext i8 %255 to i64, !dbg !1498
  %257 = getelementptr inbounds [12 x i64], [12 x i64]* %10, i64 0, i64 7, !dbg !1498
  store i64 %256, i64* %257, align 8, !dbg !1498, !tbaa !896
  %258 = getelementptr inbounds i8, i8* %87, i64 3, !dbg !1498
  %259 = load i8, i8* %258, align 1, !dbg !1498, !tbaa !765
  %260 = zext i8 %259 to i64, !dbg !1498
  %261 = getelementptr inbounds [12 x i64], [12 x i64]* %10, i64 0, i64 8, !dbg !1498
  store i64 %260, i64* %261, align 8, !dbg !1498, !tbaa !896
  %262 = load i16, i16* %119, align 2, !dbg !1498, !tbaa !1471
  %263 = zext i16 %262 to i64, !dbg !1498
  %264 = getelementptr inbounds [12 x i64], [12 x i64]* %10, i64 0, i64 9, !dbg !1498
  store i64 %263, i64* %264, align 8, !dbg !1498, !tbaa !896
  %265 = getelementptr inbounds [12 x i64], [12 x i64]* %10, i64 0, i64 10, !dbg !1498
  store i64 ptrtoint ([4 x i8]* @.str.7 to i64), i64* %265, align 8, !dbg !1498, !tbaa !896
  %266 = getelementptr inbounds i8, i8* %120, i64 4, !dbg !1498
  %267 = bitcast i8* %266 to i32*, !dbg !1498
  %268 = load i32, i32* %267, align 4, !dbg !1498, !tbaa !1481
  %269 = icmp eq i32 %268, 0, !dbg !1498
  %270 = select i1 %269, i64 ptrtoint ([8 x i8]* @.str.2 to i64), i64 ptrtoint ([7 x i8]* @.str.1 to i64), !dbg !1498
  %271 = getelementptr inbounds [12 x i64], [12 x i64]* %10, i64 0, i64 11, !dbg !1498
  store i64 %270, i64* %271, align 8, !dbg !1498, !tbaa !896
  %272 = call i64 inttoptr (i64 177 to i64 (i8*, i32, i8*, i32)*)(i8* noundef getelementptr inbounds ([56 x i8], [56 x i8]* @xdp_entry_state.___fmt.6, i64 0, i64 0), i32 noundef 56, i8* noundef nonnull %228, i32 noundef 96) #7, !dbg !1498
  call void @llvm.lifetime.end.p0i8(i64 96, i8* nonnull %228) #7, !dbg !1499
  br label %445, !dbg !1500

273:                                              ; preds = %223
  %274 = getelementptr inbounds i8, i8* %120, i64 4, !dbg !1501
  %275 = bitcast i8* %274 to i32*, !dbg !1501
  %276 = load i32, i32* %275, align 4, !dbg !1501, !tbaa !1481
  %277 = icmp eq i32 %276, 0, !dbg !1503
  %278 = bitcast i8* %120 to i32*, !dbg !1473
  %279 = load i32, i32* %278, align 4, !dbg !1473, !tbaa !1504
  br i1 %277, label %285, label %280, !dbg !1505

280:                                              ; preds = %273
  %281 = icmp ne i32 %279, 1, !dbg !1506
  %282 = and i16 %122, 4096
  %283 = icmp eq i16 %282, 0
  %284 = select i1 %281, i1 true, i1 %283, !dbg !1509
  br i1 %284, label %295, label %296, !dbg !1509

285:                                              ; preds = %273
  switch i32 %279, label %302 [
    i32 3, label %286
    i32 1, label %289
    i32 6, label %292
    i32 7, label %298
    i32 5, label %298
  ], !dbg !1510

286:                                              ; preds = %285
  call void @llvm.dbg.value(metadata i8* %70, metadata !271, metadata !DIExpression()), !dbg !1398
  %287 = and i16 %122, 4096, !dbg !1514
  %288 = icmp eq i16 %287, 0, !dbg !1514
  br i1 %288, label %302, label %300, !dbg !1515

289:                                              ; preds = %285
  call void @llvm.dbg.value(metadata i8* %70, metadata !271, metadata !DIExpression()), !dbg !1398
  %290 = and i16 %122, 256, !dbg !1516
  %291 = icmp eq i16 %290, 0, !dbg !1516
  br i1 %291, label %302, label %300, !dbg !1518

292:                                              ; preds = %285
  call void @llvm.dbg.value(metadata i8* %70, metadata !271, metadata !DIExpression()), !dbg !1398
  %293 = and i16 %122, 4096, !dbg !1519
  %294 = icmp eq i16 %293, 0, !dbg !1519
  br i1 %294, label %302, label %296, !dbg !1521

295:                                              ; preds = %280
  call void @llvm.dbg.label(metadata !385), !dbg !1522
  switch i32 %279, label %302 [
    i32 7, label %298
    i32 5, label %298
  ], !dbg !1523

296:                                              ; preds = %292, %280
  %297 = phi i32 [ 5, %280 ], [ 7, %292 ]
  store i32 %297, i32* %278, align 4, !dbg !1473, !tbaa !1504
  br label %298, !dbg !1525

298:                                              ; preds = %296, %285, %285, %295, %295
  %299 = call i64 inttoptr (i64 3 to i64 (i8*, i8*)*)(i8* noundef bitcast (%struct.anon.15* @conn_ipv4_map to i8*), i8* noundef nonnull %22) #7, !dbg !1525
  br label %304, !dbg !1527

300:                                              ; preds = %289, %286
  %301 = phi i32 [ 1, %286 ], [ 6, %289 ]
  store i32 %301, i32* %278, align 4, !dbg !1528, !tbaa !1504
  br label %302, !dbg !1529

302:                                              ; preds = %300, %285, %292, %289, %286, %295
  %303 = call i64 inttoptr (i64 2 to i64 (i8*, i8*, i8*, i64)*)(i8* noundef bitcast (%struct.anon.15* @conn_ipv4_map to i8*), i8* noundef nonnull %22, i8* noundef nonnull %120, i64 noundef 2) #7, !dbg !1529
  br label %304

304:                                              ; preds = %302, %298
  %305 = load i32, i32* %278, align 4, !dbg !1531, !tbaa !1504
  switch i32 %305, label %312 [
    i32 2, label %313
    i32 3, label %306
    i32 1, label %307
    i32 4, label %308
    i32 5, label %309
    i32 6, label %310
    i32 7, label %311
  ], !dbg !1532

306:                                              ; preds = %304
  br label %313, !dbg !1533

307:                                              ; preds = %304
  br label %313, !dbg !1535

308:                                              ; preds = %304
  br label %313, !dbg !1536

309:                                              ; preds = %304
  br label %313, !dbg !1537

310:                                              ; preds = %304
  br label %313, !dbg !1538

311:                                              ; preds = %304
  br label %313, !dbg !1539

312:                                              ; preds = %304
  br label %313, !dbg !1540

313:                                              ; preds = %304, %312, %311, %310, %309, %308, %307, %306
  %314 = phi i8* [ getelementptr inbounds ([1 x i8], [1 x i8]* @.str.14, i64 0, i64 0), %312 ], [ getelementptr inbounds ([6 x i8], [6 x i8]* @.str.13, i64 0, i64 0), %311 ], [ getelementptr inbounds ([11 x i8], [11 x i8]* @.str.12, i64 0, i64 0), %310 ], [ getelementptr inbounds ([10 x i8], [10 x i8]* @.str.11, i64 0, i64 0), %309 ], [ getelementptr inbounds ([10 x i8], [10 x i8]* @.str.10, i64 0, i64 0), %308 ], [ getelementptr inbounds ([12 x i8], [12 x i8]* @.str, i64 0, i64 0), %307 ], [ getelementptr inbounds ([9 x i8], [9 x i8]* @.str.9, i64 0, i64 0), %306 ], [ getelementptr inbounds ([9 x i8], [9 x i8]* @.str.8, i64 0, i64 0), %304 ], !dbg !1541
  %315 = bitcast [12 x i64]* %11 to i8*, !dbg !1542
  call void @llvm.lifetime.start.p0i8(i64 96, i8* nonnull %315) #7, !dbg !1542
  call void @llvm.dbg.declare(metadata [12 x i64]* %11, metadata !369, metadata !DIExpression()), !dbg !1542
  %316 = load i8, i8* %22, align 4, !dbg !1542, !tbaa !765
  %317 = zext i8 %316 to i64, !dbg !1542
  %318 = getelementptr inbounds [12 x i64], [12 x i64]* %11, i64 0, i64 0, !dbg !1542
  store i64 %317, i64* %318, align 8, !dbg !1542, !tbaa !896
  %319 = getelementptr inbounds i8, i8* %22, i64 1, !dbg !1542
  %320 = load i8, i8* %319, align 1, !dbg !1542, !tbaa !765
  %321 = zext i8 %320 to i64, !dbg !1542
  %322 = getelementptr inbounds [12 x i64], [12 x i64]* %11, i64 0, i64 1, !dbg !1542
  store i64 %321, i64* %322, align 8, !dbg !1542, !tbaa !896
  %323 = getelementptr inbounds i8, i8* %22, i64 2, !dbg !1542
  %324 = load i8, i8* %323, align 2, !dbg !1542, !tbaa !765
  %325 = zext i8 %324 to i64, !dbg !1542
  %326 = getelementptr inbounds [12 x i64], [12 x i64]* %11, i64 0, i64 2, !dbg !1542
  store i64 %325, i64* %326, align 8, !dbg !1542, !tbaa !896
  %327 = getelementptr inbounds i8, i8* %22, i64 3, !dbg !1542
  %328 = load i8, i8* %327, align 1, !dbg !1542, !tbaa !765
  %329 = zext i8 %328 to i64, !dbg !1542
  %330 = getelementptr inbounds [12 x i64], [12 x i64]* %11, i64 0, i64 3, !dbg !1542
  store i64 %329, i64* %330, align 8, !dbg !1542, !tbaa !896
  %331 = load i16, i16* %114, align 4, !dbg !1542, !tbaa !1466
  %332 = zext i16 %331 to i64, !dbg !1542
  %333 = getelementptr inbounds [12 x i64], [12 x i64]* %11, i64 0, i64 4, !dbg !1542
  store i64 %332, i64* %333, align 8, !dbg !1542, !tbaa !896
  %334 = load i8, i8* %87, align 4, !dbg !1542, !tbaa !765
  %335 = zext i8 %334 to i64, !dbg !1542
  %336 = getelementptr inbounds [12 x i64], [12 x i64]* %11, i64 0, i64 5, !dbg !1542
  store i64 %335, i64* %336, align 8, !dbg !1542, !tbaa !896
  %337 = getelementptr inbounds i8, i8* %87, i64 1, !dbg !1542
  %338 = load i8, i8* %337, align 1, !dbg !1542, !tbaa !765
  %339 = zext i8 %338 to i64, !dbg !1542
  %340 = getelementptr inbounds [12 x i64], [12 x i64]* %11, i64 0, i64 6, !dbg !1542
  store i64 %339, i64* %340, align 8, !dbg !1542, !tbaa !896
  %341 = getelementptr inbounds i8, i8* %87, i64 2, !dbg !1542
  %342 = load i8, i8* %341, align 2, !dbg !1542, !tbaa !765
  %343 = zext i8 %342 to i64, !dbg !1542
  %344 = getelementptr inbounds [12 x i64], [12 x i64]* %11, i64 0, i64 7, !dbg !1542
  store i64 %343, i64* %344, align 8, !dbg !1542, !tbaa !896
  %345 = getelementptr inbounds i8, i8* %87, i64 3, !dbg !1542
  %346 = load i8, i8* %345, align 1, !dbg !1542, !tbaa !765
  %347 = zext i8 %346 to i64, !dbg !1542
  %348 = getelementptr inbounds [12 x i64], [12 x i64]* %11, i64 0, i64 8, !dbg !1542
  store i64 %347, i64* %348, align 8, !dbg !1542, !tbaa !896
  %349 = load i16, i16* %119, align 2, !dbg !1542, !tbaa !1471
  %350 = zext i16 %349 to i64, !dbg !1542
  %351 = getelementptr inbounds [12 x i64], [12 x i64]* %11, i64 0, i64 9, !dbg !1542
  store i64 %350, i64* %351, align 8, !dbg !1542, !tbaa !896
  %352 = ptrtoint i8* %314 to i64, !dbg !1542
  %353 = getelementptr inbounds [12 x i64], [12 x i64]* %11, i64 0, i64 10, !dbg !1542
  store i64 %352, i64* %353, align 8, !dbg !1542, !tbaa !896
  %354 = load i32, i32* %275, align 4, !dbg !1542, !tbaa !1481
  %355 = icmp eq i32 %354, 0, !dbg !1542
  %356 = select i1 %355, i64 ptrtoint ([8 x i8]* @.str.2 to i64), i64 ptrtoint ([7 x i8]* @.str.1 to i64), !dbg !1542
  %357 = getelementptr inbounds [12 x i64], [12 x i64]* %11, i64 0, i64 11, !dbg !1542
  store i64 %356, i64* %357, align 8, !dbg !1542, !tbaa !896
  %358 = call i64 inttoptr (i64 177 to i64 (i8*, i32, i8*, i32)*)(i8* noundef getelementptr inbounds ([56 x i8], [56 x i8]* @xdp_entry_state.___fmt.15, i64 0, i64 0), i32 noundef 56, i8* noundef nonnull %315, i32 noundef 96) #7, !dbg !1542
  call void @llvm.lifetime.end.p0i8(i64 96, i8* nonnull %315) #7, !dbg !1543
  br label %445, !dbg !1544

359:                                              ; preds = %72
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !737, metadata !DIExpression()) #7, !dbg !1545
  call void @llvm.dbg.value(metadata i8* %17, metadata !743, metadata !DIExpression()) #7, !dbg !1545
  call void @llvm.dbg.value(metadata %struct.udphdr** undef, metadata !744, metadata !DIExpression()) #7, !dbg !1545
  call void @llvm.dbg.value(metadata i8* %70, metadata !746, metadata !DIExpression()) #7, !dbg !1545
  %360 = getelementptr inbounds i8, i8* %70, i64 8, !dbg !1548
  %361 = bitcast i8* %360 to %struct.udphdr*, !dbg !1548
  %362 = inttoptr i64 %16 to %struct.udphdr*, !dbg !1549
  %363 = icmp ugt %struct.udphdr* %361, %362, !dbg !1550
  br i1 %363, label %445, label %364, !dbg !1551

364:                                              ; preds = %359
  call void @llvm.dbg.value(metadata %struct.udphdr* %361, metadata !229, metadata !DIExpression()), !dbg !1398
  %365 = getelementptr inbounds i8, i8* %70, i64 4, !dbg !1552
  %366 = bitcast i8* %365 to i16*, !dbg !1552
  %367 = load i16, i16* %366, align 2, !dbg !1552, !tbaa !758
  %368 = tail call i16 @llvm.bswap.i16(i16 %367) #7, !dbg !1552
  call void @llvm.dbg.value(metadata i16 %368, metadata !745, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_constu, 8, DW_OP_minus, DW_OP_stack_value)) #7, !dbg !1545
  %369 = icmp ult i16 %368, 8, !dbg !1553
  br i1 %369, label %445, label %370, !dbg !1554

370:                                              ; preds = %364
  call void @llvm.dbg.value(metadata i16 %368, metadata !745, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_constu, 8, DW_OP_minus, DW_OP_stack_value)) #7, !dbg !1545
  call void @llvm.dbg.value(metadata i8* %70, metadata !293, metadata !DIExpression()), !dbg !1398
  %371 = bitcast i8* %70 to i16*, !dbg !1555
  %372 = load i16, i16* %371, align 2, !dbg !1555, !tbaa !1556
  %373 = tail call i16 @llvm.bswap.i16(i16 %372), !dbg !1555
  %374 = getelementptr inbounds %struct.conn_ipv4_key, %struct.conn_ipv4_key* %3, i64 0, i32 2, !dbg !1557
  store i16 %373, i16* %374, align 4, !dbg !1558, !tbaa !1466
  %375 = getelementptr inbounds i8, i8* %70, i64 2, !dbg !1559
  %376 = bitcast i8* %375 to i16*, !dbg !1559
  %377 = load i16, i16* %376, align 2, !dbg !1559, !tbaa !1560
  %378 = tail call i16 @llvm.bswap.i16(i16 %377), !dbg !1559
  %379 = getelementptr inbounds %struct.conn_ipv4_key, %struct.conn_ipv4_key* %3, i64 0, i32 3, !dbg !1561
  store i16 %378, i16* %379, align 2, !dbg !1562, !tbaa !1471
  %380 = bitcast [11 x i64]* %12 to i8*, !dbg !1563
  call void @llvm.lifetime.start.p0i8(i64 88, i8* nonnull %380) #7, !dbg !1563
  call void @llvm.dbg.declare(metadata [11 x i64]* %12, metadata !371, metadata !DIExpression()), !dbg !1563
  %381 = getelementptr inbounds [11 x i64], [11 x i64]* %12, i64 0, i64 0, !dbg !1563
  store i64 %89, i64* %381, align 8, !dbg !1563, !tbaa !896
  %382 = and i32 %90, 255, !dbg !1563
  %383 = zext i32 %382 to i64, !dbg !1563
  %384 = getelementptr inbounds [11 x i64], [11 x i64]* %12, i64 0, i64 1, !dbg !1563
  store i64 %383, i64* %384, align 8, !dbg !1563, !tbaa !896
  %385 = and i32 %91, 255, !dbg !1563
  %386 = zext i32 %385 to i64, !dbg !1563
  %387 = getelementptr inbounds [11 x i64], [11 x i64]* %12, i64 0, i64 2, !dbg !1563
  store i64 %386, i64* %387, align 8, !dbg !1563, !tbaa !896
  %388 = and i32 %78, 255, !dbg !1563
  %389 = zext i32 %388 to i64, !dbg !1563
  %390 = getelementptr inbounds [11 x i64], [11 x i64]* %12, i64 0, i64 3, !dbg !1563
  store i64 %389, i64* %390, align 8, !dbg !1563, !tbaa !896
  %391 = zext i16 %373 to i64, !dbg !1563
  %392 = getelementptr inbounds [11 x i64], [11 x i64]* %12, i64 0, i64 4, !dbg !1563
  store i64 %391, i64* %392, align 8, !dbg !1563, !tbaa !896
  %393 = getelementptr inbounds [11 x i64], [11 x i64]* %12, i64 0, i64 5, !dbg !1563
  store i64 %93, i64* %393, align 8, !dbg !1563, !tbaa !896
  %394 = and i32 %94, 255, !dbg !1563
  %395 = zext i32 %394 to i64, !dbg !1563
  %396 = getelementptr inbounds [11 x i64], [11 x i64]* %12, i64 0, i64 6, !dbg !1563
  store i64 %395, i64* %396, align 8, !dbg !1563, !tbaa !896
  %397 = and i32 %95, 255, !dbg !1563
  %398 = zext i32 %397 to i64, !dbg !1563
  %399 = getelementptr inbounds [11 x i64], [11 x i64]* %12, i64 0, i64 7, !dbg !1563
  store i64 %398, i64* %399, align 8, !dbg !1563, !tbaa !896
  %400 = and i32 %83, 255, !dbg !1563
  %401 = zext i32 %400 to i64, !dbg !1563
  %402 = getelementptr inbounds [11 x i64], [11 x i64]* %12, i64 0, i64 8, !dbg !1563
  store i64 %401, i64* %402, align 8, !dbg !1563, !tbaa !896
  %403 = zext i16 %378 to i64, !dbg !1563
  %404 = getelementptr inbounds [11 x i64], [11 x i64]* %12, i64 0, i64 9, !dbg !1563
  store i64 %403, i64* %404, align 8, !dbg !1563, !tbaa !896
  %405 = zext i16 %368 to i64, !dbg !1563
  %406 = getelementptr inbounds [11 x i64], [11 x i64]* %12, i64 0, i64 10, !dbg !1563
  store i64 %405, i64* %406, align 8, !dbg !1563, !tbaa !896
  %407 = call i64 inttoptr (i64 177 to i64 (i8*, i32, i8*, i32)*)(i8* noundef getelementptr inbounds ([52 x i8], [52 x i8]* @xdp_entry_state.___fmt.16, i64 0, i64 0), i32 noundef 52, i8* noundef nonnull %380, i32 noundef 88) #7, !dbg !1563
  call void @llvm.lifetime.end.p0i8(i64 88, i8* nonnull %380) #7, !dbg !1564
  br label %445, !dbg !1565

408:                                              ; preds = %72
  call void @llvm.dbg.value(metadata %struct.hdr_cursor* undef, metadata !1566, metadata !DIExpression()), !dbg !1575
  call void @llvm.dbg.value(metadata i8* %17, metadata !1572, metadata !DIExpression()), !dbg !1575
  call void @llvm.dbg.value(metadata %struct.icmphdr** undef, metadata !1573, metadata !DIExpression()), !dbg !1575
  call void @llvm.dbg.value(metadata i8* %70, metadata !1574, metadata !DIExpression()), !dbg !1575
  %409 = getelementptr inbounds i8, i8* %70, i64 8, !dbg !1578
  %410 = bitcast i8* %409 to %struct.icmphdr*, !dbg !1578
  %411 = inttoptr i64 %16 to %struct.icmphdr*, !dbg !1580
  %412 = icmp ugt %struct.icmphdr* %410, %411, !dbg !1581
  br i1 %412, label %445, label %413, !dbg !1582

413:                                              ; preds = %408
  call void @llvm.dbg.value(metadata i8* %70, metadata !1574, metadata !DIExpression()), !dbg !1575
  call void @llvm.dbg.value(metadata %struct.icmphdr* %410, metadata !229, metadata !DIExpression()), !dbg !1398
  %414 = bitcast [10 x i64]* %13 to i8*, !dbg !1583
  call void @llvm.lifetime.start.p0i8(i64 80, i8* nonnull %414) #7, !dbg !1583
  call void @llvm.dbg.declare(metadata [10 x i64]* %13, metadata !378, metadata !DIExpression()), !dbg !1583
  %415 = zext i32 %88 to i64, !dbg !1583
  %416 = getelementptr inbounds [10 x i64], [10 x i64]* %13, i64 0, i64 0, !dbg !1583
  store i64 %415, i64* %416, align 8, !dbg !1583, !tbaa !896
  %417 = and i32 %90, 255, !dbg !1583
  %418 = zext i32 %417 to i64, !dbg !1583
  %419 = getelementptr inbounds [10 x i64], [10 x i64]* %13, i64 0, i64 1, !dbg !1583
  store i64 %418, i64* %419, align 8, !dbg !1583, !tbaa !896
  %420 = and i32 %91, 255, !dbg !1583
  %421 = zext i32 %420 to i64, !dbg !1583
  %422 = getelementptr inbounds [10 x i64], [10 x i64]* %13, i64 0, i64 2, !dbg !1583
  store i64 %421, i64* %422, align 8, !dbg !1583, !tbaa !896
  %423 = and i32 %78, 255, !dbg !1583
  %424 = zext i32 %423 to i64, !dbg !1583
  %425 = getelementptr inbounds [10 x i64], [10 x i64]* %13, i64 0, i64 3, !dbg !1583
  store i64 %424, i64* %425, align 8, !dbg !1583, !tbaa !896
  %426 = zext i32 %92 to i64, !dbg !1583
  %427 = getelementptr inbounds [10 x i64], [10 x i64]* %13, i64 0, i64 4, !dbg !1583
  store i64 %426, i64* %427, align 8, !dbg !1583, !tbaa !896
  %428 = and i32 %94, 255, !dbg !1583
  %429 = zext i32 %428 to i64, !dbg !1583
  %430 = getelementptr inbounds [10 x i64], [10 x i64]* %13, i64 0, i64 5, !dbg !1583
  store i64 %429, i64* %430, align 8, !dbg !1583, !tbaa !896
  %431 = and i32 %95, 255, !dbg !1583
  %432 = zext i32 %431 to i64, !dbg !1583
  %433 = getelementptr inbounds [10 x i64], [10 x i64]* %13, i64 0, i64 6, !dbg !1583
  store i64 %432, i64* %433, align 8, !dbg !1583, !tbaa !896
  %434 = and i32 %83, 255, !dbg !1583
  %435 = zext i32 %434 to i64, !dbg !1583
  %436 = getelementptr inbounds [10 x i64], [10 x i64]* %13, i64 0, i64 7, !dbg !1583
  store i64 %435, i64* %436, align 8, !dbg !1583, !tbaa !896
  call void @llvm.dbg.value(metadata i8* %70, metadata !302, metadata !DIExpression()), !dbg !1398
  %437 = load i8, i8* %70, align 4, !dbg !1583, !tbaa !1584
  %438 = zext i8 %437 to i64, !dbg !1583
  %439 = getelementptr inbounds [10 x i64], [10 x i64]* %13, i64 0, i64 8, !dbg !1583
  store i64 %438, i64* %439, align 8, !dbg !1583, !tbaa !896
  %440 = getelementptr inbounds i8, i8* %70, i64 1, !dbg !1583
  %441 = load i8, i8* %440, align 1, !dbg !1583, !tbaa !1586
  %442 = zext i8 %441 to i64, !dbg !1583
  %443 = getelementptr inbounds [10 x i64], [10 x i64]* %13, i64 0, i64 9, !dbg !1583
  store i64 %442, i64* %443, align 8, !dbg !1583, !tbaa !896
  %444 = call i64 inttoptr (i64 177 to i64 (i8*, i32, i8*, i32)*)(i8* noundef getelementptr inbounds ([55 x i8], [55 x i8]* @xdp_entry_state.___fmt.17, i64 0, i64 0), i32 noundef 55, i8* noundef nonnull %414, i32 noundef 80) #7, !dbg !1583
  call void @llvm.lifetime.end.p0i8(i64 80, i8* nonnull %414) #7, !dbg !1587
  br label %445, !dbg !1588

445:                                              ; preds = %408, %364, %359, %106, %99, %96, %68, %63, %1, %72, %226, %313, %173, %176, %126, %370, %413, %56
  call void @llvm.dbg.label(metadata !386), !dbg !1589
  %446 = bitcast i32* %2 to i8*, !dbg !1590
  call void @llvm.lifetime.start.p0i8(i64 4, i8* nonnull %446), !dbg !1590
  call void @llvm.dbg.value(metadata %struct.xdp_md* %0, metadata !807, metadata !DIExpression()) #7, !dbg !1590
  call void @llvm.dbg.value(metadata i32 2, metadata !808, metadata !DIExpression()) #7, !dbg !1590
  store i32 2, i32* %2, align 4, !tbaa !788
  %447 = load i32, i32* %14, align 4, !dbg !1592, !tbaa !609
  call void @llvm.dbg.value(metadata i32 %447, metadata !809, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !1590
  %448 = load i32, i32* %18, align 4, !dbg !1593, !tbaa !617
  call void @llvm.dbg.value(metadata i32 %448, metadata !810, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)) #7, !dbg !1590
  call void @llvm.dbg.value(metadata i32* %2, metadata !808, metadata !DIExpression(DW_OP_deref)) #7, !dbg !1590
  %449 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* noundef bitcast (%struct.anon.17* @xdp_stats_map to i8*), i8* noundef nonnull %446) #7, !dbg !1594
  call void @llvm.dbg.value(metadata i8* %449, metadata !811, metadata !DIExpression()) #7, !dbg !1590
  %450 = icmp eq i8* %449, null, !dbg !1595
  br i1 %450, label %463, label %451, !dbg !1596

451:                                              ; preds = %445
  %452 = zext i32 %448 to i64, !dbg !1597
  call void @llvm.dbg.value(metadata i64 %452, metadata !810, metadata !DIExpression()) #7, !dbg !1590
  %453 = zext i32 %447 to i64, !dbg !1598
  call void @llvm.dbg.value(metadata i64 %453, metadata !809, metadata !DIExpression()) #7, !dbg !1590
  call void @llvm.dbg.value(metadata i8* %449, metadata !811, metadata !DIExpression()) #7, !dbg !1590
  %454 = sub nsw i64 %453, %452, !dbg !1599
  call void @llvm.dbg.value(metadata i64 %454, metadata !812, metadata !DIExpression()) #7, !dbg !1590
  %455 = bitcast i8* %449 to i64*, !dbg !1600
  %456 = load i64, i64* %455, align 8, !dbg !1601, !tbaa !928
  %457 = add i64 %456, 1, !dbg !1601
  store i64 %457, i64* %455, align 8, !dbg !1601, !tbaa !928
  %458 = getelementptr inbounds i8, i8* %449, i64 8, !dbg !1602
  %459 = bitcast i8* %458 to i64*, !dbg !1602
  %460 = load i64, i64* %459, align 8, !dbg !1603, !tbaa !932
  %461 = add i64 %454, %460, !dbg !1603
  store i64 %461, i64* %459, align 8, !dbg !1603, !tbaa !932
  %462 = load i32, i32* %2, align 4, !dbg !1604, !tbaa !788
  call void @llvm.dbg.value(metadata i32 %462, metadata !808, metadata !DIExpression()) #7, !dbg !1590
  br label %463

463:                                              ; preds = %445, %451
  %464 = phi i32 [ %462, %451 ], [ 0, %445 ], !dbg !1590
  call void @llvm.lifetime.end.p0i8(i64 4, i8* nonnull %446), !dbg !1605
  call void @llvm.lifetime.end.p0i8(i64 16, i8* nonnull %22) #7, !dbg !1606
  ret i32 %464, !dbg !1606
}

; Function Attrs: nounwind
define dso_local i32 @test(%struct.xdp_md* nocapture readnone %0) #0 section "xdp" !dbg !420 {
  call void @llvm.dbg.value(metadata %struct.xdp_md* undef, metadata !422, metadata !DIExpression()), !dbg !1607
  %2 = tail call i64 (i8*, i32, ...) inttoptr (i64 6 to i64 (i8*, i32, ...)*)(i8* noundef getelementptr inbounds ([17 x i8], [17 x i8]* @test.____fmt, i64 0, i64 0), i32 noundef 17) #7, !dbg !1608
  ret i32 2, !dbg !1610
}

; Function Attrs: nounwind
define internal i32 @match_rules_loop(i32 noundef %0, i8* nocapture noundef %1) #0 !dbg !1611 {
  %3 = alloca i32, align 4
  call void @llvm.dbg.value(metadata i32 %0, metadata !1613, metadata !DIExpression()), !dbg !1617
  store i32 %0, i32* %3, align 4, !tbaa !788
  call void @llvm.dbg.value(metadata i8* %1, metadata !1614, metadata !DIExpression()), !dbg !1617
  call void @llvm.dbg.value(metadata i8* %1, metadata !1615, metadata !DIExpression()), !dbg !1617
  %4 = bitcast i32* %3 to i8*, !dbg !1618
  call void @llvm.dbg.value(metadata i32* %3, metadata !1613, metadata !DIExpression(DW_OP_deref)), !dbg !1617
  %5 = call i8* inttoptr (i64 1 to i8* (i8*, i8*)*)(i8* noundef bitcast (%struct.anon.20* @rtcache_map4 to i8*), i8* noundef nonnull %4) #7, !dbg !1619
  call void @llvm.dbg.value(metadata i8* %5, metadata !1616, metadata !DIExpression()), !dbg !1617
  %6 = icmp eq i8* %5, null, !dbg !1620
  br i1 %6, label %20, label %7, !dbg !1622

7:                                                ; preds = %2
  %8 = bitcast i8* %1 to i32*, !dbg !1623
  %9 = load i32, i32* %8, align 4, !dbg !1623, !tbaa !1033
  %10 = bitcast i8* %5 to i32*, !dbg !1625
  %11 = load i32, i32* %10, align 4, !dbg !1625, !tbaa !1033
  call void @llvm.dbg.value(metadata i32 %9, metadata !1626, metadata !DIExpression()), !dbg !1632
  call void @llvm.dbg.value(metadata i32 %11, metadata !1631, metadata !DIExpression()), !dbg !1632
  %12 = icmp ne i32 %11, 0, !dbg !1634
  %13 = icmp ne i32 %9, %11
  %14 = and i1 %12, %13, !dbg !1636
  br i1 %14, label %20, label %15, !dbg !1637

15:                                               ; preds = %7
  %16 = getelementptr inbounds i8, i8* %1, i64 4, !dbg !1638
  %17 = getelementptr inbounds i8, i8* %5, i64 4, !dbg !1638
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 4 dereferenceable(6) %16, i8* noundef nonnull align 4 dereferenceable(6) %17, i64 6, i1 false), !dbg !1638
  %18 = getelementptr inbounds i8, i8* %1, i64 10, !dbg !1640
  %19 = getelementptr inbounds i8, i8* %5, i64 10, !dbg !1640
  call void @llvm.memcpy.p0i8.p0i8.i64(i8* noundef nonnull align 2 dereferenceable(6) %18, i8* noundef nonnull align 2 dereferenceable(6) %19, i64 6, i1 false), !dbg !1640
  br label %20, !dbg !1641

20:                                               ; preds = %7, %2, %15
  ret i32 1, !dbg !1642
}

; Function Attrs: nofree nosync nounwind readnone speculatable willreturn
declare void @llvm.dbg.value(metadata, metadata, metadata) #5

; Function Attrs: nounwind readnone
declare i1 @llvm.bpf.passthrough.i1.i1(i32, i1) #6

attributes #0 = { nounwind "frame-pointer"="all" "min-legal-vector-width"="0" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #1 = { mustprogress nofree nosync nounwind readnone speculatable willreturn }
attributes #2 = { argmemonly mustprogress nofree nosync nounwind willreturn }
attributes #3 = { argmemonly mustprogress nofree nounwind willreturn writeonly }
attributes #4 = { argmemonly mustprogress nofree nounwind willreturn }
attributes #5 = { nofree nosync nounwind readnone speculatable willreturn }
attributes #6 = { nounwind readnone }
attributes #7 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!587, !588, !589, !590}
!llvm.ident = !{!591}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "tx_port", scope: !2, file: !3, line: 59, type: !576, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C99, file: !3, producer: "Ubuntu clang version 14.0.0-1ubuntu1.1", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, retainedTypes: !62, globals: !132, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "netmanager_kern.c", directory: "/home/zmx/lmp/eBPF_Supermarket/Network_Subsystem/net_manager", checksumkind: CSK_MD5, checksum: "e01d5a95efc06c145128474d1d523224")
!4 = !{!5, !14, !45, !51}
!5 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "xdp_action", file: !6, line: 5450, baseType: !7, size: 32, elements: !8)
!6 = !DIFile(filename: "/usr/include/linux/bpf.h", directory: "", checksumkind: CSK_MD5, checksum: "fe486ce1b008b02b4869d1c3953168cc")
!7 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!8 = !{!9, !10, !11, !12, !13}
!9 = !DIEnumerator(name: "XDP_ABORTED", value: 0)
!10 = !DIEnumerator(name: "XDP_DROP", value: 1)
!11 = !DIEnumerator(name: "XDP_PASS", value: 2)
!12 = !DIEnumerator(name: "XDP_TX", value: 3)
!13 = !DIEnumerator(name: "XDP_REDIRECT", value: 4)
!14 = !DICompositeType(tag: DW_TAG_enumeration_type, file: !15, line: 28, baseType: !7, size: 32, elements: !16)
!15 = !DIFile(filename: "/usr/include/linux/in.h", directory: "", checksumkind: CSK_MD5, checksum: "078a32220dc819f6a7e2ea3cecc4e133")
!16 = !{!17, !18, !19, !20, !21, !22, !23, !24, !25, !26, !27, !28, !29, !30, !31, !32, !33, !34, !35, !36, !37, !38, !39, !40, !41, !42, !43, !44}
!17 = !DIEnumerator(name: "IPPROTO_IP", value: 0)
!18 = !DIEnumerator(name: "IPPROTO_ICMP", value: 1)
!19 = !DIEnumerator(name: "IPPROTO_IGMP", value: 2)
!20 = !DIEnumerator(name: "IPPROTO_IPIP", value: 4)
!21 = !DIEnumerator(name: "IPPROTO_TCP", value: 6)
!22 = !DIEnumerator(name: "IPPROTO_EGP", value: 8)
!23 = !DIEnumerator(name: "IPPROTO_PUP", value: 12)
!24 = !DIEnumerator(name: "IPPROTO_UDP", value: 17)
!25 = !DIEnumerator(name: "IPPROTO_IDP", value: 22)
!26 = !DIEnumerator(name: "IPPROTO_TP", value: 29)
!27 = !DIEnumerator(name: "IPPROTO_DCCP", value: 33)
!28 = !DIEnumerator(name: "IPPROTO_IPV6", value: 41)
!29 = !DIEnumerator(name: "IPPROTO_RSVP", value: 46)
!30 = !DIEnumerator(name: "IPPROTO_GRE", value: 47)
!31 = !DIEnumerator(name: "IPPROTO_ESP", value: 50)
!32 = !DIEnumerator(name: "IPPROTO_AH", value: 51)
!33 = !DIEnumerator(name: "IPPROTO_MTP", value: 92)
!34 = !DIEnumerator(name: "IPPROTO_BEETPH", value: 94)
!35 = !DIEnumerator(name: "IPPROTO_ENCAP", value: 98)
!36 = !DIEnumerator(name: "IPPROTO_PIM", value: 103)
!37 = !DIEnumerator(name: "IPPROTO_COMP", value: 108)
!38 = !DIEnumerator(name: "IPPROTO_SCTP", value: 132)
!39 = !DIEnumerator(name: "IPPROTO_UDPLITE", value: 136)
!40 = !DIEnumerator(name: "IPPROTO_MPLS", value: 137)
!41 = !DIEnumerator(name: "IPPROTO_ETHERNET", value: 143)
!42 = !DIEnumerator(name: "IPPROTO_RAW", value: 255)
!43 = !DIEnumerator(name: "IPPROTO_MPTCP", value: 262)
!44 = !DIEnumerator(name: "IPPROTO_MAX", value: 263)
!45 = !DICompositeType(tag: DW_TAG_enumeration_type, file: !6, line: 1168, baseType: !7, size: 32, elements: !46)
!46 = !{!47, !48, !49, !50}
!47 = !DIEnumerator(name: "BPF_ANY", value: 0)
!48 = !DIEnumerator(name: "BPF_NOEXIST", value: 1)
!49 = !DIEnumerator(name: "BPF_EXIST", value: 2)
!50 = !DIEnumerator(name: "BPF_F_LOCK", value: 4)
!51 = !DICompositeType(tag: DW_TAG_enumeration_type, file: !52, line: 88, baseType: !7, size: 32, elements: !53)
!52 = !DIFile(filename: "./common_kern_user.h", directory: "/home/zmx/lmp/eBPF_Supermarket/Network_Subsystem/net_manager", checksumkind: CSK_MD5, checksum: "5b834c38f16dd4e2f6f8b7774a192fc9")
!53 = !{!54, !55, !56, !57, !58, !59, !60, !61}
!54 = !DIEnumerator(name: "TCP_S_NONE", value: 0)
!55 = !DIEnumerator(name: "TCP_S_ESTABLISHED", value: 1)
!56 = !DIEnumerator(name: "TCP_S_SYN_SENT", value: 2)
!57 = !DIEnumerator(name: "TCP_S_SYN_RECV", value: 3)
!58 = !DIEnumerator(name: "TCP_S_FIN_WAIT1", value: 4)
!59 = !DIEnumerator(name: "TCP_S_FIN_WAIT2", value: 5)
!60 = !DIEnumerator(name: "TCP_S_CLOSE_WAIT", value: 6)
!61 = !DIEnumerator(name: "TCP_S_CLOSE", value: 7)
!62 = !{!63, !64, !65, !68, !69, !93, !94, !95, !96, !110, !111, !120}
!63 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!64 = !DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)
!65 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u16", file: !66, line: 24, baseType: !67)
!66 = !DIFile(filename: "/usr/include/asm-generic/int-ll64.h", directory: "", checksumkind: CSK_MD5, checksum: "b810f270733e106319b67ef512c6246e")
!67 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!68 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !66, line: 27, baseType: !7)
!69 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !70, size: 64)
!70 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "in6_addr", file: !71, line: 33, size: 128, elements: !72)
!71 = !DIFile(filename: "/usr/include/linux/in6.h", directory: "", checksumkind: CSK_MD5, checksum: "fca1889f0274df066e49cf4d8db8011e")
!72 = !{!73}
!73 = !DIDerivedType(tag: DW_TAG_member, name: "in6_u", scope: !70, file: !71, line: 40, baseType: !74, size: 128)
!74 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !70, file: !71, line: 34, size: 128, elements: !75)
!75 = !{!76, !82, !88}
!76 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr8", scope: !74, file: !71, line: 35, baseType: !77, size: 128)
!77 = !DICompositeType(tag: DW_TAG_array_type, baseType: !78, size: 128, elements: !80)
!78 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u8", file: !66, line: 21, baseType: !79)
!79 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!80 = !{!81}
!81 = !DISubrange(count: 16)
!82 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr16", scope: !74, file: !71, line: 37, baseType: !83, size: 128)
!83 = !DICompositeType(tag: DW_TAG_array_type, baseType: !84, size: 128, elements: !86)
!84 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be16", file: !85, line: 25, baseType: !65)
!85 = !DIFile(filename: "/usr/include/linux/types.h", directory: "", checksumkind: CSK_MD5, checksum: "52ec79a38e49ac7d1dc9e146ba88a7b1")
!86 = !{!87}
!87 = !DISubrange(count: 8)
!88 = !DIDerivedType(tag: DW_TAG_member, name: "u6_addr32", scope: !74, file: !71, line: 38, baseType: !89, size: 128)
!89 = !DICompositeType(tag: DW_TAG_array_type, baseType: !90, size: 128, elements: !91)
!90 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be32", file: !85, line: 27, baseType: !68)
!91 = !{!92}
!92 = !DISubrange(count: 4)
!93 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !90, size: 64)
!94 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !79, size: 64)
!95 = !DIBasicType(name: "unsigned long", size: 64, encoding: DW_ATE_unsigned)
!96 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !97, size: 64)
!97 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "match_rules_loop_ctx", file: !3, line: 170, size: 128, elements: !98)
!98 = !{!99, !100, !101}
!99 = !DIDerivedType(tag: DW_TAG_member, name: "action", scope: !97, file: !3, line: 171, baseType: !65, size: 16)
!100 = !DIDerivedType(tag: DW_TAG_member, name: "next_rule", scope: !97, file: !3, line: 172, baseType: !65, size: 16, offset: 16)
!101 = !DIDerivedType(tag: DW_TAG_member, name: "conn", scope: !97, file: !3, line: 173, baseType: !102, size: 64, offset: 64)
!102 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !103, size: 64)
!103 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "conn_ipv4", file: !52, line: 28, size: 128, elements: !104)
!104 = !{!105, !106, !107, !108, !109}
!105 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !103, file: !52, line: 29, baseType: !68, size: 32)
!106 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !103, file: !52, line: 30, baseType: !68, size: 32, offset: 32)
!107 = !DIDerivedType(tag: DW_TAG_member, name: "sport", scope: !103, file: !52, line: 31, baseType: !65, size: 16, offset: 64)
!108 = !DIDerivedType(tag: DW_TAG_member, name: "dport", scope: !103, file: !52, line: 32, baseType: !65, size: 16, offset: 80)
!109 = !DIDerivedType(tag: DW_TAG_member, name: "ip_proto", scope: !103, file: !52, line: 33, baseType: !65, size: 16, offset: 96)
!110 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !78, size: 64)
!111 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !112, size: 64)
!112 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "rt_item", file: !52, line: 62, size: 128, elements: !113)
!113 = !{!114, !115, !119}
!114 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !112, file: !52, line: 63, baseType: !68, size: 32)
!115 = !DIDerivedType(tag: DW_TAG_member, name: "eth_source", scope: !112, file: !52, line: 64, baseType: !116, size: 48, offset: 32)
!116 = !DICompositeType(tag: DW_TAG_array_type, baseType: !78, size: 48, elements: !117)
!117 = !{!118}
!118 = !DISubrange(count: 6)
!119 = !DIDerivedType(tag: DW_TAG_member, name: "eth_dest", scope: !112, file: !52, line: 65, baseType: !116, size: 48, offset: 80)
!120 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !121, size: 64)
!121 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "match_rules_loop_mac_ctx", file: !3, line: 476, size: 128, elements: !122)
!122 = !{!123, !124, !125}
!123 = !DIDerivedType(tag: DW_TAG_member, name: "action", scope: !121, file: !3, line: 477, baseType: !65, size: 16)
!124 = !DIDerivedType(tag: DW_TAG_member, name: "next_rule", scope: !121, file: !3, line: 478, baseType: !65, size: 16, offset: 16)
!125 = !DIDerivedType(tag: DW_TAG_member, name: "conn", scope: !121, file: !3, line: 479, baseType: !126, size: 64, offset: 64)
!126 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !127, size: 64)
!127 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "conn_mac", file: !52, line: 49, size: 96, elements: !128)
!128 = !{!129, !131}
!129 = !DIDerivedType(tag: DW_TAG_member, name: "dest", scope: !127, file: !52, line: 50, baseType: !130, size: 48)
!130 = !DICompositeType(tag: DW_TAG_array_type, baseType: !79, size: 48, elements: !117)
!131 = !DIDerivedType(tag: DW_TAG_member, name: "source", scope: !127, file: !52, line: 51, baseType: !130, size: 48, offset: 48)
!132 = !{!133, !142, !190, !196, !204, !210, !390, !396, !398, !404, !406, !408, !413, !418, !426, !432, !435, !448, !468, !493, !0, !509, !517, !526, !553, !558, !560, !565, !570}
!133 = !DIGlobalVariableExpression(var: !134, expr: !DIExpression())
!134 = distinct !DIGlobalVariable(name: "bpf_redirect_map", scope: !2, file: !135, line: 1325, type: !136, isLocal: true, isDefinition: true)
!135 = !DIFile(filename: "./lib/install/include/bpf/bpf_helper_defs.h", directory: "/home/zmx/lmp/eBPF_Supermarket/Network_Subsystem/net_manager", checksumkind: CSK_MD5, checksum: "65e4dc8e3121f91a5c2c9eb8563c5692")
!136 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !137)
!137 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !138, size: 64)
!138 = !DISubroutineType(types: !139)
!139 = !{!64, !63, !140, !140}
!140 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u64", file: !66, line: 31, baseType: !141)
!141 = !DIBasicType(name: "unsigned long long", size: 64, encoding: DW_ATE_unsigned)
!142 = !DIGlobalVariableExpression(var: !143, expr: !DIExpression())
!143 = distinct !DIGlobalVariable(name: "bpf_fib_lookup", scope: !2, file: !135, line: 1867, type: !144, isLocal: true, isDefinition: true)
!144 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !145)
!145 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !146, size: 64)
!146 = !DISubroutineType(types: !147)
!147 = !{!64, !63, !148, !189, !68}
!148 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !149, size: 64)
!149 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "bpf_fib_lookup", file: !6, line: 6075, size: 512, elements: !150)
!150 = !{!151, !152, !153, !154, !155, !160, !161, !167, !173, !178, !187, !188}
!151 = !DIDerivedType(tag: DW_TAG_member, name: "family", scope: !149, file: !6, line: 6079, baseType: !78, size: 8)
!152 = !DIDerivedType(tag: DW_TAG_member, name: "l4_protocol", scope: !149, file: !6, line: 6082, baseType: !78, size: 8, offset: 8)
!153 = !DIDerivedType(tag: DW_TAG_member, name: "sport", scope: !149, file: !6, line: 6083, baseType: !84, size: 16, offset: 16)
!154 = !DIDerivedType(tag: DW_TAG_member, name: "dport", scope: !149, file: !6, line: 6084, baseType: !84, size: 16, offset: 32)
!155 = !DIDerivedType(tag: DW_TAG_member, scope: !149, file: !6, line: 6086, baseType: !156, size: 16, offset: 48)
!156 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !149, file: !6, line: 6086, size: 16, elements: !157)
!157 = !{!158, !159}
!158 = !DIDerivedType(tag: DW_TAG_member, name: "tot_len", scope: !156, file: !6, line: 6088, baseType: !65, size: 16)
!159 = !DIDerivedType(tag: DW_TAG_member, name: "mtu_result", scope: !156, file: !6, line: 6091, baseType: !65, size: 16)
!160 = !DIDerivedType(tag: DW_TAG_member, name: "ifindex", scope: !149, file: !6, line: 6096, baseType: !68, size: 32, offset: 64)
!161 = !DIDerivedType(tag: DW_TAG_member, scope: !149, file: !6, line: 6098, baseType: !162, size: 32, offset: 96)
!162 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !149, file: !6, line: 6098, size: 32, elements: !163)
!163 = !{!164, !165, !166}
!164 = !DIDerivedType(tag: DW_TAG_member, name: "tos", scope: !162, file: !6, line: 6100, baseType: !78, size: 8)
!165 = !DIDerivedType(tag: DW_TAG_member, name: "flowinfo", scope: !162, file: !6, line: 6101, baseType: !90, size: 32)
!166 = !DIDerivedType(tag: DW_TAG_member, name: "rt_metric", scope: !162, file: !6, line: 6104, baseType: !68, size: 32)
!167 = !DIDerivedType(tag: DW_TAG_member, scope: !149, file: !6, line: 6110, baseType: !168, size: 128, offset: 128)
!168 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !149, file: !6, line: 6110, size: 128, elements: !169)
!169 = !{!170, !171}
!170 = !DIDerivedType(tag: DW_TAG_member, name: "ipv4_src", scope: !168, file: !6, line: 6111, baseType: !90, size: 32)
!171 = !DIDerivedType(tag: DW_TAG_member, name: "ipv6_src", scope: !168, file: !6, line: 6112, baseType: !172, size: 128)
!172 = !DICompositeType(tag: DW_TAG_array_type, baseType: !68, size: 128, elements: !91)
!173 = !DIDerivedType(tag: DW_TAG_member, scope: !149, file: !6, line: 6119, baseType: !174, size: 128, offset: 256)
!174 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !149, file: !6, line: 6119, size: 128, elements: !175)
!175 = !{!176, !177}
!176 = !DIDerivedType(tag: DW_TAG_member, name: "ipv4_dst", scope: !174, file: !6, line: 6120, baseType: !90, size: 32)
!177 = !DIDerivedType(tag: DW_TAG_member, name: "ipv6_dst", scope: !174, file: !6, line: 6121, baseType: !172, size: 128)
!178 = !DIDerivedType(tag: DW_TAG_member, scope: !149, file: !6, line: 6124, baseType: !179, size: 32, offset: 384)
!179 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !149, file: !6, line: 6124, size: 32, elements: !180)
!180 = !{!181, !186}
!181 = !DIDerivedType(tag: DW_TAG_member, scope: !179, file: !6, line: 6125, baseType: !182, size: 32)
!182 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !179, file: !6, line: 6125, size: 32, elements: !183)
!183 = !{!184, !185}
!184 = !DIDerivedType(tag: DW_TAG_member, name: "h_vlan_proto", scope: !182, file: !6, line: 6127, baseType: !84, size: 16)
!185 = !DIDerivedType(tag: DW_TAG_member, name: "h_vlan_TCI", scope: !182, file: !6, line: 6128, baseType: !84, size: 16, offset: 16)
!186 = !DIDerivedType(tag: DW_TAG_member, name: "tbid", scope: !179, file: !6, line: 6134, baseType: !68, size: 32)
!187 = !DIDerivedType(tag: DW_TAG_member, name: "smac", scope: !149, file: !6, line: 6137, baseType: !116, size: 48, offset: 416)
!188 = !DIDerivedType(tag: DW_TAG_member, name: "dmac", scope: !149, file: !6, line: 6138, baseType: !116, size: 48, offset: 464)
!189 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!190 = !DIGlobalVariableExpression(var: !191, expr: !DIExpression())
!191 = distinct !DIGlobalVariable(name: "bpf_redirect", scope: !2, file: !135, line: 621, type: !192, isLocal: true, isDefinition: true)
!192 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !193)
!193 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !194, size: 64)
!194 = !DISubroutineType(types: !195)
!195 = !{!64, !68, !140}
!196 = !DIGlobalVariableExpression(var: !197, expr: !DIExpression())
!197 = distinct !DIGlobalVariable(name: "bpf_map_lookup_elem", scope: !2, file: !135, line: 56, type: !198, isLocal: true, isDefinition: true)
!198 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !199)
!199 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !200, size: 64)
!200 = !DISubroutineType(types: !201)
!201 = !{!63, !63, !202}
!202 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !203, size: 64)
!203 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!204 = !DIGlobalVariableExpression(var: !205, expr: !DIExpression())
!205 = distinct !DIGlobalVariable(name: "bpf_map_update_elem", scope: !2, file: !135, line: 78, type: !206, isLocal: true, isDefinition: true)
!206 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !207)
!207 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !208, size: 64)
!208 = !DISubroutineType(types: !209)
!209 = !{!64, !63, !202, !202, !140}
!210 = !DIGlobalVariableExpression(var: !211, expr: !DIExpression())
!211 = distinct !DIGlobalVariable(name: "___fmt", scope: !212, file: !3, line: 664, type: !387, isLocal: true, isDefinition: true)
!212 = distinct !DISubprogram(name: "xdp_entry_state", scope: !3, file: !3, line: 603, type: !213, scopeLine: 604, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !224)
!213 = !DISubroutineType(types: !214)
!214 = !{!189, !215}
!215 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !216, size: 64)
!216 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !6, line: 5461, size: 192, elements: !217)
!217 = !{!218, !219, !220, !221, !222, !223}
!218 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !216, file: !6, line: 5462, baseType: !68, size: 32)
!219 = !DIDerivedType(tag: DW_TAG_member, name: "data_end", scope: !216, file: !6, line: 5463, baseType: !68, size: 32, offset: 32)
!220 = !DIDerivedType(tag: DW_TAG_member, name: "data_meta", scope: !216, file: !6, line: 5464, baseType: !68, size: 32, offset: 64)
!221 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_ifindex", scope: !216, file: !6, line: 5466, baseType: !68, size: 32, offset: 96)
!222 = !DIDerivedType(tag: DW_TAG_member, name: "rx_queue_index", scope: !216, file: !6, line: 5467, baseType: !68, size: 32, offset: 128)
!223 = !DIDerivedType(tag: DW_TAG_member, name: "egress_ifindex", scope: !216, file: !6, line: 5469, baseType: !68, size: 32, offset: 160)
!224 = !{!225, !226, !227, !228, !229, !234, !235, !243, !271, !293, !302, !326, !327, !328, !336, !346, !351, !356, !359, !361, !365, !369, !371, !378, !385, !386}
!225 = !DILocalVariable(name: "ctx", arg: 1, scope: !212, file: !3, line: 603, type: !215)
!226 = !DILocalVariable(name: "action", scope: !212, file: !3, line: 605, type: !68)
!227 = !DILocalVariable(name: "data_end", scope: !212, file: !3, line: 606, type: !63)
!228 = !DILocalVariable(name: "data", scope: !212, file: !3, line: 607, type: !63)
!229 = !DILocalVariable(name: "nh", scope: !212, file: !3, line: 608, type: !230)
!230 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "hdr_cursor", file: !231, line: 33, size: 64, elements: !232)
!231 = !DIFile(filename: "././common/parsing_helpers.h", directory: "/home/zmx/lmp/eBPF_Supermarket/Network_Subsystem/net_manager", checksumkind: CSK_MD5, checksum: "172efdd203783aed49c0ce78645261a8")
!232 = !{!233}
!233 = !DIDerivedType(tag: DW_TAG_member, name: "pos", scope: !230, file: !231, line: 34, baseType: !63, size: 64)
!234 = !DILocalVariable(name: "nh_type", scope: !212, file: !3, line: 609, type: !189)
!235 = !DILocalVariable(name: "eth", scope: !212, file: !3, line: 610, type: !236)
!236 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !237, size: 64)
!237 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ethhdr", file: !238, line: 168, size: 112, elements: !239)
!238 = !DIFile(filename: "/usr/include/linux/if_ether.h", directory: "", checksumkind: CSK_MD5, checksum: "ab0320da726e75d904811ce344979934")
!239 = !{!240, !241, !242}
!240 = !DIDerivedType(tag: DW_TAG_member, name: "h_dest", scope: !237, file: !238, line: 169, baseType: !130, size: 48)
!241 = !DIDerivedType(tag: DW_TAG_member, name: "h_source", scope: !237, file: !238, line: 170, baseType: !130, size: 48, offset: 48)
!242 = !DIDerivedType(tag: DW_TAG_member, name: "h_proto", scope: !237, file: !238, line: 171, baseType: !84, size: 16, offset: 96)
!243 = !DILocalVariable(name: "iph", scope: !212, file: !3, line: 611, type: !244)
!244 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !245, size: 64)
!245 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "iphdr", file: !246, line: 87, size: 160, elements: !247)
!246 = !DIFile(filename: "/usr/include/linux/ip.h", directory: "", checksumkind: CSK_MD5, checksum: "042b09a58768855e3578a0a8eba49be7")
!247 = !{!248, !249, !250, !251, !252, !253, !254, !255, !256, !258}
!248 = !DIDerivedType(tag: DW_TAG_member, name: "ihl", scope: !245, file: !246, line: 89, baseType: !78, size: 4, flags: DIFlagBitField, extraData: i64 0)
!249 = !DIDerivedType(tag: DW_TAG_member, name: "version", scope: !245, file: !246, line: 90, baseType: !78, size: 4, offset: 4, flags: DIFlagBitField, extraData: i64 0)
!250 = !DIDerivedType(tag: DW_TAG_member, name: "tos", scope: !245, file: !246, line: 97, baseType: !78, size: 8, offset: 8)
!251 = !DIDerivedType(tag: DW_TAG_member, name: "tot_len", scope: !245, file: !246, line: 98, baseType: !84, size: 16, offset: 16)
!252 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !245, file: !246, line: 99, baseType: !84, size: 16, offset: 32)
!253 = !DIDerivedType(tag: DW_TAG_member, name: "frag_off", scope: !245, file: !246, line: 100, baseType: !84, size: 16, offset: 48)
!254 = !DIDerivedType(tag: DW_TAG_member, name: "ttl", scope: !245, file: !246, line: 101, baseType: !78, size: 8, offset: 64)
!255 = !DIDerivedType(tag: DW_TAG_member, name: "protocol", scope: !245, file: !246, line: 102, baseType: !78, size: 8, offset: 72)
!256 = !DIDerivedType(tag: DW_TAG_member, name: "check", scope: !245, file: !246, line: 103, baseType: !257, size: 16, offset: 80)
!257 = !DIDerivedType(tag: DW_TAG_typedef, name: "__sum16", file: !85, line: 31, baseType: !65)
!258 = !DIDerivedType(tag: DW_TAG_member, scope: !245, file: !246, line: 104, baseType: !259, size: 64, offset: 96)
!259 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !245, file: !246, line: 104, size: 64, elements: !260)
!260 = !{!261, !266}
!261 = !DIDerivedType(tag: DW_TAG_member, scope: !259, file: !246, line: 104, baseType: !262, size: 64)
!262 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !259, file: !246, line: 104, size: 64, elements: !263)
!263 = !{!264, !265}
!264 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !262, file: !246, line: 104, baseType: !90, size: 32)
!265 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !262, file: !246, line: 104, baseType: !90, size: 32, offset: 32)
!266 = !DIDerivedType(tag: DW_TAG_member, name: "addrs", scope: !259, file: !246, line: 104, baseType: !267, size: 64)
!267 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !259, file: !246, line: 104, size: 64, elements: !268)
!268 = !{!269, !270}
!269 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !267, file: !246, line: 104, baseType: !90, size: 32)
!270 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !267, file: !246, line: 104, baseType: !90, size: 32, offset: 32)
!271 = !DILocalVariable(name: "tcph", scope: !212, file: !3, line: 612, type: !272)
!272 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !273, size: 64)
!273 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "tcphdr", file: !274, line: 25, size: 160, elements: !275)
!274 = !DIFile(filename: "/usr/include/linux/tcp.h", directory: "", checksumkind: CSK_MD5, checksum: "8d74bf2133e7b3dab885994b9916aa13")
!275 = !{!276, !277, !278, !279, !280, !281, !282, !283, !284, !285, !286, !287, !288, !289, !290, !291, !292}
!276 = !DIDerivedType(tag: DW_TAG_member, name: "source", scope: !273, file: !274, line: 26, baseType: !84, size: 16)
!277 = !DIDerivedType(tag: DW_TAG_member, name: "dest", scope: !273, file: !274, line: 27, baseType: !84, size: 16, offset: 16)
!278 = !DIDerivedType(tag: DW_TAG_member, name: "seq", scope: !273, file: !274, line: 28, baseType: !90, size: 32, offset: 32)
!279 = !DIDerivedType(tag: DW_TAG_member, name: "ack_seq", scope: !273, file: !274, line: 29, baseType: !90, size: 32, offset: 64)
!280 = !DIDerivedType(tag: DW_TAG_member, name: "res1", scope: !273, file: !274, line: 31, baseType: !65, size: 4, offset: 96, flags: DIFlagBitField, extraData: i64 96)
!281 = !DIDerivedType(tag: DW_TAG_member, name: "doff", scope: !273, file: !274, line: 32, baseType: !65, size: 4, offset: 100, flags: DIFlagBitField, extraData: i64 96)
!282 = !DIDerivedType(tag: DW_TAG_member, name: "fin", scope: !273, file: !274, line: 33, baseType: !65, size: 1, offset: 104, flags: DIFlagBitField, extraData: i64 96)
!283 = !DIDerivedType(tag: DW_TAG_member, name: "syn", scope: !273, file: !274, line: 34, baseType: !65, size: 1, offset: 105, flags: DIFlagBitField, extraData: i64 96)
!284 = !DIDerivedType(tag: DW_TAG_member, name: "rst", scope: !273, file: !274, line: 35, baseType: !65, size: 1, offset: 106, flags: DIFlagBitField, extraData: i64 96)
!285 = !DIDerivedType(tag: DW_TAG_member, name: "psh", scope: !273, file: !274, line: 36, baseType: !65, size: 1, offset: 107, flags: DIFlagBitField, extraData: i64 96)
!286 = !DIDerivedType(tag: DW_TAG_member, name: "ack", scope: !273, file: !274, line: 37, baseType: !65, size: 1, offset: 108, flags: DIFlagBitField, extraData: i64 96)
!287 = !DIDerivedType(tag: DW_TAG_member, name: "urg", scope: !273, file: !274, line: 38, baseType: !65, size: 1, offset: 109, flags: DIFlagBitField, extraData: i64 96)
!288 = !DIDerivedType(tag: DW_TAG_member, name: "ece", scope: !273, file: !274, line: 39, baseType: !65, size: 1, offset: 110, flags: DIFlagBitField, extraData: i64 96)
!289 = !DIDerivedType(tag: DW_TAG_member, name: "cwr", scope: !273, file: !274, line: 40, baseType: !65, size: 1, offset: 111, flags: DIFlagBitField, extraData: i64 96)
!290 = !DIDerivedType(tag: DW_TAG_member, name: "window", scope: !273, file: !274, line: 55, baseType: !84, size: 16, offset: 112)
!291 = !DIDerivedType(tag: DW_TAG_member, name: "check", scope: !273, file: !274, line: 56, baseType: !257, size: 16, offset: 128)
!292 = !DIDerivedType(tag: DW_TAG_member, name: "urg_ptr", scope: !273, file: !274, line: 57, baseType: !84, size: 16, offset: 144)
!293 = !DILocalVariable(name: "udph", scope: !212, file: !3, line: 613, type: !294)
!294 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !295, size: 64)
!295 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "udphdr", file: !296, line: 23, size: 64, elements: !297)
!296 = !DIFile(filename: "/usr/include/linux/udp.h", directory: "", checksumkind: CSK_MD5, checksum: "53c0d42e1bf6d93b39151764be2d20fb")
!297 = !{!298, !299, !300, !301}
!298 = !DIDerivedType(tag: DW_TAG_member, name: "source", scope: !295, file: !296, line: 24, baseType: !84, size: 16)
!299 = !DIDerivedType(tag: DW_TAG_member, name: "dest", scope: !295, file: !296, line: 25, baseType: !84, size: 16, offset: 16)
!300 = !DIDerivedType(tag: DW_TAG_member, name: "len", scope: !295, file: !296, line: 26, baseType: !84, size: 16, offset: 32)
!301 = !DIDerivedType(tag: DW_TAG_member, name: "check", scope: !295, file: !296, line: 27, baseType: !257, size: 16, offset: 48)
!302 = !DILocalVariable(name: "icmph", scope: !212, file: !3, line: 614, type: !303)
!303 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !304, size: 64)
!304 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "icmphdr", file: !305, line: 89, size: 64, elements: !306)
!305 = !DIFile(filename: "/usr/include/linux/icmp.h", directory: "", checksumkind: CSK_MD5, checksum: "a505632898dce546638b3344627d334b")
!306 = !{!307, !308, !309, !310}
!307 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !304, file: !305, line: 90, baseType: !78, size: 8)
!308 = !DIDerivedType(tag: DW_TAG_member, name: "code", scope: !304, file: !305, line: 91, baseType: !78, size: 8, offset: 8)
!309 = !DIDerivedType(tag: DW_TAG_member, name: "checksum", scope: !304, file: !305, line: 92, baseType: !257, size: 16, offset: 16)
!310 = !DIDerivedType(tag: DW_TAG_member, name: "un", scope: !304, file: !305, line: 104, baseType: !311, size: 32, offset: 32)
!311 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !304, file: !305, line: 93, size: 32, elements: !312)
!312 = !{!313, !318, !319, !324}
!313 = !DIDerivedType(tag: DW_TAG_member, name: "echo", scope: !311, file: !305, line: 97, baseType: !314, size: 32)
!314 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !311, file: !305, line: 94, size: 32, elements: !315)
!315 = !{!316, !317}
!316 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !314, file: !305, line: 95, baseType: !84, size: 16)
!317 = !DIDerivedType(tag: DW_TAG_member, name: "sequence", scope: !314, file: !305, line: 96, baseType: !84, size: 16, offset: 16)
!318 = !DIDerivedType(tag: DW_TAG_member, name: "gateway", scope: !311, file: !305, line: 98, baseType: !90, size: 32)
!319 = !DIDerivedType(tag: DW_TAG_member, name: "frag", scope: !311, file: !305, line: 102, baseType: !320, size: 32)
!320 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !311, file: !305, line: 99, size: 32, elements: !321)
!321 = !{!322, !323}
!322 = !DIDerivedType(tag: DW_TAG_member, name: "__unused", scope: !320, file: !305, line: 100, baseType: !84, size: 16)
!323 = !DIDerivedType(tag: DW_TAG_member, name: "mtu", scope: !320, file: !305, line: 101, baseType: !84, size: 16, offset: 16)
!324 = !DIDerivedType(tag: DW_TAG_member, name: "reserved", scope: !311, file: !305, line: 103, baseType: !325, size: 32)
!325 = !DICompositeType(tag: DW_TAG_array_type, baseType: !78, size: 32, elements: !91)
!326 = !DILocalVariable(name: "saddr", scope: !212, file: !3, line: 615, type: !94)
!327 = !DILocalVariable(name: "daddr", scope: !212, file: !3, line: 616, type: !94)
!328 = !DILocalVariable(name: "conn_k", scope: !212, file: !3, line: 619, type: !329)
!329 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "conn_ipv4_key", file: !52, line: 75, size: 128, elements: !330)
!330 = !{!331, !332, !333, !334, !335}
!331 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !329, file: !52, line: 76, baseType: !68, size: 32)
!332 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !329, file: !52, line: 77, baseType: !68, size: 32, offset: 32)
!333 = !DIDerivedType(tag: DW_TAG_member, name: "sport", scope: !329, file: !52, line: 78, baseType: !65, size: 16, offset: 64)
!334 = !DIDerivedType(tag: DW_TAG_member, name: "dport", scope: !329, file: !52, line: 79, baseType: !65, size: 16, offset: 80)
!335 = !DIDerivedType(tag: DW_TAG_member, name: "proto", scope: !329, file: !52, line: 80, baseType: !65, size: 16, offset: 96)
!336 = !DILocalVariable(name: "p_conn_v", scope: !337, file: !3, line: 657, type: !341)
!337 = distinct !DILexicalBlock(scope: !338, file: !3, line: 644, column: 31)
!338 = distinct !DILexicalBlock(scope: !339, file: !3, line: 644, column: 7)
!339 = distinct !DILexicalBlock(scope: !340, file: !3, line: 628, column: 38)
!340 = distinct !DILexicalBlock(scope: !212, file: !3, line: 628, column: 6)
!341 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !342, size: 64)
!342 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "conn_ipv4_val", file: !52, line: 83, size: 64, elements: !343)
!343 = !{!344, !345}
!344 = !DIDerivedType(tag: DW_TAG_member, name: "tcp_state", scope: !342, file: !52, line: 84, baseType: !68, size: 32)
!345 = !DIDerivedType(tag: DW_TAG_member, name: "rid", scope: !342, file: !52, line: 85, baseType: !68, size: 32, offset: 32)
!346 = !DILocalVariable(name: "conn_v", scope: !347, file: !3, line: 660, type: !342)
!347 = distinct !DILexicalBlock(scope: !348, file: !3, line: 659, column: 31)
!348 = distinct !DILexicalBlock(scope: !349, file: !3, line: 659, column: 8)
!349 = distinct !DILexicalBlock(scope: !350, file: !3, line: 658, column: 17)
!350 = distinct !DILexicalBlock(scope: !337, file: !3, line: 658, column: 7)
!351 = !DILocalVariable(name: "___param", scope: !352, file: !3, line: 664, type: !353)
!352 = distinct !DILexicalBlock(scope: !347, file: !3, line: 664, column: 6)
!353 = !DICompositeType(tag: DW_TAG_array_type, baseType: !141, size: 768, elements: !354)
!354 = !{!355}
!355 = !DISubrange(count: 12)
!356 = !DILocalVariable(name: "conn_v", scope: !357, file: !3, line: 670, type: !342)
!357 = distinct !DILexicalBlock(scope: !358, file: !3, line: 669, column: 23)
!358 = distinct !DILexicalBlock(scope: !348, file: !3, line: 669, column: 13)
!359 = !DILocalVariable(name: "___param", scope: !360, file: !3, line: 674, type: !353)
!360 = distinct !DILexicalBlock(scope: !357, file: !3, line: 674, column: 6)
!361 = !DILocalVariable(name: "___param", scope: !362, file: !3, line: 685, type: !353)
!362 = distinct !DILexicalBlock(scope: !363, file: !3, line: 685, column: 5)
!363 = distinct !DILexicalBlock(scope: !364, file: !3, line: 683, column: 17)
!364 = distinct !DILexicalBlock(scope: !337, file: !3, line: 683, column: 7)
!365 = !DILocalVariable(name: "tcp_state_str", scope: !337, file: !3, line: 717, type: !366)
!366 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !367, size: 64)
!367 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !368)
!368 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!369 = !DILocalVariable(name: "___param", scope: !370, file: !3, line: 754, type: !353)
!370 = distinct !DILexicalBlock(scope: !337, file: !3, line: 754, column: 5)
!371 = !DILocalVariable(name: "___param", scope: !372, file: !3, line: 767, type: !375)
!372 = distinct !DILexicalBlock(scope: !373, file: !3, line: 767, column: 4)
!373 = distinct !DILexicalBlock(scope: !374, file: !3, line: 760, column: 34)
!374 = distinct !DILexicalBlock(scope: !338, file: !3, line: 760, column: 11)
!375 = !DICompositeType(tag: DW_TAG_array_type, baseType: !141, size: 704, elements: !376)
!376 = !{!377}
!377 = !DISubrange(count: 11)
!378 = !DILocalVariable(name: "___param", scope: !379, file: !3, line: 777, type: !382)
!379 = distinct !DILexicalBlock(scope: !380, file: !3, line: 777, column: 4)
!380 = distinct !DILexicalBlock(scope: !381, file: !3, line: 772, column: 35)
!381 = distinct !DILexicalBlock(scope: !374, file: !3, line: 772, column: 11)
!382 = !DICompositeType(tag: DW_TAG_array_type, baseType: !141, size: 640, elements: !383)
!383 = !{!384}
!384 = !DISubrange(count: 10)
!385 = !DILabel(scope: !337, name: "out_tcp_conn", file: !3, line: 720)
!386 = !DILabel(scope: !212, name: "out", file: !3, line: 791)
!387 = !DICompositeType(tag: DW_TAG_array_type, baseType: !367, size: 448, elements: !388)
!388 = !{!389}
!389 = !DISubrange(count: 56)
!390 = !DIGlobalVariableExpression(var: !391, expr: !DIExpression())
!391 = distinct !DIGlobalVariable(name: "bpf_trace_vprintk", scope: !2, file: !135, line: 4154, type: !392, isLocal: true, isDefinition: true)
!392 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !393)
!393 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !394, size: 64)
!394 = !DISubroutineType(types: !395)
!395 = !{!64, !366, !68, !202, !68}
!396 = !DIGlobalVariableExpression(var: !397, expr: !DIExpression())
!397 = distinct !DIGlobalVariable(name: "___fmt", scope: !212, file: !3, line: 674, type: !387, isLocal: true, isDefinition: true)
!398 = !DIGlobalVariableExpression(var: !399, expr: !DIExpression())
!399 = distinct !DIGlobalVariable(name: "bpf_map_delete_elem", scope: !2, file: !135, line: 88, type: !400, isLocal: true, isDefinition: true)
!400 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !401)
!401 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !402, size: 64)
!402 = !DISubroutineType(types: !403)
!403 = !{!64, !63, !202}
!404 = !DIGlobalVariableExpression(var: !405, expr: !DIExpression())
!405 = distinct !DIGlobalVariable(name: "___fmt", scope: !212, file: !3, line: 685, type: !387, isLocal: true, isDefinition: true)
!406 = !DIGlobalVariableExpression(var: !407, expr: !DIExpression())
!407 = distinct !DIGlobalVariable(name: "___fmt", scope: !212, file: !3, line: 754, type: !387, isLocal: true, isDefinition: true)
!408 = !DIGlobalVariableExpression(var: !409, expr: !DIExpression())
!409 = distinct !DIGlobalVariable(name: "___fmt", scope: !212, file: !3, line: 767, type: !410, isLocal: true, isDefinition: true)
!410 = !DICompositeType(tag: DW_TAG_array_type, baseType: !367, size: 416, elements: !411)
!411 = !{!412}
!412 = !DISubrange(count: 52)
!413 = !DIGlobalVariableExpression(var: !414, expr: !DIExpression())
!414 = distinct !DIGlobalVariable(name: "___fmt", scope: !212, file: !3, line: 777, type: !415, isLocal: true, isDefinition: true)
!415 = !DICompositeType(tag: DW_TAG_array_type, baseType: !367, size: 440, elements: !416)
!416 = !{!417}
!417 = !DISubrange(count: 55)
!418 = !DIGlobalVariableExpression(var: !419, expr: !DIExpression())
!419 = distinct !DIGlobalVariable(name: "____fmt", scope: !420, file: !3, line: 799, type: !423, isLocal: true, isDefinition: true)
!420 = distinct !DISubprogram(name: "test", scope: !3, file: !3, line: 797, type: !213, scopeLine: 798, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !421)
!421 = !{!422}
!422 = !DILocalVariable(name: "ctx", arg: 1, scope: !420, file: !3, line: 797, type: !215)
!423 = !DICompositeType(tag: DW_TAG_array_type, baseType: !367, size: 136, elements: !424)
!424 = !{!425}
!425 = !DISubrange(count: 17)
!426 = !DIGlobalVariableExpression(var: !427, expr: !DIExpression())
!427 = distinct !DIGlobalVariable(name: "bpf_trace_printk", scope: !2, file: !135, line: 177, type: !428, isLocal: true, isDefinition: true)
!428 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !429)
!429 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !430, size: 64)
!430 = !DISubroutineType(types: !431)
!431 = !{!64, !366, !68, null}
!432 = !DIGlobalVariableExpression(var: !433, expr: !DIExpression())
!433 = distinct !DIGlobalVariable(name: "_license", scope: !2, file: !3, line: 803, type: !434, isLocal: false, isDefinition: true)
!434 = !DICompositeType(tag: DW_TAG_array_type, baseType: !368, size: 32, elements: !91)
!435 = !DIGlobalVariableExpression(var: !436, expr: !DIExpression())
!436 = distinct !DIGlobalVariable(name: "print_info_map", scope: !2, file: !3, line: 27, type: !437, isLocal: false, isDefinition: true)
!437 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 22, size: 256, elements: !438)
!438 = !{!439, !444, !446, !447}
!439 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !437, file: !3, line: 23, baseType: !440, size: 64)
!440 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !441, size: 64)
!441 = !DICompositeType(tag: DW_TAG_array_type, baseType: !189, size: 32, elements: !442)
!442 = !{!443}
!443 = !DISubrange(count: 1)
!444 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !437, file: !3, line: 24, baseType: !445, size: 64, offset: 64)
!445 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !65, size: 64)
!446 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !437, file: !3, line: 25, baseType: !445, size: 64, offset: 128)
!447 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !437, file: !3, line: 26, baseType: !440, size: 64, offset: 192)
!448 = !DIGlobalVariableExpression(var: !449, expr: !DIExpression())
!449 = distinct !DIGlobalVariable(name: "xdp_stats_map", scope: !2, file: !3, line: 35, type: !450, isLocal: false, isDefinition: true)
!450 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 30, size: 256, elements: !451)
!451 = !{!452, !455, !457, !463}
!452 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !450, file: !3, line: 31, baseType: !453, size: 64)
!453 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !454, size: 64)
!454 = !DICompositeType(tag: DW_TAG_array_type, baseType: !189, size: 192, elements: !117)
!455 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !450, file: !3, line: 32, baseType: !456, size: 64, offset: 64)
!456 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !68, size: 64)
!457 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !450, file: !3, line: 33, baseType: !458, size: 64, offset: 128)
!458 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !459, size: 64)
!459 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "datarec", file: !52, line: 23, size: 128, elements: !460)
!460 = !{!461, !462}
!461 = !DIDerivedType(tag: DW_TAG_member, name: "rx_packets", scope: !459, file: !52, line: 24, baseType: !140, size: 64)
!462 = !DIDerivedType(tag: DW_TAG_member, name: "rx_bytes", scope: !459, file: !52, line: 25, baseType: !140, size: 64, offset: 64)
!463 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !450, file: !3, line: 34, baseType: !464, size: 64, offset: 192)
!464 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !465, size: 64)
!465 = !DICompositeType(tag: DW_TAG_array_type, baseType: !189, size: 160, elements: !466)
!466 = !{!467}
!467 = !DISubrange(count: 5)
!468 = !DIGlobalVariableExpression(var: !469, expr: !DIExpression())
!469 = distinct !DIGlobalVariable(name: "rules_ipv4_map", scope: !2, file: !3, line: 43, type: !470, isLocal: false, isDefinition: true)
!470 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 38, size: 256, elements: !471)
!471 = !{!472, !473, !474, !488}
!472 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !470, file: !3, line: 39, baseType: !440, size: 64)
!473 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !470, file: !3, line: 40, baseType: !445, size: 64, offset: 64)
!474 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !470, file: !3, line: 41, baseType: !475, size: 64, offset: 128)
!475 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !476, size: 64)
!476 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "rules_ipv4", file: !52, line: 36, size: 192, elements: !477)
!477 = !{!478, !479, !480, !481, !482, !483, !484, !485, !486, !487}
!478 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !476, file: !52, line: 37, baseType: !68, size: 32)
!479 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !476, file: !52, line: 38, baseType: !68, size: 32, offset: 32)
!480 = !DIDerivedType(tag: DW_TAG_member, name: "saddr_mask", scope: !476, file: !52, line: 39, baseType: !78, size: 8, offset: 64)
!481 = !DIDerivedType(tag: DW_TAG_member, name: "daddr_mask", scope: !476, file: !52, line: 40, baseType: !78, size: 8, offset: 72)
!482 = !DIDerivedType(tag: DW_TAG_member, name: "sport", scope: !476, file: !52, line: 41, baseType: !65, size: 16, offset: 80)
!483 = !DIDerivedType(tag: DW_TAG_member, name: "dport", scope: !476, file: !52, line: 42, baseType: !65, size: 16, offset: 96)
!484 = !DIDerivedType(tag: DW_TAG_member, name: "ip_proto", scope: !476, file: !52, line: 43, baseType: !65, size: 16, offset: 112)
!485 = !DIDerivedType(tag: DW_TAG_member, name: "action", scope: !476, file: !52, line: 44, baseType: !65, size: 16, offset: 128)
!486 = !DIDerivedType(tag: DW_TAG_member, name: "prev_rule", scope: !476, file: !52, line: 45, baseType: !65, size: 16, offset: 144)
!487 = !DIDerivedType(tag: DW_TAG_member, name: "next_rule", scope: !476, file: !52, line: 46, baseType: !65, size: 16, offset: 160)
!488 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !470, file: !3, line: 42, baseType: !489, size: 64, offset: 192)
!489 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !490, size: 64)
!490 = !DICompositeType(tag: DW_TAG_array_type, baseType: !189, size: 8192, elements: !491)
!491 = !{!492}
!492 = !DISubrange(count: 256)
!493 = !DIGlobalVariableExpression(var: !494, expr: !DIExpression())
!494 = distinct !DIGlobalVariable(name: "rules_mac_map", scope: !2, file: !3, line: 51, type: !495, isLocal: false, isDefinition: true)
!495 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 46, size: 256, elements: !496)
!496 = !{!497, !498, !499, !508}
!497 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !495, file: !3, line: 47, baseType: !440, size: 64)
!498 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !495, file: !3, line: 48, baseType: !445, size: 64, offset: 64)
!499 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !495, file: !3, line: 49, baseType: !500, size: 64, offset: 128)
!500 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !501, size: 64)
!501 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "rules_mac", file: !52, line: 54, size: 144, elements: !502)
!502 = !{!503, !504, !505, !506, !507}
!503 = !DIDerivedType(tag: DW_TAG_member, name: "dest", scope: !501, file: !52, line: 55, baseType: !130, size: 48)
!504 = !DIDerivedType(tag: DW_TAG_member, name: "source", scope: !501, file: !52, line: 56, baseType: !130, size: 48, offset: 48)
!505 = !DIDerivedType(tag: DW_TAG_member, name: "action", scope: !501, file: !52, line: 57, baseType: !65, size: 16, offset: 96)
!506 = !DIDerivedType(tag: DW_TAG_member, name: "prev_rule", scope: !501, file: !52, line: 58, baseType: !65, size: 16, offset: 112)
!507 = !DIDerivedType(tag: DW_TAG_member, name: "next_rule", scope: !501, file: !52, line: 59, baseType: !65, size: 16, offset: 128)
!508 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !495, file: !3, line: 50, baseType: !489, size: 64, offset: 192)
!509 = !DIGlobalVariableExpression(var: !510, expr: !DIExpression())
!510 = distinct !DIGlobalVariable(name: "rtcache_map4", scope: !2, file: !3, line: 67, type: !511, isLocal: false, isDefinition: true)
!511 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 62, size: 256, elements: !512)
!512 = !{!513, !514, !515, !516}
!513 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !511, file: !3, line: 63, baseType: !440, size: 64)
!514 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !511, file: !3, line: 64, baseType: !456, size: 64, offset: 64)
!515 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !511, file: !3, line: 65, baseType: !111, size: 64, offset: 128)
!516 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !511, file: !3, line: 66, baseType: !489, size: 64, offset: 192)
!517 = !DIGlobalVariableExpression(var: !518, expr: !DIExpression())
!518 = distinct !DIGlobalVariable(name: "conn_ipv4_map", scope: !2, file: !3, line: 75, type: !519, isLocal: false, isDefinition: true)
!519 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 70, size: 256, elements: !520)
!520 = !{!521, !522, !524, !525}
!521 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !519, file: !3, line: 71, baseType: !440, size: 64)
!522 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !519, file: !3, line: 72, baseType: !523, size: 64, offset: 64)
!523 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !329, size: 64)
!524 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !519, file: !3, line: 73, baseType: !341, size: 64, offset: 128)
!525 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !519, file: !3, line: 74, baseType: !489, size: 64, offset: 192)
!526 = !DIGlobalVariableExpression(var: !527, expr: !DIExpression())
!527 = distinct !DIGlobalVariable(name: "____fmt", scope: !528, file: !3, line: 213, type: !550, isLocal: true, isDefinition: true)
!528 = distinct !DISubprogram(name: "match_rules_ipv4_loop", scope: !3, file: !3, line: 195, type: !529, scopeLine: 196, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !531)
!529 = !DISubroutineType(types: !530)
!530 = !{!189, !68, !63}
!531 = !{!532, !533, !534, !535, !536, !537, !538, !539, !542, !547, !549}
!532 = !DILocalVariable(name: "index", arg: 1, scope: !528, file: !3, line: 195, type: !68)
!533 = !DILocalVariable(name: "ctx", arg: 2, scope: !528, file: !3, line: 195, type: !63)
!534 = !DILocalVariable(name: "i", scope: !528, file: !3, line: 197, type: !189)
!535 = !DILocalVariable(name: "saddr", scope: !528, file: !3, line: 198, type: !94)
!536 = !DILocalVariable(name: "daddr", scope: !528, file: !3, line: 199, type: !94)
!537 = !DILocalVariable(name: "p_ctx", scope: !528, file: !3, line: 200, type: !96)
!538 = !DILocalVariable(name: "p_r", scope: !528, file: !3, line: 204, type: !475)
!539 = !DILocalVariable(name: "print_info", scope: !540, file: !3, line: 221, type: !110)
!540 = distinct !DILexicalBlock(scope: !541, file: !3, line: 219, column: 2)
!541 = distinct !DILexicalBlock(scope: !528, file: !3, line: 214, column: 6)
!542 = !DILocalVariable(name: "___param", scope: !543, file: !3, line: 227, type: !546)
!543 = distinct !DILexicalBlock(scope: !544, file: !3, line: 227, column: 4)
!544 = distinct !DILexicalBlock(scope: !545, file: !3, line: 223, column: 17)
!545 = distinct !DILexicalBlock(scope: !540, file: !3, line: 223, column: 6)
!546 = !DICompositeType(tag: DW_TAG_array_type, baseType: !141, size: 320, elements: !466)
!547 = !DILocalVariable(name: "___param", scope: !548, file: !3, line: 228, type: !546)
!548 = distinct !DILexicalBlock(scope: !544, file: !3, line: 228, column: 4)
!549 = !DILabel(scope: !528, name: "out_match_rules_ipv4_loop", file: !3, line: 236)
!550 = !DICompositeType(tag: DW_TAG_array_type, baseType: !367, size: 200, elements: !551)
!551 = !{!552}
!552 = !DISubrange(count: 25)
!553 = !DIGlobalVariableExpression(var: !554, expr: !DIExpression())
!554 = distinct !DIGlobalVariable(name: "___fmt", scope: !528, file: !3, line: 227, type: !555, isLocal: true, isDefinition: true)
!555 = !DICompositeType(tag: DW_TAG_array_type, baseType: !367, size: 192, elements: !556)
!556 = !{!557}
!557 = !DISubrange(count: 24)
!558 = !DIGlobalVariableExpression(var: !559, expr: !DIExpression())
!559 = distinct !DIGlobalVariable(name: "___fmt", scope: !528, file: !3, line: 228, type: !555, isLocal: true, isDefinition: true)
!560 = !DIGlobalVariableExpression(var: !561, expr: !DIExpression())
!561 = distinct !DIGlobalVariable(name: "____fmt", scope: !528, file: !3, line: 229, type: !562, isLocal: true, isDefinition: true)
!562 = !DICompositeType(tag: DW_TAG_array_type, baseType: !367, size: 232, elements: !563)
!563 = !{!564}
!564 = !DISubrange(count: 29)
!565 = !DIGlobalVariableExpression(var: !566, expr: !DIExpression())
!566 = distinct !DIGlobalVariable(name: "____fmt", scope: !528, file: !3, line: 230, type: !567, isLocal: true, isDefinition: true)
!567 = !DICompositeType(tag: DW_TAG_array_type, baseType: !367, size: 288, elements: !568)
!568 = !{!569}
!569 = !DISubrange(count: 36)
!570 = !DIGlobalVariableExpression(var: !571, expr: !DIExpression())
!571 = distinct !DIGlobalVariable(name: "bpf_loop", scope: !2, file: !135, line: 4234, type: !572, isLocal: true, isDefinition: true)
!572 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !573)
!573 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !574, size: 64)
!574 = !DISubroutineType(types: !575)
!575 = !{!64, !68, !63, !63, !140}
!576 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 54, size: 256, elements: !577)
!577 = !{!578, !583, !585, !586}
!578 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !576, file: !3, line: 55, baseType: !579, size: 64)
!579 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !580, size: 64)
!580 = !DICompositeType(tag: DW_TAG_array_type, baseType: !189, size: 448, elements: !581)
!581 = !{!582}
!582 = !DISubrange(count: 14)
!583 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !576, file: !3, line: 56, baseType: !584, size: 64, offset: 64)
!584 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !189, size: 64)
!585 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !576, file: !3, line: 57, baseType: !584, size: 64, offset: 128)
!586 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !576, file: !3, line: 58, baseType: !489, size: 64, offset: 192)
!587 = !{i32 7, !"Dwarf Version", i32 5}
!588 = !{i32 2, !"Debug Info Version", i32 3}
!589 = !{i32 1, !"wchar_size", i32 4}
!590 = !{i32 7, !"frame-pointer", i32 2}
!591 = !{!"Ubuntu clang version 14.0.0-1ubuntu1.1"}
!592 = distinct !DISubprogram(name: "xdp_entry_ipv4", scope: !3, file: !3, line: 258, type: !213, scopeLine: 259, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !593)
!593 = !{!594, !595, !597, !598, !599, !600, !601, !602, !603, !604, !605, !606}
!594 = !DILocalVariable(name: "ctx", arg: 1, scope: !592, file: !3, line: 258, type: !215)
!595 = !DILocalVariable(name: "action", scope: !592, file: !3, line: 260, type: !596)
!596 = !DIDerivedType(tag: DW_TAG_typedef, name: "xdp_act", file: !52, line: 9, baseType: !68)
!597 = !DILocalVariable(name: "data_end", scope: !592, file: !3, line: 261, type: !63)
!598 = !DILocalVariable(name: "data", scope: !592, file: !3, line: 262, type: !63)
!599 = !DILocalVariable(name: "nh", scope: !592, file: !3, line: 263, type: !230)
!600 = !DILocalVariable(name: "nh_type", scope: !592, file: !3, line: 264, type: !189)
!601 = !DILocalVariable(name: "eth", scope: !592, file: !3, line: 265, type: !236)
!602 = !DILocalVariable(name: "iph", scope: !592, file: !3, line: 266, type: !244)
!603 = !DILocalVariable(name: "tcph", scope: !592, file: !3, line: 267, type: !272)
!604 = !DILocalVariable(name: "udph", scope: !592, file: !3, line: 268, type: !294)
!605 = !DILocalVariable(name: "conn", scope: !592, file: !3, line: 269, type: !103)
!606 = !DILabel(scope: !592, name: "out", file: !3, line: 319)
!607 = !DILocation(line: 0, scope: !592)
!608 = !DILocation(line: 261, column: 38, scope: !592)
!609 = !{!610, !611, i64 4}
!610 = !{!"xdp_md", !611, i64 0, !611, i64 4, !611, i64 8, !611, i64 12, !611, i64 16, !611, i64 20}
!611 = !{!"int", !612, i64 0}
!612 = !{!"omnipotent char", !613, i64 0}
!613 = !{!"Simple C/C++ TBAA"}
!614 = !DILocation(line: 261, column: 27, scope: !592)
!615 = !DILocation(line: 261, column: 19, scope: !592)
!616 = !DILocation(line: 262, column: 34, scope: !592)
!617 = !{!610, !611, i64 0}
!618 = !DILocation(line: 262, column: 23, scope: !592)
!619 = !DILocation(line: 262, column: 15, scope: !592)
!620 = !DILocalVariable(name: "nh", arg: 1, scope: !621, file: !231, line: 124, type: !624)
!621 = distinct !DISubprogram(name: "parse_ethhdr", scope: !231, file: !231, line: 124, type: !622, scopeLine: 127, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !626)
!622 = !DISubroutineType(types: !623)
!623 = !{!189, !624, !63, !625}
!624 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !230, size: 64)
!625 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !236, size: 64)
!626 = !{!620, !627, !628}
!627 = !DILocalVariable(name: "data_end", arg: 2, scope: !621, file: !231, line: 125, type: !63)
!628 = !DILocalVariable(name: "ethhdr", arg: 3, scope: !621, file: !231, line: 126, type: !625)
!629 = !DILocation(line: 0, scope: !621, inlinedAt: !630)
!630 = distinct !DILocation(line: 274, column: 12, scope: !592)
!631 = !DILocalVariable(name: "nh", arg: 1, scope: !632, file: !231, line: 79, type: !624)
!632 = distinct !DISubprogram(name: "parse_ethhdr_vlan", scope: !231, file: !231, line: 79, type: !633, scopeLine: 83, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !642)
!633 = !DISubroutineType(types: !634)
!634 = !{!189, !624, !63, !625, !635}
!635 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !636, size: 64)
!636 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "collect_vlans", file: !231, line: 64, size: 32, elements: !637)
!637 = !{!638}
!638 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !636, file: !231, line: 65, baseType: !639, size: 32)
!639 = !DICompositeType(tag: DW_TAG_array_type, baseType: !65, size: 32, elements: !640)
!640 = !{!641}
!641 = !DISubrange(count: 2)
!642 = !{!631, !643, !644, !645, !646, !647, !648, !654, !655}
!643 = !DILocalVariable(name: "data_end", arg: 2, scope: !632, file: !231, line: 80, type: !63)
!644 = !DILocalVariable(name: "ethhdr", arg: 3, scope: !632, file: !231, line: 81, type: !625)
!645 = !DILocalVariable(name: "vlans", arg: 4, scope: !632, file: !231, line: 82, type: !635)
!646 = !DILocalVariable(name: "eth", scope: !632, file: !231, line: 84, type: !236)
!647 = !DILocalVariable(name: "hdrsize", scope: !632, file: !231, line: 85, type: !189)
!648 = !DILocalVariable(name: "vlh", scope: !632, file: !231, line: 86, type: !649)
!649 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !650, size: 64)
!650 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "vlan_hdr", file: !231, line: 42, size: 32, elements: !651)
!651 = !{!652, !653}
!652 = !DIDerivedType(tag: DW_TAG_member, name: "h_vlan_TCI", scope: !650, file: !231, line: 43, baseType: !84, size: 16)
!653 = !DIDerivedType(tag: DW_TAG_member, name: "h_vlan_encapsulated_proto", scope: !650, file: !231, line: 44, baseType: !84, size: 16, offset: 16)
!654 = !DILocalVariable(name: "h_proto", scope: !632, file: !231, line: 87, type: !65)
!655 = !DILocalVariable(name: "i", scope: !632, file: !231, line: 88, type: !189)
!656 = !DILocation(line: 0, scope: !632, inlinedAt: !657)
!657 = distinct !DILocation(line: 129, column: 9, scope: !621, inlinedAt: !630)
!658 = !DILocation(line: 93, column: 14, scope: !659, inlinedAt: !657)
!659 = distinct !DILexicalBlock(scope: !632, file: !231, line: 93, column: 6)
!660 = !DILocation(line: 93, column: 24, scope: !659, inlinedAt: !657)
!661 = !DILocation(line: 93, column: 6, scope: !632, inlinedAt: !657)
!662 = !DILocation(line: 99, column: 17, scope: !632, inlinedAt: !657)
!663 = !{!664, !664, i64 0}
!664 = !{!"short", !612, i64 0}
!665 = !DILocalVariable(name: "h_proto", arg: 1, scope: !666, file: !231, line: 68, type: !65)
!666 = distinct !DISubprogram(name: "proto_is_vlan", scope: !231, file: !231, line: 68, type: !667, scopeLine: 69, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !669)
!667 = !DISubroutineType(types: !668)
!668 = !{!189, !65}
!669 = !{!665}
!670 = !DILocation(line: 0, scope: !666, inlinedAt: !671)
!671 = distinct !DILocation(line: 106, column: 8, scope: !672, inlinedAt: !657)
!672 = distinct !DILexicalBlock(scope: !673, file: !231, line: 106, column: 7)
!673 = distinct !DILexicalBlock(scope: !674, file: !231, line: 105, column: 39)
!674 = distinct !DILexicalBlock(scope: !675, file: !231, line: 105, column: 2)
!675 = distinct !DILexicalBlock(scope: !632, file: !231, line: 105, column: 2)
!676 = !DILocation(line: 70, column: 20, scope: !666, inlinedAt: !671)
!677 = !DILocation(line: 70, column: 46, scope: !666, inlinedAt: !671)
!678 = !DILocation(line: 106, column: 8, scope: !672, inlinedAt: !657)
!679 = !DILocation(line: 106, column: 7, scope: !673, inlinedAt: !657)
!680 = !DILocation(line: 112, column: 18, scope: !673, inlinedAt: !657)
!681 = !DILocation(line: 276, column: 5, scope: !592)
!682 = !DILocalVariable(name: "nh", arg: 1, scope: !683, file: !231, line: 151, type: !624)
!683 = distinct !DISubprogram(name: "parse_iphdr", scope: !231, file: !231, line: 151, type: !684, scopeLine: 154, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !687)
!684 = !DISubroutineType(types: !685)
!685 = !{!189, !624, !63, !686}
!686 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !244, size: 64)
!687 = !{!682, !688, !689, !690, !691}
!688 = !DILocalVariable(name: "data_end", arg: 2, scope: !683, file: !231, line: 152, type: !63)
!689 = !DILocalVariable(name: "iphdr", arg: 3, scope: !683, file: !231, line: 153, type: !686)
!690 = !DILocalVariable(name: "iph", scope: !683, file: !231, line: 155, type: !244)
!691 = !DILocalVariable(name: "hdrsize", scope: !683, file: !231, line: 156, type: !189)
!692 = !DILocation(line: 0, scope: !683, inlinedAt: !693)
!693 = distinct !DILocation(line: 281, column: 13, scope: !694)
!694 = distinct !DILexicalBlock(scope: !695, file: !3, line: 279, column: 38)
!695 = distinct !DILexicalBlock(scope: !592, file: !3, line: 279, column: 6)
!696 = !DILocation(line: 161, column: 17, scope: !683, inlinedAt: !693)
!697 = !DILocation(line: 161, column: 21, scope: !683, inlinedAt: !693)
!698 = !DILocation(line: 163, column: 13, scope: !699, inlinedAt: !693)
!699 = distinct !DILexicalBlock(scope: !683, file: !231, line: 163, column: 5)
!700 = !DILocation(line: 163, column: 5, scope: !683, inlinedAt: !693)
!701 = !DILocation(line: 167, column: 14, scope: !702, inlinedAt: !693)
!702 = distinct !DILexicalBlock(scope: !683, file: !231, line: 167, column: 6)
!703 = !DILocation(line: 167, column: 24, scope: !702, inlinedAt: !693)
!704 = !DILocation(line: 167, column: 6, scope: !683, inlinedAt: !693)
!705 = !DILocation(line: 173, column: 14, scope: !683, inlinedAt: !693)
!706 = !{!707, !612, i64 9}
!707 = !{!"iphdr", !612, i64 0, !612, i64 0, !612, i64 1, !664, i64 2, !664, i64 4, !664, i64 6, !612, i64 8, !612, i64 9, !664, i64 10, !612, i64 12}
!708 = !DILocation(line: 286, column: 7, scope: !694)
!709 = !DILocalVariable(name: "nh", arg: 1, scope: !710, file: !231, line: 247, type: !624)
!710 = distinct !DISubprogram(name: "parse_tcphdr", scope: !231, file: !231, line: 247, type: !711, scopeLine: 250, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !714)
!711 = !DISubroutineType(types: !712)
!712 = !{!189, !624, !63, !713}
!713 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !272, size: 64)
!714 = !{!709, !715, !716, !717, !718}
!715 = !DILocalVariable(name: "data_end", arg: 2, scope: !710, file: !231, line: 248, type: !63)
!716 = !DILocalVariable(name: "tcphdr", arg: 3, scope: !710, file: !231, line: 249, type: !713)
!717 = !DILocalVariable(name: "len", scope: !710, file: !231, line: 251, type: !189)
!718 = !DILocalVariable(name: "h", scope: !710, file: !231, line: 252, type: !272)
!719 = !DILocation(line: 0, scope: !710, inlinedAt: !720)
!720 = distinct !DILocation(line: 287, column: 7, scope: !721)
!721 = distinct !DILexicalBlock(scope: !722, file: !3, line: 287, column: 7)
!722 = distinct !DILexicalBlock(scope: !723, file: !3, line: 286, column: 31)
!723 = distinct !DILexicalBlock(scope: !694, file: !3, line: 286, column: 7)
!724 = !DILocation(line: 254, column: 8, scope: !725, inlinedAt: !720)
!725 = distinct !DILexicalBlock(scope: !710, file: !231, line: 254, column: 6)
!726 = !DILocation(line: 254, column: 12, scope: !725, inlinedAt: !720)
!727 = !DILocation(line: 254, column: 6, scope: !710, inlinedAt: !720)
!728 = !DILocation(line: 257, column: 11, scope: !710, inlinedAt: !720)
!729 = !DILocation(line: 257, column: 16, scope: !710, inlinedAt: !720)
!730 = !DILocation(line: 259, column: 9, scope: !731, inlinedAt: !720)
!731 = distinct !DILexicalBlock(scope: !710, file: !231, line: 259, column: 5)
!732 = !DILocation(line: 259, column: 5, scope: !710, inlinedAt: !720)
!733 = !DILocation(line: 263, column: 14, scope: !734, inlinedAt: !720)
!734 = distinct !DILexicalBlock(scope: !710, file: !231, line: 263, column: 6)
!735 = !DILocation(line: 263, column: 20, scope: !734, inlinedAt: !720)
!736 = !DILocation(line: 263, column: 6, scope: !710, inlinedAt: !720)
!737 = !DILocalVariable(name: "nh", arg: 1, scope: !738, file: !231, line: 224, type: !624)
!738 = distinct !DISubprogram(name: "parse_udphdr", scope: !231, file: !231, line: 224, type: !739, scopeLine: 227, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !742)
!739 = !DISubroutineType(types: !740)
!740 = !{!189, !624, !63, !741}
!741 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !294, size: 64)
!742 = !{!737, !743, !744, !745, !746}
!743 = !DILocalVariable(name: "data_end", arg: 2, scope: !738, file: !231, line: 225, type: !63)
!744 = !DILocalVariable(name: "udphdr", arg: 3, scope: !738, file: !231, line: 226, type: !741)
!745 = !DILocalVariable(name: "len", scope: !738, file: !231, line: 228, type: !189)
!746 = !DILocalVariable(name: "h", scope: !738, file: !231, line: 229, type: !294)
!747 = !DILocation(line: 0, scope: !738, inlinedAt: !748)
!748 = distinct !DILocation(line: 295, column: 7, scope: !749)
!749 = distinct !DILexicalBlock(scope: !750, file: !3, line: 295, column: 7)
!750 = distinct !DILexicalBlock(scope: !751, file: !3, line: 294, column: 34)
!751 = distinct !DILexicalBlock(scope: !723, file: !3, line: 294, column: 11)
!752 = !DILocation(line: 231, column: 8, scope: !753, inlinedAt: !748)
!753 = distinct !DILexicalBlock(scope: !738, file: !231, line: 231, column: 6)
!754 = !DILocation(line: 231, column: 14, scope: !753, inlinedAt: !748)
!755 = !DILocation(line: 231, column: 12, scope: !753, inlinedAt: !748)
!756 = !DILocation(line: 231, column: 6, scope: !738, inlinedAt: !748)
!757 = !DILocation(line: 237, column: 8, scope: !738, inlinedAt: !748)
!758 = !{!759, !664, i64 4}
!759 = !{!"udphdr", !664, i64 0, !664, i64 2, !664, i64 4, !664, i64 6}
!760 = !DILocation(line: 238, column: 10, scope: !761, inlinedAt: !748)
!761 = distinct !DILexicalBlock(scope: !738, file: !231, line: 238, column: 6)
!762 = !DILocation(line: 238, column: 6, scope: !738, inlinedAt: !748)
!763 = !DILocation(line: 0, scope: !723)
!764 = !DILocation(line: 305, column: 16, scope: !694)
!765 = !{!612, !612, i64 0}
!766 = !DILocation(line: 305, column: 14, scope: !694)
!767 = !DILocation(line: 306, column: 16, scope: !694)
!768 = !DILocation(line: 306, column: 14, scope: !694)
!769 = !DILocation(line: 307, column: 19, scope: !694)
!770 = !DILocalVariable(name: "ctx", scope: !771, file: !3, line: 246, type: !97)
!771 = distinct !DISubprogram(name: "match_rules_ipv4", scope: !3, file: !3, line: 244, type: !772, scopeLine: 245, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !774)
!772 = !DISubroutineType(types: !773)
!773 = !{!596, !102}
!774 = !{!775, !770, !776}
!775 = !DILocalVariable(name: "conn", arg: 1, scope: !771, file: !3, line: 244, type: !102)
!776 = !DILocalVariable(name: "i", scope: !777, file: !3, line: 249, type: !189)
!777 = distinct !DILexicalBlock(scope: !771, file: !3, line: 249, column: 2)
!778 = !DILocation(line: 246, column: 30, scope: !771, inlinedAt: !779)
!779 = distinct !DILocation(line: 314, column: 12, scope: !694)
!780 = !DILocation(line: 0, scope: !771, inlinedAt: !779)
!781 = !DILocation(line: 0, scope: !777, inlinedAt: !779)
!782 = !DILocation(line: 249, column: 2, scope: !777, inlinedAt: !779)
!783 = !DILocation(line: 0, scope: !528, inlinedAt: !784)
!784 = distinct !DILocation(line: 250, column: 6, scope: !785, inlinedAt: !779)
!785 = distinct !DILexicalBlock(scope: !786, file: !3, line: 250, column: 6)
!786 = distinct !DILexicalBlock(scope: !787, file: !3, line: 249, column: 32)
!787 = distinct !DILexicalBlock(scope: !777, file: !3, line: 249, column: 2)
!788 = !{!611, !611, i64 0}
!789 = !DILocation(line: 197, column: 2, scope: !528, inlinedAt: !784)
!790 = !DILocation(line: 197, column: 6, scope: !528, inlinedAt: !784)
!791 = !DILocation(line: 201, column: 14, scope: !792, inlinedAt: !784)
!792 = distinct !DILexicalBlock(scope: !528, file: !3, line: 201, column: 5)
!793 = !DILocation(line: 201, column: 11, scope: !792, inlinedAt: !784)
!794 = !DILocation(line: 201, column: 5, scope: !528, inlinedAt: !784)
!795 = !DILocation(line: 241, column: 1, scope: !528, inlinedAt: !784)
!796 = !DILocation(line: 250, column: 6, scope: !786, inlinedAt: !779)
!797 = !DILocation(line: 204, column: 27, scope: !528, inlinedAt: !784)
!798 = !DILocation(line: 205, column: 6, scope: !799, inlinedAt: !784)
!799 = distinct !DILexicalBlock(scope: !528, file: !3, line: 205, column: 5)
!800 = !DILocation(line: 205, column: 5, scope: !528, inlinedAt: !784)
!801 = !DILocation(line: 319, column: 1, scope: !592)
!802 = !DILocation(line: 0, scope: !803, inlinedAt: !813)
!803 = distinct !DISubprogram(name: "xdp_stats_record_action", scope: !3, file: !3, line: 78, type: !804, scopeLine: 79, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !806)
!804 = !DISubroutineType(types: !805)
!805 = !{!68, !215, !68}
!806 = !{!807, !808, !809, !810, !811, !812}
!807 = !DILocalVariable(name: "ctx", arg: 1, scope: !803, file: !3, line: 78, type: !215)
!808 = !DILocalVariable(name: "action", arg: 2, scope: !803, file: !3, line: 78, type: !68)
!809 = !DILocalVariable(name: "data_end", scope: !803, file: !3, line: 80, type: !63)
!810 = !DILocalVariable(name: "data", scope: !803, file: !3, line: 81, type: !63)
!811 = !DILocalVariable(name: "rec", scope: !803, file: !3, line: 87, type: !458)
!812 = !DILocalVariable(name: "bytes", scope: !803, file: !3, line: 92, type: !140)
!813 = distinct !DILocation(line: 320, column: 9, scope: !592)
!814 = !DILocation(line: 83, column: 6, scope: !803, inlinedAt: !813)
!815 = !DILocation(line: 209, column: 26, scope: !528, inlinedAt: !784)
!816 = !{!817, !664, i64 20}
!817 = !{!"rules_ipv4", !611, i64 0, !611, i64 4, !612, i64 8, !612, i64 9, !664, i64 10, !664, i64 12, !664, i64 14, !664, i64 16, !664, i64 18, !664, i64 20}
!818 = !DILocation(line: 211, column: 5, scope: !819, inlinedAt: !784)
!819 = distinct !DILexicalBlock(scope: !528, file: !3, line: 211, column: 5)
!820 = !DILocation(line: 211, column: 11, scope: !819, inlinedAt: !784)
!821 = !DILocation(line: 211, column: 5, scope: !528, inlinedAt: !784)
!822 = !DILocation(line: 213, column: 2, scope: !823, inlinedAt: !784)
!823 = distinct !DILexicalBlock(scope: !528, file: !3, line: 213, column: 2)
!824 = !DILocation(line: 214, column: 47, scope: !541, inlinedAt: !784)
!825 = !{!817, !611, i64 0}
!826 = !DILocation(line: 214, column: 59, scope: !541, inlinedAt: !784)
!827 = !{!817, !612, i64 8}
!828 = !DILocalVariable(name: "ip_addr", arg: 1, scope: !829, file: !3, line: 177, type: !68)
!829 = distinct !DISubprogram(name: "ipv4_cidr_match", scope: !3, file: !3, line: 177, type: !830, scopeLine: 177, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !832)
!830 = !DISubroutineType(types: !831)
!831 = !{!189, !68, !68, !78}
!832 = !{!828, !833, !834, !835, !836, !837}
!833 = !DILocalVariable(name: "network_addr", arg: 2, scope: !829, file: !3, line: 177, type: !68)
!834 = !DILocalVariable(name: "cidr", arg: 3, scope: !829, file: !3, line: 177, type: !78)
!835 = !DILocalVariable(name: "subnet_mask", scope: !829, file: !3, line: 181, type: !68)
!836 = !DILocalVariable(name: "masked_ip", scope: !829, file: !3, line: 183, type: !68)
!837 = !DILocalVariable(name: "masked_network", scope: !829, file: !3, line: 184, type: !68)
!838 = !DILocation(line: 0, scope: !829, inlinedAt: !839)
!839 = distinct !DILocation(line: 214, column: 6, scope: !541, inlinedAt: !784)
!840 = !DILocation(line: 178, column: 18, scope: !841, inlinedAt: !839)
!841 = distinct !DILexicalBlock(scope: !829, file: !3, line: 178, column: 5)
!842 = !DILocation(line: 178, column: 23, scope: !841, inlinedAt: !839)
!843 = !DILocation(line: 181, column: 45, scope: !829, inlinedAt: !839)
!844 = !DILocation(line: 181, column: 38, scope: !829, inlinedAt: !839)
!845 = !DILocation(line: 185, column: 22, scope: !829, inlinedAt: !839)
!846 = !DILocation(line: 214, column: 71, scope: !541, inlinedAt: !784)
!847 = !DILocation(line: 215, column: 44, scope: !541, inlinedAt: !784)
!848 = !{!817, !611, i64 4}
!849 = !DILocation(line: 215, column: 56, scope: !541, inlinedAt: !784)
!850 = !{!817, !612, i64 9}
!851 = !DILocation(line: 0, scope: !829, inlinedAt: !852)
!852 = distinct !DILocation(line: 215, column: 3, scope: !541, inlinedAt: !784)
!853 = !DILocation(line: 178, column: 18, scope: !841, inlinedAt: !852)
!854 = !DILocation(line: 178, column: 23, scope: !841, inlinedAt: !852)
!855 = !DILocation(line: 181, column: 45, scope: !829, inlinedAt: !852)
!856 = !DILocation(line: 181, column: 38, scope: !829, inlinedAt: !852)
!857 = !DILocation(line: 185, column: 22, scope: !829, inlinedAt: !852)
!858 = !DILocation(line: 215, column: 68, scope: !541, inlinedAt: !784)
!859 = !DILocation(line: 216, column: 39, scope: !541, inlinedAt: !784)
!860 = !{!817, !664, i64 10}
!861 = !DILocalVariable(name: "conn_port", arg: 1, scope: !862, file: !3, line: 189, type: !65)
!862 = distinct !DISubprogram(name: "port_match", scope: !3, file: !3, line: 189, type: !863, scopeLine: 189, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !865)
!863 = !DISubroutineType(types: !864)
!864 = !{!189, !65, !65}
!865 = !{!861, !866}
!866 = !DILocalVariable(name: "rule_port", arg: 2, scope: !862, file: !3, line: 189, type: !65)
!867 = !DILocation(line: 0, scope: !862, inlinedAt: !868)
!868 = distinct !DILocation(line: 216, column: 3, scope: !541, inlinedAt: !784)
!869 = !DILocation(line: 190, column: 8, scope: !870, inlinedAt: !868)
!870 = distinct !DILexicalBlock(scope: !862, file: !3, line: 190, column: 6)
!871 = !DILocation(line: 216, column: 3, scope: !541, inlinedAt: !784)
!872 = !DILocation(line: 216, column: 46, scope: !541, inlinedAt: !784)
!873 = !DILocation(line: 217, column: 39, scope: !541, inlinedAt: !784)
!874 = !{!817, !664, i64 12}
!875 = !DILocation(line: 0, scope: !862, inlinedAt: !876)
!876 = distinct !DILocation(line: 217, column: 3, scope: !541, inlinedAt: !784)
!877 = !DILocation(line: 190, column: 8, scope: !870, inlinedAt: !876)
!878 = !DILocation(line: 217, column: 3, scope: !541, inlinedAt: !784)
!879 = !DILocation(line: 217, column: 46, scope: !541, inlinedAt: !784)
!880 = !DILocation(line: 218, column: 42, scope: !541, inlinedAt: !784)
!881 = !{!817, !664, i64 14}
!882 = !DILocation(line: 0, scope: !862, inlinedAt: !883)
!883 = distinct !DILocation(line: 218, column: 3, scope: !541, inlinedAt: !784)
!884 = !DILocation(line: 190, column: 8, scope: !870, inlinedAt: !883)
!885 = !DILocation(line: 218, column: 3, scope: !541, inlinedAt: !784)
!886 = !DILocation(line: 214, column: 6, scope: !528, inlinedAt: !784)
!887 = !DILocation(line: 220, column: 24, scope: !540, inlinedAt: !784)
!888 = !{!817, !664, i64 16}
!889 = !DILocation(line: 221, column: 27, scope: !540, inlinedAt: !784)
!890 = !DILocation(line: 0, scope: !540, inlinedAt: !784)
!891 = !DILocation(line: 222, column: 7, scope: !892, inlinedAt: !784)
!892 = distinct !DILexicalBlock(scope: !540, file: !3, line: 222, column: 6)
!893 = !DILocation(line: 222, column: 6, scope: !540, inlinedAt: !784)
!894 = !DILocation(line: 254, column: 9, scope: !771, inlinedAt: !779)
!895 = !DILocation(line: 227, column: 4, scope: !543, inlinedAt: !784)
!896 = !{!897, !897, i64 0}
!897 = !{!"long long", !612, i64 0}
!898 = !DILocation(line: 227, column: 4, scope: !544, inlinedAt: !784)
!899 = !DILocation(line: 228, column: 4, scope: !548, inlinedAt: !784)
!900 = !DILocation(line: 228, column: 4, scope: !544, inlinedAt: !784)
!901 = !DILocation(line: 229, column: 4, scope: !902, inlinedAt: !784)
!902 = distinct !DILexicalBlock(scope: !544, file: !3, line: 229, column: 4)
!903 = !DILocation(line: 230, column: 4, scope: !904, inlinedAt: !784)
!904 = distinct !DILexicalBlock(scope: !544, file: !3, line: 230, column: 4)
!905 = !DILocation(line: 233, column: 3, scope: !540, inlinedAt: !784)
!906 = !DILocation(line: 237, column: 10, scope: !907, inlinedAt: !784)
!907 = distinct !DILexicalBlock(scope: !528, file: !3, line: 237, column: 5)
!908 = !DILocation(line: 236, column: 1, scope: !528, inlinedAt: !784)
!909 = !DILocation(line: 237, column: 20, scope: !907, inlinedAt: !784)
!910 = !DILocation(line: 249, column: 29, scope: !787, inlinedAt: !779)
!911 = !DILocation(line: 249, column: 16, scope: !787, inlinedAt: !779)
!912 = distinct !{!912, !782, !913, !914}
!913 = !DILocation(line: 252, column: 2, scope: !777, inlinedAt: !779)
!914 = !{!"llvm.loop.mustprogress"}
!915 = !DILocation(line: 83, column: 13, scope: !916, inlinedAt: !813)
!916 = distinct !DILexicalBlock(scope: !803, file: !3, line: 83, column: 6)
!917 = !DILocation(line: 80, column: 38, scope: !803, inlinedAt: !813)
!918 = !DILocation(line: 81, column: 38, scope: !803, inlinedAt: !813)
!919 = !DILocation(line: 87, column: 24, scope: !803, inlinedAt: !813)
!920 = !DILocation(line: 88, column: 7, scope: !921, inlinedAt: !813)
!921 = distinct !DILexicalBlock(scope: !803, file: !3, line: 88, column: 6)
!922 = !DILocation(line: 88, column: 6, scope: !803, inlinedAt: !813)
!923 = !DILocation(line: 80, column: 27, scope: !803, inlinedAt: !813)
!924 = !DILocation(line: 81, column: 27, scope: !803, inlinedAt: !813)
!925 = !DILocation(line: 92, column: 25, scope: !803, inlinedAt: !813)
!926 = !DILocation(line: 98, column: 7, scope: !803, inlinedAt: !813)
!927 = !DILocation(line: 98, column: 17, scope: !803, inlinedAt: !813)
!928 = !{!929, !897, i64 0}
!929 = !{!"datarec", !897, i64 0, !897, i64 8}
!930 = !DILocation(line: 99, column: 7, scope: !803, inlinedAt: !813)
!931 = !DILocation(line: 99, column: 16, scope: !803, inlinedAt: !813)
!932 = !{!929, !897, i64 8}
!933 = !DILocation(line: 101, column: 9, scope: !803, inlinedAt: !813)
!934 = !DILocation(line: 102, column: 1, scope: !803, inlinedAt: !813)
!935 = !DILocation(line: 320, column: 2, scope: !592)
!936 = distinct !DISubprogram(name: "xdp_entry_router", scope: !3, file: !3, line: 328, type: !213, scopeLine: 329, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !937)
!937 = !{!938, !939, !940, !941, !942, !943, !944, !945, !946, !973, !974, !975, !976, !977, !981, !982}
!938 = !DILocalVariable(name: "ctx", arg: 1, scope: !936, file: !3, line: 328, type: !215)
!939 = !DILocalVariable(name: "action", scope: !936, file: !3, line: 330, type: !596)
!940 = !DILocalVariable(name: "data_end", scope: !936, file: !3, line: 331, type: !63)
!941 = !DILocalVariable(name: "data", scope: !936, file: !3, line: 332, type: !63)
!942 = !DILocalVariable(name: "ifib", scope: !936, file: !3, line: 333, type: !149)
!943 = !DILocalVariable(name: "nh", scope: !936, file: !3, line: 334, type: !230)
!944 = !DILocalVariable(name: "nh_type", scope: !936, file: !3, line: 335, type: !189)
!945 = !DILocalVariable(name: "eth", scope: !936, file: !3, line: 336, type: !236)
!946 = !DILocalVariable(name: "ip6h", scope: !936, file: !3, line: 337, type: !947)
!947 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !948, size: 64)
!948 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ipv6hdr", file: !949, line: 118, size: 320, elements: !950)
!949 = !DIFile(filename: "/usr/include/linux/ipv6.h", directory: "", checksumkind: CSK_MD5, checksum: "9926d49458ea1e0cc4651362e733e03e")
!950 = !{!951, !952, !953, !957, !958, !959, !960}
!951 = !DIDerivedType(tag: DW_TAG_member, name: "priority", scope: !948, file: !949, line: 120, baseType: !78, size: 4, flags: DIFlagBitField, extraData: i64 0)
!952 = !DIDerivedType(tag: DW_TAG_member, name: "version", scope: !948, file: !949, line: 121, baseType: !78, size: 4, offset: 4, flags: DIFlagBitField, extraData: i64 0)
!953 = !DIDerivedType(tag: DW_TAG_member, name: "flow_lbl", scope: !948, file: !949, line: 128, baseType: !954, size: 24, offset: 8)
!954 = !DICompositeType(tag: DW_TAG_array_type, baseType: !78, size: 24, elements: !955)
!955 = !{!956}
!956 = !DISubrange(count: 3)
!957 = !DIDerivedType(tag: DW_TAG_member, name: "payload_len", scope: !948, file: !949, line: 130, baseType: !84, size: 16, offset: 32)
!958 = !DIDerivedType(tag: DW_TAG_member, name: "nexthdr", scope: !948, file: !949, line: 131, baseType: !78, size: 8, offset: 48)
!959 = !DIDerivedType(tag: DW_TAG_member, name: "hop_limit", scope: !948, file: !949, line: 132, baseType: !78, size: 8, offset: 56)
!960 = !DIDerivedType(tag: DW_TAG_member, scope: !948, file: !949, line: 134, baseType: !961, size: 256, offset: 64)
!961 = distinct !DICompositeType(tag: DW_TAG_union_type, scope: !948, file: !949, line: 134, size: 256, elements: !962)
!962 = !{!963, !968}
!963 = !DIDerivedType(tag: DW_TAG_member, scope: !961, file: !949, line: 134, baseType: !964, size: 256)
!964 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !961, file: !949, line: 134, size: 256, elements: !965)
!965 = !{!966, !967}
!966 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !964, file: !949, line: 134, baseType: !70, size: 128)
!967 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !964, file: !949, line: 134, baseType: !70, size: 128, offset: 128)
!968 = !DIDerivedType(tag: DW_TAG_member, name: "addrs", scope: !961, file: !949, line: 134, baseType: !969, size: 256)
!969 = distinct !DICompositeType(tag: DW_TAG_structure_type, scope: !961, file: !949, line: 134, size: 256, elements: !970)
!970 = !{!971, !972}
!971 = !DIDerivedType(tag: DW_TAG_member, name: "saddr", scope: !969, file: !949, line: 134, baseType: !70, size: 128)
!972 = !DIDerivedType(tag: DW_TAG_member, name: "daddr", scope: !969, file: !949, line: 134, baseType: !70, size: 128, offset: 128)
!973 = !DILocalVariable(name: "iph", scope: !936, file: !3, line: 338, type: !244)
!974 = !DILocalVariable(name: "ip4_saddr", scope: !936, file: !3, line: 339, type: !7)
!975 = !DILocalVariable(name: "rc", scope: !936, file: !3, line: 341, type: !189)
!976 = !DILocalVariable(name: "nitem", scope: !936, file: !3, line: 342, type: !112)
!977 = !DILocalVariable(name: "src", scope: !978, file: !3, line: 422, type: !69)
!978 = distinct !DILexicalBlock(scope: !979, file: !3, line: 419, column: 47)
!979 = distinct !DILexicalBlock(scope: !980, file: !3, line: 419, column: 13)
!980 = distinct !DILexicalBlock(scope: !936, file: !3, line: 352, column: 6)
!981 = !DILocalVariable(name: "dst", scope: !978, file: !3, line: 423, type: !69)
!982 = !DILabel(scope: !936, name: "out", file: !3, line: 472)
!983 = !DILocation(line: 0, scope: !936)
!984 = !DILocation(line: 331, column: 38, scope: !936)
!985 = !DILocation(line: 331, column: 27, scope: !936)
!986 = !DILocation(line: 331, column: 19, scope: !936)
!987 = !DILocation(line: 332, column: 34, scope: !936)
!988 = !DILocation(line: 332, column: 23, scope: !936)
!989 = !DILocation(line: 332, column: 15, scope: !936)
!990 = !DILocation(line: 333, column: 2, scope: !936)
!991 = !DILocation(line: 333, column: 24, scope: !936)
!992 = !DILocation(line: 342, column: 2, scope: !936)
!993 = !DILocation(line: 342, column: 17, scope: !936)
!994 = !DILocation(line: 0, scope: !621, inlinedAt: !995)
!995 = distinct !DILocation(line: 347, column: 12, scope: !936)
!996 = !DILocation(line: 0, scope: !632, inlinedAt: !997)
!997 = distinct !DILocation(line: 129, column: 9, scope: !621, inlinedAt: !995)
!998 = !DILocation(line: 93, column: 14, scope: !659, inlinedAt: !997)
!999 = !DILocation(line: 93, column: 24, scope: !659, inlinedAt: !997)
!1000 = !DILocation(line: 93, column: 6, scope: !632, inlinedAt: !997)
!1001 = !DILocation(line: 97, column: 10, scope: !632, inlinedAt: !997)
!1002 = !DILocation(line: 99, column: 17, scope: !632, inlinedAt: !997)
!1003 = !DILocation(line: 0, scope: !666, inlinedAt: !1004)
!1004 = distinct !DILocation(line: 106, column: 8, scope: !672, inlinedAt: !997)
!1005 = !DILocation(line: 70, column: 20, scope: !666, inlinedAt: !1004)
!1006 = !DILocation(line: 70, column: 46, scope: !666, inlinedAt: !1004)
!1007 = !DILocation(line: 106, column: 8, scope: !672, inlinedAt: !997)
!1008 = !DILocation(line: 106, column: 7, scope: !673, inlinedAt: !997)
!1009 = !DILocation(line: 112, column: 18, scope: !673, inlinedAt: !997)
!1010 = !DILocation(line: 352, column: 6, scope: !936)
!1011 = !DILocation(line: 0, scope: !683, inlinedAt: !1012)
!1012 = distinct !DILocation(line: 353, column: 13, scope: !1013)
!1013 = distinct !DILexicalBlock(scope: !980, file: !3, line: 352, column: 38)
!1014 = !DILocation(line: 158, column: 10, scope: !1015, inlinedAt: !1012)
!1015 = distinct !DILexicalBlock(scope: !683, file: !231, line: 158, column: 6)
!1016 = !DILocation(line: 158, column: 14, scope: !1015, inlinedAt: !1012)
!1017 = !DILocation(line: 158, column: 6, scope: !683, inlinedAt: !1012)
!1018 = !DILocation(line: 161, column: 17, scope: !683, inlinedAt: !1012)
!1019 = !DILocation(line: 161, column: 21, scope: !683, inlinedAt: !1012)
!1020 = !DILocation(line: 163, column: 13, scope: !699, inlinedAt: !1012)
!1021 = !DILocation(line: 163, column: 5, scope: !683, inlinedAt: !1012)
!1022 = !DILocation(line: 167, column: 14, scope: !702, inlinedAt: !1012)
!1023 = !DILocation(line: 167, column: 24, scope: !702, inlinedAt: !1012)
!1024 = !DILocation(line: 167, column: 6, scope: !683, inlinedAt: !1012)
!1025 = !DILocation(line: 359, column: 12, scope: !1026)
!1026 = distinct !DILexicalBlock(scope: !1013, file: !3, line: 359, column: 7)
!1027 = !{!707, !612, i64 8}
!1028 = !DILocation(line: 359, column: 16, scope: !1026)
!1029 = !DILocation(line: 359, column: 7, scope: !1013)
!1030 = !DILocation(line: 363, column: 20, scope: !1013)
!1031 = !DILocation(line: 365, column: 9, scope: !1013)
!1032 = !DILocation(line: 365, column: 15, scope: !1013)
!1033 = !{!1034, !611, i64 0}
!1034 = !{!"rt_item", !611, i64 0, !612, i64 4, !612, i64 10}
!1035 = !DILocalVariable(name: "conn", arg: 1, scope: !1036, file: !3, line: 159, type: !111)
!1036 = distinct !DISubprogram(name: "match_rules", scope: !3, file: !3, line: 159, type: !1037, scopeLine: 160, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1039)
!1037 = !DISubroutineType(types: !1038)
!1038 = !{!189, !111}
!1039 = !{!1035, !1040}
!1040 = !DILocalVariable(name: "ctx", scope: !1036, file: !3, line: 161, type: !111)
!1041 = !DILocation(line: 0, scope: !1036, inlinedAt: !1042)
!1042 = distinct !DILocation(line: 368, column: 3, scope: !1013)
!1043 = !DILocation(line: 163, column: 2, scope: !1036, inlinedAt: !1042)
!1044 = !DILocation(line: 372, column: 16, scope: !1045)
!1045 = distinct !DILexicalBlock(scope: !1013, file: !3, line: 372, column: 7)
!1046 = !DILocalVariable(name: "mac_addr", arg: 1, scope: !1047, file: !3, line: 116, type: !1050)
!1047 = distinct !DISubprogram(name: "mac_zero", scope: !3, file: !3, line: 116, type: !1048, scopeLine: 116, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1052)
!1048 = !DISubroutineType(types: !1049)
!1049 = !{!189, !1050}
!1050 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1051, size: 64)
!1051 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !78)
!1052 = !{!1046, !1053}
!1053 = !DILocalVariable(name: "i", scope: !1054, file: !3, line: 118, type: !189)
!1054 = distinct !DILexicalBlock(scope: !1047, file: !3, line: 118, column: 5)
!1055 = !DILocation(line: 0, scope: !1047, inlinedAt: !1056)
!1056 = distinct !DILocation(line: 372, column: 7, scope: !1045)
!1057 = !DILocation(line: 0, scope: !1054, inlinedAt: !1056)
!1058 = !DILocation(line: 119, column: 13, scope: !1059, inlinedAt: !1056)
!1059 = distinct !DILexicalBlock(scope: !1060, file: !3, line: 119, column: 13)
!1060 = distinct !DILexicalBlock(scope: !1061, file: !3, line: 118, column: 40)
!1061 = distinct !DILexicalBlock(scope: !1054, file: !3, line: 118, column: 5)
!1062 = !DILocation(line: 119, column: 25, scope: !1059, inlinedAt: !1056)
!1063 = !DILocation(line: 119, column: 13, scope: !1060, inlinedAt: !1056)
!1064 = !DILocalVariable(name: "iph", arg: 1, scope: !1065, file: !3, line: 107, type: !244)
!1065 = distinct !DISubprogram(name: "ip_decrease_ttl", scope: !3, file: !3, line: 107, type: !1066, scopeLine: 108, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1068)
!1066 = !DISubroutineType(types: !1067)
!1067 = !{!189, !244}
!1068 = !{!1064, !1069}
!1069 = !DILocalVariable(name: "check", scope: !1065, file: !3, line: 109, type: !68)
!1070 = !DILocation(line: 0, scope: !1065, inlinedAt: !1071)
!1071 = distinct !DILocation(line: 373, column: 4, scope: !1072)
!1072 = distinct !DILexicalBlock(scope: !1045, file: !3, line: 372, column: 33)
!1073 = !DILocation(line: 109, column: 21, scope: !1065, inlinedAt: !1071)
!1074 = !{!707, !664, i64 10}
!1075 = !DILocation(line: 110, column: 8, scope: !1065, inlinedAt: !1071)
!1076 = !DILocation(line: 111, column: 38, scope: !1065, inlinedAt: !1071)
!1077 = !DILocation(line: 111, column: 29, scope: !1065, inlinedAt: !1071)
!1078 = !DILocation(line: 111, column: 13, scope: !1065, inlinedAt: !1071)
!1079 = !DILocation(line: 112, column: 9, scope: !1065, inlinedAt: !1071)
!1080 = !DILocation(line: 374, column: 4, scope: !1072)
!1081 = !DILocation(line: 375, column: 4, scope: !1072)
!1082 = !DILocation(line: 376, column: 13, scope: !1072)
!1083 = !DILocation(line: 378, column: 4, scope: !1072)
!1084 = !DILocation(line: 382, column: 15, scope: !1013)
!1085 = !{!1086, !612, i64 0}
!1086 = !{!"bpf_fib_lookup", !612, i64 0, !612, i64 1, !664, i64 2, !664, i64 4, !612, i64 6, !611, i64 8, !612, i64 12, !612, i64 16, !612, i64 32, !612, i64 48, !612, i64 52, !612, i64 58}
!1087 = !DILocation(line: 383, column: 19, scope: !1013)
!1088 = !{!707, !612, i64 1}
!1089 = !DILocation(line: 383, column: 8, scope: !1013)
!1090 = !DILocation(line: 383, column: 12, scope: !1013)
!1091 = !DILocation(line: 384, column: 27, scope: !1013)
!1092 = !DILocation(line: 384, column: 8, scope: !1013)
!1093 = !DILocation(line: 384, column: 20, scope: !1013)
!1094 = !{!1086, !612, i64 1}
!1095 = !DILocation(line: 385, column: 8, scope: !1013)
!1096 = !DILocation(line: 385, column: 14, scope: !1013)
!1097 = !{!1086, !664, i64 2}
!1098 = !DILocation(line: 386, column: 8, scope: !1013)
!1099 = !DILocation(line: 386, column: 14, scope: !1013)
!1100 = !{!1086, !664, i64 4}
!1101 = !DILocation(line: 387, column: 18, scope: !1013)
!1102 = !{!707, !664, i64 2}
!1103 = !DILocation(line: 387, column: 8, scope: !1013)
!1104 = !DILocation(line: 387, column: 16, scope: !1013)
!1105 = !DILocation(line: 388, column: 24, scope: !1013)
!1106 = !DILocation(line: 388, column: 8, scope: !1013)
!1107 = !DILocation(line: 388, column: 17, scope: !1013)
!1108 = !DILocation(line: 389, column: 24, scope: !1013)
!1109 = !DILocation(line: 389, column: 8, scope: !1013)
!1110 = !DILocation(line: 389, column: 17, scope: !1013)
!1111 = !DILocation(line: 390, column: 23, scope: !1013)
!1112 = !{!610, !611, i64 12}
!1113 = !DILocation(line: 390, column: 8, scope: !1013)
!1114 = !DILocation(line: 390, column: 16, scope: !1013)
!1115 = !{!1086, !611, i64 8}
!1116 = !DILocation(line: 393, column: 23, scope: !1013)
!1117 = !DILocation(line: 393, column: 8, scope: !1013)
!1118 = !DILocation(line: 394, column: 3, scope: !1013)
!1119 = !DILocation(line: 0, scope: !1065, inlinedAt: !1120)
!1120 = distinct !DILocation(line: 396, column: 4, scope: !1121)
!1121 = distinct !DILexicalBlock(scope: !1013, file: !3, line: 394, column: 15)
!1122 = !DILocation(line: 109, column: 21, scope: !1065, inlinedAt: !1120)
!1123 = !DILocation(line: 110, column: 8, scope: !1065, inlinedAt: !1120)
!1124 = !DILocation(line: 111, column: 38, scope: !1065, inlinedAt: !1120)
!1125 = !DILocation(line: 111, column: 29, scope: !1065, inlinedAt: !1120)
!1126 = !DILocation(line: 111, column: 13, scope: !1065, inlinedAt: !1120)
!1127 = !DILocation(line: 112, column: 9, scope: !1065, inlinedAt: !1120)
!1128 = !DILocation(line: 398, column: 4, scope: !1121)
!1129 = !DILocation(line: 399, column: 4, scope: !1121)
!1130 = !DILocation(line: 400, column: 31, scope: !1121)
!1131 = !DILocation(line: 400, column: 13, scope: !1121)
!1132 = !DILocation(line: 401, column: 4, scope: !1121)
!1133 = !DILocation(line: 407, column: 4, scope: !1121)
!1134 = !DILocalVariable(name: "nh", arg: 1, scope: !1135, file: !231, line: 132, type: !624)
!1135 = distinct !DISubprogram(name: "parse_ip6hdr", scope: !231, file: !231, line: 132, type: !1136, scopeLine: 135, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1139)
!1136 = !DISubroutineType(types: !1137)
!1137 = !{!189, !624, !63, !1138}
!1138 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !947, size: 64)
!1139 = !{!1134, !1140, !1141, !1142}
!1140 = !DILocalVariable(name: "data_end", arg: 2, scope: !1135, file: !231, line: 133, type: !63)
!1141 = !DILocalVariable(name: "ip6hdr", arg: 3, scope: !1135, file: !231, line: 134, type: !1138)
!1142 = !DILocalVariable(name: "ip6h", scope: !1135, file: !231, line: 136, type: !947)
!1143 = !DILocation(line: 0, scope: !1135, inlinedAt: !1144)
!1144 = distinct !DILocation(line: 420, column: 13, scope: !978)
!1145 = !DILocation(line: 142, column: 11, scope: !1146, inlinedAt: !1144)
!1146 = distinct !DILexicalBlock(scope: !1135, file: !231, line: 142, column: 6)
!1147 = !DILocation(line: 142, column: 17, scope: !1146, inlinedAt: !1144)
!1148 = !DILocation(line: 142, column: 15, scope: !1146, inlinedAt: !1144)
!1149 = !DILocation(line: 142, column: 6, scope: !1135, inlinedAt: !1144)
!1150 = !DILocation(line: 0, scope: !978)
!1151 = !DILocation(line: 428, column: 13, scope: !1152)
!1152 = distinct !DILexicalBlock(scope: !978, file: !3, line: 428, column: 7)
!1153 = !{!1154, !612, i64 7}
!1154 = !{!"ipv6hdr", !612, i64 0, !612, i64 0, !612, i64 1, !664, i64 4, !612, i64 6, !612, i64 7, !612, i64 8}
!1155 = !DILocation(line: 428, column: 23, scope: !1152)
!1156 = !DILocation(line: 428, column: 7, scope: !978)
!1157 = !DILocation(line: 423, column: 46, scope: !978)
!1158 = !DILocation(line: 422, column: 46, scope: !978)
!1159 = !DILocation(line: 431, column: 15, scope: !978)
!1160 = !DILocation(line: 432, column: 31, scope: !978)
!1161 = !DILocation(line: 432, column: 19, scope: !978)
!1162 = !DILocation(line: 432, column: 36, scope: !978)
!1163 = !DILocation(line: 432, column: 8, scope: !978)
!1164 = !DILocation(line: 432, column: 17, scope: !978)
!1165 = !DILocation(line: 433, column: 28, scope: !978)
!1166 = !{!1154, !612, i64 6}
!1167 = !DILocation(line: 433, column: 8, scope: !978)
!1168 = !DILocation(line: 433, column: 20, scope: !978)
!1169 = !DILocation(line: 434, column: 8, scope: !978)
!1170 = !DILocation(line: 434, column: 14, scope: !978)
!1171 = !DILocation(line: 435, column: 8, scope: !978)
!1172 = !DILocation(line: 435, column: 14, scope: !978)
!1173 = !DILocation(line: 436, column: 18, scope: !978)
!1174 = !{!1154, !664, i64 4}
!1175 = !DILocation(line: 436, column: 8, scope: !978)
!1176 = !DILocation(line: 436, column: 16, scope: !978)
!1177 = !DILocation(line: 437, column: 16, scope: !978)
!1178 = !{i64 0, i64 16, !765, i64 0, i64 16, !765, i64 0, i64 16, !765}
!1179 = !DILocation(line: 438, column: 16, scope: !978)
!1180 = !DILocation(line: 439, column: 23, scope: !978)
!1181 = !DILocation(line: 439, column: 8, scope: !978)
!1182 = !DILocation(line: 439, column: 16, scope: !978)
!1183 = !DILocation(line: 441, column: 23, scope: !978)
!1184 = !DILocation(line: 441, column: 8, scope: !978)
!1185 = !DILocation(line: 442, column: 3, scope: !978)
!1186 = !DILocation(line: 444, column: 19, scope: !1187)
!1187 = distinct !DILexicalBlock(scope: !978, file: !3, line: 442, column: 15)
!1188 = !DILocation(line: 446, column: 4, scope: !1187)
!1189 = !DILocation(line: 447, column: 4, scope: !1187)
!1190 = !DILocation(line: 448, column: 31, scope: !1187)
!1191 = !DILocation(line: 448, column: 13, scope: !1187)
!1192 = !DILocation(line: 449, column: 4, scope: !1187)
!1193 = !DILocation(line: 455, column: 4, scope: !1187)
!1194 = !DILocation(line: 472, column: 1, scope: !936)
!1195 = !DILocation(line: 0, scope: !803, inlinedAt: !1196)
!1196 = distinct !DILocation(line: 473, column: 9, scope: !936)
!1197 = !DILocation(line: 83, column: 6, scope: !803, inlinedAt: !1196)
!1198 = !DILocation(line: 83, column: 13, scope: !916, inlinedAt: !1196)
!1199 = !DILocation(line: 80, column: 38, scope: !803, inlinedAt: !1196)
!1200 = !DILocation(line: 81, column: 38, scope: !803, inlinedAt: !1196)
!1201 = !DILocation(line: 87, column: 24, scope: !803, inlinedAt: !1196)
!1202 = !DILocation(line: 88, column: 7, scope: !921, inlinedAt: !1196)
!1203 = !DILocation(line: 88, column: 6, scope: !803, inlinedAt: !1196)
!1204 = !DILocation(line: 80, column: 27, scope: !803, inlinedAt: !1196)
!1205 = !DILocation(line: 81, column: 27, scope: !803, inlinedAt: !1196)
!1206 = !DILocation(line: 92, column: 25, scope: !803, inlinedAt: !1196)
!1207 = !DILocation(line: 98, column: 7, scope: !803, inlinedAt: !1196)
!1208 = !DILocation(line: 98, column: 17, scope: !803, inlinedAt: !1196)
!1209 = !DILocation(line: 99, column: 7, scope: !803, inlinedAt: !1196)
!1210 = !DILocation(line: 99, column: 16, scope: !803, inlinedAt: !1196)
!1211 = !DILocation(line: 101, column: 9, scope: !803, inlinedAt: !1196)
!1212 = !DILocation(line: 102, column: 1, scope: !803, inlinedAt: !1196)
!1213 = !DILocation(line: 474, column: 1, scope: !936)
!1214 = distinct !DISubprogram(name: "xdp_entry_mac", scope: !3, file: !3, line: 565, type: !213, scopeLine: 566, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1215)
!1215 = !{!1216, !1217, !1218, !1219, !1220, !1221, !1222, !1223, !1224, !1226}
!1216 = !DILocalVariable(name: "ctx", arg: 1, scope: !1214, file: !3, line: 565, type: !215)
!1217 = !DILocalVariable(name: "action", scope: !1214, file: !3, line: 567, type: !596)
!1218 = !DILocalVariable(name: "data_end", scope: !1214, file: !3, line: 568, type: !63)
!1219 = !DILocalVariable(name: "data", scope: !1214, file: !3, line: 569, type: !63)
!1220 = !DILocalVariable(name: "nh", scope: !1214, file: !3, line: 570, type: !230)
!1221 = !DILocalVariable(name: "nh_type", scope: !1214, file: !3, line: 571, type: !189)
!1222 = !DILocalVariable(name: "eth", scope: !1214, file: !3, line: 572, type: !236)
!1223 = !DILocalVariable(name: "conn", scope: !1214, file: !3, line: 573, type: !127)
!1224 = !DILocalVariable(name: "i", scope: !1225, file: !3, line: 592, type: !189)
!1225 = distinct !DILexicalBlock(scope: !1214, file: !3, line: 592, column: 2)
!1226 = !DILabel(scope: !1214, name: "out", file: !3, line: 598)
!1227 = !DILocation(line: 0, scope: !1214)
!1228 = !DILocation(line: 568, column: 38, scope: !1214)
!1229 = !DILocation(line: 568, column: 27, scope: !1214)
!1230 = !DILocation(line: 568, column: 19, scope: !1214)
!1231 = !DILocation(line: 569, column: 34, scope: !1214)
!1232 = !DILocation(line: 569, column: 23, scope: !1214)
!1233 = !DILocation(line: 569, column: 15, scope: !1214)
!1234 = !DILocation(line: 0, scope: !621, inlinedAt: !1235)
!1235 = distinct !DILocation(line: 579, column: 12, scope: !1214)
!1236 = !DILocation(line: 0, scope: !632, inlinedAt: !1237)
!1237 = distinct !DILocation(line: 129, column: 9, scope: !621, inlinedAt: !1235)
!1238 = !DILocation(line: 93, column: 14, scope: !659, inlinedAt: !1237)
!1239 = !DILocation(line: 93, column: 24, scope: !659, inlinedAt: !1237)
!1240 = !DILocation(line: 93, column: 6, scope: !632, inlinedAt: !1237)
!1241 = !DILocation(line: 97, column: 10, scope: !632, inlinedAt: !1237)
!1242 = !DILocation(line: 0, scope: !1225)
!1243 = !DILocation(line: 594, column: 22, scope: !1244)
!1244 = distinct !DILexicalBlock(scope: !1245, file: !3, line: 592, column: 37)
!1245 = distinct !DILexicalBlock(scope: !1225, file: !3, line: 592, column: 2)
!1246 = !DILocation(line: 593, column: 26, scope: !1244)
!1247 = !DILocalVariable(name: "ctx", scope: !1248, file: !3, line: 552, type: !121)
!1248 = distinct !DISubprogram(name: "match_rules_mac", scope: !3, file: !3, line: 550, type: !1249, scopeLine: 551, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1251)
!1249 = !DISubroutineType(types: !1250)
!1250 = !{!596, !126}
!1251 = !{!1252, !1247, !1253}
!1252 = !DILocalVariable(name: "conn", arg: 1, scope: !1248, file: !3, line: 550, type: !126)
!1253 = !DILocalVariable(name: "i", scope: !1254, file: !3, line: 555, type: !189)
!1254 = distinct !DILexicalBlock(scope: !1248, file: !3, line: 555, column: 2)
!1255 = !DILocation(line: 552, column: 34, scope: !1248, inlinedAt: !1256)
!1256 = distinct !DILocation(line: 596, column: 11, scope: !1214)
!1257 = !DILocation(line: 0, scope: !1248, inlinedAt: !1256)
!1258 = !DILocation(line: 0, scope: !1254, inlinedAt: !1256)
!1259 = !DILocation(line: 555, column: 2, scope: !1254, inlinedAt: !1256)
!1260 = !DILocation(line: 0, scope: !1261, inlinedAt: !1268)
!1261 = distinct !DISubprogram(name: "match_rules_mac_loop", scope: !3, file: !3, line: 519, type: !529, scopeLine: 520, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1262)
!1262 = !{!1263, !1264, !1265, !1266, !1267}
!1263 = !DILocalVariable(name: "index", arg: 1, scope: !1261, file: !3, line: 519, type: !68)
!1264 = !DILocalVariable(name: "ctx", arg: 2, scope: !1261, file: !3, line: 519, type: !63)
!1265 = !DILocalVariable(name: "p_ctx", scope: !1261, file: !3, line: 521, type: !120)
!1266 = !DILocalVariable(name: "p_r", scope: !1261, file: !3, line: 524, type: !500)
!1267 = !DILabel(scope: !1261, name: "out_match_rules_mac_loop", file: !3, line: 542)
!1268 = distinct !DILocation(line: 556, column: 6, scope: !1269, inlinedAt: !1256)
!1269 = distinct !DILexicalBlock(scope: !1270, file: !3, line: 556, column: 6)
!1270 = distinct !DILexicalBlock(scope: !1271, file: !3, line: 555, column: 32)
!1271 = distinct !DILexicalBlock(scope: !1254, file: !3, line: 555, column: 2)
!1272 = !DILocation(line: 522, column: 14, scope: !1273, inlinedAt: !1268)
!1273 = distinct !DILexicalBlock(scope: !1261, file: !3, line: 522, column: 5)
!1274 = !DILocation(line: 522, column: 11, scope: !1273, inlinedAt: !1268)
!1275 = !DILocation(line: 522, column: 5, scope: !1261, inlinedAt: !1268)
!1276 = !DILocation(line: 547, column: 1, scope: !1261, inlinedAt: !1268)
!1277 = !DILocation(line: 556, column: 6, scope: !1270, inlinedAt: !1256)
!1278 = !DILocation(line: 524, column: 26, scope: !1261, inlinedAt: !1268)
!1279 = !DILocation(line: 525, column: 6, scope: !1280, inlinedAt: !1268)
!1280 = distinct !DILexicalBlock(scope: !1261, file: !3, line: 525, column: 5)
!1281 = !DILocation(line: 525, column: 5, scope: !1261, inlinedAt: !1268)
!1282 = !DILocation(line: 598, column: 1, scope: !1214)
!1283 = !DILocation(line: 0, scope: !803, inlinedAt: !1284)
!1284 = distinct !DILocation(line: 599, column: 9, scope: !1214)
!1285 = !DILocation(line: 83, column: 6, scope: !803, inlinedAt: !1284)
!1286 = !DILocation(line: 528, column: 26, scope: !1261, inlinedAt: !1268)
!1287 = !{!1288, !664, i64 16}
!1288 = !{!"rules_mac", !612, i64 0, !612, i64 6, !664, i64 12, !664, i64 14, !664, i64 16}
!1289 = !DILocation(line: 530, column: 5, scope: !1290, inlinedAt: !1268)
!1290 = distinct !DILexicalBlock(scope: !1261, file: !3, line: 530, column: 5)
!1291 = !DILocation(line: 530, column: 11, scope: !1290, inlinedAt: !1268)
!1292 = !DILocation(line: 530, column: 5, scope: !1261, inlinedAt: !1268)
!1293 = !DILocalVariable(name: "conn_mac", arg: 1, scope: !1294, file: !3, line: 495, type: !110)
!1294 = distinct !DISubprogram(name: "mac_match", scope: !3, file: !3, line: 495, type: !1295, scopeLine: 495, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1297)
!1295 = !DISubroutineType(types: !1296)
!1296 = !{!189, !110, !110}
!1297 = !{!1293, !1298, !1299}
!1298 = !DILocalVariable(name: "rule_mac", arg: 2, scope: !1294, file: !3, line: 495, type: !110)
!1299 = !DILocalVariable(name: "zero_mac", scope: !1294, file: !3, line: 496, type: !116)
!1300 = !DILocation(line: 0, scope: !1294, inlinedAt: !1301)
!1301 = distinct !DILocation(line: 536, column: 5, scope: !1302, inlinedAt: !1268)
!1302 = distinct !DILexicalBlock(scope: !1261, file: !3, line: 536, column: 5)
!1303 = !DILocalVariable(name: "a", arg: 1, scope: !1304, file: !3, line: 482, type: !202)
!1304 = distinct !DISubprogram(name: "bpf_memcmp", scope: !3, file: !3, line: 482, type: !1305, scopeLine: 482, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1309)
!1305 = !DISubroutineType(types: !1306)
!1306 = !{!189, !202, !202, !1307}
!1307 = !DIDerivedType(tag: DW_TAG_typedef, name: "size_t", file: !1308, line: 46, baseType: !95)
!1308 = !DIFile(filename: "/usr/lib/llvm-14/lib/clang/14.0.0/include/stddef.h", directory: "", checksumkind: CSK_MD5, checksum: "2499dd2361b915724b073282bea3a7bc")
!1309 = !{!1303, !1310, !1311, !1312, !1315, !1316}
!1310 = !DILocalVariable(name: "b", arg: 2, scope: !1304, file: !3, line: 482, type: !202)
!1311 = !DILocalVariable(name: "len", arg: 3, scope: !1304, file: !3, line: 482, type: !1307)
!1312 = !DILocalVariable(name: "p1", scope: !1304, file: !3, line: 483, type: !1313)
!1313 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !1314, size: 64)
!1314 = !DIDerivedType(tag: DW_TAG_const_type, baseType: !79)
!1315 = !DILocalVariable(name: "p2", scope: !1304, file: !3, line: 484, type: !1313)
!1316 = !DILocalVariable(name: "i", scope: !1304, file: !3, line: 485, type: !1307)
!1317 = !DILocation(line: 0, scope: !1304, inlinedAt: !1318)
!1318 = distinct !DILocation(line: 499, column: 9, scope: !1319, inlinedAt: !1301)
!1319 = distinct !DILexicalBlock(scope: !1294, file: !3, line: 499, column: 9)
!1320 = !DILocation(line: 488, column: 13, scope: !1321, inlinedAt: !1318)
!1321 = distinct !DILexicalBlock(scope: !1322, file: !3, line: 488, column: 13)
!1322 = distinct !DILexicalBlock(scope: !1323, file: !3, line: 487, column: 31)
!1323 = distinct !DILexicalBlock(scope: !1324, file: !3, line: 487, column: 5)
!1324 = distinct !DILexicalBlock(scope: !1304, file: !3, line: 487, column: 5)
!1325 = !DILocation(line: 488, column: 19, scope: !1321, inlinedAt: !1318)
!1326 = !DILocation(line: 488, column: 13, scope: !1322, inlinedAt: !1318)
!1327 = !DILocation(line: 504, column: 21, scope: !1328, inlinedAt: !1301)
!1328 = distinct !DILexicalBlock(scope: !1294, file: !3, line: 504, column: 9)
!1329 = !DILocation(line: 0, scope: !1304, inlinedAt: !1330)
!1330 = distinct !DILocation(line: 504, column: 9, scope: !1328, inlinedAt: !1301)
!1331 = !DILocation(line: 488, column: 13, scope: !1321, inlinedAt: !1330)
!1332 = !DILocation(line: 488, column: 19, scope: !1321, inlinedAt: !1330)
!1333 = !DILocation(line: 488, column: 13, scope: !1322, inlinedAt: !1330)
!1334 = !DILocation(line: 0, scope: !1304, inlinedAt: !1335)
!1335 = distinct !DILocation(line: 505, column: 13, scope: !1336, inlinedAt: !1301)
!1336 = distinct !DILexicalBlock(scope: !1337, file: !3, line: 505, column: 13)
!1337 = distinct !DILexicalBlock(scope: !1328, file: !3, line: 504, column: 53)
!1338 = !DILocation(line: 488, column: 22, scope: !1321, inlinedAt: !1335)
!1339 = !DILocation(line: 488, column: 19, scope: !1321, inlinedAt: !1335)
!1340 = !DILocation(line: 488, column: 13, scope: !1322, inlinedAt: !1335)
!1341 = !DILocation(line: 0, scope: !1304, inlinedAt: !1342)
!1342 = distinct !DILocation(line: 511, column: 9, scope: !1343, inlinedAt: !1301)
!1343 = distinct !DILexicalBlock(scope: !1294, file: !3, line: 511, column: 9)
!1344 = !DILocation(line: 488, column: 19, scope: !1321, inlinedAt: !1342)
!1345 = !DILocation(line: 488, column: 13, scope: !1322, inlinedAt: !1342)
!1346 = !DILocation(line: 488, column: 13, scope: !1321, inlinedAt: !1342)
!1347 = !DILocation(line: 536, column: 82, scope: !1302, inlinedAt: !1268)
!1348 = !DILocation(line: 0, scope: !1294, inlinedAt: !1349)
!1349 = distinct !DILocation(line: 536, column: 46, scope: !1302, inlinedAt: !1268)
!1350 = !DILocation(line: 0, scope: !1304, inlinedAt: !1351)
!1351 = distinct !DILocation(line: 499, column: 9, scope: !1319, inlinedAt: !1349)
!1352 = !DILocation(line: 488, column: 13, scope: !1321, inlinedAt: !1351)
!1353 = !DILocation(line: 488, column: 19, scope: !1321, inlinedAt: !1351)
!1354 = !DILocation(line: 488, column: 13, scope: !1322, inlinedAt: !1351)
!1355 = !DILocation(line: 504, column: 21, scope: !1328, inlinedAt: !1349)
!1356 = !DILocation(line: 0, scope: !1304, inlinedAt: !1357)
!1357 = distinct !DILocation(line: 504, column: 9, scope: !1328, inlinedAt: !1349)
!1358 = !DILocation(line: 488, column: 13, scope: !1321, inlinedAt: !1357)
!1359 = !DILocation(line: 488, column: 19, scope: !1321, inlinedAt: !1357)
!1360 = !DILocation(line: 488, column: 13, scope: !1322, inlinedAt: !1357)
!1361 = !DILocation(line: 0, scope: !1304, inlinedAt: !1362)
!1362 = distinct !DILocation(line: 505, column: 13, scope: !1336, inlinedAt: !1349)
!1363 = !DILocation(line: 488, column: 22, scope: !1321, inlinedAt: !1362)
!1364 = !DILocation(line: 488, column: 19, scope: !1321, inlinedAt: !1362)
!1365 = !DILocation(line: 488, column: 13, scope: !1322, inlinedAt: !1362)
!1366 = !DILocation(line: 0, scope: !1304, inlinedAt: !1367)
!1367 = distinct !DILocation(line: 511, column: 9, scope: !1343, inlinedAt: !1349)
!1368 = !DILocation(line: 488, column: 19, scope: !1321, inlinedAt: !1367)
!1369 = !DILocation(line: 488, column: 13, scope: !1322, inlinedAt: !1367)
!1370 = !DILocation(line: 488, column: 13, scope: !1321, inlinedAt: !1367)
!1371 = !DILocation(line: 542, column: 1, scope: !1261, inlinedAt: !1268)
!1372 = !DILocation(line: 543, column: 20, scope: !1373, inlinedAt: !1268)
!1373 = distinct !DILexicalBlock(scope: !1261, file: !3, line: 543, column: 5)
!1374 = !DILocation(line: 555, column: 29, scope: !1271, inlinedAt: !1256)
!1375 = !DILocation(line: 555, column: 16, scope: !1271, inlinedAt: !1256)
!1376 = distinct !{!1376, !1259, !1377, !914}
!1377 = !DILocation(line: 558, column: 2, scope: !1254, inlinedAt: !1256)
!1378 = !DILocation(line: 538, column: 24, scope: !1379, inlinedAt: !1268)
!1379 = distinct !DILexicalBlock(scope: !1302, file: !3, line: 537, column: 2)
!1380 = !{!1288, !664, i64 12}
!1381 = !DILocation(line: 560, column: 9, scope: !1248, inlinedAt: !1256)
!1382 = !DILocation(line: 83, column: 13, scope: !916, inlinedAt: !1284)
!1383 = !DILocation(line: 80, column: 38, scope: !803, inlinedAt: !1284)
!1384 = !DILocation(line: 81, column: 38, scope: !803, inlinedAt: !1284)
!1385 = !DILocation(line: 87, column: 24, scope: !803, inlinedAt: !1284)
!1386 = !DILocation(line: 88, column: 7, scope: !921, inlinedAt: !1284)
!1387 = !DILocation(line: 88, column: 6, scope: !803, inlinedAt: !1284)
!1388 = !DILocation(line: 80, column: 27, scope: !803, inlinedAt: !1284)
!1389 = !DILocation(line: 81, column: 27, scope: !803, inlinedAt: !1284)
!1390 = !DILocation(line: 92, column: 25, scope: !803, inlinedAt: !1284)
!1391 = !DILocation(line: 98, column: 7, scope: !803, inlinedAt: !1284)
!1392 = !DILocation(line: 98, column: 17, scope: !803, inlinedAt: !1284)
!1393 = !DILocation(line: 99, column: 7, scope: !803, inlinedAt: !1284)
!1394 = !DILocation(line: 99, column: 16, scope: !803, inlinedAt: !1284)
!1395 = !DILocation(line: 101, column: 9, scope: !803, inlinedAt: !1284)
!1396 = !DILocation(line: 102, column: 1, scope: !803, inlinedAt: !1284)
!1397 = !DILocation(line: 599, column: 2, scope: !1214)
!1398 = !DILocation(line: 0, scope: !212)
!1399 = !DILocation(line: 606, column: 38, scope: !212)
!1400 = !DILocation(line: 606, column: 27, scope: !212)
!1401 = !DILocation(line: 606, column: 19, scope: !212)
!1402 = !DILocation(line: 607, column: 34, scope: !212)
!1403 = !DILocation(line: 607, column: 23, scope: !212)
!1404 = !DILocation(line: 607, column: 15, scope: !212)
!1405 = !DILocation(line: 619, column: 2, scope: !212)
!1406 = !DILocation(line: 619, column: 23, scope: !212)
!1407 = !DILocation(line: 0, scope: !621, inlinedAt: !1408)
!1408 = distinct !DILocation(line: 623, column: 12, scope: !212)
!1409 = !DILocation(line: 0, scope: !632, inlinedAt: !1410)
!1410 = distinct !DILocation(line: 129, column: 9, scope: !621, inlinedAt: !1408)
!1411 = !DILocation(line: 93, column: 14, scope: !659, inlinedAt: !1410)
!1412 = !DILocation(line: 93, column: 24, scope: !659, inlinedAt: !1410)
!1413 = !DILocation(line: 93, column: 6, scope: !632, inlinedAt: !1410)
!1414 = !DILocation(line: 99, column: 17, scope: !632, inlinedAt: !1410)
!1415 = !DILocation(line: 0, scope: !666, inlinedAt: !1416)
!1416 = distinct !DILocation(line: 106, column: 8, scope: !672, inlinedAt: !1410)
!1417 = !DILocation(line: 70, column: 20, scope: !666, inlinedAt: !1416)
!1418 = !DILocation(line: 70, column: 46, scope: !666, inlinedAt: !1416)
!1419 = !DILocation(line: 106, column: 8, scope: !672, inlinedAt: !1410)
!1420 = !DILocation(line: 106, column: 7, scope: !673, inlinedAt: !1410)
!1421 = !DILocation(line: 112, column: 18, scope: !673, inlinedAt: !1410)
!1422 = !DILocation(line: 625, column: 5, scope: !212)
!1423 = !DILocation(line: 0, scope: !683, inlinedAt: !1424)
!1424 = distinct !DILocation(line: 630, column: 13, scope: !339)
!1425 = !DILocation(line: 161, column: 17, scope: !683, inlinedAt: !1424)
!1426 = !DILocation(line: 161, column: 21, scope: !683, inlinedAt: !1424)
!1427 = !DILocation(line: 163, column: 13, scope: !699, inlinedAt: !1424)
!1428 = !DILocation(line: 163, column: 5, scope: !683, inlinedAt: !1424)
!1429 = !DILocation(line: 167, column: 14, scope: !702, inlinedAt: !1424)
!1430 = !DILocation(line: 167, column: 24, scope: !702, inlinedAt: !1424)
!1431 = !DILocation(line: 167, column: 6, scope: !683, inlinedAt: !1424)
!1432 = !DILocation(line: 173, column: 14, scope: !683, inlinedAt: !1424)
!1433 = !DILocation(line: 635, column: 18, scope: !339)
!1434 = !DILocation(line: 635, column: 10, scope: !339)
!1435 = !DILocation(line: 635, column: 16, scope: !339)
!1436 = !{!1437, !611, i64 0}
!1437 = !{!"conn_ipv4_key", !611, i64 0, !611, i64 4, !664, i64 8, !664, i64 10, !664, i64 12}
!1438 = !DILocation(line: 636, column: 18, scope: !339)
!1439 = !DILocation(line: 636, column: 10, scope: !339)
!1440 = !DILocation(line: 636, column: 16, scope: !339)
!1441 = !{!1437, !611, i64 4}
!1442 = !DILocation(line: 638, column: 18, scope: !339)
!1443 = !DILocation(line: 638, column: 10, scope: !339)
!1444 = !DILocation(line: 638, column: 16, scope: !339)
!1445 = !{!1437, !664, i64 12}
!1446 = !DILocation(line: 641, column: 11, scope: !339)
!1447 = !DILocation(line: 644, column: 7, scope: !339)
!1448 = !DILocation(line: 0, scope: !710, inlinedAt: !1449)
!1449 = distinct !DILocation(line: 646, column: 7, scope: !1450)
!1450 = distinct !DILexicalBlock(scope: !337, file: !3, line: 646, column: 7)
!1451 = !DILocation(line: 254, column: 8, scope: !725, inlinedAt: !1449)
!1452 = !DILocation(line: 254, column: 12, scope: !725, inlinedAt: !1449)
!1453 = !DILocation(line: 254, column: 6, scope: !710, inlinedAt: !1449)
!1454 = !DILocation(line: 257, column: 11, scope: !710, inlinedAt: !1449)
!1455 = !DILocation(line: 257, column: 16, scope: !710, inlinedAt: !1449)
!1456 = !DILocation(line: 259, column: 9, scope: !731, inlinedAt: !1449)
!1457 = !DILocation(line: 259, column: 5, scope: !710, inlinedAt: !1449)
!1458 = !DILocation(line: 263, column: 14, scope: !734, inlinedAt: !1449)
!1459 = !DILocation(line: 263, column: 20, scope: !734, inlinedAt: !1449)
!1460 = !DILocation(line: 263, column: 6, scope: !710, inlinedAt: !1449)
!1461 = !DILocation(line: 649, column: 19, scope: !337)
!1462 = !{!1463, !664, i64 0}
!1463 = !{!"tcphdr", !664, i64 0, !664, i64 2, !611, i64 4, !611, i64 8, !664, i64 12, !664, i64 12, !664, i64 13, !664, i64 13, !664, i64 13, !664, i64 13, !664, i64 13, !664, i64 13, !664, i64 13, !664, i64 13, !664, i64 14, !664, i64 16, !664, i64 18}
!1464 = !DILocation(line: 649, column: 11, scope: !337)
!1465 = !DILocation(line: 649, column: 17, scope: !337)
!1466 = !{!1437, !664, i64 8}
!1467 = !DILocation(line: 650, column: 19, scope: !337)
!1468 = !{!1463, !664, i64 2}
!1469 = !DILocation(line: 650, column: 11, scope: !337)
!1470 = !DILocation(line: 650, column: 17, scope: !337)
!1471 = !{!1437, !664, i64 10}
!1472 = !DILocation(line: 657, column: 37, scope: !337)
!1473 = !DILocation(line: 0, scope: !337)
!1474 = !DILocation(line: 658, column: 8, scope: !350)
!1475 = !DILocation(line: 658, column: 7, scope: !337)
!1476 = !DILocation(line: 659, column: 18, scope: !348)
!1477 = !DILocation(line: 660, column: 6, scope: !347)
!1478 = !DILocation(line: 660, column: 27, scope: !347)
!1479 = !DILocation(line: 662, column: 6, scope: !347)
!1480 = !DILocation(line: 664, column: 6, scope: !352)
!1481 = !{!1482, !611, i64 4}
!1482 = !{!"conn_ipv4_val", !611, i64 0, !611, i64 4}
!1483 = !DILocation(line: 664, column: 6, scope: !347)
!1484 = !DILocation(line: 668, column: 5, scope: !348)
!1485 = !DILocation(line: 668, column: 5, scope: !347)
!1486 = !DILocation(line: 659, column: 8, scope: !348)
!1487 = !DILocation(line: 669, column: 13, scope: !348)
!1488 = !DILocation(line: 670, column: 6, scope: !357)
!1489 = !DILocation(line: 670, column: 27, scope: !357)
!1490 = !DILocation(line: 672, column: 6, scope: !357)
!1491 = !DILocation(line: 674, column: 6, scope: !360)
!1492 = !DILocation(line: 674, column: 6, scope: !357)
!1493 = !DILocation(line: 678, column: 5, scope: !358)
!1494 = !DILocation(line: 678, column: 5, scope: !357)
!1495 = !DILocation(line: 683, column: 7, scope: !364)
!1496 = !DILocation(line: 683, column: 7, scope: !337)
!1497 = !DILocation(line: 684, column: 5, scope: !363)
!1498 = !DILocation(line: 685, column: 5, scope: !362)
!1499 = !DILocation(line: 685, column: 5, scope: !363)
!1500 = !DILocation(line: 689, column: 5, scope: !363)
!1501 = !DILocation(line: 691, column: 17, scope: !1502)
!1502 = distinct !DILexicalBlock(scope: !337, file: !3, line: 691, column: 7)
!1503 = !DILocation(line: 691, column: 7, scope: !1502)
!1504 = !{!1482, !611, i64 0}
!1505 = !DILocation(line: 691, column: 7, scope: !337)
!1506 = !DILocation(line: 694, column: 28, scope: !1507)
!1507 = distinct !DILexicalBlock(scope: !1508, file: !3, line: 694, column: 8)
!1508 = distinct !DILexicalBlock(scope: !1502, file: !3, line: 692, column: 4)
!1509 = !DILocation(line: 694, column: 49, scope: !1507)
!1510 = !DILocation(line: 702, column: 46, scope: !1511)
!1511 = distinct !DILexicalBlock(scope: !1512, file: !3, line: 702, column: 8)
!1512 = distinct !DILexicalBlock(scope: !1513, file: !3, line: 700, column: 4)
!1513 = distinct !DILexicalBlock(scope: !337, file: !3, line: 699, column: 7)
!1514 = !DILocation(line: 702, column: 49, scope: !1511)
!1515 = !DILocation(line: 702, column: 8, scope: !1512)
!1516 = !DILocation(line: 707, column: 52, scope: !1517)
!1517 = distinct !DILexicalBlock(scope: !1512, file: !3, line: 707, column: 8)
!1518 = !DILocation(line: 707, column: 8, scope: !1512)
!1519 = !DILocation(line: 712, column: 51, scope: !1520)
!1520 = distinct !DILexicalBlock(scope: !1512, file: !3, line: 712, column: 8)
!1521 = !DILocation(line: 712, column: 8, scope: !1512)
!1522 = !DILocation(line: 720, column: 4, scope: !337)
!1523 = !DILocation(line: 721, column: 42, scope: !1524)
!1524 = distinct !DILexicalBlock(scope: !337, file: !3, line: 721, column: 8)
!1525 = !DILocation(line: 723, column: 6, scope: !1526)
!1526 = distinct !DILexicalBlock(scope: !1524, file: !3, line: 721, column: 83)
!1527 = !DILocation(line: 724, column: 5, scope: !1526)
!1528 = !DILocation(line: 0, scope: !1512)
!1529 = !DILocation(line: 726, column: 6, scope: !1530)
!1530 = distinct !DILexicalBlock(scope: !1524, file: !3, line: 724, column: 10)
!1531 = !DILocation(line: 729, column: 22, scope: !337)
!1532 = !DILocation(line: 729, column: 5, scope: !337)
!1533 = !DILocation(line: 735, column: 7, scope: !1534)
!1534 = distinct !DILexicalBlock(scope: !337, file: !3, line: 729, column: 33)
!1535 = !DILocation(line: 738, column: 7, scope: !1534)
!1536 = !DILocation(line: 741, column: 7, scope: !1534)
!1537 = !DILocation(line: 744, column: 7, scope: !1534)
!1538 = !DILocation(line: 747, column: 7, scope: !1534)
!1539 = !DILocation(line: 750, column: 7, scope: !1534)
!1540 = !DILocation(line: 753, column: 5, scope: !1534)
!1541 = !DILocation(line: 0, scope: !1534)
!1542 = !DILocation(line: 754, column: 5, scope: !370)
!1543 = !DILocation(line: 754, column: 5, scope: !337)
!1544 = !DILocation(line: 758, column: 5, scope: !337)
!1545 = !DILocation(line: 0, scope: !738, inlinedAt: !1546)
!1546 = distinct !DILocation(line: 762, column: 7, scope: !1547)
!1547 = distinct !DILexicalBlock(scope: !373, file: !3, line: 762, column: 7)
!1548 = !DILocation(line: 231, column: 8, scope: !753, inlinedAt: !1546)
!1549 = !DILocation(line: 231, column: 14, scope: !753, inlinedAt: !1546)
!1550 = !DILocation(line: 231, column: 12, scope: !753, inlinedAt: !1546)
!1551 = !DILocation(line: 231, column: 6, scope: !738, inlinedAt: !1546)
!1552 = !DILocation(line: 237, column: 8, scope: !738, inlinedAt: !1546)
!1553 = !DILocation(line: 238, column: 10, scope: !761, inlinedAt: !1546)
!1554 = !DILocation(line: 238, column: 6, scope: !738, inlinedAt: !1546)
!1555 = !DILocation(line: 765, column: 19, scope: !373)
!1556 = !{!759, !664, i64 0}
!1557 = !DILocation(line: 765, column: 11, scope: !373)
!1558 = !DILocation(line: 765, column: 17, scope: !373)
!1559 = !DILocation(line: 766, column: 19, scope: !373)
!1560 = !{!759, !664, i64 2}
!1561 = !DILocation(line: 766, column: 11, scope: !373)
!1562 = !DILocation(line: 766, column: 17, scope: !373)
!1563 = !DILocation(line: 767, column: 4, scope: !372)
!1564 = !DILocation(line: 767, column: 4, scope: !373)
!1565 = !DILocation(line: 771, column: 3, scope: !373)
!1566 = !DILocalVariable(name: "nh", arg: 1, scope: !1567, file: !231, line: 191, type: !624)
!1567 = distinct !DISubprogram(name: "parse_icmphdr", scope: !231, file: !231, line: 191, type: !1568, scopeLine: 194, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1571)
!1568 = !DISubroutineType(types: !1569)
!1569 = !{!189, !624, !63, !1570}
!1570 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !303, size: 64)
!1571 = !{!1566, !1572, !1573, !1574}
!1572 = !DILocalVariable(name: "data_end", arg: 2, scope: !1567, file: !231, line: 192, type: !63)
!1573 = !DILocalVariable(name: "icmphdr", arg: 3, scope: !1567, file: !231, line: 193, type: !1570)
!1574 = !DILocalVariable(name: "icmph", scope: !1567, file: !231, line: 195, type: !303)
!1575 = !DILocation(line: 0, scope: !1567, inlinedAt: !1576)
!1576 = distinct !DILocation(line: 774, column: 7, scope: !1577)
!1577 = distinct !DILexicalBlock(scope: !380, file: !3, line: 774, column: 7)
!1578 = !DILocation(line: 197, column: 12, scope: !1579, inlinedAt: !1576)
!1579 = distinct !DILexicalBlock(scope: !1567, file: !231, line: 197, column: 6)
!1580 = !DILocation(line: 197, column: 18, scope: !1579, inlinedAt: !1576)
!1581 = !DILocation(line: 197, column: 16, scope: !1579, inlinedAt: !1576)
!1582 = !DILocation(line: 197, column: 6, scope: !1567, inlinedAt: !1576)
!1583 = !DILocation(line: 777, column: 4, scope: !379)
!1584 = !{!1585, !612, i64 0}
!1585 = !{!"icmphdr", !612, i64 0, !612, i64 1, !664, i64 2, !612, i64 4}
!1586 = !{!1585, !612, i64 1}
!1587 = !DILocation(line: 777, column: 4, scope: !380)
!1588 = !DILocation(line: 781, column: 3, scope: !380)
!1589 = !DILocation(line: 791, column: 1, scope: !212)
!1590 = !DILocation(line: 0, scope: !803, inlinedAt: !1591)
!1591 = distinct !DILocation(line: 792, column: 9, scope: !212)
!1592 = !DILocation(line: 80, column: 38, scope: !803, inlinedAt: !1591)
!1593 = !DILocation(line: 81, column: 38, scope: !803, inlinedAt: !1591)
!1594 = !DILocation(line: 87, column: 24, scope: !803, inlinedAt: !1591)
!1595 = !DILocation(line: 88, column: 7, scope: !921, inlinedAt: !1591)
!1596 = !DILocation(line: 88, column: 6, scope: !803, inlinedAt: !1591)
!1597 = !DILocation(line: 81, column: 27, scope: !803, inlinedAt: !1591)
!1598 = !DILocation(line: 80, column: 27, scope: !803, inlinedAt: !1591)
!1599 = !DILocation(line: 92, column: 25, scope: !803, inlinedAt: !1591)
!1600 = !DILocation(line: 98, column: 7, scope: !803, inlinedAt: !1591)
!1601 = !DILocation(line: 98, column: 17, scope: !803, inlinedAt: !1591)
!1602 = !DILocation(line: 99, column: 7, scope: !803, inlinedAt: !1591)
!1603 = !DILocation(line: 99, column: 16, scope: !803, inlinedAt: !1591)
!1604 = !DILocation(line: 101, column: 9, scope: !803, inlinedAt: !1591)
!1605 = !DILocation(line: 102, column: 1, scope: !803, inlinedAt: !1591)
!1606 = !DILocation(line: 794, column: 1, scope: !212)
!1607 = !DILocation(line: 0, scope: !420)
!1608 = !DILocation(line: 799, column: 2, scope: !1609)
!1609 = distinct !DILexicalBlock(scope: !420, file: !3, line: 799, column: 2)
!1610 = !DILocation(line: 800, column: 2, scope: !420)
!1611 = distinct !DISubprogram(name: "match_rules_loop", scope: !3, file: !3, line: 134, type: !529, scopeLine: 135, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1612)
!1612 = !{!1613, !1614, !1615, !1616}
!1613 = !DILocalVariable(name: "index", arg: 1, scope: !1611, file: !3, line: 134, type: !68)
!1614 = !DILocalVariable(name: "ctx", arg: 2, scope: !1611, file: !3, line: 134, type: !63)
!1615 = !DILocalVariable(name: "p_ctx", scope: !1611, file: !3, line: 136, type: !111)
!1616 = !DILocalVariable(name: "p_r", scope: !1611, file: !3, line: 139, type: !111)
!1617 = !DILocation(line: 0, scope: !1611)
!1618 = !DILocation(line: 139, column: 59, scope: !1611)
!1619 = !DILocation(line: 139, column: 24, scope: !1611)
!1620 = !DILocation(line: 140, column: 6, scope: !1621)
!1621 = distinct !DILexicalBlock(scope: !1611, file: !3, line: 140, column: 5)
!1622 = !DILocation(line: 140, column: 5, scope: !1611)
!1623 = !DILocation(line: 145, column: 24, scope: !1624)
!1624 = distinct !DILexicalBlock(scope: !1611, file: !3, line: 145, column: 6)
!1625 = !DILocation(line: 145, column: 36, scope: !1624)
!1626 = !DILocalVariable(name: "conn_addr", arg: 1, scope: !1627, file: !3, line: 127, type: !68)
!1627 = distinct !DISubprogram(name: "ipv4_match", scope: !3, file: !3, line: 127, type: !1628, scopeLine: 127, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !1630)
!1628 = !DISubroutineType(types: !1629)
!1629 = !{!189, !68, !68}
!1630 = !{!1626, !1631}
!1631 = !DILocalVariable(name: "rule_addr", arg: 2, scope: !1627, file: !3, line: 127, type: !68)
!1632 = !DILocation(line: 0, scope: !1627, inlinedAt: !1633)
!1633 = distinct !DILocation(line: 145, column: 6, scope: !1624)
!1634 = !DILocation(line: 129, column: 8, scope: !1635, inlinedAt: !1633)
!1635 = distinct !DILexicalBlock(scope: !1627, file: !3, line: 129, column: 6)
!1636 = !DILocation(line: 145, column: 6, scope: !1624)
!1637 = !DILocation(line: 145, column: 6, scope: !1611)
!1638 = !DILocation(line: 147, column: 3, scope: !1639)
!1639 = distinct !DILexicalBlock(scope: !1624, file: !3, line: 145, column: 45)
!1640 = !DILocation(line: 148, column: 3, scope: !1639)
!1641 = !DILocation(line: 151, column: 3, scope: !1639)
!1642 = !DILocation(line: 156, column: 1, scope: !1611)
