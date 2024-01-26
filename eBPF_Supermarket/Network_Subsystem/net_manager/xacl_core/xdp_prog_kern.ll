; ModuleID = 'xdp_prog_kern.c'
source_filename = "xdp_prog_kern.c"
target datalayout = "e-m:e-p:64:64-i64:64-i128:128-n32:64-S128"
target triple = "bpf"

%struct.anon = type { ptr, ptr, ptr, ptr }
%struct.anon.0 = type { ptr, ptr, ptr, ptr }
%struct.anon.1 = type { ptr, ptr, ptr, ptr }
%struct.xdp_md = type { i32, i32, i32, i32, i32, i32 }
%struct.ethhdr = type { [6 x i8], [6 x i8], i16 }
%struct.datarec = type { i64, i64 }

@src_macs = dso_local global %struct.anon zeroinitializer, section ".maps", align 8, !dbg !0
@redirect_params = dso_local global %struct.anon.0 zeroinitializer, section ".maps", align 8, !dbg !54
@_license = dso_local global [4 x i8] c"GPL\00", section "license", align 1, !dbg !21
@xdp_stats_map = dso_local global %struct.anon.1 zeroinitializer, section ".maps", align 8, !dbg !27
@llvm.compiler.used = appending global [7 x ptr] [ptr @_license, ptr @filter_ethernet_drop, ptr @filter_ethernet_pass, ptr @redirect_params, ptr @src_macs, ptr @xdp_redirect_func, ptr @xdp_stats_map], section "llvm.metadata"

; Function Attrs: nounwind
define dso_local i32 @filter_ethernet_pass(ptr nocapture noundef readonly %0) #0 section "xdp" !dbg !98 {
  %2 = alloca i32, align 4
  call void @llvm.dbg.value(metadata ptr %0, metadata !111, metadata !DIExpression()), !dbg !134
  call void @llvm.dbg.value(metadata i32 1, metadata !112, metadata !DIExpression()), !dbg !134
  %3 = getelementptr inbounds %struct.xdp_md, ptr %0, i64 0, i32 1, !dbg !135
  %4 = load i32, ptr %3, align 4, !dbg !135, !tbaa !136
  %5 = zext i32 %4 to i64, !dbg !141
  %6 = inttoptr i64 %5 to ptr, !dbg !142
  call void @llvm.dbg.value(metadata ptr %6, metadata !114, metadata !DIExpression()), !dbg !134
  %7 = load i32, ptr %0, align 4, !dbg !143, !tbaa !144
  %8 = zext i32 %7 to i64, !dbg !145
  %9 = inttoptr i64 %8 to ptr, !dbg !146
  call void @llvm.dbg.value(metadata ptr %9, metadata !115, metadata !DIExpression()), !dbg !134
  call void @llvm.dbg.value(metadata ptr %9, metadata !116, metadata !DIExpression()), !dbg !134
  call void @llvm.dbg.value(metadata ptr undef, metadata !147, metadata !DIExpression()), !dbg !156
  call void @llvm.dbg.value(metadata ptr %6, metadata !154, metadata !DIExpression()), !dbg !156
  call void @llvm.dbg.value(metadata ptr undef, metadata !155, metadata !DIExpression()), !dbg !156
  call void @llvm.dbg.value(metadata ptr undef, metadata !158, metadata !DIExpression()), !dbg !183
  call void @llvm.dbg.value(metadata ptr %6, metadata !170, metadata !DIExpression()), !dbg !183
  call void @llvm.dbg.value(metadata ptr undef, metadata !171, metadata !DIExpression()), !dbg !183
  call void @llvm.dbg.value(metadata ptr null, metadata !172, metadata !DIExpression()), !dbg !183
  call void @llvm.dbg.value(metadata ptr %9, metadata !173, metadata !DIExpression()), !dbg !183
  call void @llvm.dbg.value(metadata i32 14, metadata !174, metadata !DIExpression()), !dbg !183
  %10 = getelementptr i8, ptr %9, i64 14, !dbg !185
  %11 = icmp ugt ptr %10, %6, !dbg !187
  br i1 %11, label %32, label %12, !dbg !188

12:                                               ; preds = %1
  call void @llvm.dbg.value(metadata ptr %10, metadata !116, metadata !DIExpression()), !dbg !134
  call void @llvm.dbg.value(metadata ptr %10, metadata !175, metadata !DIExpression()), !dbg !183
  %13 = getelementptr inbounds %struct.ethhdr, ptr %9, i64 0, i32 2, !dbg !189
  call void @llvm.dbg.value(metadata i16 poison, metadata !181, metadata !DIExpression()), !dbg !183
  call void @llvm.dbg.value(metadata i32 0, metadata !182, metadata !DIExpression()), !dbg !183
  %14 = load i16, ptr %13, align 1, !dbg !183, !tbaa !190
  call void @llvm.dbg.value(metadata i16 %14, metadata !181, metadata !DIExpression()), !dbg !183
  call void @llvm.dbg.value(metadata i16 %14, metadata !192, metadata !DIExpression()), !dbg !197
  %15 = icmp eq i16 %14, 129, !dbg !203
  %16 = icmp eq i16 %14, -22392, !dbg !204
  %17 = tail call i1 @llvm.bpf.passthrough.i1.i1(i32 0, i1 %15)
  %18 = or i1 %16, %17, !dbg !204
  %19 = getelementptr i8, ptr %9, i64 18
  %20 = icmp ule ptr %19, %6
  %21 = select i1 %18, i1 %20, i1 false, !dbg !205
  br i1 %21, label %22, label %27, !dbg !205

22:                                               ; preds = %12
  call void @llvm.dbg.value(metadata i16 poison, metadata !181, metadata !DIExpression()), !dbg !183
  %23 = getelementptr i8, ptr %9, i64 16, !dbg !206
  call void @llvm.dbg.value(metadata ptr %19, metadata !175, metadata !DIExpression()), !dbg !183
  call void @llvm.dbg.value(metadata i32 1, metadata !182, metadata !DIExpression()), !dbg !183
  %24 = load i16, ptr %23, align 1, !dbg !183, !tbaa !190
  call void @llvm.dbg.value(metadata i16 %24, metadata !181, metadata !DIExpression()), !dbg !183
  call void @llvm.dbg.value(metadata i16 %24, metadata !192, metadata !DIExpression()), !dbg !197
  %25 = icmp eq i16 %24, 129, !dbg !203
  %26 = tail call i1 @llvm.bpf.passthrough.i1.i1(i32 0, i1 %25)
  br label %27, !dbg !205

27:                                               ; preds = %22, %12
  call void @llvm.dbg.value(metadata ptr poison, metadata !116, metadata !DIExpression()), !dbg !134
  call void @llvm.dbg.value(metadata i16 poison, metadata !121, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !134
  call void @llvm.dbg.value(metadata ptr %9, metadata !122, metadata !DIExpression()), !dbg !134
  %28 = getelementptr inbounds %struct.ethhdr, ptr %9, i64 0, i32 1, !dbg !207
  %29 = tail call ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @src_macs, ptr noundef nonnull %28) #6, !dbg !208
  call void @llvm.dbg.value(metadata ptr %29, metadata !132, metadata !DIExpression()), !dbg !134
  %30 = icmp eq ptr %29, null, !dbg !209
  br i1 %30, label %32, label %31, !dbg !211

31:                                               ; preds = %27
  call void @llvm.dbg.value(metadata i32 2, metadata !112, metadata !DIExpression()), !dbg !134
  br label %32, !dbg !212

32:                                               ; preds = %1, %27, %31
  %33 = phi i32 [ 2, %31 ], [ 1, %27 ], [ 1, %1 ], !dbg !134
  call void @llvm.dbg.value(metadata i32 %33, metadata !112, metadata !DIExpression()), !dbg !134
  call void @llvm.dbg.label(metadata !133), !dbg !214
  call void @llvm.lifetime.start.p0(i64 4, ptr nonnull %2), !dbg !215
  call void @llvm.dbg.value(metadata ptr %0, metadata !220, metadata !DIExpression()), !dbg !215
  call void @llvm.dbg.value(metadata i32 %33, metadata !221, metadata !DIExpression()), !dbg !215
  store i32 %33, ptr %2, align 4, !tbaa !227
  %34 = load i32, ptr %3, align 4, !dbg !228, !tbaa !136
  call void @llvm.dbg.value(metadata i32 %34, metadata !222, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !215
  %35 = load i32, ptr %0, align 4, !dbg !229, !tbaa !144
  call void @llvm.dbg.value(metadata i32 %35, metadata !223, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !215
  call void @llvm.dbg.value(metadata ptr %2, metadata !221, metadata !DIExpression(DW_OP_deref)), !dbg !215
  %36 = call ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @xdp_stats_map, ptr noundef nonnull %2) #6, !dbg !230
  call void @llvm.dbg.value(metadata ptr %36, metadata !224, metadata !DIExpression()), !dbg !215
  %37 = icmp eq ptr %36, null, !dbg !231
  br i1 %37, label %48, label %38, !dbg !233

38:                                               ; preds = %32
  %39 = zext i32 %35 to i64, !dbg !234
  call void @llvm.dbg.value(metadata i64 %39, metadata !223, metadata !DIExpression()), !dbg !215
  %40 = zext i32 %34 to i64, !dbg !235
  call void @llvm.dbg.value(metadata i64 %40, metadata !222, metadata !DIExpression()), !dbg !215
  %41 = sub nsw i64 %40, %39, !dbg !236
  call void @llvm.dbg.value(metadata i64 %41, metadata !225, metadata !DIExpression()), !dbg !215
  %42 = load i64, ptr %36, align 8, !dbg !237, !tbaa !238
  %43 = add i64 %42, 1, !dbg !237
  store i64 %43, ptr %36, align 8, !dbg !237, !tbaa !238
  %44 = getelementptr inbounds %struct.datarec, ptr %36, i64 0, i32 1, !dbg !241
  %45 = load i64, ptr %44, align 8, !dbg !242, !tbaa !243
  %46 = add i64 %41, %45, !dbg !242
  store i64 %46, ptr %44, align 8, !dbg !242, !tbaa !243
  %47 = load i32, ptr %2, align 4, !dbg !244, !tbaa !227
  call void @llvm.dbg.value(metadata i32 %47, metadata !221, metadata !DIExpression()), !dbg !215
  br label %48

48:                                               ; preds = %32, %38
  %49 = phi i32 [ %47, %38 ], [ 0, %32 ], !dbg !215
  call void @llvm.lifetime.end.p0(i64 4, ptr nonnull %2), !dbg !245
  ret i32 %49, !dbg !246
}

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.start.p0(i64 immarg, ptr nocapture) #1

; Function Attrs: mustprogress nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.label(metadata) #2

; Function Attrs: mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite)
declare void @llvm.lifetime.end.p0(i64 immarg, ptr nocapture) #1

; Function Attrs: nounwind
define dso_local i32 @filter_ethernet_drop(ptr nocapture noundef readonly %0) #0 section "xdp" !dbg !247 {
  %2 = alloca i32, align 4
  call void @llvm.dbg.value(metadata ptr %0, metadata !249, metadata !DIExpression()), !dbg !258
  call void @llvm.dbg.value(metadata i32 2, metadata !250, metadata !DIExpression()), !dbg !258
  %3 = getelementptr inbounds %struct.xdp_md, ptr %0, i64 0, i32 1, !dbg !259
  %4 = load i32, ptr %3, align 4, !dbg !259, !tbaa !136
  %5 = zext i32 %4 to i64, !dbg !260
  %6 = inttoptr i64 %5 to ptr, !dbg !261
  call void @llvm.dbg.value(metadata ptr %6, metadata !251, metadata !DIExpression()), !dbg !258
  %7 = load i32, ptr %0, align 4, !dbg !262, !tbaa !144
  %8 = zext i32 %7 to i64, !dbg !263
  %9 = inttoptr i64 %8 to ptr, !dbg !264
  call void @llvm.dbg.value(metadata ptr %9, metadata !252, metadata !DIExpression()), !dbg !258
  call void @llvm.dbg.value(metadata ptr %9, metadata !253, metadata !DIExpression()), !dbg !258
  call void @llvm.dbg.value(metadata ptr undef, metadata !147, metadata !DIExpression()), !dbg !265
  call void @llvm.dbg.value(metadata ptr %6, metadata !154, metadata !DIExpression()), !dbg !265
  call void @llvm.dbg.value(metadata ptr undef, metadata !155, metadata !DIExpression()), !dbg !265
  call void @llvm.dbg.value(metadata ptr undef, metadata !158, metadata !DIExpression()), !dbg !267
  call void @llvm.dbg.value(metadata ptr %6, metadata !170, metadata !DIExpression()), !dbg !267
  call void @llvm.dbg.value(metadata ptr undef, metadata !171, metadata !DIExpression()), !dbg !267
  call void @llvm.dbg.value(metadata ptr null, metadata !172, metadata !DIExpression()), !dbg !267
  call void @llvm.dbg.value(metadata ptr %9, metadata !173, metadata !DIExpression()), !dbg !267
  call void @llvm.dbg.value(metadata i32 14, metadata !174, metadata !DIExpression()), !dbg !267
  %10 = getelementptr i8, ptr %9, i64 14, !dbg !269
  %11 = icmp ugt ptr %10, %6, !dbg !270
  br i1 %11, label %32, label %12, !dbg !271

12:                                               ; preds = %1
  call void @llvm.dbg.value(metadata ptr %10, metadata !253, metadata !DIExpression()), !dbg !258
  call void @llvm.dbg.value(metadata ptr %10, metadata !175, metadata !DIExpression()), !dbg !267
  %13 = getelementptr inbounds %struct.ethhdr, ptr %9, i64 0, i32 2, !dbg !272
  call void @llvm.dbg.value(metadata i16 poison, metadata !181, metadata !DIExpression()), !dbg !267
  call void @llvm.dbg.value(metadata i32 0, metadata !182, metadata !DIExpression()), !dbg !267
  %14 = load i16, ptr %13, align 1, !dbg !267, !tbaa !190
  call void @llvm.dbg.value(metadata i16 %14, metadata !181, metadata !DIExpression()), !dbg !267
  call void @llvm.dbg.value(metadata i16 %14, metadata !192, metadata !DIExpression()), !dbg !273
  %15 = icmp eq i16 %14, 129, !dbg !275
  %16 = icmp eq i16 %14, -22392, !dbg !276
  %17 = tail call i1 @llvm.bpf.passthrough.i1.i1(i32 0, i1 %15)
  %18 = or i1 %16, %17, !dbg !276
  %19 = getelementptr i8, ptr %9, i64 18
  %20 = icmp ule ptr %19, %6
  %21 = select i1 %18, i1 %20, i1 false, !dbg !277
  br i1 %21, label %22, label %27, !dbg !277

22:                                               ; preds = %12
  call void @llvm.dbg.value(metadata i16 poison, metadata !181, metadata !DIExpression()), !dbg !267
  %23 = getelementptr i8, ptr %9, i64 16, !dbg !278
  call void @llvm.dbg.value(metadata ptr %19, metadata !175, metadata !DIExpression()), !dbg !267
  call void @llvm.dbg.value(metadata i32 1, metadata !182, metadata !DIExpression()), !dbg !267
  %24 = load i16, ptr %23, align 1, !dbg !267, !tbaa !190
  call void @llvm.dbg.value(metadata i16 %24, metadata !181, metadata !DIExpression()), !dbg !267
  call void @llvm.dbg.value(metadata i16 %24, metadata !192, metadata !DIExpression()), !dbg !273
  %25 = icmp eq i16 %24, 129, !dbg !275
  %26 = tail call i1 @llvm.bpf.passthrough.i1.i1(i32 0, i1 %25)
  br label %27, !dbg !277

27:                                               ; preds = %22, %12
  call void @llvm.dbg.value(metadata ptr poison, metadata !253, metadata !DIExpression()), !dbg !258
  call void @llvm.dbg.value(metadata i16 poison, metadata !254, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !258
  call void @llvm.dbg.value(metadata ptr %9, metadata !255, metadata !DIExpression()), !dbg !258
  %28 = getelementptr inbounds %struct.ethhdr, ptr %9, i64 0, i32 1, !dbg !279
  %29 = tail call ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @src_macs, ptr noundef nonnull %28) #6, !dbg !280
  call void @llvm.dbg.value(metadata ptr %29, metadata !256, metadata !DIExpression()), !dbg !258
  %30 = icmp eq ptr %29, null, !dbg !281
  br i1 %30, label %32, label %31, !dbg !283

31:                                               ; preds = %27
  call void @llvm.dbg.value(metadata i32 1, metadata !250, metadata !DIExpression()), !dbg !258
  br label %32, !dbg !284

32:                                               ; preds = %1, %27, %31
  %33 = phi i32 [ 1, %31 ], [ 2, %27 ], [ 2, %1 ], !dbg !258
  call void @llvm.dbg.value(metadata i32 %33, metadata !250, metadata !DIExpression()), !dbg !258
  call void @llvm.dbg.label(metadata !257), !dbg !286
  call void @llvm.lifetime.start.p0(i64 4, ptr nonnull %2), !dbg !287
  call void @llvm.dbg.value(metadata ptr %0, metadata !220, metadata !DIExpression()), !dbg !287
  call void @llvm.dbg.value(metadata i32 %33, metadata !221, metadata !DIExpression()), !dbg !287
  store i32 %33, ptr %2, align 4, !tbaa !227
  %34 = load i32, ptr %3, align 4, !dbg !289, !tbaa !136
  call void @llvm.dbg.value(metadata i32 %34, metadata !222, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !287
  %35 = load i32, ptr %0, align 4, !dbg !290, !tbaa !144
  call void @llvm.dbg.value(metadata i32 %35, metadata !223, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !287
  call void @llvm.dbg.value(metadata ptr %2, metadata !221, metadata !DIExpression(DW_OP_deref)), !dbg !287
  %36 = call ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @xdp_stats_map, ptr noundef nonnull %2) #6, !dbg !291
  call void @llvm.dbg.value(metadata ptr %36, metadata !224, metadata !DIExpression()), !dbg !287
  %37 = icmp eq ptr %36, null, !dbg !292
  br i1 %37, label %48, label %38, !dbg !293

38:                                               ; preds = %32
  %39 = zext i32 %35 to i64, !dbg !294
  call void @llvm.dbg.value(metadata i64 %39, metadata !223, metadata !DIExpression()), !dbg !287
  %40 = zext i32 %34 to i64, !dbg !295
  call void @llvm.dbg.value(metadata i64 %40, metadata !222, metadata !DIExpression()), !dbg !287
  %41 = sub nsw i64 %40, %39, !dbg !296
  call void @llvm.dbg.value(metadata i64 %41, metadata !225, metadata !DIExpression()), !dbg !287
  %42 = load i64, ptr %36, align 8, !dbg !297, !tbaa !238
  %43 = add i64 %42, 1, !dbg !297
  store i64 %43, ptr %36, align 8, !dbg !297, !tbaa !238
  %44 = getelementptr inbounds %struct.datarec, ptr %36, i64 0, i32 1, !dbg !298
  %45 = load i64, ptr %44, align 8, !dbg !299, !tbaa !243
  %46 = add i64 %41, %45, !dbg !299
  store i64 %46, ptr %44, align 8, !dbg !299, !tbaa !243
  %47 = load i32, ptr %2, align 4, !dbg !300, !tbaa !227
  call void @llvm.dbg.value(metadata i32 %47, metadata !221, metadata !DIExpression()), !dbg !287
  br label %48

48:                                               ; preds = %32, %38
  %49 = phi i32 [ %47, %38 ], [ 0, %32 ], !dbg !287
  call void @llvm.lifetime.end.p0(i64 4, ptr nonnull %2), !dbg !301
  ret i32 %49, !dbg !302
}

; Function Attrs: nounwind
define dso_local i32 @xdp_redirect_func(ptr nocapture noundef readonly %0) #0 section "xdp" !dbg !303 {
  %2 = alloca i32, align 4
  call void @llvm.dbg.value(metadata ptr %0, metadata !305, metadata !DIExpression()), !dbg !316
  %3 = getelementptr inbounds %struct.xdp_md, ptr %0, i64 0, i32 1, !dbg !317
  %4 = load i32, ptr %3, align 4, !dbg !317, !tbaa !136
  %5 = zext i32 %4 to i64, !dbg !318
  %6 = inttoptr i64 %5 to ptr, !dbg !319
  call void @llvm.dbg.value(metadata ptr %6, metadata !306, metadata !DIExpression()), !dbg !316
  %7 = load i32, ptr %0, align 4, !dbg !320, !tbaa !144
  %8 = zext i32 %7 to i64, !dbg !321
  %9 = inttoptr i64 %8 to ptr, !dbg !322
  call void @llvm.dbg.value(metadata ptr %9, metadata !307, metadata !DIExpression()), !dbg !316
  call void @llvm.dbg.value(metadata i32 2, metadata !311, metadata !DIExpression()), !dbg !316
  call void @llvm.dbg.value(metadata i32 0, metadata !314, metadata !DIExpression()), !dbg !316
  call void @llvm.dbg.value(metadata ptr %9, metadata !308, metadata !DIExpression()), !dbg !316
  call void @llvm.dbg.value(metadata ptr undef, metadata !147, metadata !DIExpression()), !dbg !323
  call void @llvm.dbg.value(metadata ptr %6, metadata !154, metadata !DIExpression()), !dbg !323
  call void @llvm.dbg.value(metadata ptr undef, metadata !155, metadata !DIExpression()), !dbg !323
  call void @llvm.dbg.value(metadata ptr undef, metadata !158, metadata !DIExpression()), !dbg !325
  call void @llvm.dbg.value(metadata ptr %6, metadata !170, metadata !DIExpression()), !dbg !325
  call void @llvm.dbg.value(metadata ptr undef, metadata !171, metadata !DIExpression()), !dbg !325
  call void @llvm.dbg.value(metadata ptr null, metadata !172, metadata !DIExpression()), !dbg !325
  call void @llvm.dbg.value(metadata ptr %9, metadata !173, metadata !DIExpression()), !dbg !325
  call void @llvm.dbg.value(metadata i32 14, metadata !174, metadata !DIExpression()), !dbg !325
  %10 = getelementptr i8, ptr %9, i64 14, !dbg !327
  %11 = icmp ugt ptr %10, %6, !dbg !328
  br i1 %11, label %31, label %12, !dbg !329

12:                                               ; preds = %1
  call void @llvm.dbg.value(metadata ptr %10, metadata !308, metadata !DIExpression()), !dbg !316
  call void @llvm.dbg.value(metadata ptr %10, metadata !175, metadata !DIExpression()), !dbg !325
  %13 = getelementptr inbounds %struct.ethhdr, ptr %9, i64 0, i32 2, !dbg !330
  call void @llvm.dbg.value(metadata i16 poison, metadata !181, metadata !DIExpression()), !dbg !325
  call void @llvm.dbg.value(metadata i32 0, metadata !182, metadata !DIExpression()), !dbg !325
  %14 = load i16, ptr %13, align 1, !dbg !325, !tbaa !190
  call void @llvm.dbg.value(metadata i16 %14, metadata !181, metadata !DIExpression()), !dbg !325
  call void @llvm.dbg.value(metadata i16 %14, metadata !192, metadata !DIExpression()), !dbg !331
  %15 = icmp eq i16 %14, 129, !dbg !333
  %16 = icmp eq i16 %14, -22392, !dbg !334
  %17 = tail call i1 @llvm.bpf.passthrough.i1.i1(i32 0, i1 %15)
  %18 = or i1 %16, %17, !dbg !334
  %19 = getelementptr i8, ptr %9, i64 18
  %20 = icmp ule ptr %19, %6
  %21 = select i1 %18, i1 %20, i1 false, !dbg !335
  br i1 %21, label %22, label %27, !dbg !335

22:                                               ; preds = %12
  call void @llvm.dbg.value(metadata i16 poison, metadata !181, metadata !DIExpression()), !dbg !325
  %23 = getelementptr i8, ptr %9, i64 16, !dbg !336
  call void @llvm.dbg.value(metadata ptr %19, metadata !175, metadata !DIExpression()), !dbg !325
  call void @llvm.dbg.value(metadata i32 1, metadata !182, metadata !DIExpression()), !dbg !325
  %24 = load i16, ptr %23, align 1, !dbg !325, !tbaa !190
  call void @llvm.dbg.value(metadata i16 %24, metadata !181, metadata !DIExpression()), !dbg !325
  call void @llvm.dbg.value(metadata i16 %24, metadata !192, metadata !DIExpression()), !dbg !331
  %25 = icmp eq i16 %24, 129, !dbg !333
  %26 = tail call i1 @llvm.bpf.passthrough.i1.i1(i32 0, i1 %25)
  br label %27, !dbg !335

27:                                               ; preds = %22, %12
  call void @llvm.dbg.value(metadata ptr poison, metadata !308, metadata !DIExpression()), !dbg !316
  call void @llvm.dbg.value(metadata i16 poison, metadata !310, metadata !DIExpression(DW_OP_LLVM_convert, 16, DW_ATE_unsigned, DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !316
  call void @llvm.dbg.value(metadata ptr %9, metadata !309, metadata !DIExpression()), !dbg !316
  %28 = getelementptr inbounds %struct.ethhdr, ptr %9, i64 0, i32 1, !dbg !337
  %29 = tail call ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @redirect_params, ptr noundef nonnull %28) #6, !dbg !338
  call void @llvm.dbg.value(metadata ptr %29, metadata !312, metadata !DIExpression()), !dbg !316
  %30 = icmp eq ptr %29, null, !dbg !339
  br i1 %30, label %31, label %32, !dbg !341

31:                                               ; preds = %27, %1
  call void @llvm.dbg.value(metadata i32 2, metadata !311, metadata !DIExpression()), !dbg !316
  call void @llvm.dbg.label(metadata !315), !dbg !342
  call void @llvm.lifetime.start.p0(i64 4, ptr nonnull %2), !dbg !343
  call void @llvm.dbg.value(metadata ptr %0, metadata !220, metadata !DIExpression()), !dbg !343
  call void @llvm.dbg.value(metadata i32 2, metadata !221, metadata !DIExpression()), !dbg !343
  store i32 2, ptr %2, align 4, !tbaa !227
  call void @llvm.dbg.value(metadata i32 poison, metadata !222, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !343
  call void @llvm.dbg.value(metadata i32 poison, metadata !223, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !343
  br label %36, !dbg !345

32:                                               ; preds = %27
  call void @llvm.dbg.value(metadata ptr %9, metadata !309, metadata !DIExpression()), !dbg !316
  tail call void @llvm.memcpy.p0.p0.i64(ptr noundef nonnull align 1 dereferenceable(6) %9, ptr noundef nonnull align 1 dereferenceable(6) %29, i64 6, i1 false), !dbg !346
  %33 = tail call i64 inttoptr (i64 23 to ptr)(i32 noundef 0, i64 noundef 0) #6, !dbg !347
  %34 = trunc i64 %33 to i32, !dbg !347
  call void @llvm.dbg.value(metadata i32 %34, metadata !311, metadata !DIExpression()), !dbg !316
  call void @llvm.dbg.label(metadata !315), !dbg !342
  call void @llvm.lifetime.start.p0(i64 4, ptr nonnull %2), !dbg !343
  call void @llvm.dbg.value(metadata ptr %0, metadata !220, metadata !DIExpression()), !dbg !343
  call void @llvm.dbg.value(metadata i32 %34, metadata !221, metadata !DIExpression()), !dbg !343
  store i32 %34, ptr %2, align 4, !tbaa !227
  call void @llvm.dbg.value(metadata i32 poison, metadata !222, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !343
  call void @llvm.dbg.value(metadata i32 poison, metadata !223, metadata !DIExpression(DW_OP_LLVM_convert, 32, DW_ATE_unsigned, DW_OP_LLVM_convert, 64, DW_ATE_unsigned, DW_OP_stack_value)), !dbg !343
  %35 = icmp ugt i32 %34, 4, !dbg !348
  br i1 %35, label %51, label %36, !dbg !345

36:                                               ; preds = %31, %32
  %37 = load i32, ptr %3, align 4, !dbg !350, !tbaa !136
  %38 = load i32, ptr %0, align 4, !dbg !351, !tbaa !144
  call void @llvm.dbg.value(metadata ptr %2, metadata !221, metadata !DIExpression(DW_OP_deref)), !dbg !343
  %39 = call ptr inttoptr (i64 1 to ptr)(ptr noundef nonnull @xdp_stats_map, ptr noundef nonnull %2) #6, !dbg !352
  call void @llvm.dbg.value(metadata ptr %39, metadata !224, metadata !DIExpression()), !dbg !343
  %40 = icmp eq ptr %39, null, !dbg !353
  br i1 %40, label %51, label %41, !dbg !354

41:                                               ; preds = %36
  %42 = zext i32 %37 to i64, !dbg !355
  %43 = zext i32 %38 to i64, !dbg !356
  %44 = sub nsw i64 %42, %43, !dbg !357
  call void @llvm.dbg.value(metadata i64 %44, metadata !225, metadata !DIExpression()), !dbg !343
  %45 = load i64, ptr %39, align 8, !dbg !358, !tbaa !238
  %46 = add i64 %45, 1, !dbg !358
  store i64 %46, ptr %39, align 8, !dbg !358, !tbaa !238
  %47 = getelementptr inbounds %struct.datarec, ptr %39, i64 0, i32 1, !dbg !359
  %48 = load i64, ptr %47, align 8, !dbg !360, !tbaa !243
  %49 = add i64 %44, %48, !dbg !360
  store i64 %49, ptr %47, align 8, !dbg !360, !tbaa !243
  %50 = load i32, ptr %2, align 4, !dbg !361, !tbaa !227
  call void @llvm.dbg.value(metadata i32 %50, metadata !221, metadata !DIExpression()), !dbg !343
  br label %51

51:                                               ; preds = %32, %36, %41
  %52 = phi i32 [ 0, %32 ], [ %50, %41 ], [ 0, %36 ], !dbg !343
  call void @llvm.lifetime.end.p0(i64 4, ptr nonnull %2), !dbg !362
  ret i32 %52, !dbg !363
}

; Function Attrs: mustprogress nocallback nofree nounwind willreturn memory(argmem: readwrite)
declare void @llvm.memcpy.p0.p0.i64(ptr noalias nocapture writeonly, ptr noalias nocapture readonly, i64, i1 immarg) #3

; Function Attrs: nocallback nofree nosync nounwind speculatable willreturn memory(none)
declare void @llvm.dbg.value(metadata, metadata, metadata) #4

; Function Attrs: nounwind memory(none)
declare i1 @llvm.bpf.passthrough.i1.i1(i32, i1) #5

attributes #0 = { nounwind "frame-pointer"="all" "no-trapping-math"="true" "stack-protector-buffer-size"="8" }
attributes #1 = { mustprogress nocallback nofree nosync nounwind willreturn memory(argmem: readwrite) }
attributes #2 = { mustprogress nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #3 = { mustprogress nocallback nofree nounwind willreturn memory(argmem: readwrite) }
attributes #4 = { nocallback nofree nosync nounwind speculatable willreturn memory(none) }
attributes #5 = { nounwind memory(none) }
attributes #6 = { nounwind }

!llvm.dbg.cu = !{!2}
!llvm.module.flags = !{!93, !94, !95, !96}
!llvm.ident = !{!97}

!0 = !DIGlobalVariableExpression(var: !1, expr: !DIExpression())
!1 = distinct !DIGlobalVariable(name: "src_macs", scope: !2, file: !3, line: 30, type: !82, isLocal: false, isDefinition: true)
!2 = distinct !DICompileUnit(language: DW_LANG_C11, file: !3, producer: "Ubuntu clang version 16.0.6 (15)", isOptimized: true, runtimeVersion: 0, emissionKind: FullDebug, enums: !4, retainedTypes: !14, globals: !20, splitDebugInlining: false, nameTableKind: None)
!3 = !DIFile(filename: "xdp_prog_kern.c", directory: "/home/a/lmp/eBPF_Supermarket/Network_Subsystem/net_manager/xacl_core", checksumkind: CSK_MD5, checksum: "9a73bc09468517283373b60d537953aa")
!4 = !{!5}
!5 = !DICompositeType(tag: DW_TAG_enumeration_type, name: "xdp_action", file: !6, line: 6201, baseType: !7, size: 32, elements: !8)
!6 = !DIFile(filename: "/usr/include/linux/bpf.h", directory: "", checksumkind: CSK_MD5, checksum: "c8368d268df2d203be10308c6a67c158")
!7 = !DIBasicType(name: "unsigned int", size: 32, encoding: DW_ATE_unsigned)
!8 = !{!9, !10, !11, !12, !13}
!9 = !DIEnumerator(name: "XDP_ABORTED", value: 0)
!10 = !DIEnumerator(name: "XDP_DROP", value: 1)
!11 = !DIEnumerator(name: "XDP_PASS", value: 2)
!12 = !DIEnumerator(name: "XDP_TX", value: 3)
!13 = !DIEnumerator(name: "XDP_REDIRECT", value: 4)
!14 = !{!15, !16, !17}
!15 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: null, size: 64)
!16 = !DIBasicType(name: "long", size: 64, encoding: DW_ATE_signed)
!17 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u16", file: !18, line: 24, baseType: !19)
!18 = !DIFile(filename: "/usr/include/asm-generic/int-ll64.h", directory: "", checksumkind: CSK_MD5, checksum: "b810f270733e106319b67ef512c6246e")
!19 = !DIBasicType(name: "unsigned short", size: 16, encoding: DW_ATE_unsigned)
!20 = !{!21, !27, !0, !54, !69, !77}
!21 = !DIGlobalVariableExpression(var: !22, expr: !DIExpression())
!22 = distinct !DIGlobalVariable(name: "_license", scope: !2, file: !3, line: 173, type: !23, isLocal: false, isDefinition: true)
!23 = !DICompositeType(tag: DW_TAG_array_type, baseType: !24, size: 32, elements: !25)
!24 = !DIBasicType(name: "char", size: 8, encoding: DW_ATE_signed_char)
!25 = !{!26}
!26 = !DISubrange(count: 4)
!27 = !DIGlobalVariableExpression(var: !28, expr: !DIExpression())
!28 = distinct !DIGlobalVariable(name: "xdp_stats_map", scope: !2, file: !3, line: 22, type: !29, isLocal: false, isDefinition: true)
!29 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 17, size: 256, elements: !30)
!30 = !{!31, !37, !40, !49}
!31 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !29, file: !3, line: 18, baseType: !32, size: 64)
!32 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !33, size: 64)
!33 = !DICompositeType(tag: DW_TAG_array_type, baseType: !34, size: 192, elements: !35)
!34 = !DIBasicType(name: "int", size: 32, encoding: DW_ATE_signed)
!35 = !{!36}
!36 = !DISubrange(count: 6)
!37 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !29, file: !3, line: 19, baseType: !38, size: 64, offset: 64)
!38 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !39, size: 64)
!39 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u32", file: !18, line: 27, baseType: !7)
!40 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !29, file: !3, line: 20, baseType: !41, size: 64, offset: 128)
!41 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !42, size: 64)
!42 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "datarec", file: !43, line: 14, size: 128, elements: !44)
!43 = !DIFile(filename: "./common_kern_user.h", directory: "/home/a/lmp/eBPF_Supermarket/Network_Subsystem/net_manager/xacl_core", checksumkind: CSK_MD5, checksum: "d34c6fe3156fc1c7e021a5224c55042b")
!44 = !{!45, !48}
!45 = !DIDerivedType(tag: DW_TAG_member, name: "rx_packets", scope: !42, file: !43, line: 15, baseType: !46, size: 64)
!46 = !DIDerivedType(tag: DW_TAG_typedef, name: "__u64", file: !18, line: 31, baseType: !47)
!47 = !DIBasicType(name: "unsigned long long", size: 64, encoding: DW_ATE_unsigned)
!48 = !DIDerivedType(tag: DW_TAG_member, name: "rx_bytes", scope: !42, file: !43, line: 16, baseType: !46, size: 64, offset: 64)
!49 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !29, file: !3, line: 21, baseType: !50, size: 64, offset: 192)
!50 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !51, size: 64)
!51 = !DICompositeType(tag: DW_TAG_array_type, baseType: !34, size: 160, elements: !52)
!52 = !{!53}
!53 = !DISubrange(count: 5)
!54 = !DIGlobalVariableExpression(var: !55, expr: !DIExpression())
!55 = distinct !DIGlobalVariable(name: "redirect_params", scope: !2, file: !3, line: 38, type: !56, isLocal: false, isDefinition: true)
!56 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 33, size: 256, elements: !57)
!57 = !{!58, !63, !67, !68}
!58 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !56, file: !3, line: 34, baseType: !59, size: 64)
!59 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !60, size: 64)
!60 = !DICompositeType(tag: DW_TAG_array_type, baseType: !34, size: 32, elements: !61)
!61 = !{!62}
!62 = !DISubrange(count: 1)
!63 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !56, file: !3, line: 35, baseType: !64, size: 64, offset: 64)
!64 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !65, size: 64)
!65 = !DICompositeType(tag: DW_TAG_array_type, baseType: !66, size: 48, elements: !35)
!66 = !DIBasicType(name: "unsigned char", size: 8, encoding: DW_ATE_unsigned_char)
!67 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !56, file: !3, line: 36, baseType: !64, size: 64, offset: 128)
!68 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !56, file: !3, line: 37, baseType: !59, size: 64, offset: 192)
!69 = !DIGlobalVariableExpression(var: !70, expr: !DIExpression())
!70 = distinct !DIGlobalVariable(name: "bpf_map_lookup_elem", scope: !2, file: !71, line: 56, type: !72, isLocal: true, isDefinition: true)
!71 = !DIFile(filename: "../lib/install/include/bpf/bpf_helper_defs.h", directory: "/home/a/lmp/eBPF_Supermarket/Network_Subsystem/net_manager/xacl_core", checksumkind: CSK_MD5, checksum: "5260f06f90b94eed43b746c45e4828c2")
!72 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !73, size: 64)
!73 = !DISubroutineType(types: !74)
!74 = !{!15, !15, !75}
!75 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !76, size: 64)
!76 = !DIDerivedType(tag: DW_TAG_const_type, baseType: null)
!77 = !DIGlobalVariableExpression(var: !78, expr: !DIExpression())
!78 = distinct !DIGlobalVariable(name: "bpf_redirect", scope: !2, file: !71, line: 621, type: !79, isLocal: true, isDefinition: true)
!79 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !80, size: 64)
!80 = !DISubroutineType(types: !81)
!81 = !{!16, !39, !46}
!82 = distinct !DICompositeType(tag: DW_TAG_structure_type, file: !3, line: 25, size: 256, elements: !83)
!83 = !{!84, !85, !87, !88}
!84 = !DIDerivedType(tag: DW_TAG_member, name: "type", scope: !82, file: !3, line: 26, baseType: !59, size: 64)
!85 = !DIDerivedType(tag: DW_TAG_member, name: "key", scope: !82, file: !3, line: 27, baseType: !86, size: 64, offset: 64)
!86 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !34, size: 64)
!87 = !DIDerivedType(tag: DW_TAG_member, name: "value", scope: !82, file: !3, line: 28, baseType: !38, size: 64, offset: 128)
!88 = !DIDerivedType(tag: DW_TAG_member, name: "max_entries", scope: !82, file: !3, line: 29, baseType: !89, size: 64, offset: 192)
!89 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !90, size: 64)
!90 = !DICompositeType(tag: DW_TAG_array_type, baseType: !34, size: 32768, elements: !91)
!91 = !{!92}
!92 = !DISubrange(count: 1024)
!93 = !{i32 7, !"Dwarf Version", i32 5}
!94 = !{i32 2, !"Debug Info Version", i32 3}
!95 = !{i32 1, !"wchar_size", i32 4}
!96 = !{i32 7, !"frame-pointer", i32 2}
!97 = !{!"Ubuntu clang version 16.0.6 (15)"}
!98 = distinct !DISubprogram(name: "filter_ethernet_pass", scope: !3, file: !3, line: 70, type: !99, scopeLine: 71, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !110)
!99 = !DISubroutineType(types: !100)
!100 = !{!34, !101}
!101 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !102, size: 64)
!102 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "xdp_md", file: !6, line: 6212, size: 192, elements: !103)
!103 = !{!104, !105, !106, !107, !108, !109}
!104 = !DIDerivedType(tag: DW_TAG_member, name: "data", scope: !102, file: !6, line: 6213, baseType: !39, size: 32)
!105 = !DIDerivedType(tag: DW_TAG_member, name: "data_end", scope: !102, file: !6, line: 6214, baseType: !39, size: 32, offset: 32)
!106 = !DIDerivedType(tag: DW_TAG_member, name: "data_meta", scope: !102, file: !6, line: 6215, baseType: !39, size: 32, offset: 64)
!107 = !DIDerivedType(tag: DW_TAG_member, name: "ingress_ifindex", scope: !102, file: !6, line: 6217, baseType: !39, size: 32, offset: 96)
!108 = !DIDerivedType(tag: DW_TAG_member, name: "rx_queue_index", scope: !102, file: !6, line: 6218, baseType: !39, size: 32, offset: 128)
!109 = !DIDerivedType(tag: DW_TAG_member, name: "egress_ifindex", scope: !102, file: !6, line: 6220, baseType: !39, size: 32, offset: 160)
!110 = !{!111, !112, !114, !115, !116, !121, !122, !132, !133}
!111 = !DILocalVariable(name: "ctx", arg: 1, scope: !98, file: !3, line: 70, type: !101)
!112 = !DILocalVariable(name: "action", scope: !98, file: !3, line: 72, type: !113)
!113 = !DIDerivedType(tag: DW_TAG_typedef, name: "xdp_act", file: !43, line: 9, baseType: !39)
!114 = !DILocalVariable(name: "data_end", scope: !98, file: !3, line: 73, type: !15)
!115 = !DILocalVariable(name: "data", scope: !98, file: !3, line: 74, type: !15)
!116 = !DILocalVariable(name: "nh", scope: !98, file: !3, line: 75, type: !117)
!117 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "hdr_cursor", file: !118, line: 33, size: 64, elements: !119)
!118 = !DIFile(filename: "./../common/parsing_helpers.h", directory: "/home/a/lmp/eBPF_Supermarket/Network_Subsystem/net_manager/xacl_core", checksumkind: CSK_MD5, checksum: "172efdd203783aed49c0ce78645261a8")
!119 = !{!120}
!120 = !DIDerivedType(tag: DW_TAG_member, name: "pos", scope: !117, file: !118, line: 34, baseType: !15, size: 64)
!121 = !DILocalVariable(name: "nh_type", scope: !98, file: !3, line: 76, type: !34)
!122 = !DILocalVariable(name: "eth", scope: !98, file: !3, line: 77, type: !123)
!123 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !124, size: 64)
!124 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "ethhdr", file: !125, line: 173, size: 112, elements: !126)
!125 = !DIFile(filename: "/usr/include/linux/if_ether.h", directory: "", checksumkind: CSK_MD5, checksum: "163f54fb1af2e21fea410f14eb18fa76")
!126 = !{!127, !128, !129}
!127 = !DIDerivedType(tag: DW_TAG_member, name: "h_dest", scope: !124, file: !125, line: 174, baseType: !65, size: 48)
!128 = !DIDerivedType(tag: DW_TAG_member, name: "h_source", scope: !124, file: !125, line: 175, baseType: !65, size: 48, offset: 48)
!129 = !DIDerivedType(tag: DW_TAG_member, name: "h_proto", scope: !124, file: !125, line: 176, baseType: !130, size: 16, offset: 96)
!130 = !DIDerivedType(tag: DW_TAG_typedef, name: "__be16", file: !131, line: 32, baseType: !17)
!131 = !DIFile(filename: "/usr/include/linux/types.h", directory: "", checksumkind: CSK_MD5, checksum: "bf9fbc0e8f60927fef9d8917535375a6")
!132 = !DILocalVariable(name: "value", scope: !98, file: !3, line: 78, type: !38)
!133 = !DILabel(scope: !98, name: "out", file: !3, line: 98)
!134 = !DILocation(line: 0, scope: !98)
!135 = !DILocation(line: 73, column: 38, scope: !98)
!136 = !{!137, !138, i64 4}
!137 = !{!"xdp_md", !138, i64 0, !138, i64 4, !138, i64 8, !138, i64 12, !138, i64 16, !138, i64 20}
!138 = !{!"int", !139, i64 0}
!139 = !{!"omnipotent char", !140, i64 0}
!140 = !{!"Simple C/C++ TBAA"}
!141 = !DILocation(line: 73, column: 27, scope: !98)
!142 = !DILocation(line: 73, column: 19, scope: !98)
!143 = !DILocation(line: 74, column: 34, scope: !98)
!144 = !{!137, !138, i64 0}
!145 = !DILocation(line: 74, column: 23, scope: !98)
!146 = !DILocation(line: 74, column: 15, scope: !98)
!147 = !DILocalVariable(name: "nh", arg: 1, scope: !148, file: !118, line: 124, type: !151)
!148 = distinct !DISubprogram(name: "parse_ethhdr", scope: !118, file: !118, line: 124, type: !149, scopeLine: 127, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !153)
!149 = !DISubroutineType(types: !150)
!150 = !{!34, !151, !15, !152}
!151 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !117, size: 64)
!152 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !123, size: 64)
!153 = !{!147, !154, !155}
!154 = !DILocalVariable(name: "data_end", arg: 2, scope: !148, file: !118, line: 125, type: !15)
!155 = !DILocalVariable(name: "ethhdr", arg: 3, scope: !148, file: !118, line: 126, type: !152)
!156 = !DILocation(line: 0, scope: !148, inlinedAt: !157)
!157 = distinct !DILocation(line: 83, column: 12, scope: !98)
!158 = !DILocalVariable(name: "nh", arg: 1, scope: !159, file: !118, line: 79, type: !151)
!159 = distinct !DISubprogram(name: "parse_ethhdr_vlan", scope: !118, file: !118, line: 79, type: !160, scopeLine: 83, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !169)
!160 = !DISubroutineType(types: !161)
!161 = !{!34, !151, !15, !152, !162}
!162 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !163, size: 64)
!163 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "collect_vlans", file: !118, line: 64, size: 32, elements: !164)
!164 = !{!165}
!165 = !DIDerivedType(tag: DW_TAG_member, name: "id", scope: !163, file: !118, line: 65, baseType: !166, size: 32)
!166 = !DICompositeType(tag: DW_TAG_array_type, baseType: !17, size: 32, elements: !167)
!167 = !{!168}
!168 = !DISubrange(count: 2)
!169 = !{!158, !170, !171, !172, !173, !174, !175, !181, !182}
!170 = !DILocalVariable(name: "data_end", arg: 2, scope: !159, file: !118, line: 80, type: !15)
!171 = !DILocalVariable(name: "ethhdr", arg: 3, scope: !159, file: !118, line: 81, type: !152)
!172 = !DILocalVariable(name: "vlans", arg: 4, scope: !159, file: !118, line: 82, type: !162)
!173 = !DILocalVariable(name: "eth", scope: !159, file: !118, line: 84, type: !123)
!174 = !DILocalVariable(name: "hdrsize", scope: !159, file: !118, line: 85, type: !34)
!175 = !DILocalVariable(name: "vlh", scope: !159, file: !118, line: 86, type: !176)
!176 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !177, size: 64)
!177 = distinct !DICompositeType(tag: DW_TAG_structure_type, name: "vlan_hdr", file: !118, line: 42, size: 32, elements: !178)
!178 = !{!179, !180}
!179 = !DIDerivedType(tag: DW_TAG_member, name: "h_vlan_TCI", scope: !177, file: !118, line: 43, baseType: !130, size: 16)
!180 = !DIDerivedType(tag: DW_TAG_member, name: "h_vlan_encapsulated_proto", scope: !177, file: !118, line: 44, baseType: !130, size: 16, offset: 16)
!181 = !DILocalVariable(name: "h_proto", scope: !159, file: !118, line: 87, type: !17)
!182 = !DILocalVariable(name: "i", scope: !159, file: !118, line: 88, type: !34)
!183 = !DILocation(line: 0, scope: !159, inlinedAt: !184)
!184 = distinct !DILocation(line: 129, column: 9, scope: !148, inlinedAt: !157)
!185 = !DILocation(line: 93, column: 14, scope: !186, inlinedAt: !184)
!186 = distinct !DILexicalBlock(scope: !159, file: !118, line: 93, column: 6)
!187 = !DILocation(line: 93, column: 24, scope: !186, inlinedAt: !184)
!188 = !DILocation(line: 93, column: 6, scope: !159, inlinedAt: !184)
!189 = !DILocation(line: 99, column: 17, scope: !159, inlinedAt: !184)
!190 = !{!191, !191, i64 0}
!191 = !{!"short", !139, i64 0}
!192 = !DILocalVariable(name: "h_proto", arg: 1, scope: !193, file: !118, line: 68, type: !17)
!193 = distinct !DISubprogram(name: "proto_is_vlan", scope: !118, file: !118, line: 68, type: !194, scopeLine: 69, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !196)
!194 = !DISubroutineType(types: !195)
!195 = !{!34, !17}
!196 = !{!192}
!197 = !DILocation(line: 0, scope: !193, inlinedAt: !198)
!198 = distinct !DILocation(line: 106, column: 8, scope: !199, inlinedAt: !184)
!199 = distinct !DILexicalBlock(scope: !200, file: !118, line: 106, column: 7)
!200 = distinct !DILexicalBlock(scope: !201, file: !118, line: 105, column: 39)
!201 = distinct !DILexicalBlock(scope: !202, file: !118, line: 105, column: 2)
!202 = distinct !DILexicalBlock(scope: !159, file: !118, line: 105, column: 2)
!203 = !DILocation(line: 70, column: 20, scope: !193, inlinedAt: !198)
!204 = !DILocation(line: 70, column: 46, scope: !193, inlinedAt: !198)
!205 = !DILocation(line: 106, column: 7, scope: !200, inlinedAt: !184)
!206 = !DILocation(line: 112, column: 18, scope: !200, inlinedAt: !184)
!207 = !DILocation(line: 91, column: 46, scope: !98)
!208 = !DILocation(line: 91, column: 10, scope: !98)
!209 = !DILocation(line: 92, column: 6, scope: !210)
!210 = distinct !DILexicalBlock(scope: !98, file: !3, line: 92, column: 6)
!211 = !DILocation(line: 92, column: 6, scope: !98)
!212 = !DILocation(line: 95, column: 3, scope: !213)
!213 = distinct !DILexicalBlock(scope: !210, file: !3, line: 92, column: 13)
!214 = !DILocation(line: 98, column: 1, scope: !98)
!215 = !DILocation(line: 0, scope: !216, inlinedAt: !226)
!216 = distinct !DISubprogram(name: "xdp_stats_record_action", scope: !3, file: !3, line: 41, type: !217, scopeLine: 42, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagLocalToUnit | DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !219)
!217 = !DISubroutineType(types: !218)
!218 = !{!39, !101, !39}
!219 = !{!220, !221, !222, !223, !224, !225}
!220 = !DILocalVariable(name: "ctx", arg: 1, scope: !216, file: !3, line: 41, type: !101)
!221 = !DILocalVariable(name: "action", arg: 2, scope: !216, file: !3, line: 41, type: !39)
!222 = !DILocalVariable(name: "data_end", scope: !216, file: !3, line: 43, type: !15)
!223 = !DILocalVariable(name: "data", scope: !216, file: !3, line: 44, type: !15)
!224 = !DILocalVariable(name: "rec", scope: !216, file: !3, line: 50, type: !41)
!225 = !DILocalVariable(name: "bytes", scope: !216, file: !3, line: 55, type: !46)
!226 = distinct !DILocation(line: 99, column: 9, scope: !98)
!227 = !{!138, !138, i64 0}
!228 = !DILocation(line: 43, column: 38, scope: !216, inlinedAt: !226)
!229 = !DILocation(line: 44, column: 38, scope: !216, inlinedAt: !226)
!230 = !DILocation(line: 50, column: 24, scope: !216, inlinedAt: !226)
!231 = !DILocation(line: 51, column: 7, scope: !232, inlinedAt: !226)
!232 = distinct !DILexicalBlock(scope: !216, file: !3, line: 51, column: 6)
!233 = !DILocation(line: 51, column: 6, scope: !216, inlinedAt: !226)
!234 = !DILocation(line: 44, column: 27, scope: !216, inlinedAt: !226)
!235 = !DILocation(line: 43, column: 27, scope: !216, inlinedAt: !226)
!236 = !DILocation(line: 55, column: 25, scope: !216, inlinedAt: !226)
!237 = !DILocation(line: 61, column: 17, scope: !216, inlinedAt: !226)
!238 = !{!239, !240, i64 0}
!239 = !{!"datarec", !240, i64 0, !240, i64 8}
!240 = !{!"long long", !139, i64 0}
!241 = !DILocation(line: 62, column: 7, scope: !216, inlinedAt: !226)
!242 = !DILocation(line: 62, column: 16, scope: !216, inlinedAt: !226)
!243 = !{!239, !240, i64 8}
!244 = !DILocation(line: 64, column: 9, scope: !216, inlinedAt: !226)
!245 = !DILocation(line: 65, column: 1, scope: !216, inlinedAt: !226)
!246 = !DILocation(line: 99, column: 2, scope: !98)
!247 = distinct !DISubprogram(name: "filter_ethernet_drop", scope: !3, file: !3, line: 104, type: !99, scopeLine: 105, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !248)
!248 = !{!249, !250, !251, !252, !253, !254, !255, !256, !257}
!249 = !DILocalVariable(name: "ctx", arg: 1, scope: !247, file: !3, line: 104, type: !101)
!250 = !DILocalVariable(name: "action", scope: !247, file: !3, line: 106, type: !113)
!251 = !DILocalVariable(name: "data_end", scope: !247, file: !3, line: 107, type: !15)
!252 = !DILocalVariable(name: "data", scope: !247, file: !3, line: 108, type: !15)
!253 = !DILocalVariable(name: "nh", scope: !247, file: !3, line: 109, type: !117)
!254 = !DILocalVariable(name: "nh_type", scope: !247, file: !3, line: 110, type: !34)
!255 = !DILocalVariable(name: "eth", scope: !247, file: !3, line: 111, type: !123)
!256 = !DILocalVariable(name: "value", scope: !247, file: !3, line: 112, type: !38)
!257 = !DILabel(scope: !247, name: "out", file: !3, line: 131)
!258 = !DILocation(line: 0, scope: !247)
!259 = !DILocation(line: 107, column: 38, scope: !247)
!260 = !DILocation(line: 107, column: 27, scope: !247)
!261 = !DILocation(line: 107, column: 19, scope: !247)
!262 = !DILocation(line: 108, column: 34, scope: !247)
!263 = !DILocation(line: 108, column: 23, scope: !247)
!264 = !DILocation(line: 108, column: 15, scope: !247)
!265 = !DILocation(line: 0, scope: !148, inlinedAt: !266)
!266 = distinct !DILocation(line: 117, column: 12, scope: !247)
!267 = !DILocation(line: 0, scope: !159, inlinedAt: !268)
!268 = distinct !DILocation(line: 129, column: 9, scope: !148, inlinedAt: !266)
!269 = !DILocation(line: 93, column: 14, scope: !186, inlinedAt: !268)
!270 = !DILocation(line: 93, column: 24, scope: !186, inlinedAt: !268)
!271 = !DILocation(line: 93, column: 6, scope: !159, inlinedAt: !268)
!272 = !DILocation(line: 99, column: 17, scope: !159, inlinedAt: !268)
!273 = !DILocation(line: 0, scope: !193, inlinedAt: !274)
!274 = distinct !DILocation(line: 106, column: 8, scope: !199, inlinedAt: !268)
!275 = !DILocation(line: 70, column: 20, scope: !193, inlinedAt: !274)
!276 = !DILocation(line: 70, column: 46, scope: !193, inlinedAt: !274)
!277 = !DILocation(line: 106, column: 7, scope: !200, inlinedAt: !268)
!278 = !DILocation(line: 112, column: 18, scope: !200, inlinedAt: !268)
!279 = !DILocation(line: 124, column: 46, scope: !247)
!280 = !DILocation(line: 124, column: 10, scope: !247)
!281 = !DILocation(line: 125, column: 6, scope: !282)
!282 = distinct !DILexicalBlock(scope: !247, file: !3, line: 125, column: 6)
!283 = !DILocation(line: 125, column: 6, scope: !247)
!284 = !DILocation(line: 128, column: 3, scope: !285)
!285 = distinct !DILexicalBlock(scope: !282, file: !3, line: 125, column: 13)
!286 = !DILocation(line: 131, column: 1, scope: !247)
!287 = !DILocation(line: 0, scope: !216, inlinedAt: !288)
!288 = distinct !DILocation(line: 132, column: 9, scope: !247)
!289 = !DILocation(line: 43, column: 38, scope: !216, inlinedAt: !288)
!290 = !DILocation(line: 44, column: 38, scope: !216, inlinedAt: !288)
!291 = !DILocation(line: 50, column: 24, scope: !216, inlinedAt: !288)
!292 = !DILocation(line: 51, column: 7, scope: !232, inlinedAt: !288)
!293 = !DILocation(line: 51, column: 6, scope: !216, inlinedAt: !288)
!294 = !DILocation(line: 44, column: 27, scope: !216, inlinedAt: !288)
!295 = !DILocation(line: 43, column: 27, scope: !216, inlinedAt: !288)
!296 = !DILocation(line: 55, column: 25, scope: !216, inlinedAt: !288)
!297 = !DILocation(line: 61, column: 17, scope: !216, inlinedAt: !288)
!298 = !DILocation(line: 62, column: 7, scope: !216, inlinedAt: !288)
!299 = !DILocation(line: 62, column: 16, scope: !216, inlinedAt: !288)
!300 = !DILocation(line: 64, column: 9, scope: !216, inlinedAt: !288)
!301 = !DILocation(line: 65, column: 1, scope: !216, inlinedAt: !288)
!302 = !DILocation(line: 132, column: 2, scope: !247)
!303 = distinct !DISubprogram(name: "xdp_redirect_func", scope: !3, file: !3, line: 137, type: !99, scopeLine: 138, flags: DIFlagPrototyped | DIFlagAllCallsDescribed, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !304)
!304 = !{!305, !306, !307, !308, !309, !310, !311, !312, !314, !315}
!305 = !DILocalVariable(name: "ctx", arg: 1, scope: !303, file: !3, line: 137, type: !101)
!306 = !DILocalVariable(name: "data_end", scope: !303, file: !3, line: 139, type: !15)
!307 = !DILocalVariable(name: "data", scope: !303, file: !3, line: 140, type: !15)
!308 = !DILocalVariable(name: "nh", scope: !303, file: !3, line: 141, type: !117)
!309 = !DILocalVariable(name: "eth", scope: !303, file: !3, line: 142, type: !123)
!310 = !DILocalVariable(name: "eth_type", scope: !303, file: !3, line: 143, type: !34)
!311 = !DILocalVariable(name: "action", scope: !303, file: !3, line: 144, type: !34)
!312 = !DILocalVariable(name: "dst", scope: !303, file: !3, line: 145, type: !313)
!313 = !DIDerivedType(tag: DW_TAG_pointer_type, baseType: !66, size: 64)
!314 = !DILocalVariable(name: "ifindex", scope: !303, file: !3, line: 146, type: !7)
!315 = !DILabel(scope: !303, name: "out", file: !3, line: 168)
!316 = !DILocation(line: 0, scope: !303)
!317 = !DILocation(line: 139, column: 38, scope: !303)
!318 = !DILocation(line: 139, column: 27, scope: !303)
!319 = !DILocation(line: 139, column: 19, scope: !303)
!320 = !DILocation(line: 140, column: 34, scope: !303)
!321 = !DILocation(line: 140, column: 23, scope: !303)
!322 = !DILocation(line: 140, column: 15, scope: !303)
!323 = !DILocation(line: 0, scope: !148, inlinedAt: !324)
!324 = distinct !DILocation(line: 152, column: 13, scope: !303)
!325 = !DILocation(line: 0, scope: !159, inlinedAt: !326)
!326 = distinct !DILocation(line: 129, column: 9, scope: !148, inlinedAt: !324)
!327 = !DILocation(line: 93, column: 14, scope: !186, inlinedAt: !326)
!328 = !DILocation(line: 93, column: 24, scope: !186, inlinedAt: !326)
!329 = !DILocation(line: 93, column: 6, scope: !159, inlinedAt: !326)
!330 = !DILocation(line: 99, column: 17, scope: !159, inlinedAt: !326)
!331 = !DILocation(line: 0, scope: !193, inlinedAt: !332)
!332 = distinct !DILocation(line: 106, column: 8, scope: !199, inlinedAt: !326)
!333 = !DILocation(line: 70, column: 20, scope: !193, inlinedAt: !332)
!334 = !DILocation(line: 70, column: 46, scope: !193, inlinedAt: !332)
!335 = !DILocation(line: 106, column: 7, scope: !200, inlinedAt: !326)
!336 = !DILocation(line: 112, column: 18, scope: !200, inlinedAt: !326)
!337 = !DILocation(line: 157, column: 51, scope: !303)
!338 = !DILocation(line: 157, column: 8, scope: !303)
!339 = !DILocation(line: 158, column: 7, scope: !340)
!340 = distinct !DILexicalBlock(scope: !303, file: !3, line: 158, column: 6)
!341 = !DILocation(line: 158, column: 6, scope: !303)
!342 = !DILocation(line: 168, column: 1, scope: !303)
!343 = !DILocation(line: 0, scope: !216, inlinedAt: !344)
!344 = distinct !DILocation(line: 169, column: 9, scope: !303)
!345 = !DILocation(line: 46, column: 6, scope: !216, inlinedAt: !344)
!346 = !DILocation(line: 162, column: 2, scope: !303)
!347 = !DILocation(line: 165, column: 11, scope: !303)
!348 = !DILocation(line: 46, column: 13, scope: !349, inlinedAt: !344)
!349 = distinct !DILexicalBlock(scope: !216, file: !3, line: 46, column: 6)
!350 = !DILocation(line: 43, column: 38, scope: !216, inlinedAt: !344)
!351 = !DILocation(line: 44, column: 38, scope: !216, inlinedAt: !344)
!352 = !DILocation(line: 50, column: 24, scope: !216, inlinedAt: !344)
!353 = !DILocation(line: 51, column: 7, scope: !232, inlinedAt: !344)
!354 = !DILocation(line: 51, column: 6, scope: !216, inlinedAt: !344)
!355 = !DILocation(line: 43, column: 27, scope: !216, inlinedAt: !344)
!356 = !DILocation(line: 44, column: 27, scope: !216, inlinedAt: !344)
!357 = !DILocation(line: 55, column: 25, scope: !216, inlinedAt: !344)
!358 = !DILocation(line: 61, column: 17, scope: !216, inlinedAt: !344)
!359 = !DILocation(line: 62, column: 7, scope: !216, inlinedAt: !344)
!360 = !DILocation(line: 62, column: 16, scope: !216, inlinedAt: !344)
!361 = !DILocation(line: 64, column: 9, scope: !216, inlinedAt: !344)
!362 = !DILocation(line: 65, column: 1, scope: !216, inlinedAt: !344)
!363 = !DILocation(line: 169, column: 2, scope: !303)
