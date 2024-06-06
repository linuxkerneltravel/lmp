#include <stdio.h>
/*----------------------------------------------*/
/*          ewma算法                            */
/*----------------------------------------------*/
//滑动窗口周期，用于计算alpha
#define CYCLE 10
//阈值容错空间；
#define TOLERANCE 1.0
struct ewma_info{
	double previousEWMA;
	int count;
	int cycle;//cycle是滑动窗口周期大小
};

double calculateEWMA(double previousEWMA, double dataPoint, double alpha) {
    return alpha * dataPoint + (1 - alpha) * previousEWMA;//当前时间点的ewma
}

bool dynamic_filter(struct ewma_info *ewma_syscall_delay, double dataPoint) {
    double alpha,ewma,threshold;;
	if(ewma_syscall_delay->cycle==0) alpha = 2.0 /(CYCLE + 1); // 计算 alpha
	else alpha = 2.0 /(ewma_syscall_delay->cycle + 1); 

	if(ewma_syscall_delay->previousEWMA == 0) {//初始化ewma算法，则赋值previousEWMA = dataPoint 并打印
		ewma_syscall_delay->previousEWMA = dataPoint;
		return 1;
	}
	if(ewma_syscall_delay->count <30){
		ewma_syscall_delay->previousEWMA = calculateEWMA(ewma_syscall_delay->previousEWMA,dataPoint,alpha);//计算
		return 1;
	}
	else{
		ewma_syscall_delay->previousEWMA = calculateEWMA(ewma_syscall_delay->previousEWMA,dataPoint,alpha);//计算
		threshold = ewma_syscall_delay->previousEWMA * TOLERANCE;
		if(dataPoint >= threshold) return 1;
	}
    return 0;
}