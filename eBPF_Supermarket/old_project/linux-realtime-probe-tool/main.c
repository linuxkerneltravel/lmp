#include <linux/module.h>
#include <linux/init.h>
#include "include/proc.h"


static int __init my_init(void)
{
	root_init();
    node_init();
	return 0;
}

static void __exit my_exit(void)
{
    if(getNodeParm(enable)!=0)
        changeEnableStatus(OFF);
    
    node_exit();
	root_exit();
}

module_init(my_init);
module_exit(my_exit);
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
MODULE_DESCRIPTION("trace irq info");
MODULE_AUTHOR("XUPT");