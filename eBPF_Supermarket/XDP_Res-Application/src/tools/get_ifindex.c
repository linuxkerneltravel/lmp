#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
 
int main()
{
        struct if_nameindex *if_lst = if_nameindex();
        struct if_nameindex *if_node = if_lst;
 
        while(if_node&&if_node->if_index != 0)
        {
                printf("index:%d, name:%s\n", if_node->if_index, if_node->if_name);
                ++if_node;
        }
 
        if_freenameindex(if_lst);
 
        return 0;
}