#include<stdio.h>
#include<unistd.h>
#include"balloc.h"
#include"jsw_rbtree.h"
#include"define.h"
#if 0
int main(void)
{ 
    init();
    DEV * device=NULL;
    device=(struct device*)balloc(sizeof( struct device));
    device->remote_ip=322;
    device->sn=200;
    device_insert(device);

    device=(struct device*)balloc(sizeof( struct device));
    device->remote_ip=12;
    device->sn=200;
    device_insert(device);

    device=(struct device*)balloc(sizeof( struct device));
    device->remote_ip=32;
    device->sn=200;
    device_insert(device);

    device=(struct device*)balloc(sizeof( struct device));
    device->remote_ip=42;
    device->sn=200;
    device_insert(device);

    device_print();

    DEV *ptr=NULL;
    ptr=find_device(322);
    if(ptr==NULL)
       printf("Not find device \n");
    else
    	printf("find device :%d :%d \n",ptr->remote_ip,ptr->sn);
    return 0;
}
#endif
