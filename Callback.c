#include"Callback.h"
#include"jsw_rbtree.h"
#include"thpool.h"
#include"ini/dictionary.h"
#include"ini/iniparser.h"
#include"ini/config.h"
#include"ini/load.h"
#include"define.h"
//#define KEY_MAX_LENGTH (16)
//#define KEY_COUNT (1024)
map_t mymap;
map_t map;
//head check
extern int fd;

extern threadpool thpool;
extern struct jsw_rbtree  *centroidset;
dictionary * device_update=NULL ;
INI ini;
INI copy;
#define WAITTIME 3
void task5()
{
	sleep(8);
	DEV  *centroid;
	jsw_rbtrav_t *rbtrav;
	rbtrav = jsw_rbtnew();
	if(!centroidset)
	{
		printf("return trans timer\n");
		return ;
	}
	strncpy(ini.devname,"device.ini",10);
	ini.func_init=&init_config;
	ini.dic=ini.func_init(ini.devname);
	ini.func_write=&write_file;
	strncpy(copy.devname,"copy.ini",8);
	copy.func_init=&init_config;
	copy.dic=ini.func_init(ini.devname);
	copy.func_write=&write_file;
	centroid = jsw_rbtfirst(rbtrav, centroidset);
	if(centroid==NULL)
	    return ;
	do{
          //
		long size=get_file_size("copy.ini");
		if(size>0)
		{
			printf("copy return \n");
			return ;
		}
	 char key[16]="\0";
	 printf("check trans %s\n",inet_ntoa(centroid->addr.sin_addr));
     sprintf(key,"%s",inet_ntoa(centroid->addr.sin_addr));
     //modify by 3/16

    // if(-1==find_is_exist(copy.dic,key))
      //   continue;

   //  printf("new key %s has load \n",key);
	 //
     char buff[1024]="\0";
     sprintf(buff,"[%s]\nstate=\ntime=\noffset=\nfile=\nsize=\n",key);
     printf("buff is %s\n",buff);
     ini_add(copy.dic,buff,"copy.ini");
	}while ((centroid = jsw_rbtnext(rbtrav)) != NULL) ;
		jsw_rbtdelete(rbtrav);
}
void task4()
{
	while(1)
	{
	sleep(WAITTIME);
	DEV  *centroid;
	jsw_rbtrav_t *rbtrav;
	rbtrav = jsw_rbtnew();
	if(!centroidset)
	{
		PLOG_ERROR("task 4 centroidset error\n");
		return ;
	}
	centroid = jsw_rbtfirst(rbtrav, centroidset);
    if(centroid==NULL)
    	return ;
	do{
		char key[16]="\0";
		UPDEV_INFO *ptr=NULL;
		printf("check trans %s\n",inet_ntoa(centroid->addr.sin_addr));
		sprintf(key,"%s",inet_ntoa(centroid->addr.sin_addr));
		int err=hashmap_get(map,key, (void**)(&ptr));
		if(err!=MAP_MISSING)// find device
		{
			long now=time(NULL);
			printf("now %d ptr->time=%d\n",now,ptr->time);
			if(((now-ptr->time)>10)&& ptr->state!=4 && ptr->state!=2)
			{
				printf("Over time \n");
				//update info to ini file
				char buff[1024]="\0";
				ptr->state=2;//break
	            sprintf(buff,"[%s]\nstate=%d\ntime=%ld\noffset=%d\nfile=%s\nsize=%d\n",key,ptr->state,ptr->time,ptr->offset,ptr->file,ptr->send_size);
	            ini_modify_string(copy.dic,key,ptr->file,"file",copy.devname);
	            ini_modify_num(copy.dic,key,ptr->offset,"offset",copy.devname);
	            ini_modify_num(copy.dic,key,ptr->state,"state",copy.devname);
	            ini_modify_num(copy.dic,key,ptr->time,"time",copy.devname);
	            ini_modify_num(copy.dic,key,ptr->send_size,"size",copy.devname);
	            //   ini_add(ini.dic,buff,"copy.ini");
	            // ini.func_write(ini.dic,"copy.ini");
			}
			else if(((now-ptr->time>WAITTIME) & (now-ptr->time<2*WAITTIME)) && ((4==ptr->state)||(3==ptr->state)||(5==ptr->state)))
			{
				printf("write to copy ini\n");
				char buff[1024]="\0";
				sprintf(buff,"[%s]\nstate=%d\ntime=%ld\noffset=%d\nfile=%s\nsize=%d\n",key,ptr->state,ptr->time,ptr->offset,ptr->file,ptr->send_size);
			    ini_modify_string(copy.dic,key,ptr->file,"file",copy.devname);
			    ini_modify_num(copy.dic,key,ptr->offset,"offset",copy.devname);
				ini_modify_num(copy.dic,key,ptr->state,"state",copy.devname);
				ini_modify_num(copy.dic,key,ptr->time,"time",copy.devname);
				ini_modify_num(copy.dic,key,ptr->send_size,"size",copy.devname);
			}
	    }
		else
		{
			//printf("not find\n");
			continue;
		}

	}while ((centroid = jsw_rbtnext(rbtrav)) != NULL) ;
	jsw_rbtdelete(rbtrav);
	}
}
int send_restart(int ip)
{
	DEV *ptr=NULL;
    ptr=find_device(ip);
	if(ptr==NULL)
	{
		 printf("Not find device \n");
		 return -1;
	}
	else
		  printf("find device :%d :%d \n",ptr->remote_ip,ptr->sn);
	//F=0x04，T=0x02， P0=0，无数据D
	char buf[PKT_SIZE], hmac[64];
	struct dms_pkt *pkt = (struct dms_pkt *)buf;
	pkt->type = 0x4;
	pkt->version = 0x1;
	pkt->company = 0x4;

    unsigned int  sn_return=sn_ret(ptr->remote_ip);
    if(-1==sn_return)
    {
        printf("end return sn error\n");
       // sleep(5);
    	return -1;
    }
    pkt->sn =  htonl(++sn_return);
    sn_set(ptr->remote_ip,sn_return);
	pkt->action = 0x2;
	pkt->para = 0x0;
	pkt->len = htons(4);
	//pkt->data=(unsigned char *)malloc(sizeof(16));
	//memset(pkt->data,0,sizeof(pkt->data));
	//sm3_hmac(hmac_key, 32, buf + SEC_HEAD_LEN - 4, 4 + BODY_HEAD_LEN + rand_len, hmac);
	memset(pkt->hmac,0,sizeof(pkt->hmac));
	memcpy(pkt->hmac, "zx", 2);
	printf("retart print\n");
	sendto(fd, buf,sizeof(struct dms_pkt), 0, (struct sockaddr*)&ptr->addr, sizeof(struct sockaddr));
	//free(pkt->data);
	return 0;
}
int send_devinfo(int ip)
{
	//F=0x05，T=0x02， P0=0，无数据D
	DEV *ptr=NULL;
	ptr=find_device(ip);
    if(ptr==NULL)
	{
		printf("Not find device \n");
		return -1;
    }
	else
		printf("find device :%d :%d \n",ptr->remote_ip,ptr->sn);
	char buf[PKT_SIZE]="\0", hmac[64]="\0";
	struct dms_pkt *pkt = (struct dms_pkt *)buf;
	pkt->type = 0x5;
	pkt->version = 0x1;
	pkt->company = 0x4;

    unsigned int  sn_return=sn_ret(ptr->remote_ip);
    if(-1==sn_return)
    {
        printf("end return sn error\n");
       // sleep(5);
    	return -1;
    }
    pkt->sn =  htonl(++sn_return);
    sn_set(ptr->remote_ip,sn_return);
	pkt->action = 0x2;
	pkt->para = 0x0;
	pkt->len = htons(4);
	//pkt->data=(unsigned char *)malloc(sizeof(16));
	memset(pkt->data,0,sizeof(pkt->data));
	memcpy(pkt->data, "randbufdata", strlen("randbufdata"));
	//sm3_hmac(hmac_key, 32, buf + SEC_HEAD_LEN - 4, 4 + BODY_HEAD_LEN + rand_len, hmac);
	memset(pkt->hmac,0,sizeof(pkt->hmac));
	memcpy(pkt->hmac, "zx", 2);
	printf("send devinfo  print\n");
	sendto(fd, buf,sizeof(struct dms_pkt) ,0, (struct sockaddr*)&ptr->addr, sizeof(struct sockaddr));

	return 0;
}
int send_sysinfo(int ip)
{
	DEV *ptr=NULL;
    ptr=find_device(ip);
	if(ptr==NULL)
	{
		 printf("Not find device \n");
		 return -1;
	}
	else
		  printf("find device :%d :%d \n",ptr->remote_ip,ptr->sn);
	char buf[PKT_SIZE]="\0", hmac[64]="\0";
	struct dms_pkt *pkt = (struct dms_pkt *)buf;
	pkt->type = 0x6;
	pkt->version = 0x1;
	pkt->company = 0x4;

    unsigned int  sn_return=sn_ret(ptr->remote_ip);
    if(-1==sn_return)
    {
        printf("end return sn error\n");
       // sleep(5);
    	return -1;
    }
    pkt->sn =  htonl(++sn_return);
    sn_set(ptr->remote_ip,sn_return);
	pkt->action = 0x2;
	pkt->para = 0x0;
	pkt->len = htons(4);
	memset(pkt->data,0,sizeof(pkt->data));
	memset(pkt->hmac,0,sizeof(pkt->hmac));
	memcpy(pkt->data, "randbufdata", strlen("randbufdata"));
	//sm3_hmac(hmac_key, 32, buf + SEC_HEAD_LEN - 4, 4 + BODY_HEAD_LEN + rand_len, hmac);
	memcpy(pkt->hmac, "zx", 2);
	printf("sysinfo  print\n");
	sendto(fd, buf,sizeof(struct dms_pkt), 0, (struct sockaddr*)&ptr->addr, sizeof(struct sockaddr));
	return 0;
}
int send_set_sysinfo(int ip,char * buff)
{
	DEV *ptr=NULL;
	ptr=find_device(ip);
	if(ptr==NULL)
	{
		printf("Not find device \n");
	    return -1;
	}
	else
		 printf("find device :%d :%d \n",ptr->remote_ip,ptr->sn);
	//F=0x07，T=0x02， P0=0，无数据D
	char buf[PKT_SIZE]="\0", hmac[64]="\0";
	struct dms_pkt *pkt = (struct dms_pkt *)buf;
	memset(pkt->data,0,sizeof(pkt->data));
	memset(pkt->hmac,0,sizeof(pkt->hmac));
	pkt->type = 0x7;
	pkt->version = 0x1;
	pkt->company = 0x4;

    unsigned int  sn_return=sn_ret(ptr->remote_ip);
    if(-1==sn_return)
    {
        printf("end return sn error\n");
       // sleep(5);
    	return -1;
    }
    pkt->sn =  htonl(++sn_return);
    sn_set(ptr->remote_ip,sn_return);
	pkt->action = 0x2;
	pkt->para = 0x0;
	pkt->len = htons(4);
	//pkt->data=(unsigned char *)malloc(sizeof(16));
	memcpy(pkt->data, "randbufdata", strlen("randbufdata"));
	//sm3_hmac(hmac_key, 32, buf + SEC_HEAD_LEN - 4, 4 + BODY_HEAD_LEN + rand_len, hmac);
	memcpy(pkt->hmac, "zx", 2);
	printf("retart print\n");
	sendto(fd, buf,sizeof(struct dms_pkt), 0, (struct sockaddr*)&ptr->addr, sizeof(struct sockaddr));
	//
	return 0;
}
int send_upgrade(int ip)
{
	//F=0x09，T=0x02， P0=0，数据D=升级文件信息。
//	char key_string[16]="\0";
	printf("send update device \n");
	DEV *ptr=NULL;
	ptr=find_device(ip);
	if(ptr==NULL)
	{
		printf("Not find device \n");
		return -1;
	}
    else
		printf("find device :%d :%d \n",ptr->remote_ip,ptr->sn);
	char buf[PKT_SIZE]="\0", hmac[64]="\0";
	struct dms_update udp;
    udp.action=0x09;
    udp.version = 0x1;
    udp.company = 0x4;
    unsigned int  sn_return=sn_ret(ptr->remote_ip);
    if(-1==sn_return)
    {
        printf("end return sn error\n");
       // sleep(5);
    	return -1;
    }
    udp.sn =  htonl(++sn_return);
    sn_set(ptr->remote_ip,sn_return);
    udp.para = 0x0;
    udp.len = htons(4);
    printf("size %ld\n",get_file_size("1"));
	udp.packet.reqmsg.len=htonl(get_file_size("1"));
	sprintf(udp.packet.reqmsg.msg,"zx",2);
	printf("send packet %d %s\n",udp.packet.reqmsg.len,udp.packet.reqmsg.msg);
	memcpy(buf,&udp,sizeof(UDP));
	sendto(fd, buf,sizeof(struct dms_update), 0, (struct sockaddr*)&ptr->addr, sizeof(struct sockaddr));
}
int head_check(unsigned char *buff,struct sockaddr_in *from)
{
   //check ok dispatch
    printf("Head Check\n");
	CALLBACK * value=NULL;
    if(!buff)
			return 0;
	struct dms_pkt *pkt = (struct dms_pkt *)buff;
	//need check hmac

	//(pkt->action)
	char buf[10]={0};
	sprintf(buf,"%d",pkt->action);
	if(hashmap_get(mymap,buf,(void**)(&value))==MAP_MISSING)
	{
		PLOG_ERROR("Dispatch action error ");
	    return -1;
	}
	else
	{
		printf("action:%d\n",pkt->action);
	    value->func.function(pkt->action,buff,from);
	    return 0;
	}

}
//function time return
int time_funciton(int type,unsigned char *buff,struct sockaddr_in *from)
{
	printf("time function enter  \n");
#if 1
    UDP pkt;
    memcpy(&pkt,buff,sizeof(UDP));
    time_t now;
    time(&now);
    pkt.type=0x01;
    pkt.version=0x01;
    pkt.company=0x04;
   // pkt.hmac;
    memcpy(pkt.hmac, "zx", 2);
    pkt.sn=htonl(0);

    pkt.action=0x01;
    pkt.para=0;
    pkt.len=htons(4);
    pkt.packet.timepac.time=htonl(now);
    memcpy(buff,&pkt,sizeof(UDP));
    sendto(fd, buff,sizeof(UDP), 0, (struct sockaddr*)from, sizeof(struct sockaddr));
#endif
#if 0
	struct dms_pkt *pkt=(struct dms_pkt * )balloc(sizeof(struct dms_pkt ));
	memcpy(pkt,buff,sizeof(struct dms_pkt));
	time_t now;
	time(&now);
	memset(pkt->data,0,sizeof(pkt->data));
	sprintf(pkt->data,"%d",htonl(now));
	pkt->type=0x01;
	pkt->para = 0x0;
	pkt->len = htons(4);
	pkt->action=0x01;
	//sm3_hmac(hmac_key, 32, buf + SEC_HEAD_LEN - 4, 4 + BODY_HEAD_LEN + 4, hmac);
	//memcpy(pkt->hmac, hmac, 2);
	if(!fd)
	{
		bfree(pkt);
		PLOG_ERROR("Server fd is error\n");
		return -1;
	}
	sendto(fd, buff,sizeof(struct dms_pkt), 0, (struct sockaddr*)from, sizeof(struct sockaddr));
	bfree(pkt);
	printf("time function end\n");
#endif
	return 0;
}

int restart_funciton(int type,unsigned char *buff,struct sockaddr_in *from)
{
	printf("restart  function enter  \n");
	if(!buff)
				return 0;
	struct dms_pkt *pkt = (struct dms_pkt *)buff;
	int state=pkt->para;
	PLOG_WARNING("Restat device is  %d\n",ntohl(from->sin_addr.s_addr));
}
int devinfo_funciton(int type,unsigned char *buff,struct sockaddr_in *from)
{
	printf("device info  function enter  \n");
	if(!buff)
	{
		PLOG_WARNING("Devinfo buff is NULL");
		return -1;
	}
	struct dms_pkt *pkt = (struct dms_pkt *)buff;
	if(!pkt->data)
		return -1;
	DEV_INFO *info=(DEV_INFO*)balloc(sizeof(DEV_INFO));
	memcpy(info,pkt->data,sizeof(DEV_INFO));
	//DEV_INFO *info=pkt->data;
	//insert into map
	DEV *device=find_device(from->sin_addr.s_addr);
	if(device)
	{
       // device->info=(DEV*)malloc(sizeof(DEV));
		if(strlen(pkt->data)<sizeof(DEV_INFO))
					return -1;
		printf("find info device\n");
        memcpy(device->info.dev_name,info->dev_name,40);
        device->info.dev_type=ntohl(info->dev_type);
        device->info.dev_runtime=ntohl(info->dev_runtime);
        device->info.dev_factory=ntohl(info->dev_factory);
        device->info.dev_version=ntohl(info->dev_version);
        bfree(info);
        return 0;
	}
	else
	{
		PLOG_WARNING("Device not in map \n");
        bfree(info);
        return -1;
	}

}
int sysinfo_function(int type,unsigned char *buff,struct sockaddr_in *from)
{
	printf("sysinfo  function enter  \n");
	if(!buff)
			return -1;
	struct dms_pkt *pkt = (struct dms_pkt *)buff;
	if(!pkt->data)
		return -1;
	DEV_SYS *sys=(DEV_SYS *)balloc(sizeof(DEV_SYS));
	memcpy(sys,pkt->data,sizeof(DEV_SYS));
	//strcpy(sys,pkt->data);
//	DEV_INFO *info=pkt->data;
	//insert into map
	DEV *device=find_device(from->sin_addr.s_addr);
	if(device)
	{
		if(strlen(pkt->data)<sizeof(DEV_SYS))
			return -1;
         strcpy(device->sys.sys_type,sys->sys_type);
         strcpy(device->sys.sys_dial,sys->sys_dial);
         strcpy(device->sys.sys_net,sys->sys_net);
         strcpy(device->sys.sys_serial,sys->sys_serial);
         strcpy(device->sys.sys_policy,sys->sys_policy);
         bfree(sys);
	}
	else
	bfree(sys);
}
int set_sysinfo_function(int type,unsigned char *buff,struct sockaddr_in *from)
{
	printf("set sysinfo  function enter  \n");
	if(!buff)
				return 0;
	struct dms_pkt *pkt = (struct dms_pkt *)buff;
	int state=pkt->para;
	printf("set sysinfo  state %d\n",state);
}
int negotiate_funciton(int type,unsigned char *buff,struct sockaddr_in *from)
{
//F=0x03，T=0x03，P0=0，D=密钥交换数据
	printf("negotiate function enter  \n");
	struct dms_pkt *pkt = (struct dms_pkt *)buff;
	//pkt->data=(unsigned int *)malloc(sizeof(int));
	//sprintf(pkt->data,"%d",)
	pkt->para = 0x0;
	pkt->len = htons(4);
	//sm3_hmac(hmac_key, 32, buf + SEC_HEAD_LEN - 4, 4 + BODY_HEAD_LEN + 4, hmac);
	//memcpy(pkt->hmac, hmac, 2);
	if(!fd)
	{
	//	free(pkt->data);
	    return 0;
	}
	sendto(fd, buff,sizeof(struct dms_pkt), 0, (struct sockaddr*)from, sizeof(struct sockaddr));
	//free(pkt->data);

}
int state_funciton(int type,unsigned char *buff,struct sockaddr_in *from)
{
	printf("state function enter  \n");
	struct dms_pkt *pkt = (struct dms_pkt *)buff;
	//验证报文体 -》更新设备map状态
	DEV *ptr=NULL;
	ptr=find_device(from->sin_addr.s_addr);
	if(ptr==NULL)
		     printf("Not find device \n");
	else
	{
		ptr->online=1;
	}

}

int test_funciton(int type,unsigned char *buff,struct sockaddr_in *from)
{
    printf("test function %s\n",buff);
    start_response(type,buff,from);
#if 1
    struct dms_pkt *pkt=(struct dms_pkt * )balloc(sizeof(struct dms_pkt ));
   // pkt->data=(unsigned char *)balloc(sizeof(200));
    memcpy(pkt,buff,sizeof(struct dms_pkt));
    printf("test:%d %d %d %d",pkt->action,pkt->sn,pkt->version,pkt->type);
    //char BUFF[1024]="\0";
     // pkt->data=(unsigned char *)malloc(1024);
   // strcpy(BUFF,pkt->data);
  //  memcpy(BUFF,pkt->data,strlen(pkt->data));
    printf("recv data:%s\n",pkt->data);
   // bfree(pkt->data);
   // bfree(pkt);
#endif
#if 0
    struct dms_pkt *pkt = (struct dms_pkt *)buff;
    char BUFF[1024]="\0";
   // pkt->data=(unsigned char *)malloc(1024);
    memcpy(BUFF,pkt->data,sizeof(BUFF));
    printf("recv data:%s\n",BUFF);
#endif
}

unsigned long get_file_size(const char *filename)
{
    struct stat buf;
    if(stat(filename, &buf)<0)
    {
        return 0;
    }
    return (unsigned long)buf.st_size;
}
unsigned long get_file_pos(const  FILE * file,unsigned int size)
{
	fseek(file, size, SEEK_SET);
	return ftell(file);
}
char key_string[16]="\0";
int start_response(int type,unsigned char *buff,struct sockaddr_in *from)
{
    //UPDEV_INFO
	//RSPMSG
	printf("start response");
	UPDEV_INFO *ptr=NULL;
	RSPMSG msg;
	UDP packet;
	char key_string[16]="\0";
	memcpy(&packet,buff,sizeof(UDP));
	memcpy(&msg,&packet.packet.rsqmsg,sizeof(RSPMSG));

	//sprintf(key_string,"%d",from->sin_addr.s_addr);
	sprintf(key_string,"%s",inet_ntoa(from->sin_addr));
	//memcpy(key_string,inet_ntoa(from->sin_addr),strlen(inet_ntoa(from->sin_addr)))
	printf("ip is %s\n",key_string);
	int err=hashmap_get(map,key_string, (void**)(&ptr));
	if(err==MAP_MISSING)//not fond device
	{
		printf("insert device info \n");
		//sprintf(key_string,"%s",inet_ntoa(from->sin_addr));
		ptr=(UPDEV_INFO *)malloc(sizeof(UPDEV_INFO));
		ptr->ip=from->sin_addr.s_addr;
		ptr->offset=msg.recv_len;
		ptr->state=1;
		ptr->len=msg.max_len;
		ptr->send_size=0;
		memcpy(&ptr->Ip,from,sizeof(struct sockaddr_in));
		sprintf(ptr->file,"a.tar.gz");
		ptr->time=time(NULL);
		strcpy(ptr->key_string,key_string);
	    int  error = hashmap_put(map, ptr->key_string, ptr);
	    if(error==-1)
	    {
	    	PLOG_WARNING("hash map insert device remote %s error",key_string);
	    	return -1;
	    }
	 //   sleep(4);
	}
	else
	{

	// ptr->ip=from->sin_addr.s_addr;
	// ptr->offset=msg.recv_len;
	// ptr->state=1;
	// ptr->len=msg.max_len;
	// memcpy(&ptr->Ip,from,sizeof(struct sockaddr_in));
	 //sprintf(ptr->file,"1");
	 ptr->time=time(NULL);
	//strcpy(ptr->key_string,key_string);
     ptr->offset=msg.recv_len;
     ptr->state=1;
     ptr->len=msg.max_len;
     printf("start response 2 \n");
}
	 //trans data
//	memset(ptr->file,0,50);
   // sprintf(ptr->file,"1");

	if(0x0C==packet.para)
	{
		ptr->state=3;
		PLOG_ERROR("Device:%s  remote get 0x0c ",key_string);
		return -1;
	}
	else if(0x0D==packet.para)
	{
		ptr->state=5;
		PLOG_ERROR("Device:%s  remote get 0x0D ",key_string);
		return -1;
	}
	if(ptr->file)
	{
	   printf("0x08 trans \n");
	   FILE *fp =NULL;
       ptr->total_size=get_file_size(ptr->file);
       fp = fopen(ptr->file, "r");
       trans_data(type,buff,from);// put thread job
       if(fp)
       free(fp);
       return 0;
	}

}
//long LEN=0;

int trans_data(int type,unsigned char *buff,struct sockaddr_in *from)
{
	UPDEV_INFO *ptr=NULL;
	//ptr=(UPDEV_INFO*)malloc(sizeof(UPDEV_INFO));
	printf("enter function trans data\n");

	char key_string[16]="\0";
	sprintf(key_string,"%s",inet_ntoa(from->sin_addr));
	printf("key is %s\n",key_string);
	//sleep(5);
	int err=hashmap_get(map, key_string, (void**)(&ptr));
	if(err==MAP_MISSING)
	{
		PLOG_ERROR("Not find device %s",key_string);
		return 0;
	}
	FILE *fp =NULL;
	ptr->total_size=get_file_size(ptr->file);
	fp = fopen(ptr->file, "r");
	//memcpy(&ptr->Ip,from,sizeof(struct sockaddr_in));
	PLOG_INFO("device:%s ip=%d len=%d offset=%d send_size=%d time=%d file=%s total_size=%d",key_string,ptr->ip,ptr->len,ptr->offset,ptr->send_size,ptr->time,ptr->file,ptr->total_size);
	//sleep(5);
	struct dms_update udp;
	int len=0;
	char buf[PKT_SIZE];
	udp.action=0x08;
	udp.version = 0x1;
	udp.company = 0x4;
	unsigned int  sn_return=sn_ret(from->sin_addr.s_addr);
	if(-1==sn_return)
	{
		PLOG_ERROR("return sn error");
        //sleep(5);
		return -1;
	}
	udp.sn =  htonl(++sn_return);
	sn_set(from->sin_addr.s_addr,sn_return);
	udp.para = 0x0;
    udp.len = htons(4);
    udp.packet.senpac.digest;
    udp.packet.senpac.offset=ptr->offset;
    udp.packet.senpac.len=htonl(ptr->len);
    printf("file name :%s \n",ptr->file);
 //   FILE *fp = fopen(ptr->file, "r");
    if(NULL == fp)
    {
    	PLOG_ERROR("Remote file:%s Not Found.\n", ptr->file);
    }
    else
    {
    	//
       printf("offset is %d\n",ptr->offset);
     //  fseek(fp,ptr->offset,SEEK_SET);
       fseek(fp,ptr->offset,SEEK_SET);
     //  printf("offset is %d\n",LEN);
       memset(&udp.packet.senpac.packet,0,sizeof(SEDPAC));
       if((len = fread(udp.packet.senpac.packet, sizeof(char), 1000, fp)) > 0)
      {
    	    //udp.packet.senpac.packet,
    	   	//sprintf(udp.packet.reqmsg.msg,"zx",2);
    	    udp.packet.reqmsg.len=len;
    	   	printf("send packet %d %s\n",udp.packet.senpac.len,udp.packet.senpac.packet);
    	   	memcpy(buf,&udp,sizeof(UDP));
    	   	sendto(fd, buf,sizeof(struct dms_update), 0, (struct sockaddr*)from, sizeof(struct sockaddr));
    	    ptr->offset+=len;
    	    ptr->send_size+=len;
    	    ptr->time=time(NULL);
    	   // LEN+=len;
    	    printf("121933 len %d :offset is %d\n",len, ptr->offset);
    	    printf("ip=%d len=%d offset=%d send_size=%d time=%d file=%s total_size=%d\n",ptr->ip,ptr->len,ptr->offset,ptr->send_size,ptr->time,ptr->file,ptr->total_size);
    	   // sleep(4);
    	   if(fp)
    		   free(fp);
      }
      else if(len<1024)
      {
    	 // if(ptr->offset==ptr->total_size)
    	  end_response(type,buff,from,ptr->total_size);
    	  ptr->state=4;
    	  if(fp)
    		  free(fp);
          return 1;
      }
      else
      {
    	  PLOG_ERROR("Read error\n");
           if(fp)
        	   free(fp);
      }
     }

}
int end_response(int type,unsigned char *buff,struct sockaddr_in *from,unsigned long size)
{
	printf("end response \n");
	struct dms_update udp;
	udp.action=0x0A;
	udp.version = 0x0A;
	udp.company = 0x4;
	unsigned int  sn_return=sn_ret(from->sin_addr.s_addr);
	if(-1==sn_return)
	{
		PLOG_ERROR("end return sn error\n");
       // sleep(5);
		return -1;
	}

	udp.sn =  htonl(++sn_return);
	sn_set(from->sin_addr.s_addr,sn_return);
	udp.para = 0x0;
	udp.len = htons(4);
	udp.packet.reqmsg.len=size;
	memcpy(udp.packet.reqmsg.msg,"zx",40);
	char buf[PKT_SIZE];
	memcpy(buf,&udp,sizeof(UDP));
   	sendto(fd, buf,sizeof(struct dms_update), 0, (struct sockaddr*)from, sizeof(struct sockaddr));

}
int end_res(int type,unsigned char *buff,struct sockaddr_in *from)
{
	printf("get client trans \n");
	UPDEV_INFO *ptr=NULL;
	UDP packet;
	char key_string[16]="\0";
	memcpy(&packet,buff,sizeof(UDP));
	sprintf(key_string,"%s",inet_ntoa(from->sin_addr));
	int err=hashmap_get(map,key_string, (void**)(&ptr));
	if(err==MAP_MISSING)//not fond device
	{
		PLOG_ERROR("device:%s not find in map",key_string);
		return -1;
	}
	else
	{
        //check po
		PLOG_INFO("device %s remote success time is %ld",key_string,time(NULL));
		ptr->state=4;
	}
}

int RegisterCommandHandler(int type)
{
	CALLBACK * value=NULL;
	switch(type)
	{
	case CHECKHEAD:
		value = malloc(sizeof(CALLBACK));
		value->type=type;
		value->func.function=head_check;
		hashmap_put(mymap, "0", value);
		break;
	case 0x01://time return function register
		value = malloc(sizeof(CALLBACK));
		value->type=type;
		value->func.function=time_funciton;
		hashmap_put(mymap, "1", value);
		break;
	case 0x02://在线状态探测
		value = malloc(sizeof(CALLBACK));
		value->type=type;
		value->func.function=state_funciton;
		hashmap_put(mymap, "2", value);
		break;
	case 0x03://远程管理密钥协商
		value = malloc(sizeof(CALLBACK));
		value->type=type;
		value->func.function=negotiate_funciton;
		hashmap_put(mymap, "3", value);
		break;
	case 0x04://设备重启
		value = malloc(sizeof(CALLBACK));
		value->type=type;
		value->func.function=restart_funciton;
		hashmap_put(mymap, "4", value);
		break;
	case 0x05://获取设备基本信息
		value = malloc(sizeof(CALLBACK));
		value->type=type;
		value->func.function=devinfo_funciton;
		hashmap_put(mymap, "5", value);
		break;
	case 0x06 ://读取系统参数
		value = malloc(sizeof(CALLBACK));
		value->type=type;
		value->func.function=sysinfo_function;
		hashmap_put(mymap, "6", value);
		break;
	case 0x07://设置系统参数
		value = malloc(sizeof(CALLBACK));
		value->type=type;
		value->func.function=set_sysinfo_function;
		hashmap_put(mymap, "7", value);
		break;
	case 0x08://软件升级
		value = malloc(sizeof(CALLBACK));
		value->type=type;
		value->func.function= trans_data;
		hashmap_put(mymap, "8", value);
		break;
	case 0x09:
		value = malloc(sizeof(CALLBACK));
		value->type=type;
		value->func.function=start_response;
		hashmap_put(mymap, "9", value);
		break;
	case 0x0A:
			////升级end
		value = malloc(sizeof(CALLBACK));
		value->type=type;
		value->func.function=end_res;
		hashmap_put(mymap, "10", value);
		break;
	case 0x0D:
		////升级文件已经存在
		value = malloc(sizeof(CALLBACK));
		value->type=type;
		value->func.function=time_funciton;
		hashmap_put(mymap, "13", value);
		break;
	case 0x0c:
		//无效的升级文件分片
		value = malloc(sizeof(CALLBACK));
		value->type=type;
		value->func.function=time_funciton;
		hashmap_put(mymap, "12", value);
		break;
	case 0x10://for test
		value = malloc(sizeof(CALLBACK));
		value->type=type;
		value->func.function=test_funciton;
		hashmap_put(mymap, "16", value);
		break;
	}
}
//load file

int load_cfg(const unsigned char *config)
{
	FILE *fp = NULL;
	char str[256] = {0}, *w;
	fp = fopen(config, "r");
	if(!fp)
	{
		printf("read error\n");
		return -1;
	}
	 DEV * tmp=NULL;
	 DEV * tmp1=NULL;
	while(fgets(str, sizeof str, fp)){
		tmp=(struct device*)balloc(sizeof( struct device));
		if(!tmp)
			goto parse_error;
		memset(tmp, 0, sizeof(struct device));

		if(!(w = strtok(str, ",")))
			goto parse_error;
		if(!(w = strtok(NULL, ",")))
			goto parse_error;
		if(!(w = strtok(NULL, ",")))
			goto parse_error;
		if(!(w = strtok(NULL, ",")))
			goto parse_error;

		if(!(w = strtok(NULL, ",")))
			goto parse_error;
		printf("ip is %s\n",w);
		tmp->remote_ip = inet_addr(w);

		memset(&tmp->addr, 0, sizeof(struct sockaddr_in));
		tmp->addr.sin_family = AF_INET;
		tmp->addr.sin_addr.s_addr = tmp->remote_ip;
		tmp->addr.sin_port = htons(DMS_PORT);
		tmp->inuse = 1;

		     // printf("find device :%d :%d \n",tmp->remote_ip,tmp->sn);
		continue;

	parse_error:
		if(tmp)
			bfree(tmp);
	}

	if(fp)
		fclose(fp);
	return 0;
}
int  init_register()
{
	PLOG_INFO("register function \n");
	//move to function.c init(),modify 3/10
	mymap = hashmap_new(50);
	map=hashmap_new(2000);
	RegisterCommandHandler(CHECKHEAD);
	RegisterCommandHandler(0x01);
	RegisterCommandHandler(0x02);
	RegisterCommandHandler(0x03);
	RegisterCommandHandler(0x04);
	RegisterCommandHandler(0x05);
	RegisterCommandHandler(0x06);
	RegisterCommandHandler(0x07);
	RegisterCommandHandler(0x08);
	RegisterCommandHandler(0x09);
	RegisterCommandHandler(0x0A);
	RegisterCommandHandler(0x10);
	RegisterCommandHandler(0x0c);
	RegisterCommandHandler(0x0d);
	//modify 3 13
	thpool_add_work(thpool, (void*)task4, NULL);
	thpool_add_work(thpool, (void*)task5, NULL);
	return 1;

}
