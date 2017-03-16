#include <sys/types.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include<stdio.h>
#include<unistd.h>
#include<time.h>
#include"balloc.h"
#include"jsw_rbtree.h"
#include"define.h"
#include"Callback.h"
#include "thpool.h"
#define TIMER_STATE (10)
#define TIMER_CHECK (7200)
extern map_t mymap;
int fd;
#define MAX_UDP_MESSAGE 2048
int affichage(unsigned char * message, int nboctets,struct sockaddr_in *from);//prototype

int initialisationSocketUDP(char *service){

	struct addrinfo precisions,*resultat;
	int statut;
	//int fd;
	/* Construction de la structure adresse */
	memset(&precisions,0,sizeof precisions);
	precisions.ai_family=AF_UNSPEC;
	precisions.ai_socktype=SOCK_DGRAM;
	precisions.ai_flags=AI_PASSIVE;
	statut=getaddrinfo(NULL,service,&precisions,&resultat);
	if(statut<0){ perror("initialisationSocketUDP.getaddrinfo"); exit(EXIT_FAILURE); }

	/* Creation d'une socket */
	fd=socket(resultat->ai_family,resultat->ai_socktype,resultat->ai_protocol);
	if(fd<0)
	{
		perror("SocketUDP.socket");
		exit(EXIT_FAILURE);
	}

	/* Options utiles */
	int vrai=1;
	if(setsockopt(fd,SOL_SOCKET,SO_REUSEADDR,&vrai,sizeof(vrai))<0)
	{
		perror("UDPgenerique.setsockopt (REUSEADDR)");
		exit(-1);
	}

	/* socket */
	statut=bind(fd,resultat->ai_addr,resultat->ai_addrlen);
	if(statut<0) {perror("initialisationServeurUDP.bind"); exit(-1);}


	freeaddrinfo(resultat);
	return fd;
}

//find the device or add device ,then dispatch task
int update_map(struct sockaddr_in *from)
{
	DEV *ptr=NULL;
	ptr=find_device(from->sin_addr.s_addr);
	if(ptr==NULL)
	{
		 printf("Not find device \n");
		 DEV * device=NULL;
		 device=(struct device*)balloc(sizeof( struct device));
		 device->remote_ip=from->sin_addr.s_addr;
		// device->sn=200;
		 device->old_time=time(NULL);
		 memcpy(&device->addr,from,sizeof(struct sockaddr_in));
		 device->online=1;
		 device_insert(device);
		 printf("DATA:%d:%s\n",device->addr.sin_addr.s_addr,inet_ntoa(device->addr.sin_addr));
	}
	else
		 printf("find device :%d :%d \n",ptr->remote_ip,ptr->online);
}
int boucleServeurUDP(int s,int (*traitement)(unsigned char *,int,struct sockaddr_in *)){

	while(1){

		struct sockaddr_in adresse;
		socklen_t taille=sizeof(adresse);
		unsigned char message[MAX_UDP_MESSAGE]="\0";
		int nboctets=recvfrom(s,message,MAX_UDP_MESSAGE,0,(struct sockaddr *)&adresse,&taille);
		if(nboctets<0) continue;
		printf("recv recv size =%d\n",nboctets);
		//update_map(&adresse);
		printf("IP:%d:%s\n",adresse.sin_addr.s_addr,inet_ntoa(adresse.sin_addr));
		if(traitement(message,nboctets,&adresse)<0) break;
	}
	return 0;

}

void print_hex(unsigned char *buf, int len)
{
    int i;
    if (len == 0) return;
    for (i=0; i<len; i++)
    {
        if (i % 0x10 == 0) {
        printf("\n%08Xh: ", i);
    }
    printf("%02X ", buf[i]);
    }
    printf("\n");
}
int affichage(unsigned char * message, int nboctets,struct sockaddr_in *from){

	DEV *ptr=NULL;
	ptr=find_device(from->sin_addr.s_addr);
	if(ptr==NULL)
	{
	   //device is not in trust map
#ifdef TEST
		DEV * device=NULL;
		device=(struct device*)balloc(sizeof( struct device));
		device->remote_ip=from->sin_addr.s_addr;
	//	sprintf(&device->addr,"%s",from);
        memcpy(&device->addr,from,sizeof(struct sockaddr_in));
		printf("Port is %d %d\n",device->addr.sin_port,device->addr.sin_addr.s_addr);
	    // device->sn=200;
		device->old_time=time(NULL);
		memcpy(&device->addr,from,sizeof(struct sockaddr_in));
		device->online=1;
		device_insert(device);
		printf("DATA:%d:%s\n",device->addr.sin_addr.s_addr,inet_ntoa(device->addr.sin_addr));

#endif
	}
	else//update
	{
	ptr->remote_ip=from->sin_addr.s_addr;
	memcpy(&ptr->addr,from,sizeof(struct sockaddr_in));
	ptr->old_time=time(NULL);
	memcpy(&ptr->addr,from,sizeof(struct sockaddr_in));
	ptr->online=1;
	printf("find device :%d :%d \n",ptr->remote_ip,ptr->online);
	}
	//printf("%s\n",message);
//	print_hex(message, sizeof(struct dms_pkt));
	//first check head
	//task dispatch
	head_check(message,from);
	return 0;
}


//在线状态探测
void task1(){
	printf("Thread #%u working on task1\n", (int)pthread_self());
    while(1)
{
	sleep(TIMER_STATE);
	// 遍历map表，发送探测包
    device_print();
}
}

//两小时周期协商远程管理密钥
void task2(){
	printf("Thread #%u working on task2\n", (int)pthread_self());
	//update_key();
	while(1)
	{
        sleep(TIMER_CHECK);
        update_key();
	}
}
void task3()
{
	//while(1)
	//{
	sleep(8);
	printf("upgrate #%u working on task3 \n",(int)pthread_self());
	send_upgrade(16777343);

//	}
}
#include<signal.h>
static int SigNum = 0;
static sigset_t SigSet;
static int pid = 0;

void TranslateSig(int sig)
{
	SigNum = sig;
}
#include"log/plog.h"
#include <fcntl.h>
#if 1
#define H_DEBUG
threadpool thpool;
int main(int argc,char *argv[]){
#ifndef H_DEBUG
	int fd = open("/dev/null", O_RDWR);
	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	if (fd > 2) close(fd);
#endif
	//signal
	 signal(SIGTERM, TranslateSig);
	 signal(SIGHUP, TranslateSig);
	 signal(SIGPIPE,TranslateSig);
	 sigfillset(&SigSet);
	 sigdelset(&SigSet, SIGTERM);
	 sigdelset(&SigSet, SIGHUP);
	 SigNum = 0;
     int state=0;
	//thread pool
    //log
	plog_open("log/log", PLOG_LEVEL_DEBUG  ,  5*1024*1024);
	//PLOG_ERROR PLOG_LEVEL_DEBUG
	PLOG_DEBUG("Function start : %d", time(NULL));
	printf("Making threadpool with 8 threads");
	thpool = thpool_init(8);
	if(NULL==thpool)
	{
		PLOG_ERROR("Init pool error\n");
		return 0;
	}
	thpool_add_work(thpool, (void*)task1, NULL);
	thpool_add_work(thpool, (void*)task2, NULL);
	thpool_add_work(thpool,(void *)task3, NULL);
	//init map ,init device configure
	state=init();
	if(-1==state)
		PLOG_ERROR("Init error\n");
	//function register
    init_register();

#ifdef TEST_
	DEV * device=NULL;
	device=(struct device*)balloc(sizeof( struct device));
	device->remote_ip=322;
	device->sn=200;
	device_insert(device);
    DEV *ptr=NULL;
	ptr=find_device(322);
	if(ptr==NULL)
	     printf("Not find device \n");
	else
	     printf("Find device :%d :%d \n",ptr->remote_ip,ptr->sn);
#endif
	char *service="5588";
	int s=initialisationSocketUDP(service);
	boucleServeurUDP(s,affichage);
	thpool_destroy(thpool);
	plog_close();
	return 0;
}
#endif
