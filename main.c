#include <stdio.h>
#include <stdlib.h>
#include<string.h>
#include<unistd.h>
#include<errno.h>

extern void CapturePacket(void);
//device name
extern char device[16];
//username
extern char username[16];
//password
extern char password[16];

int main(int argc,char*argv[])
{
    //not use fork to create protect process
    //please use linux command & to run it in background task
    //arguments list:  1.device name   2.username   3.password
    //such as: eth0.2 2013314XXX 314XXX
    if(argc<4)
    {
        printf("Please provide device name,username and password arguments!\n");
        return 0;
    }

    strcpy(device,argv[1]);
    strcpy(username,argv[2]);
    strcpy(password,argv[3]);

    CapturePacket();
    return 0;
}
