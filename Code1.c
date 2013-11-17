#include<pcap.h>
#include<stdio.h>
#include<stdlib.h> // for exit()
#include<string.h> //for memset

#include<sys/socket.h>
#include<arpa/inet.h> // for inet_ntoa()
#include<net/ethernet.h>
#include<netinet/ip_icmp.h>	//Provides declarations for icmp header
#include<netinet/udp.h>	//Provides declarations for udp header
#include<netinet/tcp.h>	//Provides declarations for tcp header
#include<netinet/ip.h>	//Provides declarations for ip header

void process_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
void process_ip_packet(const u_char * , int);
void print_ip_packet(const u_char * , int);
void print_tcp_packet(const u_char *  , int );
void print_udp_packet(const u_char * , int);
void print_icmp_packet(const u_char * , int );
//void PrintData (const u_char * , int);

FILE *attackfile,*trafficfile,*payloadfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;	
static unsigned long int syn_count=0;
           static unsigned long int ack_count=0;
char hostip[30]="10.16.15.180";
 static int ssh_dic_count=0;
static int icmp_req_count=0;
static unsigned long int packet_count=0,tcp_count=0,udp_count=0,icmp_count=0,igmp_count=0,other_count=0;
static unsigned long int mal_count=0;
main(int argc, char **argv)
{
	pcap_if_t *alldevsp , *device;
	pcap_t *handle; //Handle of the device that shall be sniffed

	char errbuf[100] , *devname , devs[100][100];
	int count = 1 , n;
        struct bpf_program fp; 
        bpf_u_int32 netp; 

	//First get the list of available devices
	/*
        printf("Finding available devices ... ");
	if( pcap_findalldevs( &alldevsp , errbuf) )
	{
		printf("Error finding devices : %s" , errbuf);
		exit(1);
	}
	printf("Done");

	//Print the available devices
	printf("\nAvailable Devices are :\n");
	for(device = alldevsp ; device != NULL ; device = device->next)
	{
		printf("%d. %s - %s\n" , count , device->name , device->description);
		if(device->name != NULL)
		{
			strcpy(devs[count] , device->name);
		}
		count++;
	}

	//Ask user which device to sniff
	printf("Enter the number of the device you want to sniff : ");
	scanf("%d" , &n);
	devname = devs[n];

	//Open the device for sniffing
	printf("Opening device %s for sniffing ... " , devname);
	//handle = pcap_open_live(devname , 65536 , 1 , 0 , errbuf);
*/
////////////////////////////////////////////////////////////////////////
/* Open a capture file */
    if ( (handle = pcap_open_offline("/home/cobb/outsidefriday.pcap", errbuf) ) == NULL)
    {
        fprintf(stderr,"\nError opening dump file\n");
        return -1;
    }
    
/////////////////////////////////////////////////////////////////


	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open file %s : %s\n" , devname , errbuf);
		exit(1);
	}
	printf("Done\n");

	/*logfile=fopen("log.txt","w");
	if(logfile==NULL)
	{
		printf("Unable to create file.");
	}
*/
//////////////////////////////////////////////////////////////////////////////
attackfile=fopen("attack.txt","w");
	if(attackfile==NULL)
	{
		printf("Unable to create file.");
	}

trafficfile=fopen("trafficfile.txt","w");
if(trafficfile==NULL)
{
printf("Unable to create file.");
}
payloadfile=fopen("payloadfile.txt","w");
if(payloadfile==NULL)
{
printf("Unable to create file");
}
fprintf(attackfile,"\n\n\n***********************************MALICIOUS ACTIVITIES DESCRIPTION**************************************************");
fprintf(attackfile,"\n\n ATTACKER \t \t TARGET \t \t DESCRIPTION");

 /* Lets try and compile the program.. non-optimized */
 //if(pcap_compile(handle,&fp,"host 10.16.15.180",0,netp) == -1)
 //{ fprintf(stderr,"Error calling pcap_compile\n"); exit(1); }

    /* set the compiled program as the filter */
// if(pcap_setfilter(handle,&fp) == -1)
// { fprintf(stderr,"Error setting filter\n"); exit(1); }

//////////////////////////////////////////////////////////////////////////////
	//Put the device in sniff loop
	pcap_loop(handle , -1 , process_packet , NULL);
printf("\n***************************************************NETWORK TRAFFIC************************************************************");
printf("\n\n\n\t SOURCE IP \t\t DESTINATION IP \t SIZE \t TTL \t\t PROTOCOL"); 

fprintf(trafficfile,"\n***************************************************NETWORK TRAFFIC************************************************************");
fprintf(trafficfile,"\n\n\n\t SOURCE IP \t\t DESTINATION IP \t SIZE \t TTL \t\t PROTOCOL"); 
	return 0;
}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
	int size = header->len;

	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	if (iph->protocol==6) //Check the Protocol and do accordingly...
	{
          ++tcp;
	print_tcp_packet(buffer , size);
        tcp_count++;
       }
  
    if(iph->protocol==1)

    {
        //ICMP Protocol
	++icmp;
	print_icmp_packet( buffer , size);
        icmp_count++;
}		

   if(iph->protocol==2)
  { 
   //IGMP Protocol
   ++igmp;
  igmp_count++;
}

if(iph->protocol==17)
{
 //UDP Protocol
	++udp;
	print_udp_packet(buffer , size);
       udp_count++;
}
	
if(iph->protocol!=1 && iph->protocol!=2 && iph->protocol!=17 && iph->protocol!=6)
{
other_count++;
}

packet_count=tcp_count+udp_count+icmp_count+igmp_count+other_count;
printf("\n\nTotal packets:%ld",packet_count);
printf("\n\nTCP packets:%ld",tcp_count);
printf("\n\nUDP packets:%ld",udp_count);
printf("\n\nICMP packets:%ld",icmp_count);
printf("\n\nIGMP packets:%ld",igmp_count);
printf("\n\nOther packets:%ld",other_count);
//printf("TCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\r", tcp , udp , icmp , igmp , others , total);
}
