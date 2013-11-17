

int payl_detection_tcp(char *substring,const u_char * Buffer,int header_size)
{
        
        struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	unsigned short iphdrlen;
        iphdrlen = iph->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	header_size=sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

        char *payload=Buffer+header_size;
        
        int c1=0, c2=0,flag=0,i,j;
fprintf(payloadfile,"\n\n\n\n\n\n\n\n\n\n\n%s",payload);
fprintf(payloadfile,"\nHeader size TCP:%d",header_size);
while(payload[c1]!='\0')
        c1++;

        while(substring[c2]!='\0')
        c2++;
     
        for(i=0;i<=c1-c2;i++)
        {
         for(j=i;j<i+c2;j++)
         {
          flag=1;
        if(payload[j]!=substring[j-i])
        {
         flag=0;
         break;
        }
       }
     if(flag==1)
      break;
}   
if(flag==1)
{ 
return 1;
//printf("\n\n Sample Payload Found");  
//fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tSample Payload Found :",inet_ntoa(source.sin_addr));
}
}


void print_tcp_packet(const u_char * Buffer, int Size)
{
	unsigned short iphdrlen;
       int x;
int bd1,bd2,bd3,bd4,bd5,bd6,bd7,bd8,bd9,bd10,bd11,bd12,bd13,bd14,bd15,bd16,bd17,bd18,bd19,bd20,bd21,bd22,bd23,bd24,bd25,bd26,bd27,bd28,bd29,bd30,bd31,bd32,bd33;
        int d1,d2,d3,d4,d5,d6;
int dir;
int s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13;



 char *sip,*dip;
           sip=inet_ntoa(source.sin_addr);
           dip=inet_ntoa(dest.sin_addr);
          struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	iphdrlen = iph->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
        bpf_u_int32 netp;
	pcap_t *handle;
        struct bpf_program fp; 
  
/*
x=payl_detection_tcp("Vega while connected",Buffer,header_size);
if(x==1)
fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tSample Payload Found :",inet_ntoa(source.sin_addr));
*/

        
bd2=payl_detection_tcp("NetBus",Buffer,header_size);
if(bd2==1)
fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tBackdoor Alert in TCP:BACKDOOR netbus active ",inet_ntoa(source.sin_addr));
