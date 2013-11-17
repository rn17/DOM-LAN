
if( strcmp(inet_ntoa(dest.sin_addr),"10.16.15.180")!=0 && ( (ntohs(tcph->source)!=21) || (ntohs(tcph->source)!=22) || (ntohs(tcph->source)!=23)) && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
{
//fprintf(attackfile,"\n\n %s \t\t10.16.15.180\t\t Connection establishment Malicious Activity ",inet_ntoa(source.sin_addr));
}

if(ntohs(tcph->source)==22 && (unsigned int)tcph->syn==1 && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
{
ssh_dic_count++;
if(ssh_dic_count>=24 && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
{
fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\t SSH Dictionary Attack Sequence No%u:",inet_ntoa(source.sin_addr),ntohl(tcph->seq));
}
}
//printf("\nSSH Connection COUNT=%d",ssh_dic_count);

/*if( (unsigned int)tcph->syn==1) 
{
if(strcmp(sip,dip)==0) 
{
fprintf(attackfile,"\n\n%s\t\t ",inet_ntoa(source.sin_addr));      
fprintf(attackfile,"%s\t\tLAND(Local Area Network Denial)",inet_ntoa(dest.sin_addr));
}
}
*/
 
if( (unsigned int)tcph->syn==1 && (unsigned int)tcph->fin==1 && (unsigned int)tcph->psh==1 )
{
fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\t Malicious packet SYN-FIN-PSH combination",inet_ntoa(source.sin_addr));      
}

if( (unsigned int)tcph->fin==1 && (unsigned int)tcph->urg==1 && (unsigned int)tcph->psh==1 )
{
fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tMalicious Packet CHRISTMAS TREE PACKET",inet_ntoa(source.sin_addr));
}


if( (unsigned int)tcph->syn==1 && (unsigned int)tcph->fin==1 && (unsigned int)tcph->rst==1 )
{
fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\t Malicious packet SYN-FIN-RST combination",inet_ntoa(source.sin_addr));      
}

if( (unsigned int)tcph->syn==1 && (unsigned int)tcph->fin==1 && (unsigned int)tcph->rst==1 && (unsigned int)tcph->psh==1)
{
fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\t Malicious packet SYN-FIN-RST-PSH combination",inet_ntoa(source.sin_addr));      
}


       if( (unsigned int)tcph->syn==1 && (unsigned int)tcph->ack==0 && Size-header_size==0)
            {
             syn_count++;
            }
          if( (unsigned int)tcph->ack==1 && (unsigned int)tcph->syn==0 && Size-header_size==0)
           {
            ack_count++;
           }
//          printf("\n\nSyn packets=%ld",syn_count);
 //         printf("\n\nAck Packets=%ld",ack_count);       

        if(syn_count>2*ack_count && syn_count>100 && ack_count>50 && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
         {
     fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tSYN-FLOOD ATTACK",inet_ntoa(source.sin_addr));
         }

        if((unsigned int)tcph->fin==1 && (unsigned int)tcph->ack==0 && (unsigned int)tcph->syn==0 && (unsigned int)tcph->rst==0 && (unsigned int)tcph->psh==0 && (unsigned int)tcph->urg==0 && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
{
 fprintf(attackfile,"\n\n%s\t\t10.16.15.180 \t\tA packet should not have only fin set",inet_ntoa(source.sin_addr));
}

        if( (unsigned int)tcph->ack==1 && ntohl(tcph->ack_seq)==0 && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
         {
      fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\t Acknowledgement Number should not be set to zero when ACK Flag is set",inet_ntoa(source.sin_addr));
         }
         
         if(ntohs(tcph->source)==0 && ntohs(tcph->dest)==0 && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
  {
    fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tALERT Source and Destination Port set to zero",inet_ntoa(source.sin_addr));
  }

  if( (unsigned int)tcph->syn==0 && (unsigned int)tcph->ack==0 && (Size-header_size==0) && (unsigned int)tcph->fin==0 && (unsigned int)tcph->psh==0 && (unsigned int)tcph->urg==0 && (unsigned int)tcph->rst==0 && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
   {
   fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tNULL Packet",inet_ntoa(source.sin_addr));
   }
 

     if( ((unsigned int)tcph->syn==1) && ((unsigned int)tcph->fin==1) && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
   
   {
   fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tSYN FIN COMBINATION ",inet_ntoa(source.sin_addr));
   }   

   if( (unsigned int)tcph->syn==1 && (Size-header_size!=0) && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
    {
    fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tSYN only packet should not contain data",inet_ntoa(source.sin_addr));
    }

 
  //   if(ntohs(tcph->source)==5554 && do for ftp
      
/* 
        if(ntohs(tcph->source)==1 && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tTrojan Detected:Socks Des Troie at port  %d\tSequence No:%u",inet_ntoa(source.sin_addr),ntohs(tcph->source),ntohl(tcph->seq));
        
if(ntohs(tcph->source)==2 && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tTrojan Detected:Death at port  %d\tSequence No:%u",inet_ntoa(source.sin_addr),ntohs(tcph->source),ntohl(tcph->seq)); 

 if(ntohs(tcph->source)==20 && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tTrojan Detected:Senna Spy at port  %d\tSequence No:%u",inet_ntoa(source.sin_addr),ntohs(tcph->source),ntohl(tcph->seq));



if(ntohs(tcph->source)==22 && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tTrojan Detected:Shaft at port  %d\tSequence No:%u",inet_ntoa(source.sin_addr),ntohs(tcph->source),ntohl(tcph->seq));

if(ntohs(tcph->source)==23 && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tTrojan Detected:Fire Hacker at port  %d\tSequence No:%u",inet_ntoa(source.sin_addr),ntohs(tcph->source),ntohl(tcph->seq));

if(ntohs(tcph->source)==25 && strcmp(hostip,inet_ntoa(source.sin_addr))!=0)
fprintf(attackfile,"\n\n%s\t\t10.16.15.180\t\tTrojan Detected:I Love You at port  %d\tSequence No:%u",inet_ntoa(source.sin_addr),ntohs(tcph->source),ntohl(tcph->seq));

int payl_detection_udp(char *substring,const u_char * Buffer,int header_size)
{
        
        
/*tcp
struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
	unsigned short iphdrlen;
        iphdrlen = iph->ihl*4;
	struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));
	header_size=sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

*/

/*


	struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
	unsigned short iphdrlen;

         iphdrlen = iph->ihl*4;

	struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

          header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;
fprintf(payloadfile,"\nHeader size udp:%d",header_size);
        char *payload=Buffer+header_size;
        
        int c1=0, c2=0,flag=0,i,j;
fprintf(payloadfile,"%s",payload);

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

*/
//}

