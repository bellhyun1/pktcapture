#include <pcap.h>
#include <stdio.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void userprint(int start, int end, const u_char* s)
{
	int i;
	printf("from %d~%d :  ",start,end);
	for(i=start;i<end;i++){
		printf("%02x ",s[i]);
	}
	printf("\n");
}

void userprintd(int start, int end, const u_char* s)
{
        int i;
        printf("from %d~%d :  ",start,end);
        for(i=start;i<end-1;i++){
                printf("%d.",s[i]);
        }
		printf("%d",s[i]);
        printf("\n");
}




int main(int argc, char* argv[]) {
  int ipend=0,tcpend=0;// ip header end. tcp start
  int sp,dp;
  int datal=0;
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("eth DA and SA\n");
    userprint(0,6,packet);
    userprint(6,12,packet);
    if(packet[12]*256+packet[13]!=2048){
        printf("not ip protocol\n");
        continue;
    }
    //14부터 ip시작,14+12가 sa 4B, da 4B
    printf("ip SA and DA\n");
    userprintd(26,30,packet);
    userprintd(30,34,packet);
    if(packet[23]!=6){
        printf("not tcp protocol");
        continue;
    }

    ipend=14+(packet[14]%16)*4;// 바로 여기부터 그냥 쓰면 된다
    printf("tcp SP and DP\n");
    sp=packet[ipend]*256+packet[ipend+1];
    dp=packet[ipend+2]*256+packet[ipend+3];
    printf("%d\n",sp);
    printf("%d\n",dp);  
    tcpend=ipend+((int)(packet[ipend+12]/16))*4;
    datal=header->caplen-tcpend;
    printf("data:\n");
    if(datal==0){
	printf("no data\n");
    }
    else if(datal<=32){
	userprint(tcpend,tcpend+datal,packet);
    }
    else 
	userprint(tcpend,tcpend+32,packet);
    printf("%u bytes captured\n", header->caplen);
  }

  pcap_close(handle);
  return 0;
}
