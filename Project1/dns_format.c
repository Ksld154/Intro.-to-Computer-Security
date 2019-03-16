#include<stdio.h>
#include<string.h>




void dns_query_format(unsigned char *dns, unsigned char *host){
	int lock = 0, i;
	strcat((char*)host, ".");
	for(i = 0 ; i < strlen((char*)host) ; i++) {
		if(host[i]=='.'){
			*dns++ = i-lock;
			for(; lock < i; lock++) {
				*dns++ = host[lock];
			}
			lock++;
		}
	}
	*dns++=0x00;
}


int main(){

    unsigned char dns[64];
    unsigned char domain[]  = "www.google.com";
    int domain_len = strlen((const char*)domain);
    
    printf("len: %d\n", domain_len);

    dns_query_format(dns, domain);

    for(int i = 0; i <= domain_len+1; i++){
        printf("%d ", dns[i]);
    }
    printf("\n");
   
    for(int i = 0; i < domain_len; i++){
        printf("%c ", domain[i]);
    }
    printf("\n");
    // unsigned char domain2[] = "www.google.com";
    // for(int i = 0; i <= domain_len; i++){
    //     printf("%d ", domain2[i]);
    // }
    // printf("\n");
    // printf("%s\n", dns);
    return 0;
}