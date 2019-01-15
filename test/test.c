#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "srp.h"
#define USERNAME "test-mest"
#define PASSWORD "secret-mecret"

int main(){
	SRPSession *serv_ses=srp_session_new(SRP_SHA512,SRP_NG_3072, NULL,NULL);
	printf ("SRPSession created @ %p\n",serv_ses);
	if (serv_ses==NULL) return -1;

	const unsigned char *serv_salt; int serv_salt_len=16;
	const unsigned char *serv_ver; int serv_ver_len;
	const unsigned char *server_pubkey; int server_pubkey_len;
	srp_create_salted_verification_key1(serv_ses,USERNAME,PASSWORD,strlen(PASSWORD),&serv_salt,serv_salt_len,&serv_ver,&serv_ver_len);
	printf ("server_verifier    @ %p len:%d\n",serv_ver,serv_ver_len);
	printf ("server_salt        @ %p len:%d\n",serv_ver,serv_ver_len);


	SRPKeyPair *server_keys=srp_keypair_new(serv_ses,serv_ver,serv_ver_len,&server_pubkey,&server_pubkey_len);
	printf ("server_keys        @ %p pk len:%d\n",server_keys,server_pubkey_len);



	srp_keypair_delete(server_keys);
	srp_session_delete(serv_ses);
	return 0;
}