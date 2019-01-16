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
	int PASSWORD_len=strlen(PASSWORD);
	srp_create_salted_verification_key1(serv_ses,USERNAME,PASSWORD,PASSWORD_len,&serv_salt,serv_salt_len,&serv_ver,&serv_ver_len);
	printf ("server_verifier    @ %p len:%d\n",serv_ver,serv_ver_len);
	printf ("server_salt        @ %p len:%d\n",serv_salt,serv_salt_len);
	if (serv_salt==NULL || serv_ver==NULL) return -2;

	SRPKeyPair *server_keys=srp_keypair_new(serv_ses,serv_ver,serv_ver_len,&server_pubkey,&server_pubkey_len);
	printf ("server_keys        @ %p pk len:%d\n",server_keys,server_pubkey_len);
	if (server_keys==NULL) return -3;


	SRPUser *usr=srp_user_new1(SRP_SHA512,srp_ng_new(SRP_NG_3072,NULL,NULL),USERNAME,PASSWORD,PASSWORD_len);
	printf ("user session       @ %p\n",usr);
	const unsigned char *usr_pubkey; int usr_pubkey_len;
	srp_user_start_authentication (usr,NULL,&usr_pubkey,&usr_pubkey_len);
	printf ("user_pubkey        @ %p pk len:%d\n",usr_pubkey,usr_pubkey_len);

	//MIX AND MATCH:
	const unsigned char *usr_proof; int usr_proof_len;
	srp_user_process_challenge (usr,serv_salt,serv_salt_len,server_pubkey,server_pubkey_len,&usr_proof,&usr_proof_len);
	printf ("user_proof         @ %p len:%d\n",usr_proof,usr_proof_len);

	srp_verifier_new1 (serv_ses,USERNAME,0,serv_salt,serv_salt_len,serv_ver,serv_ver_len,usr_pubkey,usr_pubkey_len,NULL,NULL,server_keys);


	srp_keypair_delete(server_keys);
	srp_session_delete(serv_ses);
	return 0;
}