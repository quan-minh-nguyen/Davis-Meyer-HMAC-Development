#include <tomcrypt.h>

unsigned char* Read_File (char fileName[], int *fileLen);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen);
void Write_Hex_To_File(char fileName[], unsigned char hex[], int hexLength);
unsigned char* AES_ECB_ENC(unsigned char plaintext[], unsigned char key[], int key_size, int plaintext_length);
void Show_in_Hex(char name[], unsigned char hex[], int hexlen);
unsigned char* DM(unsigned char* message, int messageLength, unsigned char* iv);

int main(int argc, char* argv[]){
    //Reading the message
    int messageLength;
    unsigned char* message = Read_File(argv[1], &messageLength);

    //Reading the seed
    int seedLength;
    unsigned char* seed = Read_File(argv[2], &seedLength);

    //Generating the key and writing it to a file
    unsigned char* key = PRNG(seed, seedLength, 16);
    Write_Hex_To_File("Key.txt", key, 16);

    //Reading the initial value
    int ivLength;
    unsigned char* iv = Read_File(argv[3], &ivLength);

    //Hashing the message using DM hash function and writing it to file
    unsigned char* h = DM(message, messageLength, iv);
    Write_Hex_To_File("DM.txt", h, 16);


    //Creating the tag//

    //concat1 is the key and message concatenated for the first hash. It is the length of the message and the key combined
    unsigned char concat1[messageLength+16];
    for(int i = 0; i < 16; i++) concat1[i] = key[i];
    for(int i = 0; i < messageLength; i++) concat1[i+16] = message[i];

    //hash on concat1 is performed and saved in hash1
    unsigned char* hash1 = DM(concat1, messageLength + 16, iv);

    //concat2 is the key and hash1 concatenated for the second hash (the tag). It is the length of the key and hash1 combined
    unsigned char concat2[32];
    for(int i = 0; i < 16; i++) concat2[i] = key[i];
    for(int i = 0; i < 16; i++) concat2[i+16] = hash1[i];

    //hash on concat2 to create the tag (saved in hash2)
    unsigned char* hash2 = DM(concat2, 32, iv);

    //Writing tag to file
    Write_Hex_To_File("TAG.txt", hash2, 16);

    free(h);
    free(hash1);
    free(hash2);
    return 0;
}

/*============================
        Read from File
==============================*/
unsigned char* Read_File (char fileName[], int *fileLen)
{
    FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;
	return output;
}

/*============================
        PRNG Fucntion 
==============================*/
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnlen)
{
	int err;
    unsigned char *pseudoRandomNumber = (unsigned char*) malloc(prnlen);

	prng_state prng;                                                                     //LibTomCrypt structure for PRNG
    if ((err = chacha20_prng_start(&prng)) != CRYPT_OK){                                //Sets up the PRNG state without a seed
        printf("Start error: %s\n", error_to_string(err));
    }					                
	if ((err = chacha20_prng_add_entropy(seed, seedlen, &prng)) != CRYPT_OK) {           //Uses a seed to add entropy to the PRNG
        printf("Add_entropy error: %s\n", error_to_string(err));
    }	            
    if ((err = chacha20_prng_ready(&prng)) != CRYPT_OK) {                                   //Puts the entropy into action
        printf("Ready error: %s\n", error_to_string(err));
    }
    chacha20_prng_read(pseudoRandomNumber, prnlen, &prng);                                //Writes the result into pseudoRandomNumber[]

    if ((err = chacha20_prng_done(&prng)) != CRYPT_OK) {                                   //Finishes the PRNG state
        printf("Done error: %s\n", error_to_string(err));
    }

    return (unsigned char*)pseudoRandomNumber;
}

//Writes the given unsigned char array "hex[]" as hex to a file with fileName
void Write_Hex_To_File(char fileName[], unsigned char hex[], int hexLength){
    FILE *pFile;
    pFile = fopen(fileName, "w");
    if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}

    for (int i = 0 ; i < hexLength ; i++) fprintf(pFile, "%02x", hex[i]);
    fclose(pFile);
}

/*============================
        AES ECB Encryption Fucntion
==============================*/
unsigned char* AES_ECB_ENC(unsigned char plaintext[], unsigned char key[], int key_size, int plaintext_length)
{
	int number_of_rounds = 10, cipherSize = 16;
	unsigned char temp_ciphertext[cipherSize];
	unsigned char* ciphertext = malloc(plaintext_length * sizeof(ciphertext));
	int err;

	symmetric_key skey;															//libtom structure to setup AES-ECB key
	if((err = aes_setup(key, key_size, number_of_rounds, &skey)) != CRYPT_OK){ 	//Sets up cipher for use with specified key and number of rounds
		printf("Setup error: %s\n", error_to_string(err));
		return 0;
	}						
	aes_ecb_encrypt(plaintext, temp_ciphertext, &skey);			    	//Encrypts plaintext w/ skey and stores it in ciphertext
	memcpy(ciphertext, temp_ciphertext, 16);							//Copies block of decrypted text into the full decryptTxt array
	//Show_in_Hex("Ciphertext:", ciphertext, 16);
	aes_done(&skey);												//Terminate the cipher context

	return ciphertext;
}

/*============================
        Showing in Hex 
==============================*/
void Show_in_Hex(char name[], unsigned char hex[], int hexlen)
{
	printf("%s: ", name);
	for (int i = 0 ; i < hexlen ; i++)
   		printf("%02x", hex[i]);
	printf("\n");
}

//Davies-Meyer Hash Function
unsigned char* DM(unsigned char* message, int messageLength, unsigned char* iv){
    int n = messageLength/16;       //n is the number of submessages and number of times recursive hash is performed
    unsigned char* h = malloc(16);  //hash is always 16 bytes
    unsigned char* encryption;
    unsigned char m[16];            //submessage is 16 bytes

    //h{0} = iv
    for(int i = 0; i < 16; i++) h[i] = iv[i];

    for(int i = 0; i < n; i++){
        memcpy(m, message+(16*i), 16);
        //perform AES encryption on h{i-1} using m{i} as key
        encryption = AES_ECB_ENC(h, m, 16, 16);
        
        //performing XOR to get h{i}
        for(int j = 0; j < 16; j++){
            h[j] = encryption[j] ^ m[j];
        }
    }

    //h{n} is returned as the value of the DM hash
    return h;
}