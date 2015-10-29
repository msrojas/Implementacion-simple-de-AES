/*
    Copyright (c) 2015 Alejandro Torres Hernandez

    This file is part of Implementacion simple de AES.

    Implementacion simple de AES is free software: you can redistribute it and/or modify it under the terms of the GNU 
    General Public License as published by the Free Software Foundation, either version 3 of the 
    License, or (at your option) any later version.

    Implementacion simple de AES is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without 
    even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR 
    PURPOSE. See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along with Foobar. If not, 
    see http://www.gnu.org/licenses/.

*/
#include "aes.h"

unsigned char Rcon[255] = {
0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb};

unsigned char sbox[256] =   {
//0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, //0
0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, //1
0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, //2
0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, //3
0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, //4
0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, //5
0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, //6
0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, //7
0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, //8
0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, //9
0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, //A
0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, //B
0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, //C
0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, //D
0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, //E
0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 }; //F

unsigned char mix_column[16] = {
2,3,1,1,
1,2,3,1,
1,1,2,3,
3,1,1,2
};

inline unsigned char rcon_value(unsigned char num)
{
    return Rcon[num];
}

inline unsigned char getSboxValue(unsigned char num)
{
    return sbox[num];
}

inline void print_char_as_hex(unsigned char * buffer)
{
    uint8_t i;
    for(i=0;i<16;i++)
        printf("%2.2x", buffer[i]);
    printf(" ");
}

inline void print_char_as_int(unsigned char * buffer)
{
    uint8_t i;
    for(i=0;i<16;i++)
        printf("%d ", buffer[i]);
    printf("\n");
}

uint8_t * block_malloc(uint8_t * block)
{
    uint8_t * str = (char *)malloc(16+1);
    if(str == NULL)
    {
        fprintf(stderr, "Error: ocurrio un inconveniente en la heap\n");
        exit(1);
    }

    uint8_t i;

    for(i=0;i<16;i++)
        str[i] = block[i];
    str[17] = '\0';

    return str;
}

uint8_t mix_column_3(uint8_t byte)
{
    uint8_t c = byte;
    uint8_t check_bit = byte & 0x80;
    byte <<= 1;
    byte ^= c;
    if(check_bit > 0)
        byte ^= 0x1B;

    return byte;
}

uint8_t mix_column_2(uint8_t byte)
{
    uint8_t check_bit = byte & 0x80;
    byte <<= 1;
    if(check_bit > 0)
        byte ^= 0x1B;

    return byte;
}

void MixColumn(unsigned char * block)
{
    uint8_t ii, indice = 0, byte_temp = 0;
    uint8_t j = 0, bits = 0;
    uint8_t mask = 0, t = 0;

    unsigned char block_de_4bits[5], temp[5];

    memset(block_de_4bits, 0, sizeof(block_de_4bits));
    memset(temp, 0, sizeof(temp));

    for(ii=0;ii<16;ii++) //MIX COLUMN 
    {
        block_de_4bits[indice++] = block[bits+j];

        bits = bits + 4;

        if((ii == 3) || (ii == 7) || (ii == 11) || (ii == 15))
        {
            indice = 0;
            for(t=0;t<16;t++)
            {
                byte_temp = block_de_4bits[indice];
                if(mix_column[t] == 2)
                {
                    byte_temp = mix_column_2(byte_temp);
                    temp[indice] = byte_temp;
                }
                else if(mix_column[t] == 3)
                {
                    byte_temp = mix_column_3(byte_temp);
                    temp[indice] = byte_temp;
                }
                else
                    temp[indice] = byte_temp;

                indice++;
                if(indice == 4)
                {
                    mask = ((temp[0] ^ temp[1]) ^ temp[2]) ^ temp[3];

                    if(t == 3)
                        block[0+j] = mask;
                    else if(t == 7)
                        block[4+j] = mask;
                    else if(t == 11) 
                        block[8+j] = mask;
                    else if(t == 15)
                        block[12+j] = mask;
						
                    indice = 0;
                    memset(temp, 0, sizeof(temp));
                }
            }
            j++;
            bits = 0;
            memset(block_de_4bits, 0, sizeof(block_de_4bits));
        }
    }
}

void shift_row(unsigned char * block)
{
    uint8_t i;
    uint8_t temp = block[4];
    for(i=4;i<8;i++) //SEGUNDA LINEA. 1 BYTE LEFT SHIFT
        block[i] = block[i+1];
    block[7] = temp;

    //TERCERA LINEA. 2 BYTE LEFT SHIFT
    temp = block[8];
    block[8] = block[10];
    block[10] = temp;
    temp = block[9];
    block[9] = block[11];
    block[11] = temp;

    //CUARTA LINEA. 3 BYTE LEFT SHIFT
    temp = block[12];
    block[12] = block[15];
    block[15] = block[14];
    block[14] = block[13];
    block[13] = temp;	
}

void byte_substitution(unsigned char * block)
{
    uint8_t i, byte = 0;
    for(i=0;i<16;i++)
    {	
        byte = getSboxValue(block[i]);
        block[i] = byte;
   }
}

unsigned char * rounds(unsigned char block[], unsigned char * expanded_key)
{
    uint8_t i, ii, indice = 0;
    char * cipher = NULL;
    short bits_key = 0, key_limit = 16;

    for(ii=bits_key;ii<key_limit;ii++) //XOR KEY
        block[indice++] ^= expanded_key[ii];

    bits_key += 16;
    key_limit += 16;
    indice = 0;  //Reiniciamos valor para cada iteracion	

    for(i=0;i<10;i++)
    {
        byte_substitution(block); //BYTE SUBSTITUTION
        shift_row(block); //SHIFT ROW
        if(i != 9) //EN EL ROUND 10 SE OMITE MIX COLUMN
            MixColumn(block); //MIX COLUMN

        for(ii=bits_key;ii<key_limit;ii++) //XOR KEY
            block[indice++] ^= expanded_key[ii];

        bits_key += 16;
        key_limit += 16;
        indice = 0;  //Reiniciamos valor para cada iteracion
    }

    cipher = block_malloc(block);

    return cipher;
}

unsigned char * encripta(unsigned char * cipher_text, unsigned char * expanded_key, int len)
{
    unsigned char block_de_128bits[17];
    unsigned char * rounds_cipher = NULL;
    unsigned char * cipher = (char *)malloc(len+1);
    int i, indice = 0;
    uint8_t t = 0;
    short ii = 0;

    memset(block_de_128bits, 0, sizeof(block_de_128bits));

    for(i=0;i<len;i++)
    {
        block_de_128bits[t++] = cipher_text[i];	

        if(t == 16)
        {
            rounds_cipher = rounds(block_de_128bits, expanded_key);

            for(ii=0;ii<16;ii++)
                cipher[indice++] = rounds_cipher[ii];

            t = 0;
            memset(block_de_128bits, 0, sizeof(block_de_128bits));
            free(rounds_cipher);
        }
    }

    cipher[indice] = '\0';
    return cipher;
}

unsigned char * rotate(unsigned char word[])
{
    unsigned char c = 0;
    unsigned char * temp_word = NULL;
    short i;

    c = word[0];
    for(i=0;i<3;i++)
        word[i] = word[i+1];
    word[3] = c;

    temp_word = (char *)malloc(strlen(word)+1);
    if(!temp_word)
    {
        printf("Error en malloc\n");
        exit(1);
    }
    strcpy(temp_word, word);

    return temp_word;
}

unsigned char * core(unsigned char word[], int iteration)
{
    short i;

    unsigned char * temp_word = NULL;
    temp_word = rotate(word);

    for(i=0;i<4;i++)
        temp_word[i] = getSboxValue(temp_word[i]);

    unsigned char c = rcon_value(iteration);

    temp_word[0] = temp_word[0] ^ c;

    return temp_word;
}

unsigned char * expandKey(char key[], int size, int expandedKeySize)
{
    int currentSize = 0;
    int rconIteration = 1;
    short i = 0, v_core = 0;

    unsigned char t[10];
    unsigned char * expandedKey = (char *)malloc(expandedKeySize+1);
    unsigned char * temp = NULL;

    for(i=0;i<size;i++)
        expandedKey[i] = key[i];
    currentSize = size;

    memset(t, 0, sizeof(t));

    while(currentSize < expandedKeySize)
	{
        for(i=0;i<4;i++)
            t[i] = expandedKey[(currentSize - 4) + i];
		
        if(currentSize % size == 0)
        {
            temp = core(t, rconIteration++);
            v_core = 1;
        }

        for(i=0;i<4;i++)
        {	
            if(v_core == 1)
                expandedKey[currentSize] = expandedKey[currentSize - size] ^ temp[i];
            else
                expandedKey[currentSize] = expandedKey[currentSize - size] ^ t[i];
            currentSize++;
        }

        if(v_core == 1)
        {
            free(temp);
            v_core = 0;
        }

        memset(t, 0, sizeof(t));
    }

    expandedKey[expandedKeySize+1] = '\0';

    return expandedKey;
}	
