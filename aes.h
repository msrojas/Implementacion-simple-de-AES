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
#ifndef AES_H
#define AES_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

inline unsigned char rcon_value(unsigned char num);
inline unsigned char getSboxValue(unsigned char num);
inline void print_char_as_hex(unsigned char * buffer);
inline void print_char(unsigned char * buffer);
uint8_t * block_malloc(uint8_t * block);
uint8_t mix_column_3(uint8_t byte);
uint8_t mix_column_2(uint8_t byte);
void MixColumn(unsigned char * block);
void shift_row(unsigned char * block);
void byte_substitution(unsigned char * block);
unsigned char * rounds(unsigned char block[], unsigned char * expande_key);
unsigned char * encripta(unsigned char * cipher_text, unsigned char * expande_key, int len);
unsigned char * rotate(unsigned char word[]);
unsigned char * core(unsigned char word[], int iteration);
unsigned char * expandKey(char key[], int size, int expandedKeySize);

#endif