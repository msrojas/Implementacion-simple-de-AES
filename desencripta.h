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
#ifndef DESENCRIPTA_H
#define DESENCRIPTA_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

void print_block_as_int(uint8_t buffer[]);
inline get_inverse_Sbox(uint8_t num);
void inverse_MixColumn(uint8_t * block);
void inverse_byte_substitution(uint8_t * block);
void inverse_shift_row(uint8_t * valores);
uint8_t * rounds_des(uint8_t block[], unsigned char * expanded_key);
uint8_t * desencripta(unsigned char * cipher, unsigned char * expanded_key,int len);

#endif