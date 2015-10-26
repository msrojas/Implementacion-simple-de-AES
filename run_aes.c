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
#include "desencripta.h"

#define BUFFER_SIZE 16 //Key y bloques de 128 bits

void print_cipher(unsigned char * cipher, int longitud)
{
    uint8_t indice = 0;
    int t;

    for(t=0;t<longitud;t++)
    {
        printf("%2.2x", cipher[t]);
        indice++;

        if(indice == BUFFER_SIZE)
        {
            printf(" ");
            indice = 0;
        }
    }

    printf("\n");
}

int main()
{
    /*
    #######################################
                kEY EXPANSION
    #######################################
    */
    int expandedKeySize = 176; //Expansion para 128 bits
    unsigned char * expandedKey = NULL;
    unsigned char key[BUFFER_SIZE] = "0123456789abcdef";  //NO USES ESTA LLAVE PARA ALGO SERIO
 
    int size = BUFFER_SIZE;

    expandedKey = expandKey(key, size, expandedKeySize);

    /*
    #######################################
            FINAL DE KEY EXPANSION
    #######################################
    */

    /*
    #######################################
              PLAIN TEXT PADDING
    #######################################
    */		

    unsigned char chars[] = "Hola, esto es una prueba"; //PLAIN TEXT
    int len = strlen(chars);
    int resto = BUFFER_SIZE - (len % BUFFER_SIZE);	 //Calculamos resto para verificar si tenemos que agregar padding
    unsigned char * cipher_text = NULL; 
    uint8_t padding = 0;
    uint8_t * text_padding = NULL;

    printf("Texto:\n");
    printf("%s\n\n", chars);

    if(resto > 0) //Si resto es mayor a cero tendremos que agregar padding
    {
        if(resto > BUFFER_SIZE) //El resto no debe ser mayor a BUFFER_SIZE. De ser asi, posiblemente haya un overflow
        {
        	fprintf(stderr, "Error: los bytes exceden el BUFFER_SIZE\n");
            exit(1);
        }

        text_padding = (char *)malloc(len+resto+1);
        if(text_padding == NULL)
        {
            fprintf(stderr, "Error: ocurrior un inconveniente en la heap\n");
            exit(1);
        }

        unsigned char bytes_restantes[BUFFER_SIZE];  //Variable para almacenar los bytes que faltan
        memset(bytes_restantes, 0, sizeof(bytes_restantes));

        short i;
        for(i=0;i<resto;i++)
            bytes_restantes[i] = resto;  //Almacenamos...

        strncpy(text_padding, chars, len);
        strncat(text_padding, bytes_restantes, resto);

        text_padding[len+resto+1] = '\0';

        padding = 1;
    }
    /*
    #####################################################################
                          FIN DE PLAIN TEXT PADDING
    #####################################################################
    */

    int longitud = len + resto;

    /*
    ######################################################################
                           ENCRIPTAR PLAIN TEXT
    ######################################################################
    */
    unsigned char * cipher = NULL;

    if(padding == 1)
    {
        cipher = encripta(text_padding, expandedKey, longitud);
        free(text_padding);
    }
    else 
        cipher = encripta(chars, expandedKey, longitud);

    printf("Texto encriptado\n");
    print_cipher(cipher, longitud);
    printf("\n");
    /*
    ######################################################################
                           FIN DE ENCRIPTAR PLAIN TEXT
    ######################################################################
    */

    /*
    ######################################################################
                           DESENCRIPTAR CIPHER
    ######################################################################
    */
    uint8_t * return_cipher = NULL;						  

    return_cipher = desencripta(cipher, expandedKey,longitud);
    /*
    ######################################################################
                         FIN DE DESENCRIPTAR CIPHER
    ######################################################################
    */

    /*
    ######################################################################
                        ELIMINAMOS PADDING SI ES NECESARIO
    ######################################################################
    */					  
    int indice = 0;
    int ii;

    if(resto > 0)
    {
        indice = longitud - resto;
        for(ii=indice;ii<longitud;ii++)
            return_cipher[ii] = '\0';
    }
    /*
    ######################################################################
                           FIN DE ELMINAR PADDING
    ######################################################################
    */

    printf("Texto desencriptado\n");
    printf("%s\n", return_cipher);

    /*
    ######################################################################
                                 LIBERAMOS
    ######################################################################
    */

    free(return_cipher);
    free(cipher);					 
    free(cipher_text);
    free(expandedKey);

    return 0;
}
