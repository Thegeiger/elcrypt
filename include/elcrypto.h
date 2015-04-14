/*
** elcrypto.h for elcrypto in /home/rouss_p/rendu/elcrypt
** 
** Made by pierre rousselle
** Login   <rouss_p@epitech.net>
** 
** Started on  Sat Feb 28 17:58:45 2015 pierre rousselle
** Last update Sun Mar  1 13:57:50 2015 pierre rousselle
*/

#ifndef ELCRYPTO_H_
#define ELCRYPTO_H_

# include <stdio.h>
# include <stdlib.h>
# include <sys/stat.h>
# include <fcntl.h>
# include <string.h>
# include <unistd.h>

# define ISPARITYON 1
# define ENCRYPT 1
# define DECRYPT 2
# define VERSION1 1
# define VERSION2 2
# define RESET (void *)0

typedef struct  s_crypt
{
  char          *key;
  char          *srcname;
  int           fdsrc;
  char          *targetname;
  int           fdtarget;
  char          optodo;
  int		blocknbr;
  char		version;
}               t_crypt;

char *keytbin(char *);

#endif /* !ELCRYPTO_H_*/
