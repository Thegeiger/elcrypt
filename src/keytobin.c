/*
** keytobin.c for ktb in /home/geiger_a/rendu/elcrypt
**
** Made by anthony geiger
** Login   <geiger_a@epitech.net>
**
** Started on  Sat Feb 28 16:51:36 2015 anthony geiger
** Last update Sat Feb 28 23:18:05 2015 pierre rousselle
*/

#include "elcrypto.h"

static char	*ascii_in_bin(char *key, char *str)
{
  int           i;
  int           n;
  char          c;
  int		j;

  i = 0;
  j = 0;
  while (str[i])
    {
      n = 0;
      c = str[i];
      while (n != 8)
        {
          if ((c & (128) >> n) & (128 >> n))
	    key[j] = '1';
          else
	    key[j] = '0';
	  j++;
          n++;
        }
      i++;
    }
  return (key);
}

static char	*deci_in_bin(int deci, char *key)
{
  static int	j = 0;
  int		i;
  char		tmp;

  i = 0;
  while (i < 4)
    {
      key[j] = deci % 2 + 48;
      deci = deci / 2;
      i++;
      j++;
    }
  i = 0;
  tmp = key[3];
  key[3] = key[0];
  key[0] = tmp;
  tmp = key[2];
  key[2] = key[1];
  key[1] = tmp;
  return (key);
}

static char		*hexa_in_bin(char *key, char *str)
{
  int			i;
  char			tmp;
  int			deci;

  i = 2;
  deci = 0;
  while (i != 18)
    {
      tmp = '\0';
      strncat(&tmp, str + i, 1);
      deci = (int)strtol(&tmp, NULL, 16);
      key = deci_in_bin(deci, key);
      i++;
    }
  return (key);
}

char		*keytbin(char *str)
{
  char		*key;

  if ((key = malloc(sizeof(char) * 64)) == NULL)
    exit(-1);
  if (strlen(str) == 8)
    key = ascii_in_bin(key, str);
  else if (strlen(str) == 18)
    key = hexa_in_bin(key, str);
  else if (strlen(str) == 65)
    return (str + 1);
  else
    {
      puts("Unknow key.\n");
      exit(-1);
    }
  return (key);
}
