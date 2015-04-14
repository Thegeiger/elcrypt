/*
** elcrypt.c for elcrypt in /home/rouss_p/rendu/tmpcrypt
**
** Made by pierre rousselle
** Login   <rouss_p@epitech.net>
**
** Started on  Sat Feb 28 09:32:57 2015 pierre rousselle
** Last update Sun Mar  1 13:59:44 2015 pierre rousselle
*/

#include "elcrypto.h"

void            my_rightshift(char *key, int dec, int size)//
{
  int           i;
  int           j;
  char		rot;

  i = 0;
  while (i < dec)
    {
      rot = key[size];
      j = size - 1;
      while (j > 0)
	{
          key[j + 1] = key[j];
          j--;
        }
      key[j] = rot;
      ++i;
    }
}

void		my_leftshift(char *key, int dec, int size)
{
  int		i;
  int		j;
  char		rot;

  i = 0;
  while (i < dec)
    {
      j = 0;
      rot = key[j];
      while (j < size)
	{
	  key[j] = key[j + 1];
	  j++;
	}
      key[j] = rot;
      ++i;
    }
}

char		*my_subkey(t_crypt *crypt)
{
  static int	offset = -1;
  char		*key;
  char		*asciikey;
  char		*v2subsubkeya;
  char          *v2subsubkeyb;
  static char	keytab[16][4];
  int		i;
  int		k;

  if (offset == -1)
    {
      offset = 0;
      if (crypt->version == VERSION1)
	while (offset < 8)
	  {
	    if ((key = malloc(56)) == NULL || (asciikey = malloc(7)) == NULL)
	      {
		printf("malloc() error.\n");
		exit(-1);
	      }
	    strncpy(key, crypt->key, 56);
	    my_leftshift(key, 4 * offset, 55);
	    i = 0;
	    k = 0;
	    while (i < 56)
	      {
		if (key[i] == '1')
		  {
		    asciikey[k] |= ((128) >> i % 8);
		  }
		if (i % 8 == 7)
		  k++;
		i++;
	      }
	    free(key);
	    keytab[offset][0] = asciikey[3];
	    keytab[offset][1] = asciikey[4];
	    keytab[offset][2] = asciikey[5];
	    keytab[offset][3] = asciikey[6];
	    free(asciikey);
	    offset++;
	  }
      if (crypt->version == VERSION2)
	while (offset < 16)
	  {
	    if ((key = malloc(56)) == NULL || (asciikey = malloc(5)) == NULL || (v2subsubkeya = malloc(29)) == NULL || (v2subsubkeyb = malloc(29)) == NULL)
              {
                printf("malloc() error.\n");
                exit(-1);
              }
            strncpy(key, crypt->key, 56);////
	    strncpy(v2subsubkeya, key, 28);
            strncpy(v2subsubkeya, key + 28, 28);
	    my_leftshift(v2subsubkeya, offset, 27);
            my_leftshift(v2subsubkeyb, offset, 27);
	    strncpy(key, v2subsubkeya + 16, 16);
            strncpy(key + 16, v2subsubkeyb, 16);
	    free(v2subsubkeya);
	    free(v2subsubkeyb);
	    i = 0;
            k = 0;
            while (i < 32)
              {
                if (key[i] == '1')
                  {
                    asciikey[k] |= ((128) >> i % 8);
                  }
                if (i % 8 == 7)
                  k++;
                i++;
              }
	    keytab[offset][0] = asciikey[0];
            keytab[offset][1] = asciikey[1];
            keytab[offset][2] = asciikey[2];
            keytab[offset][3] = asciikey[3];
	    free(asciikey);
	    offset++;
	  }
      offset = 0;
      return (NULL);
    }


  if (crypt == RESET)
    {
      offset = 0;
      return ("offset reseted");
    }
  if (crypt->version == VERSION1)
    {
      if (crypt->optodo == ENCRYPT)
	return (keytab[offset++]);
      if (crypt->optodo == DECRYPT)
	return (keytab[7 - offset++]);
    }
  if (crypt->version == VERSION2)
    {
      if (crypt->optodo == ENCRYPT)
        return (keytab[offset++]);
      if (crypt->optodo == DECRYPT)
        return (keytab[15 - offset++]);
    }
  return (NULL);
}

void		writeblock(t_crypt *crypt, char *blocka, char *blockb, int blockoffset)
{
  char		block[8];
  int		i;
  int		offset;

  block[0] = blocka[0];
  block[1] = blocka[1];
  block[2] = blocka[2];
  block[3] = blocka[3];
  block[4] = blockb[0];
  block[5] = blockb[1];
  block[6] = blockb[2];
  block[7] = blockb[3];

  if (crypt->optodo == DECRYPT && blockoffset == crypt->blocknbr)
    {
      if (block[0] == '8' && block[1] == '8' && block[2] == '8' && block[3] == '8' && block[4] == '8' && block[5] == '8' && block[6] == '8' && block[7] == '8')//
	{
	  return ;
	}

      else
	{
	  offset = 1;
	  i = 7;
	  while (i > 0 && block[i] == block[i -1])//
	    {
	      offset++;
	      --i;
	    }
	  if (block[7] == '0' + offset)//
	    {
	      if (write(crypt->fdtarget, block, 8 - offset) == -1)
		{
		  printf("Write error.\n");
		  exit(-1);
		}
	    }
	}
    }
  else
    if (write(crypt->fdtarget, block, 8) == -1)
      {
	printf("Write error.\n");
	exit(-1);
      }
}

void		processblock(t_crypt *crypt, char block[8])
{
  static int	blockoffset = 1;
  int		cycle;
  char		sublocka[4];
  char		sublockb[4];
  char		crypted[4];
  char		buffer[4];
  char		*subkey;

  if (crypt->optodo == ENCRYPT)
    {
      sublockb[0] = block[0];
      sublockb[1] = block[1];
      sublockb[2] = block[2];
      sublockb[3] = block[3];
      sublocka[0] = block[4];
      sublocka[1] = block[5];
      sublocka[2] = block[6];
      sublocka[3] = block[7];
    }
  else if (crypt->optodo == DECRYPT)
    {
      sublockb[0] = block[0];
      sublockb[1] = block[1];
      sublockb[2] = block[2];
      sublockb[3] = block[3];
      sublocka[0] = block[4];
      sublocka[1] = block[5];
      sublocka[2] = block[6];
      sublocka[3] = block[7];
    }
  cycle = 0;
  my_subkey(RESET);
  while (cycle < crypt->version * 8)
    {
      subkey = my_subkey(crypt);
      crypted[0] = sublockb[0] ^ subkey[0];
      crypted[1] = sublockb[1] ^ subkey[1];
      crypted[2] = sublockb[2] ^ subkey[2];
      crypted[3] = sublockb[3] ^ subkey[3];

      sublocka[0] ^= crypted[0];
      sublocka[1] ^= crypted[1];
      sublocka[2] ^= crypted[2];
      sublocka[3] ^= crypted[3];

      buffer[0] = sublocka[0];
      buffer[1] = sublocka[1];
      buffer[2] = sublocka[2];
      buffer[3] = sublocka[3];

      sublocka[0] = sublockb[0];
      sublocka[1] = sublockb[1];
      sublocka[2] = sublockb[2];
      sublocka[3] = sublockb[3];

      sublockb[0] = buffer[0];
      sublockb[1] = buffer[1];
      sublockb[2] = buffer[2];
      sublockb[3] = buffer[3];

      cycle++;
    }
  writeblock(crypt, sublocka, sublockb, blockoffset);
  ++blockoffset;
}

void		processdata(t_crypt *crypt)
{
  char		block[8];
  char		padchar;
  int		ret;
  int		blocknbr;

  blocknbr = 0;
  if (crypt->optodo == DECRYPT)
    {
      while ((ret = read(crypt->fdsrc, block, 8)) == 8)
	++blocknbr;
      close(crypt->fdsrc);
      if ((crypt->fdsrc = open(crypt->srcname, O_RDONLY)) == -1)
	{
	  printf("Can't open %s.", crypt->srcname);
	  exit(-1);
	}
    }
  crypt->blocknbr = blocknbr;
  my_subkey(crypt);
  while ((ret = read(crypt->fdsrc, block, 8)) == 8)
    {
      processblock(crypt, block);
    }
  if (crypt->optodo == ENCRYPT)
    {
      crypt->blocknbr +=1;
      if (ret == 0)
	{
	  ++(crypt->blocknbr);
	  strcpy(block, "88888888");
	}
      else if (ret > 0)
	{
	  padchar = 8 - ret + '0';
	  while (ret <= 8)
	    {
	      ++ret;
	      block[ret - 1] = padchar;
	    }
	}
      processblock(crypt, block);
    }
}

t_crypt		my_get_tag(int argc, char **argv)
{
  int		i;
  t_crypt	crypt;
  char		buf;

  buf = '\0';
  crypt.version = -1;
  crypt.optodo = 0;
  crypt.fdsrc = -1;
  crypt.fdtarget= -1;
  crypt.key = &buf;
  i = 1;
  while (i < argc)
    {
      if (strcmp(argv[i], "-1") == 0)
        {
          if (crypt.version == VERSION2)
            {
              printf("Flag -1 and -2 are mutualy exclusiv.\n");
              exit(-1);
            }
          else
            crypt.version = VERSION1;
        }

      if (strcmp(argv[i], "-2") == 0)
        {
          if (crypt.version == VERSION1)
            {
              printf("Flag -1 and -2 are mutualy exclusiv.\n");
              exit(-1);
            }
          else
            crypt.version = VERSION2;
        }
      if (strcmp(argv[i], "-d") == 0)
	{
	  if (crypt.optodo == ENCRYPT)
	    {
	      printf("Flag -d and -e are mutualy exclusiv.\n");
	      exit(-1);
	    }
	  else
	    crypt.optodo = DECRYPT;
	}
      if (strcmp(argv[i], "-e") == 0)
	{
          if (crypt.optodo == DECRYPT)
            {
              printf("Flag -d and -e are mutualy exclusiv.\n");
              exit(-1);
            }
          else
            crypt.optodo = ENCRYPT;
        }
      if (strcmp(argv[i], "-f") == 0)
        {
          if (crypt.fdsrc != -1)
            {
              printf("Flag -f must occur only one time.\n");
              exit(-1);
            }
	  if (i + 1 >= argc)
	    {
	      printf("Flag -f must preced a filename.\n");
	      exit(-1);
	    }
	  crypt.srcname = argv[i + 1];
          if ((crypt.fdsrc = open(crypt.srcname, O_RDONLY)) == -1)
	    {
	      printf("Can't open %s.", crypt.srcname);
	      exit(-1);
            }
        }
      if (strcmp(argv[i], "-o") == 0)
        {
          if (crypt.fdtarget != -1)
            {
              printf("Flag -o must occur only one time.\n");
              exit(-1);
            }
          if (i + 1 >= argc)
            {
              printf("Flag -o must preced a filename.\n");
              exit(-1);
            }
          crypt.targetname = argv[i + 1];
          if ((crypt.fdtarget = open(crypt.targetname, (O_WRONLY | O_CREAT | O_TRUNC), (S_IRUSR | S_IWUSR))) == -1)
            {
              printf("Can't open %s.", crypt.targetname);
              exit(-1);
            }
        }
      if (strcmp(argv[i], "-k") == 0)
        {
          if (crypt.key[0] != '\0')
            {
              printf("Flag -k must occur only one time.\n");
              exit(-1);
            }
          if (i + 1 >= argc)
            {
              printf("Flag -k must preced a key.\n");
              exit(-1);
            }
	  if (strlen(argv[1 + i]) != 8 && strlen(argv[i + 1]) != 65 && strlen(argv[i + 1]) != 18)
	    {
	      printf("Key must be 8 bytes long for ascii code, 18 bytes long for hexa or 65 byte long for binary.\n");
	      exit(-1);
	    }
          crypt.key = argv[i + 1];
        }
      i++;
    }
  if (crypt.fdtarget == -1 || crypt.fdsrc == -1 || crypt.optodo == -1)
    {
      printf("Not enough paramter : elcrypt -d/e -f source -o target -k key\n");
      exit(-1);
    }
  if (crypt.version == -1)
    crypt.version = VERSION2;
  return (crypt);
}

char            *decodekey_parity(char *key)
{
  char          *binkey;
  char          *binkey_np;
  int           i;
  int           j;
  int		parity;

  binkey = keytbin(key);
  if ((binkey_np = malloc(56)) == NULL)
    {
      printf("malloc() error.\n");
      exit(-1);
    }
  i = 1;
  j = 0;
  parity = 0;
  while (i <= 64)
    {
      binkey_np[j] = binkey[i - 1];
      if (binkey[i - 1] == 1)
	++parity;
      i++;
      if (i % 8 == 0)
	{
	  if ((parity % 2 == 0 && binkey[i - 1]) != 0 || (parity % 2 == 1 && binkey[i - 1] != 1))
	    {
	      printf("Parity bit incorrect.\n");
	      exit(-1);
	    }
	  i++;
	  parity = 0;
	}
      j++;
    }
  return (binkey_np);
}

char		*decodekey(char *key)
{
  char		*binkey;
  char		*binkey_np;
  int		i;
  int		j;

  binkey = keytbin(key);
  if ((binkey_np = malloc(56)) == NULL)
    {
      printf("malloc() error.\n");
      exit(-1);
    }
  i = 1;
  j = 0;
  while (i <= 64)
    {
      binkey_np[j] = binkey[i - 1];
      i++;
      if (i % 8 == 0)
        i++;
      j++;
    }
  return (binkey_np);
}

int		main(int argc, char **argv)
{
  t_crypt	crypt;
  crypt = my_get_tag(argc, argv);
  if (crypt.version == VERSION1 || ISPARITYON != 1)
    crypt.key = decodekey(crypt.key);
  else if (crypt.version == VERSION2)
    crypt.key = decodekey_parity(crypt.key);
  processdata(&crypt);
  close(crypt.fdsrc);
  close(crypt.fdtarget);
}
