##
## Makefile for make in /home/geiger_a/Makefile
## 
## Made by anthony geiger
## Login   <geiger_a@epitech.net>
## 
## Started on  Sat Jan  3 12:39:16 2015 anthony geiger
## Last update Sun Mar  1 14:06:43 2015 anthony geiger
##

RM	= rm -f

DEBUG	= 0

VERIF	= 0

CC	= gcc

NAME	= elcrypt

SRCS	= elcrypt.c \
	keytobin.c

SRCS_DIR	= src/

SRCS	:= $(addprefix $(SRCS_DIR), $(SRCS))

OBJS	= $(SRCS:.c=.o)

CFLAGS  = -I./include/
CFLAGS  += -Wall -Wextra -W
CFLAGS  += -pedantic -ansi -std=c99

LDFLAGS =

ifeq ($(DEBUG), 1)
        CFLAGS  += -g -std=c99
        CC      := clang
endif

ifeq ($(VERIF), 1)
        CFLAGS  += -g -std=c99
        LDFLAGS += -lstdc++
        CC      := gcc
endif


all: $(NAME)

$(NAME): $(OBJS)
	$(CC) $(OBJS) -o $(NAME) $(LDFLAGS)

re:	fclean all

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

.PHONY: all clean fclean re
