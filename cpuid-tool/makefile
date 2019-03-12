color?=yes

CPP_FILES=$(shell find . -type f -name '*.cpp')
HEADER_FILES=$(shell find . -type f \( -iname \*.hpp -o -iname \*.h \))

CC=g++-8
CPP_FLAGS=-std=c++11 -O3 -Wall -Wextra -Werror -pedantic-errors
ifeq (color, yes)
all::
	CPP_FLAGS += -fdiagnostics-color=always
endif

EXEC=cpuid

COMPILE=$(CC) $(CPP_FLAGS) $(CPP_FILES)

all: $(CPP_FILES) $(HEADER_FILES)
	$(COMPILE) -o $(EXEC)
