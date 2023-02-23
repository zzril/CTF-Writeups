CHALLENGE_FILES=chall.S
BIN=a.out
LIB=debug.so

# --------

CC=gcc
CFLAGS=-Wall -Wextra -pedantic

# --------

all: $(CHALLENGE_FILES) $(BIN) $(LIB)

clean:
	rm $(BIN) $(LIB) || true

# --------

chall.S:
	wget 'https://mercury.picoctf.net/static/4b062ca73355f923a41be8d673206a78/chall.S'

$(BIN): $(CHALLENGE_FILES)
	$(CC) -o $@ $^

%.so: %.c
	$(CC) $(CFLAGS) -shared -o $@ $^


