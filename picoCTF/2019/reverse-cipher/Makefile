CHALLENGE_FILES=rev rev_this

# --------

all: $(CHALLENGE_FILES)

clean:
	rm $(CHALLENGE_FILES) patch *.hex *.txt || true

# --------

rev:
	wget 'https://jupiter.challenges.picoctf.org/static/48babf8f8c4c6b8baf336680ea5b9ddf/rev' && chmod u+x $@

rev_this:
	wget 'https://jupiter.challenges.picoctf.org/static/48babf8f8c4c6b8baf336680ea5b9ddf/rev_this'


