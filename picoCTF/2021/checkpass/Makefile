CHALLENGE_FILES=checkpass

# --------

all: $(CHALLENGE_FILES)

clean:
	rm $(CHALLENGE_FILES) || true

# --------

checkpass:
	wget 'https://mercury.picoctf.net/static/f9620d2398e030be834cfa10fb8e971a/checkpass' && chmod u+x $@


