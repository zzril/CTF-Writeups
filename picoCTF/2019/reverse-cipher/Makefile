CHALLENGE_FILES=rev rev_this.bak
CIPHER=flag.txt
FLAG=rev_this

# --------

all: $(CHALLENGE_FILES) $(FLAG)

clean:
	rm $(CIPHER) $(FLAG) *.hex patch || true

# --------

rev:
	wget 'https://jupiter.challenges.picoctf.org/static/48babf8f8c4c6b8baf336680ea5b9ddf/rev'

rev_this.bak:
	wget 'https://jupiter.challenges.picoctf.org/static/48babf8f8c4c6b8baf336680ea5b9ddf/rev_this' -O $@

$(CIPHER): rev_this.bak
	cp $^ $@

rev.hex: rev
	xxd -p $^ $@

patch.hex: rev.hex
	sed -e 's/83c005/83e805/g;s/83e802/83c002/g' $^ > $@

patch: patch.hex
	xxd -r -p $^ $@ && chmod u+x $@

$(FLAG): patch $(CIPHER)
	./$< && cat $@


