all:
	cd tc_redirect && go generate
	cd tc_sequencer && go generate
	git add .
	git commit -m "update"
	git push