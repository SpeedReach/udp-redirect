all:
	cd tc_redirect && go generate
	git add .
	git commit -m "update"
	git push