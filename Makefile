all:
	cd tc_redirect 
	go generate
	cd .. 
	git add .
	git commit -m "update"
	git push