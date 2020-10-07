if gcc -o randomFile randomFile.c; then
	./randomFile $1
	rm -r randomFile
fi


