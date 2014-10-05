PG=IDZSwiftCommonCrypto/README.playground
RSRC_DIR=$(PG)/Resources

$(PG): README.md
	playground README.md -p ios -d IDZSwiftCommonCrypto
	mkdir -p  ${RSRC_DIR}
	cp IDZSwiftCommonCrypto/Riscal.jpg ${RSRC_DIR}

clean:
	rm -rf $(PG)
