REPO=IDZPodspecs
NAME=IDZSwiftCommonCrypto
PG=IDZSwiftCommonCrypto/README.playground
RSRC_DIR=$(PG)/Resources

$(PG): README.md
	playground README.md -p ios -d IDZSwiftCommonCrypto
	mkdir -p  ${RSRC_DIR}
	cp IDZSwiftCommonCrypto/Riscal.jpg ${RSRC_DIR}


clean:
	rm -rf $(PG)

# push tags to GitHub
push_tags:
	git push origin --tags

# Lint the podspec
lint_pod:
	pod spec lint --verbose ${NAME}.podspec --sources=https://github.com/iosdevzone/IDZPodspecs.git

# Push pod to private spec repository
push_pod:
	pod repo push ${REPO} ${NAME}.podspec
