REPO=IDZPodspecs
NAME=IDZSwiftCommonCrypto

OS=9.1

PG=README.playground
RSRC_DIR=$(PG)/Resources

$(PG): README.md
	playground README.md -p ios 
	mkdir -p  ${RSRC_DIR}
	cp Riscal.jpg ${RSRC_DIR}
	git config --global push.default simple
	git diff-files --exit-code; if [[ "$?" == "1" ]]; then git commit -a -m "Playground update from Travis [ci skip]"; git push; fi
#
# Build
#
build:
	xcodebuild build -scheme IDZSwiftCommonCrypto -destination 'platform=iOS Simulator,name=iPhone 6,OS=${OS}'
test:
	xcodebuild test -scheme IDZSwiftCommonCrypto -destination 'platform=iOS Simulator,name=iPhone 6,OS=${OS}'
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
