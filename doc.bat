cargo doc --no-deps -p "pe-util*" --all-features
rmdir /s ./docs
robocopy target/doc docs /s
echo|set /p="<meta http-equiv="refresh" content="0; url=pe_util/index.html">" > docs/index.html