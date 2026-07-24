# AES-CMAC for COSE

The internet-draft is tracked as [draft-ietf-cose-cmac](https://datatracker.ietf.org/doc/draft-ietf-cose-cmac/).

A local build of the current main branch is available [draft-ietf-cose-cmac.html](https://briansipos.github.io/draft-ietf-cose-cmac/draft-ietf-cose-cmac.html).
A difference from the datatracker draft and this local version can be [viewed side-by-side](https://author-tools.ietf.org/diff?doc_1=draft-ietf-cose-cmac&url_2=https://briansipos.github.io/draft-ietf-cose-cmac/draft-ietf-cose-cmac.txt&raw=1).

Prerequisites to building can be installed on Ubuntu with:
```sh
sudo apt-get install -y cmake python3-pip python3-wheel ruby xmlstarlet aspell
pip3 install xml2rfc
```

Then the document can be built with
```sh
cmake -S . -B build/default
cmake --build build/default
```
finally opened with
```sh
xdg-open build/default/draft-*.html
```

Example cases can be generated with
```sh
python3 -m pytest src
```