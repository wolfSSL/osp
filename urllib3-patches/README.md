# urllib3 wolfSSL port

This folder contains patches to add support for wolfSSL to urllib3 project.
Subfolder x.yy.zz contains patches for urllib3 version x.yy.zz.

## Installation instructions

1. clone urllib3 repository and checkout to the right verion (eg. 1.26.18)
```bash
git clone https://github.com/urllib3/urllib3.git
git checkout 1.26.18
```
2. apply patches from this repository
```bash
git am path/to/osp/urllib3-patches/1.26.18/*.patch
```
3. Install wolfssl-py

Follow instructions in [wolfssl-py](https://github.com/wolfssl/wolfssl-py) repository.

4. (Optional) if you want to run the test suite install urllib3 dev requirements
```bash
python -m pip install -r urllib3/dev-requirements.txt
```
5. Install urllib3 from the folder where you applied patches
```bash
python -m pip install -e .
```
6. (Optional) run the test suite
```bash
python -m pytest
```
