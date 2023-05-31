# Overview
 `micropython-wolfssl` is a collection of [user modules](https://docs.micropython.org/en/v1.19.1/develop/cmodules.html) for [micropython](https://micropython.org/) that enable [wolfSSL](https://www.wolfssl.com) to be used for TLS and cryptographic operations. It is an API-compatible replacement for the built-in implementations provided by MicroPython's `ussl`, `ucryptolib` and `uhashlib` modules.

# How it works
`micropython-wolfssl` provides three modules: `wolfssl`, `wolfcryptolib`, and `uhashlib`. These modules implement the same API as MicroPython's built-in implementations of of SSL/TLS (`ussl`), encryption (`ucryptolib`), and hashing (`uhashlib`). This means that python code utilizing these modules should not need to be changed (other than the name of the imported modules) when `micropython-wolfssl` is used, and all MicroPython documentation for these modules can be followed. The only changes in behavior are different SSL error codes returned on failure. WolfSSL has much more comprehensive error codes than most other SSL libraries, and are detailed in [appendix F of the wolfSSL manual](https://www.wolfssl.com/documentation/manuals/wolfssl/appendix06.html).

## Module Structure
```
micropython-wolfssl/
├── micropython.mk          <-- makefile fragment parsed by MicroPython
├── moducryptolib_wolfssl.c <-- implementation of ucryptolib
├── moduhashlib_wolfssl.c   <-- implemenation of uhashlib
├── modussl_wolfssl.c       <-- implementation of ussl
├── ports                   <-- directory containing port-specific configuration and code
├── README.md
├── tests
```
## Port-specific configuration
`micropython-wolfssl` supports a subset of the official ports included in MicroPython. The names of the ports are the same, and you must specify the port you are targeting when building MicroPython using the makefile variable `WOLFSSL_PORT` (more on this in the steps below). Valid values for `WOLFSSL_PORT` are: `unix` and `stm32`. If left unspecified, the default port is the `unix` port. Each port supported by `micropython-wolfssl` can be found in its own directory under `micropython-wolfssl/ports`. Each port contains a `user_settings.h` file, and optionally, a `wolfssl_port.c` file.

## User settings
wolfSSL can be customized for a specific target application or platform using a `user_settings.h` file. This module provides a default `user_settings.h` file for each port located in the `ports` directory. If you wish you further customise wolfSSL, you can create your own `user_settings.h` and pass it to the build system through the `WOLFSSL_USER_SETTINGS_FILE` variable. This will override the default one located in the `ports/$(WOLFSSL_PORT)` directory. The directory containing this file will be added to the compiler include path, so it is recommended you create a new directory holding this file with nothing else in it. Information on the various build options that can tailor wolfSSL to your application can be found in [chapter 2 of the wolfSSL manual](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter02.html#features-defined-as-c-pre-processor-macro).

## Port-specific hardware
Some ports also contain a `wolfssl_port.c` file containing implementations of certain functions required to enable wolfSSL to work on a specific hardware platform. These port files can be found in `ports/` directory, where each subdirectory corresponds to the specific MicroPython port. Information on porting wolfSSL to a new platform can be found in [Chapter 5: Portability](https://www.wolfssl.com/documentation/manuals/wolfssl/chapter05.htmlf) and [Appendix H: Porting Guide](https://www.wolfssl.com/documentation/manuals/wolfssl/appendix08.html) in the wolfSSL manual.

# Building micropython with `micropython-wolfssl`

## Steps

1. Familiarize yourself with the MicroPython [documentation for user modules](https://docs.micropython.org/en/v1.19.1/develop/cmodules.html), specifically for how user modules are included in the build
2. Clone the wolfSSL repo and checkout a compatible version tag 
```
# first, navigate to the directory where you wish to clone wolfSSL, then run the following
git clone https://github.com/wolfssl/wolfssl.git
cd wolfssl
git checkout v5.6.0-stable
```
3. Clone the OSP repository 
```
# first, navigate to the directory where you wish to clone osp, then run the following
git clone https://github.com/wolfssl/osp.git
```
4. **OPTIONAL but recommended:** In the main MicroPython repository, disable support for the `ussl`, `ucryptolib` and `uhashlib` modules in your port by ensuring the following C macros are defined to 0 at compile time
```C
#define MICROPY_PY_USSL       0
#define MICROPY_PY_UCRYPTOLIB 0
#define MICROPY_PY_UHASHLIB   0
```
**NOTE**: See [port-specific-macros](#port-specific-macros) section below for instructions on the best way to do this for your port.

5. Ensure the C macro `MICROPY_TRACKED_ALLOC` is defined to `1` for your port at build-time. This is also detailed in the [port-specific-macros](#port-specific-macros) section below. 
6. Run `make clean` for your port (for some ports you need to include the `BOARD` or `VARIANT` argument to make)
7. Build your MicroPython port, providing `make` with three important command line variables: The path to the parent directory containing this user module (the OSP repo's `micropython-modules` directory) in the `USER_C_MODULES` variable, the path to your wolfSSL source tree in the `WOLFSSL_SOURCE` variable, and the target port for wolfSSL in the `WOLFSSL_PORT` variable. If your port requires other build arguments, make sure to include those too
```
make USER_C_MODULES=/path/to/osp/micropython-modules WOLFSSL_SOURCE=/path/to/wolfssl WOLFSSL_PORT=unix
```
If you want to use a custom `user_settings.h` for your port, pass it to make through the `WOLFSSL_USER_SETTINGS_FILE` variable:
```
make USER_C_MODULES=/path/to/osp/micropython-modules  WOLFSSL_SOURCE=/path/to/wolfssl WOLFSSL_PORT=unix \
     WOLFSSL_USER_SETTINGS_FILE=/path/to/user_settings.h
```

## Port-specific Macros

When using `micropython-wolfssl`, most users will want to disable the built-in implementations of TLS, crypto, and hashing in order to reduce code size (including two TLS stacks in MicroPython will result in a very large binary). This requires setting a few important C macros in your port's build configuration to prevent the default implementations from being compiled. These macros are:

 ```C
#define MICROPY_PY_USSL       0   // turns off built-in ussl module
#define MICROPY_PY_UCRYPTOLIB 0   // turns off built-in ucryptolib module
#define MICROPY_PY_UHASHLIB   0   // turns off built-in uhashlib module
```

Additionally, the C macro `MICROPY_TRACKED_ALLOC` must be defined to 1, which not all ports do by default.

Unfortunately, there is little consistency between the makefiles/cmake files for each each MicroPython port with regards to these macros. As such, each port might define these macros in a different location, might optionally define them based on a different macro, or might not define them at all, relying on a default value instead. Therefore it might take a little bit of hunting through the source code to find out the best way to disable these macros in your port. The following steps show
how to disable these modules for various ports. It is possible these instructions could become out of date if MicroPython makes changes to their build system. If the following steps don't work (if you get errors about multiple definitions for `uhashlib` and `ucryptolib` fucntions or types) then it is possible the build system has changed and you need to find another way to ensure the `MICROPY_PY_USSL`, `MICROPY_PY_UCRYPTOLIB` and `MICROPY_PY_UHASHLIB` C macros are all defined to zero at build time. `grep` will be your friend here...

### unix
For the unix port, the three C macros above can be easily disabled by setting the `MICROPY_PY_USSL=0` makefile variable in `ports/unix/mpconfigport.mk`. This should automatically ensure the `MICROPY_PY_USSL` C macro is not set, as well as prevent the `MICROPY_PY_UCRYPTOLIB` and `MICROPY_PY_UHASHLIB` C macros  from later being defined to 1 in `port/unix/variants/mpconfigvariant_common.h`. `MICROPY_TRACKED_ALLOC` should be set to 1 by default and no further action is needed. 

### stm32
- If your board config makefile (`ports/stm32/board/$(BOARD)/mpconfigboard.mk`) contains the makefile variable "`MICROPY_PY_USSL=1`", then change the assignment to set this variable to 0.
- If your board config makefile contains the makefile variable "`MICROPY_SSL_MBEDTLS=1`" then change the assignment to set this variable to 0
- Modify `ports/stm32/mpconfigport.h` such that the `MICROPY_PY_UCRYPTOLIB` C macro is never defined
- Modify `ports/stm32/mpconfigport.h` such that the `MICROPY_TRACKED_ALLOC` C macro is EXPLICITLY defined to 1, and not set to the value of another macro

# Using `micropython-wolfssl`
You can now directly import the three modules (`wolfssl`, `wolfcryptolib`, `wolfhashlib`) provided by `micropython-wolfssl` using python's `import` statement. Because `micropython-wolfssl` is API compatible with the default implementations, you can simply alias the `micropython-wolfssl` modules to the name of the internal module you were using before and no further modification to your code should be needed. For example, to set up a TLS connection: 

```python
# alias wolfssl to ussl on import
import wolfssl as ussl

# existing code is unchanged
ss = ussl.wrap_socket(...)

```

Features of the `micropython-wolfssl` modules can also be configured using the existing configuration macros, so these can be left unchanged in your port's build. Please see the micropython documentation for more details. The existing macros used to configure the modules include:

```
MICROPY_PY_USSL_FINALISER    // includes MicroPython "finalizer" for SSL module
MICROPY_PY_UHASHLIB_SHA256   // includes SHA256 algorithm 
MICROPY_PY_UHASHLIB_SHA1     // includes SHA1 algorithm  
MICROPY_PY_UHASHLIB_MD5      // includes MD5 algorithm 
MICROPY_PY_UCRYPTOLIB_CTR    // includes AES counter mode 
MICROPY_PY_UCRYPTOLIB_CONSTS // includes AES ECB and CBC mode ROM constants
```

