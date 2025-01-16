# VS2022/include

This is the home directory of the wolfSSL `user_settings.h` file.

See the respective settings in `wolfssl-GlobalProperties.props`:

* `WOLFSSL_ROOT`
* `WOLFSSL_USER_SETTINGS_DIR_TEMP` build-time calculated based on current build directory (`MSBuildThisFileDirectory`/include).
* `WOLFSSL_USER_SETTINGS_DIRECTORY` a slash-direction & slash-duplicate cleaned value of `WOLFSSL_USER_SETTINGS_DIR_TEMP`.
* `WOLFSSL_USER_SETTINGS_FILE` the actual wolfssl `user_settings.h` file.

See also the respective project `AdditionalIncludeDirectories` that will look something like this:

```
    <AdditionalIncludeDirectories>$(WOLFSSL_USER_SETTINGS_DIRECTORY);$(WOLFSSL_ROOT);$(REALM_CORE_ROOT)\src;$(REALM_VS2022_ROOT)\src;%(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
```
