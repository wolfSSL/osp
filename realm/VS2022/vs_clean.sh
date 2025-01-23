#!/bin/bash

# Reference $(CurrentVsInstallRoot), not fully-qualified path
find . -type f -name "*.vcxproj" -exec sed -i 's|C:\\Program Files\\Microsoft Visual Studio\\2022\\Enterprise|$(CurrentVsInstallRoot)|g' {} +
find . -type f -name "*.vcxproj" -exec sed -i 's|C:\\Program Files\\Microsoft Visual Studio\\2022\\Professional|$(CurrentVsInstallRoot)|g' {} +
find . -type f -name "*.vcxproj" -exec sed -i 's|C:\\Program Files\\Microsoft Visual Studio\\2022\\Community|$(CurrentVsInstallRoot)|g' {} +
