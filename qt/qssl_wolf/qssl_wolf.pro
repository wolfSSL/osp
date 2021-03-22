CONFIG += testcase

SOURCES += tst_wolfssl.cpp
QT = core core-private network-private testlib

TARGET = tst_qssl_wolf

TESTDATA += certs

requires(qtConfig(private_tests))

win32 {
  CONFIG(debug, debug|release) {
    DESTDIR = debug
} else {
    DESTDIR = release
  }
}
