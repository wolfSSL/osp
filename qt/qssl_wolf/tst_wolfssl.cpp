/* QSslSocket program for wolfSSL verification */
#include <QtCore/qglobal.h>
#include <QtCore/qthread.h>
#include <QtCore/qelapsedtimer.h>
#include <QtCore/qrandom.h>
#include <QtNetwork/qhostaddress.h>
#include <QtNetwork/qhostinfo.h>
#include <QtNetwork/qnetworkproxy.h>
#include <QtNetwork/qsslcipher.h>
#include <QtNetwork/qsslconfiguration.h>
#include <QtNetwork/qsslkey.h>
#include <QtNetwork/qsslsocket.h>
#include <QtNetwork/qtcpserver.h>
#include <QtNetwork/qsslpresharedkeyauthenticator.h>
#include <QtTest/QtTest>

#include <QNetworkProxy>
#include <QAuthenticator>

#include "../../../network-settings.h"

#ifndef QT_NO_SSL
#ifndef QT_NO_OPENSSL
#include "private/qsslsocket_openssl_p.h"
#include "private/qsslsocket_openssl_symbols_p.h"
#endif
#include "private/qsslsocket_p.h"
#include "private/qsslconfiguration_p.h"

Q_DECLARE_LOGGING_CATEGORY(lcSsl)

Q_DECLARE_METATYPE(QSslSocket::SslMode)
typedef QVector<QSslError::SslError> SslErrorList;
Q_DECLARE_METATYPE(SslErrorList)
Q_DECLARE_METATYPE(QSslError)
Q_DECLARE_METATYPE(QSslKey)
Q_DECLARE_METATYPE(QSsl::SslProtocol)
Q_DECLARE_METATYPE(QSslSocket::PeerVerifyMode);
typedef QSharedPointer<QSslSocket> QSslSocketPtr;
// Non-OpenSSL backends are not able to report a specific error code
// for self-signed certificates.
#ifndef QT_NO_OPENSSL

static const QString PSK_CIPHER_WITHOUT_AUTH = QStringLiteral("PSK-AES256-CBC-SHA");
static const quint16 PSK_SERVER_PORT = 4433;
static const QByteArray PSK_CLIENT_PRESHAREDKEY = QByteArrayLiteral("\x1a\x2b\x3c\x4d\x5e\x6f");
static const QByteArray PSK_SERVER_IDENTITY_HINT = QByteArrayLiteral("QtTestServerHint");
static const QByteArray PSK_CLIENT_IDENTITY = QByteArrayLiteral("Client_identity");

#define FLUKE_CERTIFICATE_ERROR QSslError::UnableToGetLocalIssuerCertificate
#endif
#endif // QT_NO_SSL

class tst_QSslWolfSSL : public QObject
{
    Q_OBJECT
    
    int proxyAuthCalled;
    
public:
    tst_QSslWolfSSL();
    
    static void enterLoop(int secs)
    {
        ++loopLevel;
        QTestEventLoop::instance().enterLoop(secs);
    }

    static bool timeout()
    {
        return QTestEventLoop::instance().timeout();
    }

#ifndef QT_NO_SSL
    QSslSocketPtr newSocket();
    
    enum PskConnectTestType {
        PskConnectDoNotHandlePsk,
        PskConnectEmptyCredentials,
        PskConnectWrongCredentials,
        PskConnectWrongIdentity,
        PskConnectWrongPreSharedKey,
        PskConnectRightCredentialsPeerVerifyFailure,
        PskConnectRightCredentialsVerifyPeer,
        PskConnectRightCredentialsDoNotVerifyPeer,
    };
    
private slots:
    void constructing();
    void hash();
    void connectToHostEncrypted();
    void connectTocricbuzzcom();
    void sessionCipher();
    void peerCertificateChainToWWWpQTpIO();
    void privateKeyOpaque();
    void ciphers();
    void localCertificate();
    void protocol();
    void addCaCertificate();
    void addCaCertificates();
    void addCaCertificates2();
    void pskServer();
    
    /* server side */
    void protocolServerSide_data();
    void protocolServerSide();
    void serverCipherPreferences();
    void setCaCertificates();
    void setLocalCertificateChain();
    void localCertificateChain();
    void setLocalCertificate();
    void setSocketDescriptor();
    void setSslConfiguration_data();
    void setSslConfiguration();
    void waitForEncrypted();
    void waitForEncryptedMinusOne();
    void addDefaultCaCertificate();
    void startClientEncryption();
    void startServerEncryption();
    void defaultCaCertificates();
    void defaultCiphers();
    void resetDefaultCiphers();
    void setDefaultCaCertificates();
    void setDefaultCiphers();
    void supportedCiphers();
    void systemCaCertificates();
    void wildcardCertificateNames();
    void isMatchingHostname();
    
    /* serve 2 */
    void setEmptyKey();
    void spontaneousWrite();
    void setReadBufferSize();
    
    /* server 3 */
    void waitForMinusOne();
    
    /* verify server */
    void verifyMode();
    void verifyDepth();
    void disconnectFromHostWhenConnecting();
    void disconnectFromHostWhenConnected();
    
    void resetProxy();
    void ignoreSslErrorsList_data();
    void ignoreSslErrorsList();
    void ignoreSslErrorsListWithSlot_data();
    void ignoreSslErrorsListWithSlot();
    void abortOnSslErrors();
    void readFromClosedSocket();
    void writeBigChunk();
    void blacklistedCertificates();
    void versionAccessors();
    void sslOptions();
    void encryptWithoutConnecting();
    void resume_data();
    void resume();
    
    /* server 4 */
    void qtbug18498_peek();
    
    /* server 5 */
    void qtbug18498_peek2();
    
    void ephemeralServerKey_data();
    void ephemeralServerKey();
    void signatureAlgorithm_data();
    void signatureAlgorithm();
    void disabledProtocols_data();
    void disabledProtocols();
    void oldErrorsOnSocketReuse();
    
    void dhServer();
    void ecdhServer();
    void verifyClientCertificate_data();
    void verifyClientCertificate();
    void readBufferMaxSize();
    void setEmptyDefaultConfiguration();
    void allowedProtocolNegotiation();
    
    bool isMatchingHostname(const QSslCertificate &cert, const QString &peerName);
    bool isMatchingHostname(const QString &cn, const QString &hostname);
    
 protected slots:

    static void exitLoop()
    {
        // Safe exit - if we aren't in an event loop, don't
        // exit one.
        if (loopLevel > 0) {
            --loopLevel;
            QTestEventLoop::instance().exitLoop();
        }
    }
    
    void displayErrorSlot(const QList<QSslError> &errors)
    {
        for (const QSslError &err : errors)
            qDebug() << err.error();
    }
    
    void ignoreHostNameMismatchErrorSlot(const QList<QSslError> &errors)
    {
        if (errors.size() == 1 &&
            errors.first().error() == QSslError::HostNameMismatch) {
            socket->ignoreSslErrors();
        }
    }
    
    void ignoreErrorSlot()
    {
        socket->ignoreSslErrors();
    }
    void abortOnErrorSlot()
    {
        QSslSocket *sock = static_cast<QSslSocket *>(sender());
        sock->abort();
    }
    void untrustedWorkaroundSlot(const QList<QSslError> &errors)
    {
        if (errors.size() == 1 &&
                (errors.first().error() == QSslError::CertificateUntrusted ||
                        errors.first().error() == QSslError::SelfSignedCertificate))
            socket->ignoreSslErrors();
    }
    void ignoreErrorListSlot(const QList<QSslError> &errors);
#endif

public slots:
    void initTestCase();
#ifndef QT_NO_NETWORKPROXY
    void proxyAuthenticationRequired(const QNetworkProxy &, QAuthenticator *auth);
#endif
    
private:
    static int loopLevel;
    QSslSocket *socket;
    QList<QSslError> storedExpectedSslErrors;
    
    bool skip_connectTocricbuzzcom;
    bool skip_peerCertificateChainToWWWpQTpIO;
    bool skip_connectToHostEncrypted;
    bool skip_localCertificate;
    bool skip_sessionCipher;
    bool skip_privateKeyOpaque;
    bool skip_protocol;
    bool skip_protocolServerSide;
    bool skip_serverCipherPreferences;
    bool skip_setCaCertificates;
    bool skip_setLocalCertificateChain;
    bool skip_localCertificateChain;
    bool skip_setSocketDescriptor;
    bool skip_setSslConfiguration;
    bool skip_waitForEncrypted;
    bool skip_waitForEncryptedMinusOne;
    bool skip_addDefaultCaCertificate;
    bool skip_defaultCiphers;
    bool skip_defaultCaCertificates;
    bool skip_systemCaCertificates;
    bool skip_supportedCiphers;
    bool skip_wildcardCertificateNames;
    bool skip_isMatchingHostname;
    bool skip_setEmptyKey;
    bool skip_spontaneousWrite;
    bool skip_setReadBufferSize;
    bool skip_waitForMinusOne;
    bool skip_verifyMode;
    bool skip_qtbug18498_peek;
    bool skip_qtbug18498_peek2;
    
    bool skip_ignoreSslErrorsListWithSlot;
    bool skip_abortOnSslErrors;
    bool skip_ignoreSslErrorsList;
    bool skip_resetProxy;
    bool skip_readFromClosedSocket;
    bool skip_writeBigChunk;
    bool skip_blacklistedCertificates;
    bool skip_sslOptions;
    bool skip_versionAccessors;
    bool skip_encryptWithoutConnecting;
    bool skip_resume;
    bool skip_ephemeralServerKey;
    bool skip_signatureAlgorithm;
    bool skip_disabledProtocols;
    bool skip_oldErrorsOnSocketReuse;
    
    bool skip_disconnectFromHostWhenConnected;
    bool skip_disconnectFromHostWhenConnecting;
    
    bool skip_dhServer;
    bool skip_ecdhServer;
    bool skip_verifyClientCertificate;
    bool skip_readBufferMaxSize;
    bool skip_setEmptyDefaultConfiguration;
    bool skip_pskServer;
    bool skip_simplePskConnect;
    
public:
    static QString testDataDir;
    static QString EXAMPLE_SERVER;
    static int EXAMPLE_SERVER_PORT;
};

QString tst_QSslWolfSSL::testDataDir;
int tst_QSslWolfSSL::loopLevel = 0;
QString tst_QSslWolfSSL::EXAMPLE_SERVER = "192.168.11.49";
int tst_QSslWolfSSL::EXAMPLE_SERVER_PORT = 11111;

Q_DECLARE_METATYPE(tst_QSslWolfSSL::PskConnectTestType)

QString httpServerCertChainPath()
{
    return tst_QSslWolfSSL::testDataDir + QStringLiteral("certs/ca-cert.pem");
}

#ifndef QT_NO_SSL

tst_QSslWolfSSL::tst_QSslWolfSSL()
{
#ifndef QT_NO_SSL
    qRegisterMetaType<QList<QSslError> >("QList<QSslError>");
    qRegisterMetaType<QSslError>("QSslError");
    qRegisterMetaType<QAbstractSocket::SocketState>("QAbstractSocket::SocketState");
    qRegisterMetaType<QAbstractSocket::SocketError>("QAbstractSocket::SocketError");

#ifndef QT_NO_OPENSSL
    qRegisterMetaType<QSslPreSharedKeyAuthenticator *>();
    qRegisterMetaType<tst_QSslWolfSSL::PskConnectTestType>();
#endif
#endif
}

void tst_QSslWolfSSL::initTestCase()
{
    testDataDir = QFileInfo(QFINDTESTDATA("certs")).absolutePath();
    if (testDataDir.isEmpty())
        testDataDir = QCoreApplication::applicationDirPath();
    if (!testDataDir.endsWith(QLatin1String("/")))
        testDataDir += QLatin1String("/");
    
    skip_connectTocricbuzzcom               = false;
    skip_peerCertificateChainToWWWpQTpIO    = false;
    skip_connectToHostEncrypted             = false;
    skip_localCertificate                   = false;
    skip_sessionCipher                      = false;
    skip_privateKeyOpaque                   = false;
    skip_protocol                           = false;
    skip_protocolServerSide                 = false;
    skip_serverCipherPreferences            = false;
    skip_setCaCertificates                  = false;
    skip_setLocalCertificateChain           = false;
    skip_localCertificateChain              = false;
    skip_setSocketDescriptor                = false;
    skip_setSslConfiguration                = false;
    skip_waitForEncrypted                   = false;
    skip_waitForEncryptedMinusOne           = false;
    skip_addDefaultCaCertificate            = false;
    skip_defaultCiphers                     = false;
    skip_defaultCaCertificates              = false;
    skip_systemCaCertificates               = false;
    skip_supportedCiphers                   = false;
    skip_wildcardCertificateNames           = false;
    skip_isMatchingHostname                 = false;
    skip_setEmptyKey                        = false;
    skip_spontaneousWrite                   = false;
    skip_setReadBufferSize                  = false;
    skip_waitForMinusOne                    = false;
    skip_verifyMode                         = false;
    skip_qtbug18498_peek                    = false;
    skip_qtbug18498_peek2                   = false;
    skip_ignoreSslErrorsListWithSlot        = false;
    skip_abortOnSslErrors                   = false;
    skip_ignoreSslErrorsList                = false;
    skip_resetProxy                         = false;
    skip_readFromClosedSocket               = false;
    skip_writeBigChunk                      = false;
    skip_blacklistedCertificates            = false;
    skip_sslOptions                         = false;
    skip_versionAccessors                   = false;
    skip_encryptWithoutConnecting           = false;
    skip_resume                             = false;
    skip_ephemeralServerKey                 = false;
    skip_signatureAlgorithm                 = false;
    skip_disabledProtocols                  = false;
    skip_oldErrorsOnSocketReuse             = false;
    skip_disconnectFromHostWhenConnected    = false;
    skip_disconnectFromHostWhenConnecting   = false;
    
    skip_ecdhServer                         = false;
    skip_verifyClientCertificate            = false;
    skip_dhServer                           = false;
    skip_readBufferMaxSize                  = false;
    skip_setEmptyDefaultConfiguration       = false;
    skip_pskServer                          = false;
}

QSslSocketPtr tst_QSslWolfSSL::newSocket()
{
    const auto socket = QSslSocketPtr::create();

    proxyAuthCalled = 0;
    connect(socket.data(), SIGNAL(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)),
            SLOT(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)),
            Qt::DirectConnection);

    return socket;
}

/* functions from QSslSocket to know what they do */
bool tst_QSslWolfSSL::isMatchingHostname(const QSslCertificate &cert, const QString &peerName)
{
    QHostAddress hostAddress(peerName);
    if (!hostAddress.isNull()) {
        const auto subjectAlternativeNames = cert.subjectAlternativeNames();
        const auto ipAddresses = subjectAlternativeNames.equal_range(QSsl::AlternativeNameEntryType::IpAddressEntry);
        //qDebug() << "subjectAlternativeNames " << subjectAlternativeNames;
        
        for (auto it = ipAddresses.first; it != ipAddresses.second; it++) {
            qDebug() << "ipAddresses " << (*it);
            if (QHostAddress(*it).isEqual(hostAddress, QHostAddress::StrictConversion))
                return true;
        }
    }

    const QString lowerPeerName = QString::fromLatin1(QUrl::toAce(peerName));
    const QStringList commonNames = cert.subjectInfo(QSslCertificate::CommonName);

    for (const QString &commonName : commonNames) {
        qDebug() << "commonName " << commonName;
        if (isMatchingHostname(commonName, lowerPeerName))
            return true;
    }

    const auto subjectAlternativeNames = cert.subjectAlternativeNames();
    const auto altNames = subjectAlternativeNames.equal_range(QSsl::DnsEntry);
    for (auto it = altNames.first; it != altNames.second; ++it) {
        qDebug() << "altName " << (*it);
        if (isMatchingHostname(*it, lowerPeerName))
            return true;
    }

    return false;
}

bool tst_QSslWolfSSL::isMatchingHostname(const QString &cn, const QString &hostname)
{
    int wildcard = cn.indexOf(QLatin1Char('*'));

    // Check this is a wildcard cert, if not then just compare the strings
    if (wildcard < 0)
        return QLatin1String(QUrl::toAce(cn)) == hostname;

    int firstCnDot = cn.indexOf(QLatin1Char('.'));
    int secondCnDot = cn.indexOf(QLatin1Char('.'), firstCnDot+1);

    // Check at least 3 components
    if ((-1 == secondCnDot) || (secondCnDot+1 >= cn.length()))
        return false;

    // Check * is last character of 1st component (ie. there's a following .)
    if (wildcard+1 != firstCnDot)
        return false;

    // Check only one star
    if (cn.lastIndexOf(QLatin1Char('*')) != wildcard)
        return false;

    // Reject wildcard character embedded within the A-labels or U-labels of an internationalized
    // domain name (RFC6125 section 7.2)
    if (cn.startsWith(QLatin1String("xn--"), Qt::CaseInsensitive))
        return false;

    // Check characters preceding * (if any) match
    if (wildcard && hostname.leftRef(wildcard).compare(cn.leftRef(wildcard), Qt::CaseInsensitive) != 0)
        return false;

    // Check characters following first . match
    int hnDot = hostname.indexOf(QLatin1Char('.'));
    if (hostname.midRef(hnDot + 1) != cn.midRef(firstCnDot + 1)
        && hostname.midRef(hnDot + 1) != QLatin1String(QUrl::toAce(cn.mid(firstCnDot + 1)))) {
        return false;
    }

    // Check if the hostname is an IP address, if so then wildcards are not allowed
    QHostAddress addr(hostname);
    if (!addr.isNull())
        return false;

    // Ok, I guess this was a wildcard CN and the hostname matches.
    return true;
}

#ifndef QT_NO_NETWORKPROXY
void tst_QSslWolfSSL::proxyAuthenticationRequired(const QNetworkProxy &, QAuthenticator *auth)
{
    ++proxyAuthCalled;
    auth->setUser("qsockstest");
    auth->setPassword("password");
}
#endif // !QT_NO_NETWORKPROXY

void tst_QSslWolfSSL::constructing()
{
    const char readNotOpenMessage[] = "QIODevice::read (QSslSocket): device not open";
    const char writeNotOpenMessage[] = "QIODevice::write (QSslSocket): device not open";

    if (!QSslSocket::supportsSsl())
        return;

    QSslSocket socket;

    QCOMPARE(socket.state(), QSslSocket::UnconnectedState);
    QCOMPARE(socket.mode(), QSslSocket::UnencryptedMode);
    QVERIFY(!socket.isEncrypted());
    QCOMPARE(socket.bytesAvailable(), qint64(0));
    QCOMPARE(socket.bytesToWrite(), qint64(0));
    QVERIFY(!socket.canReadLine());
    QVERIFY(socket.atEnd());
    QCOMPARE(socket.localCertificate(), QSslCertificate());
    QCOMPARE(socket.sslConfiguration(), QSslConfiguration::defaultConfiguration());
    QCOMPARE(socket.errorString(), QString("Unknown error"));
    char c = '\0';
    QTest::ignoreMessage(QtWarningMsg, readNotOpenMessage);
    QVERIFY(!socket.getChar(&c));
    QCOMPARE(c, '\0');
    QVERIFY(!socket.isOpen());
    QVERIFY(!socket.isReadable());
    QVERIFY(socket.isSequential());
    QVERIFY(!socket.isTextModeEnabled());
    QVERIFY(!socket.isWritable());
    QCOMPARE(socket.openMode(), QIODevice::NotOpen);
    QTest::ignoreMessage(QtWarningMsg, readNotOpenMessage);
    QVERIFY(socket.peek(2).isEmpty());
    QCOMPARE(socket.pos(), qint64(0));
    QTest::ignoreMessage(QtWarningMsg, writeNotOpenMessage);
    QVERIFY(!socket.putChar('c'));
    QTest::ignoreMessage(QtWarningMsg, readNotOpenMessage);
    QVERIFY(socket.read(2).isEmpty());
    QTest::ignoreMessage(QtWarningMsg, readNotOpenMessage);
    QCOMPARE(socket.read(0, 0), qint64(-1));
    QTest::ignoreMessage(QtWarningMsg, readNotOpenMessage);
    QVERIFY(socket.readAll().isEmpty());
    QTest::ignoreMessage(QtWarningMsg, "QIODevice::readLine (QSslSocket): Called with maxSize < 2");
    QCOMPARE(socket.readLine(0, 0), qint64(-1));
    char buf[10];
    QCOMPARE(socket.readLine(buf, sizeof(buf)), qint64(-1));
    QTest::ignoreMessage(QtWarningMsg, "QIODevice::seek (QSslSocket): Cannot call seek on a sequential device");
    QVERIFY(!socket.reset());
    QTest::ignoreMessage(QtWarningMsg, "QIODevice::seek (QSslSocket): Cannot call seek on a sequential device");
    QVERIFY(!socket.seek(2));
    QCOMPARE(socket.size(), qint64(0));
    QVERIFY(!socket.waitForBytesWritten(10));
    QVERIFY(!socket.waitForReadyRead(10));
    QTest::ignoreMessage(QtWarningMsg, writeNotOpenMessage);
    QCOMPARE(socket.write(0, 0), qint64(-1));
    QTest::ignoreMessage(QtWarningMsg, writeNotOpenMessage);
    QCOMPARE(socket.write(QByteArray()), qint64(-1));
    QCOMPARE(socket.error(), QAbstractSocket::UnknownSocketError);
    QVERIFY(!socket.flush());
    QVERIFY(!socket.isValid());
    QCOMPARE(socket.localAddress(), QHostAddress());
    QCOMPARE(socket.localPort(), quint16(0));
    QCOMPARE(socket.peerAddress(), QHostAddress());
    QVERIFY(socket.peerName().isEmpty());
    QCOMPARE(socket.peerPort(), quint16(0));
#ifndef QT_NO_NETWORKPROXY
    QCOMPARE(socket.proxy().type(), QNetworkProxy::DefaultProxy);
#endif
    QCOMPARE(socket.readBufferSize(), qint64(0));
    QCOMPARE(socket.socketDescriptor(), qintptr(-1));
    QCOMPARE(socket.socketType(), QAbstractSocket::TcpSocket);
    QVERIFY(!socket.waitForConnected(10));
    QTest::ignoreMessage(QtWarningMsg, "QSslSocket::waitForDisconnected() is not allowed in UnconnectedState");
    QVERIFY(!socket.waitForDisconnected(10));
    QCOMPARE(socket.protocol(), QSsl::SecureProtocols);

    QSslConfiguration savedDefault = QSslConfiguration::defaultConfiguration();

    auto sslConfig = socket.sslConfiguration();
    sslConfig.setCaCertificates(QSslConfiguration::systemCaCertificates());
    socket.setSslConfiguration(sslConfig);

    auto defaultConfig = QSslConfiguration::defaultConfiguration();
    defaultConfig.setCaCertificates(QList<QSslCertificate>());
    defaultConfig.setCiphers(QList<QSslCipher>());
    QSslConfiguration::setDefaultConfiguration(defaultConfig);

    QVERIFY(!socket.sslConfiguration().caCertificates().isEmpty());
    QVERIFY(!socket.sslConfiguration().ciphers().isEmpty());

    // verify the default as well:
    QVERIFY(QSslConfiguration::defaultConfiguration().caCertificates().isEmpty());
    QVERIFY(QSslConfiguration::defaultConfiguration().ciphers().isEmpty());

    QSslConfiguration::setDefaultConfiguration(savedDefault);
}

void tst_QSslWolfSSL::hash()
{
    // mostly a compile-only test, to check that qHash(QSslError) is found
    QSet<QSslError> errors;
    errors << QSslError();
    QCOMPARE(errors.size(), 1);
}


void tst_QSslWolfSSL::connectTocricbuzzcom()
{
    if (skip_connectTocricbuzzcom)
        QSKIP("connectTocricbuzzcom()");
    
    if (!QSslSocket::supportsSsl())
        return;
    
    QSslSocket socket;
    // connect again to a different server
    connect(&socket, SIGNAL(sslErrors(QList<QSslError>)), this,
                    SLOT(displayErrorSlot(QList<QSslError>)));
        
    socket.connectToHostEncrypted("cricbuzz.com", 443);
    socket.waitForEncrypted(10000);
    const auto socketSslErrors = socket.sslHandshakeErrors();
    for (const QSslError &err : socketSslErrors)
        qDebug() << " error " << err.error();
    
}

void tst_QSslWolfSSL::connectToHostEncrypted()
{
    if (skip_connectToHostEncrypted)
        QSKIP("connectToHostEncrypted()");
    
    if (!QSslSocket::supportsSsl())
        return;
    
    QSslSocketPtr socket = newSocket();
#if QT_CONFIG(schannel) // old certificate not supported with TLS 1.2
    socket->setProtocol(QSsl::SslProtocol::TlsV1_1);
#endif
    this->socket = socket.data();
    connect(socket.data(), SIGNAL(sslErrors(QList<QSslError>)), this, 
                    SLOT(ignoreHostNameMismatchErrorSlot(QList<QSslError>)));
    
    auto config = socket->sslConfiguration();
    QVERIFY(config.addCaCertificates(httpServerCertChainPath()));
    socket->setSslConfiguration(config);
    
    socket->setLocalCertificate(testDataDir + "certs/client-cert.pem");
    socket->setPrivateKey(testDataDir + "certs/client-key.pem");
    
    
#ifdef QSSLSOCKET_CERTUNTRUSTED_WORKAROUND
    connect(socket.data(), SIGNAL(sslErrors(QList<QSslError>)),
            this, SLOT(untrustedWorkaroundSlot(QList<QSslError>)));
#endif
    socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
    socket->waitForEncrypted(10000);
    socket->write("Authentication Succeded");
    
    socket->disconnectFromHost();
    QVERIFY(socket->waitForDisconnected());
}

void tst_QSslWolfSSL::ciphers()
{
    if (!QSslSocket::supportsSsl())
        return;

    QSslSocket socket;
    QCOMPARE(socket.sslConfiguration().ciphers(), QSslConfiguration::defaultConfiguration().ciphers());

    auto sslConfig = socket.sslConfiguration();
    sslConfig.setCiphers(QList<QSslCipher>());
    socket.setSslConfiguration(sslConfig);
    QVERIFY(socket.sslConfiguration().ciphers().isEmpty());

    sslConfig.setCiphers(QSslConfiguration::defaultConfiguration().ciphers());
    socket.setSslConfiguration(sslConfig);
    QCOMPARE(socket.sslConfiguration().ciphers(), QSslConfiguration::defaultConfiguration().ciphers());

    sslConfig.setCiphers(QSslConfiguration::defaultConfiguration().ciphers());
    socket.setSslConfiguration(sslConfig);
    QCOMPARE(socket.sslConfiguration().ciphers(), QSslConfiguration::defaultConfiguration().ciphers());

    // Task 164356
    sslConfig.setCiphers({QSslCipher("ALL"), QSslCipher("!ADH"), QSslCipher("!LOW"),
                          QSslCipher("!EXP"), QSslCipher("!MD5"), QSslCipher("@STRENGTH")});
    socket.setSslConfiguration(sslConfig);
}

void tst_QSslWolfSSL::localCertificate()
{
    if (skip_localCertificate)
        QSKIP("localCertificate()");
    
    if (!QSslSocket::supportsSsl())
        return;

    // This test does not make 100% sense yet. We just set some local CA/cert/key and use it
    // to authenticate ourselves against the server. The server does not actually check this
    // values. This test should just run the codepath inside qsslsocket_openssl.cpp

    QSslSocketPtr socket = newSocket();
    this->socket = socket.data();
    connect(socket.data(), SIGNAL(sslErrors(QList<QSslError>)), this, 
                    SLOT(ignoreHostNameMismatchErrorSlot(QList<QSslError>)));
    
    QList<QSslCertificate> localCert = QSslCertificate::fromPath(httpServerCertChainPath());
    
    auto sslConfig = socket->sslConfiguration();
    sslConfig.setCaCertificates(localCert);
    socket->setSslConfiguration(sslConfig);
    
    socket->setProtocol(QSsl::TlsV1_2);
    socket->setLocalCertificate(testDataDir + "certs/client-cert.pem");
    socket->setPrivateKey(testDataDir + "certs/client-key.pem");
    
    socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);

    socket->waitForEncrypted(10000);
    socket->write("Authentication Succeded");
    
    socket->disconnectFromHost();
    QVERIFY(socket->waitForDisconnected());
    QCOMPARE(socket->mode(), QSslSocket::SslClientMode);
}

void tst_QSslWolfSSL::addCaCertificate()
{
    if (!QSslSocket::supportsSsl())
        return;
}

void tst_QSslWolfSSL::addCaCertificates()
{
    if (!QSslSocket::supportsSsl())
        return;
}

void tst_QSslWolfSSL::addCaCertificates2()
{
    if (!QSslSocket::supportsSsl())
        return;
}

void tst_QSslWolfSSL::sessionCipher()
{
    if (skip_sessionCipher)
       QSKIP("sessionCipher()");
    if (!QSslSocket::supportsSsl())
        return;

    QSslSocketPtr socket = newSocket();
    this->socket = socket.data();
    /* socket->setProtocol(QSsl::SslProtocol::TlsV1_2); */
    auto config = socket->sslConfiguration();
    
    QVERIFY(config.addCaCertificates(httpServerCertChainPath()));
    socket->setProtocol(QSsl::SslProtocol::TlsV1_2);
    socket->setSslConfiguration(config);
    socket->setLocalCertificate(testDataDir + "certs/client-cert.pem");
    socket->setPrivateKey(testDataDir + "certs/client-key.pem");
    
    connect(socket.data(), SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
    QVERIFY(socket->sessionCipher().isNull());
    socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
    socket->waitForEncrypted(10000);
    socket->write("Authentication Succeded");
    QVERIFY(!socket->sessionCipher().isNull());

    qDebug() << "---";
    qDebug() << "Supported Ciphers:"    << QSslConfiguration::supportedCiphers() << Qt::endl;
    qDebug() << "Default Ciphers:"      << QSslConfiguration::defaultConfiguration().ciphers() << Qt::endl;
    qDebug() << "Session Cipher:"       << socket->sessionCipher() << Qt::endl;
    qDebug() << "";
    qDebug() << "--";
    
    QVERIFY(QSslConfiguration::supportedCiphers().contains(socket->sessionCipher()));
    socket->disconnectFromHost();
    QVERIFY(socket->waitForDisconnected());
}

void tst_QSslWolfSSL::peerCertificateChainToWWWpQTpIO()
{
    if (skip_peerCertificateChainToWWWpQTpIO)
        QSKIP("peerCertificateChainToWWWpQTpIO");
    
    if (!QSslSocket::supportsSsl())
        return;

    QSslSocketPtr socket = newSocket();
    this->socket = socket.data();
 
    // connect again to a different server
    socket->connectToHostEncrypted("www.qt.io", 443);
    socket->ignoreSslErrors();
    QCOMPARE(socket->mode(), QSslSocket::UnencryptedMode);
    QVERIFY(socket->peerCertificateChain().isEmpty());
    socket->waitForEncrypted(10000);

    QList<QSslCertificate> certChain = socket->peerCertificateChain();
    QCOMPARE(certChain.first(), socket->peerCertificate());
    QCOMPARE(certChain.count(), 2);
    QCOMPARE(certChain.at(0).issuerDisplayName(), "Cloudflare Inc ECC CA-3");
    QCOMPARE(certChain.at(1).issuerDisplayName(), "Baltimore CyberTrust Root");
    /*for (const QSslCertificate &cert : certChain){
        qDebug() << cert.toText();
        qDebug() << cert.issuerDisplayName() << " " << cert.serialNumber();
    }*/
    
    socket->disconnectFromHost();
    QVERIFY(socket->waitForDisconnected());
}

#ifndef QT_NO_OPENSSL
void tst_QSslWolfSSL::privateKeyOpaque()
{
    if (skip_privateKeyOpaque)
        QSKIP("privateKeyOpaque()");
    
    if (!QSslSocket::supportsSsl())
        return;
    qDebug() << "Start privateKeyOpaque";
    
    QFile file(testDataDir + "certs/client-key.pem");
    QVERIFY(file.open(QIODevice::ReadOnly));
    QSslKey key(file.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    QVERIFY(!key.isNull());

    qDebug() << "key is verified.";
    
    EVP_PKEY *pkey = q_EVP_PKEY_new();
    q_EVP_PKEY_set1_RSA(pkey, reinterpret_cast<RSA *>(key.handle()));
    
    // This test does not make 100% sense yet. We just set some local CA/cert/key and use it
    // to authenticate ourselves against the server. The server does not actually check this
    // values. This test should just run the codepath inside qsslsocket_openssl.cpp

    QSslSocketPtr socket = newSocket();
    QList<QSslCertificate> localCert = QSslCertificate::fromPath(httpServerCertChainPath());

    auto sslConfig = socket->sslConfiguration();
    sslConfig.setCaCertificates(localCert);
    socket->setSslConfiguration(sslConfig);

    socket->setLocalCertificate(testDataDir + "certs/client-cert.pem");
    socket->setPrivateKey(QSslKey(reinterpret_cast<Qt::HANDLE>(pkey)));

    socket->setPeerVerifyMode(QSslSocket::QueryPeer);
    socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
    socket->waitForEncrypted(10000);
}

void tst_QSslWolfSSL::protocol()
{
    if (skip_protocol)
        QSKIP("protocol()");
        
    if (!QSslSocket::supportsSsl())
        return;

    QSslSocketPtr socket = newSocket();
    this->socket = socket.data();
    QList<QSslCertificate> certs = QSslCertificate::fromPath(httpServerCertChainPath());

    auto sslConfig = socket->sslConfiguration();
    sslConfig.setCaCertificates(certs);
    socket->setSslConfiguration(sslConfig);

    /* inform client identity */
    socket->setLocalCertificate(testDataDir + "certs/client-cert.pem");
    socket->setPrivateKey(testDataDir + "certs/client-key.pem");
    
#ifdef QSSLSOCKET_CERTUNTRUSTED_WORKAROUND
    connect(socket, SIGNAL(sslErrors(QList<QSslError>)),
            this, SLOT(untrustedWorkaroundSlot(QList<QSslError>)));
#endif

    QCOMPARE(socket->protocol(), QSsl::SecureProtocols);
    //QFETCH_GLOBAL(bool, setProxy);
#if 1
    {
        // qt-test-server allows TLSV1.
        socket->setProtocol(QSsl::TlsV1_0);
        QCOMPARE(socket->protocol(), QSsl::TlsV1_0);
        socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
        socket->waitForEncrypted(1000);

        QCOMPARE(socket->protocol(), QSsl::TlsV1_0);
        socket->abort();
        QCOMPARE(socket->protocol(), QSsl::TlsV1_0);
        socket->abort();
    }
#endif
    {
        // qt-test-server probably doesn't allow TLSV1.1
        socket->setProtocol(QSsl::TlsV1_1);
        QCOMPARE(socket->protocol(), QSsl::TlsV1_1);
        socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
        socket->waitForEncrypted(1000);

        QCOMPARE(socket->protocol(), QSsl::TlsV1_1);
        socket->abort();
        QCOMPARE(socket->protocol(), QSsl::TlsV1_1);
        socket->abort();
    }
    {
        // qt-test-server probably doesn't allows TLSV1.2
        socket->setProtocol(QSsl::TlsV1_2);
        QCOMPARE(socket->protocol(), QSsl::TlsV1_2);
        socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
        socket->waitForEncrypted(1000);

        QCOMPARE(socket->protocol(), QSsl::TlsV1_2);
        socket->abort();
    }
#if 0
#ifdef TLS1_3_VERSION
    {
        // qt-test-server probably doesn't allow TLSV1.3
        socket->setProtocol(QSsl::TlsV1_3);
        QCOMPARE(socket->protocol(), QSsl::TlsV1_3);
        socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
        socket->waitForEncrypted(1000);

        QCOMPARE(socket->protocol(), QSsl::TlsV1_3);
        socket->abort();
    }
#endif // TLS1_3_VERSION


    {
        // qt-test-server allows SSLV3, so it allows AnyProtocol.
        socket->setProtocol(QSsl::AnyProtocol);
        QCOMPARE(socket->protocol(), QSsl::AnyProtocol);
        socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
        socket->waitForEncrypted(1000);

        QCOMPARE(socket->protocol(), QSsl::AnyProtocol);
        socket->abort();
    }
    {
        // qt-test-server allows TlsV1, so it allows TlsV1SslV3
        socket->setProtocol(QSsl::TlsV1SslV3);
        QCOMPARE(socket->protocol(), QSsl::TlsV1SslV3);
        socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
        socket->waitForEncrypted(1000);

        QCOMPARE(socket->protocol(), QSsl::TlsV1SslV3);
        socket->abort();
    }
#endif
}
#endif

class SslServer : public QTcpServer
{
    Q_OBJECT

    
public:
    SslServer(const QString &keyFile = tst_QSslWolfSSL::testDataDir + "certs/fluke.key",
              const QString &certFile = tst_QSslWolfSSL::testDataDir + "certs/fluke.cert",
              const QString &interFile = QString())
        : socket(0),
          config(QSslConfiguration::defaultConfiguration()),
          ignoreSslErrors(true),
          peerVerifyMode(QSslSocket::AutoVerifyPeer),
          protocol(QSsl::TlsV1_0),
          m_keyFile(keyFile),
          m_certFile(certFile),
          m_interFile(interFile)
          { }
    QSslSocket *socket;
    QSslConfiguration config;
    QString addCaCertificates;
    bool ignoreSslErrors;
    QSslSocket::PeerVerifyMode peerVerifyMode;
    QSsl::SslProtocol protocol;
    QString m_keyFile;
    QString m_certFile;
    QString m_interFile;
    QList<QSslCipher> ciphers;

signals:
    void socketError(QAbstractSocket::SocketError);

protected:
    void incomingConnection(qintptr socketDescriptor)
    {
        QSslConfiguration configuration = config;
        socket = new QSslSocket(this);
        configuration.setPeerVerifyMode(peerVerifyMode);
        configuration.setProtocol(protocol);
        if (ignoreSslErrors)
            connect(socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
        connect(socket, SIGNAL(errorOccurred(QAbstractSocket::SocketError)), this, SIGNAL(socketError(QAbstractSocket::SocketError)));

        QFile file(m_keyFile);
        QVERIFY(file.open(QIODevice::ReadOnly));
        QSslKey key(file.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
        QVERIFY(!key.isNull());
        configuration.setPrivateKey(key);

        // Add CA certificates to verify client certificate
        if (!addCaCertificates.isEmpty()) {
            QList<QSslCertificate> caCert = QSslCertificate::fromPath(addCaCertificates);
            QVERIFY(!caCert.isEmpty());
            QVERIFY(!caCert.first().isNull());
            configuration.addCaCertificates(caCert);
        }

        // If we have a cert issued directly from the CA
        if (m_interFile.isEmpty()) {
            QList<QSslCertificate> localCert = QSslCertificate::fromPath(m_certFile);
            QVERIFY(!localCert.isEmpty());
            QVERIFY(!localCert.first().isNull());
            configuration.setLocalCertificate(localCert.first());
        } else {
            QList<QSslCertificate> localCert = QSslCertificate::fromPath(m_certFile);
            QVERIFY(!localCert.isEmpty());
            QVERIFY(!localCert.first().isNull());

            QList<QSslCertificate> interCert = QSslCertificate::fromPath(m_interFile);
            QVERIFY(!interCert.isEmpty());
            QVERIFY(!interCert.first().isNull());

            configuration.setLocalCertificateChain(localCert + interCert);
        }

        if (!ciphers.isEmpty())
            configuration.setCiphers(ciphers);
        socket->setSslConfiguration(configuration);

        QVERIFY(socket->setSocketDescriptor(socketDescriptor, QAbstractSocket::ConnectedState));
        QVERIFY(!socket->peerAddress().isNull());
        QVERIFY(socket->peerPort() != 0);
        QVERIFY(!socket->localAddress().isNull());
        QVERIFY(socket->localPort() != 0);

        socket->startServerEncryption();
    }

protected slots:
    void ignoreErrorSlot()
    {
        socket->ignoreSslErrors();
    }
};

void tst_QSslWolfSSL::protocolServerSide_data()
{
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif
    QTest::addColumn<QSsl::SslProtocol>("serverProtocol");
    QTest::addColumn<QSsl::SslProtocol>("clientProtocol");
    QTest::addColumn<bool>("works");

    QTest::newRow("tls1.0-tls1.0") << QSsl::TlsV1_0 << QSsl::TlsV1_0 << true;
    QTest::newRow("tls1ssl3-tls1ssl3") << QSsl::TlsV1SslV3 << QSsl::TlsV1SslV3 << true;
    QTest::newRow("any-any") << QSsl::AnyProtocol << QSsl::AnyProtocol << true;
    QTest::newRow("secure-secure") << QSsl::SecureProtocols << QSsl::SecureProtocols << true;

    QTest::newRow("tls1-tls1ssl3") << QSsl::TlsV1_0 << QSsl::TlsV1SslV3 << true;
    QTest::newRow("tls1.0-secure") << QSsl::TlsV1_0 << QSsl::SecureProtocols << true;
    QTest::newRow("tls1.0-any") << QSsl::TlsV1_0 << QSsl::AnyProtocol << true;

    QTest::newRow("tls1ssl3-tls1.0") << QSsl::TlsV1SslV3 << QSsl::TlsV1_0 << true;
    QTest::newRow("tls1ssl3-secure") << QSsl::TlsV1SslV3 << QSsl::SecureProtocols << true;
    QTest::newRow("tls1ssl3-any") << QSsl::TlsV1SslV3 << QSsl::AnyProtocol << true;

    QTest::newRow("secure-tls1.0") << QSsl::SecureProtocols << QSsl::TlsV1_0 << true;
    QTest::newRow("secure-tls1ssl3") << QSsl::SecureProtocols << QSsl::TlsV1SslV3 << true;
    QTest::newRow("secure-any") << QSsl::SecureProtocols << QSsl::AnyProtocol << true;

    QTest::newRow("tls1.0orlater-tls1.0") << QSsl::TlsV1_0OrLater << QSsl::TlsV1_0 << true;
    QTest::newRow("tls1.0orlater-tls1.1") << QSsl::TlsV1_0OrLater << QSsl::TlsV1_1 << true;
    QTest::newRow("tls1.0orlater-tls1.2") << QSsl::TlsV1_0OrLater << QSsl::TlsV1_2 << true;
#ifdef TLS1_3_VERSION
    QTest::newRow("tls1.0orlater-tls1.3") << QSsl::TlsV1_0OrLater << QSsl::TlsV1_3 << true;
#endif

    QTest::newRow("tls1.1orlater-tls1.0") << QSsl::TlsV1_1OrLater << QSsl::TlsV1_0 << false;
    QTest::newRow("tls1.1orlater-tls1.1") << QSsl::TlsV1_1OrLater << QSsl::TlsV1_1 << true;
    QTest::newRow("tls1.1orlater-tls1.2") << QSsl::TlsV1_1OrLater << QSsl::TlsV1_2 << true;

#ifdef TLS1_3_VERSION
    QTest::newRow("tls1.1orlater-tls1.3") << QSsl::TlsV1_1OrLater << QSsl::TlsV1_3 << true;
#endif

    QTest::newRow("tls1.2orlater-tls1.0") << QSsl::TlsV1_2OrLater << QSsl::TlsV1_0 << false;
    QTest::newRow("tls1.2orlater-tls1.1") << QSsl::TlsV1_2OrLater << QSsl::TlsV1_1 << false;
    QTest::newRow("tls1.2orlater-tls1.2") << QSsl::TlsV1_2OrLater << QSsl::TlsV1_2 << true;
#ifdef TLS1_3_VERSION
    QTest::newRow("tls1.2orlater-tls1.3") << QSsl::TlsV1_2OrLater << QSsl::TlsV1_3 << true;
#endif
#ifdef TLS1_3_VERSION
    QTest::newRow("tls1.3orlater-tls1.0") << QSsl::TlsV1_3OrLater << QSsl::TlsV1_0 << false;
    QTest::newRow("tls1.3orlater-tls1.1") << QSsl::TlsV1_3OrLater << QSsl::TlsV1_1 << false;
    QTest::newRow("tls1.3orlater-tls1.2") << QSsl::TlsV1_3OrLater << QSsl::TlsV1_2 << false;
    QTest::newRow("tls1.3orlater-tls1.3") << QSsl::TlsV1_3OrLater << QSsl::TlsV1_3 << true;
#endif // TLS1_3_VERSION

    QTest::newRow("any-tls1.0") << QSsl::AnyProtocol << QSsl::TlsV1_0 << true;
    QTest::newRow("any-tls1ssl3") << QSsl::AnyProtocol << QSsl::TlsV1SslV3 << true;
    QTest::newRow("any-secure") << QSsl::AnyProtocol << QSsl::SecureProtocols << true;
}

void tst_QSslWolfSSL::protocolServerSide()
{
    if (skip_protocolServerSide)
        QSKIP("protocolServerSide()");
    
    if (!QSslSocket::supportsSsl()) {
        qWarning("SSL not supported, skipping test");
        return;
    }

    /*QFETCH_GLOBAL(bool, setProxy);
    if (setProxy)
        return;*/

    QFETCH(QSsl::SslProtocol, serverProtocol);
    SslServer server;
    server.ignoreSslErrors = true;
    server.protocol = serverProtocol;
    QVERIFY(server.listen());

    QEventLoop loop;
    connect(&server, SIGNAL(socketError(QAbstractSocket::SocketError)), &loop, SLOT(quit()));
    QTimer::singleShot(5000, &loop, SLOT(quit()));

    QSslSocket client;
    socket = &client;
    QFETCH(QSsl::SslProtocol, clientProtocol);
    socket->setProtocol(clientProtocol);
    // upon SSL wrong version error, errorOccurred will be triggered, not sslErrors
    connect(socket, SIGNAL(errorOccurred(QAbstractSocket::SocketError)), &loop, SLOT(quit()));
    connect(socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
    connect(socket, SIGNAL(encrypted()), &loop, SLOT(quit()));

    client.connectToHostEncrypted(QHostAddress(QHostAddress::LocalHost).toString(), server.serverPort());

    loop.exec();

    QFETCH(bool, works);
    QAbstractSocket::SocketState expectedState = (works) ? QAbstractSocket::ConnectedState : QAbstractSocket::UnconnectedState;
    // Determine whether the client or the server caused the event loop
    // to quit due to a socket error, and investigate the culprit.
    if (client.error() != QAbstractSocket::UnknownSocketError) {
        // It can happen that the client, after TCP connection established, before
        // incomingConnection() slot fired, hits TLS initialization error and stops
        // the loop, so the server socket is not created yet.
        if (server.socket)
            QVERIFY(server.socket->error() == QAbstractSocket::UnknownSocketError);
        
        const auto socketSslErrors = server.socket->sslHandshakeErrors();
        qDebug() << "server errors ";
        for (const QSslError &err : socketSslErrors)
            qDebug() << err.error();
        
        QCOMPARE(client.state(), expectedState);
    } else if (server.socket->error() != QAbstractSocket::UnknownSocketError) {
        QVERIFY(client.error() == QAbstractSocket::UnknownSocketError);
        QCOMPARE(server.socket->state(), expectedState);
    }

    QCOMPARE(client.isEncrypted(), works);
}

void tst_QSslWolfSSL::serverCipherPreferences()
{
    if (skip_serverCipherPreferences)
        QSKIP("serverCipherPreferences()");
    
    /* minVersion = TLS1_VERSION in qsslcontext_openssl */
    /* not available SSLv3 cipher suites */
    #if QT_CONFIG(openssl)
        const char* cipher1 = "AES128-SHA";
        const char* cipher2 = "AES256-SHA";
    #else
        const char* cipher1 = "AES128-SHA256";
        const char* cipher2 = "AES256-SHA256";
     #endif
     
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif
    if (!QSslSocket::supportsSsl()) {
        qWarning("SSL not supported, skipping test");
        return;
    }

    // First using the default (server preference)
    {
        SslServer server;
        server.ciphers = {QSslCipher(cipher1), QSslCipher(cipher2)};
        QVERIFY(server.listen());

        QEventLoop loop;
        QTimer::singleShot(5000, &loop, SLOT(quit()));

        QSslSocket client;
        socket = &client;

        auto sslConfig = socket->sslConfiguration();
        sslConfig.setCiphers({QSslCipher(cipher2), QSslCipher(cipher1)});
        socket->setSslConfiguration(sslConfig);
        /*for (const QSslCipher &cipher : sslConfig.ciphers()) {
            qDebug() << "local cipher : " << cipher.name().toLatin1();
        }*/
    
        // upon SSL wrong version error, errorOccurred will be triggered, not sslErrors
        connect(socket, SIGNAL(errorOccurred(QAbstractSocket::SocketError)), &loop, SLOT(quit()));
        connect(socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
        connect(socket, SIGNAL(encrypted()), &loop, SLOT(quit()));

        client.connectToHostEncrypted(QHostAddress(QHostAddress::LocalHost).toString(), server.serverPort());

        loop.exec();

        QVERIFY(client.isEncrypted());
        QCOMPARE(client.sessionCipher().name(), QString(cipher1));
    }

    {
        // Now using the client preferences
        SslServer server;
        QSslConfiguration config = QSslConfiguration::defaultConfiguration();
        config.setSslOption(QSsl::SslOptionDisableServerCipherPreference, true);
        server.config = config;
        server.ciphers = {QSslCipher(cipher1), QSslCipher(cipher2)};
        QVERIFY(server.listen());

        QEventLoop loop;
        QTimer::singleShot(5000, &loop, SLOT(quit()));

        QSslSocket client;
        socket = &client;

        auto sslConfig = socket->sslConfiguration();
        sslConfig.setCiphers({QSslCipher(cipher2), QSslCipher(cipher1)});
        socket->setSslConfiguration(sslConfig);

        // upon SSL wrong version error, errorOccurred will be triggered, not sslErrors
        connect(socket, SIGNAL(errorOccurred(QAbstractSocket::SocketError)), &loop, SLOT(quit()));
        connect(socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
        connect(socket, SIGNAL(encrypted()), &loop, SLOT(quit()));

        client.connectToHostEncrypted(QHostAddress(QHostAddress::LocalHost).toString(), server.serverPort());

        loop.exec();

        QVERIFY(client.isEncrypted());
        // will fail because of SSL_OP_CIPHER_xxx definition diff
        QCOMPARE(client.sessionCipher().name(), QString(cipher2));
    }
}

void tst_QSslWolfSSL::setCaCertificates()
{
    if (skip_setCaCertificates)
        QSKIP("setCaCertificates");
    
    if (!QSslSocket::supportsSsl())
        return;

    QSslSocket socket;
    QCOMPARE(socket.sslConfiguration().caCertificates(),
             QSslConfiguration::defaultConfiguration().caCertificates());

    auto sslConfig = socket.sslConfiguration();
    sslConfig.setCaCertificates(
                QSslCertificate::fromPath(testDataDir + "certs/qt-test-server-cacert.pem"));
    socket.setSslConfiguration(sslConfig);
    QCOMPARE(socket.sslConfiguration().caCertificates().size(), 1);

    sslConfig.setCaCertificates(QSslConfiguration::defaultConfiguration().caCertificates());
    socket.setSslConfiguration(sslConfig);
    QCOMPARE(socket.sslConfiguration().caCertificates(),
             QSslConfiguration::defaultConfiguration().caCertificates());
}

void tst_QSslWolfSSL::setLocalCertificate()
{
}

void tst_QSslWolfSSL::localCertificateChain()
{
    if (skip_localCertificateChain)
        QSKIP("localCertificateChain");
        
    if (!QSslSocket::supportsSsl())
        return;

    QSslSocket socket;
    socket.setLocalCertificate(testDataDir + "certs/fluke.cert");

    QSslConfiguration conf = socket.sslConfiguration();
    QList<QSslCertificate> chain = conf.localCertificateChain();
    QCOMPARE(chain.size(), 1);
    QCOMPARE(chain[0], conf.localCertificate());
    QCOMPARE(chain[0], socket.localCertificate());
}

void tst_QSslWolfSSL::setLocalCertificateChain()
{
    if (skip_setLocalCertificateChain)
        QSKIP("setLocalCertificateChain");
        
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif
    if (!QSslSocket::supportsSsl())
        return;

    SslServer server(testDataDir + "certs/leaf.key",
                     testDataDir + "certs/leaf.crt",
                     testDataDir + "certs/inter.crt");

    QVERIFY(server.listen());

    QEventLoop loop;
    QTimer::singleShot(5000, &loop, SLOT(quit()));

    const QScopedPointer<QSslSocket, QScopedPointerDeleteLater> client(new QSslSocket);
    socket = client.data();
    connect(socket, SIGNAL(encrypted()), &loop, SLOT(quit()));
    connect(socket, SIGNAL(errorOccurred(QAbstractSocket::SocketError)), &loop, SLOT(quit()));
    connect(socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));

    socket->connectToHostEncrypted(QHostAddress(QHostAddress::LocalHost).toString(), server.serverPort());
    loop.exec();

    QList<QSslCertificate> chain = socket->peerCertificateChain();
#if QT_CONFIG(schannel)
    QEXPECT_FAIL("", "Schannel cannot send intermediate certificates not "
                     "located in a system certificate store",
                 Abort);
#endif
    QCOMPARE(chain.size(), 2);
    qDebug() << chain[0].serialNumber();
    qDebug() << chain[1].serialNumber();
    QCOMPARE(chain[0].serialNumber(), QByteArray("10:a0:ad:77:58:f6:6e:ae:46:93:a3:43:f9:59:8a:9e"));
    QCOMPARE(chain[1].serialNumber(), QByteArray("3b:eb:99:c5:ea:d8:0b:5d:0b:97:5d:4f:06:75:4b:e1"));
}


void tst_QSslWolfSSL::setSocketDescriptor()
{
    if (skip_setSocketDescriptor)
        QSKIP("setSocketDescriptor");
        
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif
    if (!QSslSocket::supportsSsl())
        return;

    SslServer server;
    QVERIFY(server.listen());

    QEventLoop loop;
    QTimer::singleShot(5000, &loop, SLOT(quit()));

    QSslSocket client;
    socket = &client;
    connect(socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
    connect(socket, SIGNAL(encrypted()), &loop, SLOT(quit()));

    client.connectToHostEncrypted(QHostAddress(QHostAddress::LocalHost).toString(), server.serverPort());

    loop.exec();

    QCOMPARE(client.state(), QAbstractSocket::ConnectedState);
    QVERIFY(client.isEncrypted());
    QVERIFY(!client.peerAddress().isNull());
    QVERIFY(client.peerPort() != 0);
    QVERIFY(!client.localAddress().isNull());
    QVERIFY(client.localPort() != 0);
}

void tst_QSslWolfSSL::setSslConfiguration_data()
{
    QTest::addColumn<QSslConfiguration>("configuration");
    QTest::addColumn<bool>("works");

    QTest::newRow("empty") << QSslConfiguration() << false;
    QSslConfiguration conf = QSslConfiguration::defaultConfiguration();
    QTest::newRow("default") << conf << false; // does not contain test server cert
    QList<QSslCertificate> testServerCert = QSslCertificate::fromPath(httpServerCertChainPath());
    conf.setCaCertificates(testServerCert);
    QTest::newRow("set-root-cert") << conf << true;
    conf.setProtocol(QSsl::SecureProtocols);
    QTest::newRow("secure") << conf << true;
}

void tst_QSslWolfSSL::setSslConfiguration()
{
    if (skip_setSslConfiguration)
        QSKIP("setSslConfiguration");
        
    if (!QSslSocket::supportsSsl())
        return;

    QSslSocketPtr socket = newSocket();
    this->socket = socket.data();
    connect(socket.data(), SIGNAL(sslErrors(QList<QSslError>)), this, 
                    SLOT(ignoreHostNameMismatchErrorSlot(QList<QSslError>)));
                    
    QFETCH(QSslConfiguration, configuration);
    socket->setSslConfiguration(configuration);
#if QT_CONFIG(schannel) // old certificate not supported with TLS 1.2
    socket->setProtocol(QSsl::SslProtocol::TlsV1_1);
#endif
    this->socket = socket.data();
    socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
    QFETCH(bool, works);
    
    socket->waitForEncrypted(10000);
    if (works) {
        socket->disconnectFromHost();
        QVERIFY2(socket->waitForDisconnected(), qPrintable(socket->errorString()));
    }
}

void tst_QSslWolfSSL::waitForEncrypted()
{
    if (skip_waitForEncrypted)
        QSKIP("waitForEncrypted");
        
    if (!QSslSocket::supportsSsl())
        return;

    QSslSocketPtr socket = newSocket();
    this->socket = socket.data();

    connect(this->socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
    socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);

    socket->waitForEncrypted(10000);
}

void tst_QSslWolfSSL::waitForEncryptedMinusOne()
{
    if (skip_waitForEncryptedMinusOne)
        QSKIP("waitForEncryptedMinusOne");
        
#ifdef Q_OS_WIN
    QSKIP("QTBUG-24451 - indefinite wait may hang");
#endif
    if (!QSslSocket::supportsSsl())
        return;

    QSslSocketPtr socket = newSocket();
    this->socket = socket.data();

    connect(this->socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
    socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);

    socket->waitForEncrypted(-1);
}

void tst_QSslWolfSSL::startClientEncryption()
{
}

void tst_QSslWolfSSL::startServerEncryption()
{
}

void tst_QSslWolfSSL::addDefaultCaCertificate()
{
    if (skip_addDefaultCaCertificate)
        QSKIP("addDefaultCaCertificate");
        
    if (!QSslSocket::supportsSsl())
        return;

    // Reset the global CA chain
    auto sslConfig = QSslConfiguration::defaultConfiguration();
    sslConfig.setCaCertificates(QSslConfiguration::systemCaCertificates());
    QSslConfiguration::setDefaultConfiguration(sslConfig);

    QList<QSslCertificate> flukeCerts = QSslCertificate::fromPath(httpServerCertChainPath());
    QCOMPARE(flukeCerts.size(), 1);
    QList<QSslCertificate> globalCerts = QSslConfiguration::defaultConfiguration().caCertificates();
    QVERIFY(!globalCerts.contains(flukeCerts.first()));
    sslConfig.addCaCertificate(flukeCerts.first());
    QSslConfiguration::setDefaultConfiguration(sslConfig);
    QCOMPARE(QSslConfiguration::defaultConfiguration().caCertificates().size(),
             globalCerts.size() + 1);
    QVERIFY(QSslConfiguration::defaultConfiguration().caCertificates()
            .contains(flukeCerts.first()));

    // Restore the global CA chain
    sslConfig = QSslConfiguration::defaultConfiguration();
    sslConfig.setCaCertificates(QSslConfiguration::systemCaCertificates());
    QSslConfiguration::setDefaultConfiguration(sslConfig);
}

void tst_QSslWolfSSL::defaultCaCertificates()
{
    if (skip_defaultCaCertificates)
        QSKIP("defaultCaCertificates");
        
    if (!QSslSocket::supportsSsl())
        return;

    QList<QSslCertificate> certs = QSslConfiguration::defaultConfiguration().caCertificates();
    QVERIFY(certs.size() > 1);
    QCOMPARE(certs, QSslConfiguration::systemCaCertificates());
}

void tst_QSslWolfSSL::defaultCiphers()
{
    if (skip_defaultCiphers)
        QSKIP("defaultCiphers");
        
    if (!QSslSocket::supportsSsl())
        return;

    QList<QSslCipher> ciphers = QSslConfiguration::defaultConfiguration().ciphers();
    QVERIFY(ciphers.size() > 1);

    QSslSocket socket;
    QCOMPARE(socket.sslConfiguration().defaultConfiguration().ciphers(), ciphers);
    QCOMPARE(socket.sslConfiguration().ciphers(), ciphers);
}

void tst_QSslWolfSSL::resetDefaultCiphers()
{
}

void tst_QSslWolfSSL::setDefaultCaCertificates()
{
}

void tst_QSslWolfSSL::setDefaultCiphers()
{
}

void tst_QSslWolfSSL::supportedCiphers()
{
    if (skip_supportedCiphers)
        QSKIP("supportedCiphers");
        
    if (!QSslSocket::supportsSsl())
        return;

    QList<QSslCipher> ciphers = QSslConfiguration::supportedCiphers();
    QVERIFY(ciphers.size() > 1);

    QSslSocket socket;
    QCOMPARE(socket.sslConfiguration().supportedCiphers(), ciphers);
}

void tst_QSslWolfSSL::systemCaCertificates()
{
    if (skip_systemCaCertificates)
        QSKIP("systemCaCertificates");
        
    if (!QSslSocket::supportsSsl())
        return;

    QList<QSslCertificate> certs = QSslConfiguration::systemCaCertificates();
    QVERIFY(certs.size() > 1);
    QCOMPARE(certs, QSslConfiguration::defaultConfiguration().systemCaCertificates());
}

void tst_QSslWolfSSL::wildcardCertificateNames()
{
    if (skip_wildcardCertificateNames)
        QSKIP("wildcardCertificateNames");
        
    // Passing CN matches
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("www.example.com"), QString("www.example.com")), true );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("WWW.EXAMPLE.COM"), QString("www.example.com")), true );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("*.example.com"), QString("www.example.com")), true );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("xxx*.example.com"), QString("xxxwww.example.com")), true );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("f*.example.com"), QString("foo.example.com")), true );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("192.168.0.0"), QString("192.168.0.0")), true );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("foo.éxample.com"), QString("foo.xn--xample-9ua.com")), true );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("*.éxample.com"), QString("foo.xn--xample-9ua.com")), true );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("xn--kcry6tjko.example.org"), QString("xn--kcry6tjko.example.org")), true);
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("*.xn--kcry6tjko.example.org"), QString("xn--kcr.xn--kcry6tjko.example.org")), true);

    // Failing CN matches
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("xxx.example.com"), QString("www.example.com")), false );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("*"), QString("www.example.com")), false );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("*.*.com"), QString("www.example.com")), false );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("*.example.com"), QString("baa.foo.example.com")), false );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("f*.example.com"), QString("baa.example.com")), false );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("*.com"), QString("example.com")), false );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("*fail.com"), QString("example.com")), false );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("*.example."), QString("www.example.")), false );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("*.example."), QString("www.example")), false );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString(""), QString("www")), false );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("*"), QString("www")), false );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("*.168.0.0"), QString("192.168.0.0")), false );
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("xn--kcry6tjko*.example.org"), QString("xn--kcry6tjkoanc.example.org")), false );  // RFC 6125 §7.2
    QCOMPARE( QSslSocketPrivate::isMatchingHostname(QString("å*.example.org"), QString("xn--la-xia.example.org")), false );
}

void tst_QSslWolfSSL::isMatchingHostname()
{
    if (skip_isMatchingHostname)
        QSKIP("isMatchingHostname");
        
    // with normalization:  (the certificate has *.SCHÄUFELE.DE as a CN)
    // openssl req -x509 -nodes -subj "/CN=*.SCHÄUFELE.DE" -newkey rsa:512 -keyout /dev/null -out xn--schufele-2za.crt
    QList<QSslCertificate> certs = QSslCertificate::fromPath(testDataDir + "certs/xn--schufele-2za.crt");
    QVERIFY(!certs.isEmpty());
    QSslCertificate cert = certs.first();

    QCOMPARE(QSslSocketPrivate::isMatchingHostname(cert, QString::fromUtf8("WWW.SCHÄUFELE.DE")), true);
    QCOMPARE(QSslSocketPrivate::isMatchingHostname(cert, QString::fromUtf8("www.xn--schufele-2za.de")), true);
    QCOMPARE(QSslSocketPrivate::isMatchingHostname(cert, QString::fromUtf8("www.schäufele.de")), true);
    QCOMPARE(QSslSocketPrivate::isMatchingHostname(cert, QString::fromUtf8("föo.schäufele.de")), true);

    QCOMPARE(QSslSocketPrivate::isMatchingHostname(cert, QString::fromUtf8("foo.foo.xn--schufele-2za.de")), false);
    QCOMPARE(QSslSocketPrivate::isMatchingHostname(cert, QString::fromUtf8("www.schaufele.de")), false);
    QCOMPARE(QSslSocketPrivate::isMatchingHostname(cert, QString::fromUtf8("www.schufele.de")), false);

    /* Generated with the following command (only valid with openssl >= 1.1.1 due to "-addext"):
       openssl req -x509 -nodes -subj "/CN=example.org" \
            -addext "subjectAltName = IP:192.5.8.16, IP:fe80::3c29:2fa1:dd44:765" \
            -newkey rsa:2048 -keyout /dev/null -out subjectAltNameIP.crt
    */
    certs = QSslCertificate::fromPath(testDataDir + "certs/subjectAltNameIP.crt");
    QVERIFY(!certs.isEmpty());
    cert = certs.first();
    QCOMPARE(QSslSocketPrivate::isMatchingHostname(cert, QString::fromUtf8("192.5.8.16")), true);
    QCOMPARE(QSslSocketPrivate::isMatchingHostname(cert, QString::fromUtf8("fe80::3c29:2fa1:dd44:765")), true);

    /* openssl req -x509 -nodes -new -newkey rsa -keyout /dev/null -out 127-0-0-1-as-CN.crt \
            -subj "/CN=127.0.0.1"
    */
    certs = QSslCertificate::fromPath(testDataDir + "certs/127-0-0-1-as-CN.crt");
    QVERIFY(!certs.isEmpty());
    cert = certs.first();
    QCOMPARE(QSslSocketPrivate::isMatchingHostname(cert, QString::fromUtf8("127.0.0.1")), true);
}

class SslServer2 : public QTcpServer
{
protected:
    void incomingConnection(qintptr socketDescriptor)
    {
        QSslSocket *socket = new QSslSocket(this);
        socket->ignoreSslErrors();

        // Only set the certificate
        QList<QSslCertificate> localCert = QSslCertificate::fromPath(tst_QSslWolfSSL::testDataDir + "certs/fluke.cert");
        QVERIFY(!localCert.isEmpty());
        QVERIFY(!localCert.first().isNull());
        socket->setLocalCertificate(localCert.first());

        QVERIFY(socket->setSocketDescriptor(socketDescriptor, QAbstractSocket::ConnectedState));

        socket->startServerEncryption();
    }
};

void tst_QSslWolfSSL::setEmptyKey()
{
    if (skip_setEmptyKey)
        QSKIP("setEmptyKey");
        
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif
    if (!QSslSocket::supportsSsl())
        return;

    SslServer2 server;
    server.listen();

    QSslSocket socket;
    socket.connectToHostEncrypted("127.0.0.1", server.serverPort());

    QTestEventLoop::instance().enterLoop(2);

    QCOMPARE(socket.state(), QAbstractSocket::ConnectedState);
    QCOMPARE(socket.error(), QAbstractSocket::UnknownSocketError);
}

void tst_QSslWolfSSL::spontaneousWrite()
{
    if (skip_spontaneousWrite)
        QSKIP("spontaneousWrite");
        
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif

    
    SslServer server;
    QSslSocket *receiver = new QSslSocket(this);
    connect(receiver, SIGNAL(readyRead()), SLOT(exitLoop()));

    // connect two sockets to each other:
    QVERIFY(server.listen(QHostAddress::LocalHost));
    receiver->connectToHost("127.0.0.1", server.serverPort());
    QVERIFY(receiver->waitForConnected(5000));
    QVERIFY(server.waitForNewConnection(0));

    QSslSocket *sender = server.socket;
    QVERIFY(sender);
    QCOMPARE(sender->state(), QAbstractSocket::ConnectedState);
    receiver->setObjectName("receiver");
    sender->setObjectName("sender");
    receiver->ignoreSslErrors();
    receiver->startClientEncryption();

    // SSL handshake:
    connect(receiver, SIGNAL(encrypted()), SLOT(exitLoop()));
    enterLoop(1);
    QVERIFY(!timeout());
    QVERIFY(sender->isEncrypted());
    QVERIFY(receiver->isEncrypted());

    // make sure there's nothing to be received on the sender:
    while (sender->waitForReadyRead(10) || receiver->waitForBytesWritten(10)) {}

    // spontaneously write something:
    QByteArray data("Hello World");
    sender->write(data);

    // check if the other side receives it:
    enterLoop(1);
    QVERIFY(!timeout());
    QCOMPARE(receiver->bytesAvailable(), qint64(data.size()));
    QCOMPARE(receiver->readAll(), data);
}

void tst_QSslWolfSSL::setReadBufferSize()
{
    if (skip_setReadBufferSize)
        QSKIP("setReadBufferSize");
        
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif

    
    SslServer server;
    QSslSocket *receiver = new QSslSocket(this);
    connect(receiver, SIGNAL(readyRead()), SLOT(exitLoop()));

    // connect two sockets to each other:
    QVERIFY(server.listen(QHostAddress::LocalHost));
    receiver->connectToHost("127.0.0.1", server.serverPort());
    QVERIFY(receiver->waitForConnected(5000));
    QVERIFY(server.waitForNewConnection(0));

    QSslSocket *sender = server.socket;
    QVERIFY(sender);
    QCOMPARE(sender->state(), QAbstractSocket::ConnectedState);
    receiver->setObjectName("receiver");
    sender->setObjectName("sender");
    receiver->ignoreSslErrors();
    receiver->startClientEncryption();

    // SSL handshake:
    connect(receiver, SIGNAL(encrypted()), SLOT(exitLoop()));
    enterLoop(1);
    QVERIFY(!timeout());
    QVERIFY(sender->isEncrypted());
    QVERIFY(receiver->isEncrypted());

    QByteArray data(2048, 'b');
    receiver->setReadBufferSize(39 * 1024); // make it a non-multiple of the data.size()

    // saturate the incoming buffer
    while (sender->state() == QAbstractSocket::ConnectedState &&
           receiver->state() == QAbstractSocket::ConnectedState &&
           receiver->bytesAvailable() < receiver->readBufferSize()) {
        sender->write(data);
        //qDebug() << receiver->bytesAvailable() << "<" << receiver->readBufferSize() << (receiver->bytesAvailable() < receiver->readBufferSize());

        while (sender->bytesToWrite())
            QVERIFY(sender->waitForBytesWritten(10));

        // drain it:
        while (receiver->bytesAvailable() < receiver->readBufferSize() &&
               receiver->waitForReadyRead(10)) {}
    }

    //qDebug() << sender->bytesToWrite() << "bytes to write";
    //qDebug() << receiver->bytesAvailable() << "bytes available";

    // send a bit more
    sender->write(data);
    sender->write(data);
    sender->write(data);
    sender->write(data);
    //qDebug() << sender->bytesToWrite() << "bytes to write";
    //qDebug() << receiver->bytesAvailable() << "bytes available";
    QVERIFY(sender->waitForBytesWritten(10));

    qint64 oldBytesAvailable = receiver->bytesAvailable();

    // now unset the read buffer limit and iterate
    receiver->setReadBufferSize(0);
    enterLoop(1);
    QVERIFY(!timeout());

    QVERIFY(receiver->bytesAvailable() > oldBytesAvailable);
}

class SslServer3 : public QTcpServer
{
    Q_OBJECT
public:
    SslServer3() : socket(0) { }
    QSslSocket *socket;

protected:
    void incomingConnection(qintptr socketDescriptor)
    {
        socket = new QSslSocket(this);
        connect(socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));

        QFile file(tst_QSslWolfSSL::testDataDir + "certs/fluke.key");
        QVERIFY(file.open(QIODevice::ReadOnly));
        QSslKey key(file.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
        QVERIFY(!key.isNull());
        socket->setPrivateKey(key);

        QList<QSslCertificate> localCert = QSslCertificate::fromPath(tst_QSslWolfSSL::testDataDir
                                                                     + "certs/fluke.cert");
        QVERIFY(!localCert.isEmpty());
        QVERIFY(!localCert.first().isNull());
        socket->setLocalCertificate(localCert.first());

        QVERIFY(socket->setSocketDescriptor(socketDescriptor, QAbstractSocket::ConnectedState));
        QVERIFY(!socket->peerAddress().isNull());
        QVERIFY(socket->peerPort() != 0);
        QVERIFY(!socket->localAddress().isNull());
        QVERIFY(socket->localPort() != 0);
    }

protected slots:
    void ignoreErrorSlot()
    {
        socket->ignoreSslErrors();
    }
};

class ThreadedSslServer: public QThread
{
    Q_OBJECT
public:
    QSemaphore dataReadSemaphore;
    int serverPort;
    bool ok;

    ThreadedSslServer() : serverPort(-1), ok(false)
    { }

    ~ThreadedSslServer()
    {
        if (isRunning()) wait(2000);
        QVERIFY(ok);
    }

signals:
    void listening();

protected:
    void run()
    {
        // if all goes well (no timeouts), this thread will sleep for a total of 500 ms
        // (i.e., 5 times 100 ms, one sleep for each operation)

        SslServer3 server;
        server.listen(QHostAddress::LocalHost);
        serverPort = server.serverPort();
        emit listening();

        // delayed acceptance:
        QTest::qSleep(100);
        bool ret = server.waitForNewConnection(2000);
        Q_UNUSED(ret);

        // delayed start of encryption
        QTest::qSleep(100);
        QSslSocket *socket = server.socket;
        if (!socket || !socket->isValid())
            return;             // error
        socket->ignoreSslErrors();
        socket->startServerEncryption();
        if (!socket->waitForEncrypted(2000))
            return;             // error

        // delayed reading data
        QTest::qSleep(100);
        if (!socket->waitForReadyRead(2000) && socket->bytesAvailable() == 0)
            return;             // error
        socket->readAll();
        dataReadSemaphore.release();

        // delayed sending data
        QTest::qSleep(100);
        socket->write("Hello, World");
        while (socket->bytesToWrite())
            if (!socket->waitForBytesWritten(2000))
                return;             // error

        delete socket;
        ok = true;
    }
};

void tst_QSslWolfSSL::waitForMinusOne()
{
    if (skip_waitForMinusOne)
        QSKIP("waitForMinusOne");
        
#ifdef Q_OS_WIN
    QSKIP("QTBUG-24451 - indefinite wait may hang");
#endif
#ifdef Q_OS_WINRT // This can stay in case the one above goes away
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif

    
    ThreadedSslServer server;
    connect(&server, SIGNAL(listening()), SLOT(exitLoop()));
    
    // start the thread and wait for it to be ready
    server.start();
    enterLoop(1);
    QVERIFY(!timeout());

    // connect to the server
    QSslSocket socket;
    QTest::qSleep(100);
    
    socket.connectToHost("127.0.0.1", server.serverPort);
    QVERIFY(socket.waitForConnected(-1));
    socket.ignoreSslErrors();
    socket.startClientEncryption();

    // first verification: this waiting should take 200 ms
    socket.waitForEncrypted(-1);
    QVERIFY(socket.isEncrypted());
    QCOMPARE(socket.state(), QAbstractSocket::ConnectedState);
    QCOMPARE(socket.bytesAvailable(), Q_INT64_C(0));

    // second verification: write and make sure the other side got it (100 ms)
    socket.write("How are you doing?");
    QVERIFY(socket.bytesToWrite() != 0);
    QVERIFY(socket.waitForBytesWritten(-1));
    QVERIFY(server.dataReadSemaphore.tryAcquire(1, 2500));

    // third verification: it should wait for 100 ms:
    QVERIFY(socket.waitForReadyRead(-1));
    QVERIFY(socket.isEncrypted());
    QCOMPARE(socket.state(), QAbstractSocket::ConnectedState);
    QVERIFY(socket.bytesAvailable() != 0);

}

class VerifyServer : public QTcpServer
{
    Q_OBJECT
public:
    VerifyServer() : socket(0) { }
    QSslSocket *socket;

protected:
    void incomingConnection(qintptr socketDescriptor)
    {
        socket = new QSslSocket(this);

        socket->setPrivateKey(tst_QSslWolfSSL::testDataDir + "certs/fluke.key");
        socket->setLocalCertificate(tst_QSslWolfSSL::testDataDir + "certs/fluke.cert");
        socket->setSocketDescriptor(socketDescriptor);
        socket->startServerEncryption();
    }
};

void tst_QSslWolfSSL::verifyMode()
{
    if (skip_verifyMode)
        QSKIP("verifyMode");
        
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif


    QSslSocket socket;
#if QT_CONFIG(schannel) // old certificate not supported with TLS 1.2
    socket.setProtocol(QSsl::SslProtocol::TlsV1_1);
#endif
    QCOMPARE(socket.peerVerifyMode(), QSslSocket::AutoVerifyPeer);
    socket.setPeerVerifyMode(QSslSocket::VerifyNone);
    QCOMPARE(socket.peerVerifyMode(), QSslSocket::VerifyNone);
    socket.setPeerVerifyMode(QSslSocket::VerifyNone);
    socket.setPeerVerifyMode(QSslSocket::VerifyPeer);
    QCOMPARE(socket.peerVerifyMode(), QSslSocket::VerifyPeer);
    socket.setPeerVerifyMode(QSslSocket::VerifyNone);
    socket.connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
    socket.waitForEncrypted();
    
    QList<QSslError> expectedErrors = QList<QSslError>()
                                      << QSslError(QSslError::HostNameMismatch);
    
    qDebug() << "EXAMPLE SERVER" << tst_QSslWolfSSL::EXAMPLE_SERVER;
    qDebug() << "PORT " << tst_QSslWolfSSL::EXAMPLE_SERVER_PORT;
    auto config = socket.sslConfiguration();
    isMatchingHostname(config.peerCertificate(), tst_QSslWolfSSL::EXAMPLE_SERVER);
    
    QCOMPARE(socket.sslHandshakeErrors().size(), expectedErrors.size());
    socket.abort();

    VerifyServer server;
    server.listen();

    QSslSocket clientSocket;
    clientSocket.connectToHostEncrypted("127.0.0.1", server.serverPort());
    clientSocket.ignoreSslErrors();

    QEventLoop loop;
    QTimer::singleShot(5000, &loop, SLOT(quit()));
    connect(&clientSocket, SIGNAL(encrypted()), &loop, SLOT(quit()));
    loop.exec();

    QVERIFY(clientSocket.isEncrypted());
    QVERIFY(server.socket->sslHandshakeErrors().isEmpty());
}

void tst_QSslWolfSSL::verifyDepth()
{
    QSslSocket socket;
    QCOMPARE(socket.peerVerifyDepth(), 0);
    socket.setPeerVerifyDepth(1);
    QCOMPARE(socket.peerVerifyDepth(), 1);
    QTest::ignoreMessage(QtWarningMsg, "QSslSocket::setPeerVerifyDepth: cannot set negative depth of -1");
    socket.setPeerVerifyDepth(-1);
    QCOMPARE(socket.peerVerifyDepth(), 1);
}

void tst_QSslWolfSSL::disconnectFromHostWhenConnecting()
{
    if (skip_disconnectFromHostWhenConnecting)
        QSKIP("disconnectFromHostWhenConnecting");
    
    QSslSocketPtr socket = newSocket();
    socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
    socket->ignoreSslErrors();
    socket->write("XXXX LOGOUT\r\n");
    QAbstractSocket::SocketState state = socket->state();
    // without proxy, the state will be HostLookupState;
    // with    proxy, the state will be ConnectingState.
    QVERIFY(socket->state() == QAbstractSocket::HostLookupState ||
            socket->state() == QAbstractSocket::ConnectingState);
    socket->disconnectFromHost();
    // the state of the socket must be the same before and after calling
    // disconnectFromHost()
    QCOMPARE(state, socket->state());
    QVERIFY(socket->state() == QAbstractSocket::HostLookupState ||
            socket->state() == QAbstractSocket::ConnectingState);
    socket->waitForDisconnected(10000);
    //    QSKIP("Skipping flaky test - See QTBUG-29941");
    QCOMPARE(socket->state(), QAbstractSocket::UnconnectedState);
    // we did not call close, so the socket must be still open
    QVERIFY(socket->isOpen());
    QCOMPARE(socket->bytesToWrite(), qint64(0));

    // don't forget to login
    QCOMPARE((int) socket->write("USER ftptest\r\n"), 14);

}

void tst_QSslWolfSSL::disconnectFromHostWhenConnected()
{
    if (skip_disconnectFromHostWhenConnected)
        QSKIP("disconnectFromHostWhenConnected");
        
    QSslSocketPtr socket = newSocket();
    socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
    socket->ignoreSslErrors();
    socket->waitForEncrypted(5000);
    //    QSKIP("Skipping flaky test - See QTBUG-29941");
    socket->write("XXXX LOGOUT\r\n");
    QCOMPARE(socket->state(), QAbstractSocket::ConnectedState);
    socket->disconnectFromHost();
    QCOMPARE(socket->state(), QAbstractSocket::ClosingState);
    QVERIFY(socket->waitForDisconnected(5000));
    QCOMPARE(socket->bytesToWrite(), qint64(0));
}

class WebSocket : public QSslSocket
{
    Q_OBJECT
public:
    explicit WebSocket(qintptr socketDescriptor,
                       const QString &keyFile = tst_QSslWolfSSL::testDataDir + "certs/fluke.key",
                       const QString &certFile = tst_QSslWolfSSL::testDataDir + "certs/fluke.cert");

protected slots:
    void onReadyReadFirstBytes(void);

private:
    void _startServerEncryption(void);

    QString m_keyFile;
    QString m_certFile;

private:
    Q_DISABLE_COPY(WebSocket)
};

WebSocket::WebSocket (qintptr socketDescriptor, const QString &keyFile, const QString &certFile)
    : m_keyFile(keyFile),
      m_certFile(certFile)
{
    QVERIFY(setSocketDescriptor(socketDescriptor, QAbstractSocket::ConnectedState, QIODevice::ReadWrite | QIODevice::Unbuffered));
    connect (this, SIGNAL(readyRead()), this, SLOT(onReadyReadFirstBytes()));
}

void WebSocket::_startServerEncryption (void)
{
    QFile file(m_keyFile);
    QVERIFY(file.open(QIODevice::ReadOnly));
    QSslKey key(file.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    QVERIFY(!key.isNull());
    setPrivateKey(key);

    QList<QSslCertificate> localCert = QSslCertificate::fromPath(m_certFile);
    QVERIFY(!localCert.isEmpty());
    QVERIFY(!localCert.first().isNull());
    setLocalCertificate(localCert.first());

    QVERIFY(!peerAddress().isNull());
    QVERIFY(peerPort() != 0);
    QVERIFY(!localAddress().isNull());
    QVERIFY(localPort() != 0);

    setProtocol(QSsl::AnyProtocol);
    setPeerVerifyMode(QSslSocket::VerifyNone);
    ignoreSslErrors();
    startServerEncryption();
}

void WebSocket::onReadyReadFirstBytes (void)
{
    peek(1);
    disconnect(this,SIGNAL(readyRead()), this, SLOT(onReadyReadFirstBytes()));
    _startServerEncryption();
}

class SslServer4 : public QTcpServer
{
    Q_OBJECT
public:

    QScopedPointer<WebSocket> socket;

protected:
    void incomingConnection(qintptr socketDescriptor) override
    {
        socket.reset(new WebSocket(socketDescriptor));
    }
};

void tst_QSslWolfSSL::qtbug18498_peek()
{
    if (skip_qtbug18498_peek)
        QSKIP("qtbug18498_peek");
        
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif
    
    SslServer4 server;
    QVERIFY(server.listen(QHostAddress::LocalHost));

    QSslSocket client;
    client.connectToHost("127.0.0.1", server.serverPort());
    QVERIFY(client.waitForConnected(5000));
    QVERIFY(server.waitForNewConnection(1000));
    client.ignoreSslErrors();

    int encryptedCounter = 2;
    connect(&client, &QSslSocket::encrypted, this, [&encryptedCounter](){
        if (!--encryptedCounter)
            exitLoop();
    });
    WebSocket *serversocket = server.socket.data();
    connect(serversocket, &QSslSocket::encrypted, this, [&encryptedCounter](){
        if (!--encryptedCounter)
            exitLoop();
    });
    connect(&client, SIGNAL(disconnected()), this, SLOT(exitLoop()));

    client.startClientEncryption();
    QVERIFY(serversocket);

    enterLoop(1);
    QVERIFY(!timeout());
    QVERIFY(serversocket->isEncrypted());
    QVERIFY(client.isEncrypted());

    QByteArray data("abc123");
    client.write(data.data());

    connect(serversocket, SIGNAL(readyRead()), this, SLOT(exitLoop()));
    enterLoop(1);
    QVERIFY(!timeout());

    QByteArray peek1_data;
    peek1_data.reserve(data.size());
    QByteArray peek2_data;
    QByteArray read_data;

    int lngth = serversocket->peek(peek1_data.data(), 10);
    peek1_data.resize(lngth);

    peek2_data = serversocket->peek(10);
    read_data = serversocket->readAll();

    QCOMPARE(peek1_data, data);
    QCOMPARE(peek2_data, data);
    QCOMPARE(read_data, data);
}

class SslServer5 : public QTcpServer
{
    Q_OBJECT
public:
    SslServer5() : socket(0) {}
    QSslSocket *socket;

protected:
    void incomingConnection(qintptr socketDescriptor)
    {
        socket =  new QSslSocket;
        socket->setSocketDescriptor(socketDescriptor);
    }
};

void tst_QSslWolfSSL::qtbug18498_peek2()
{
    if (skip_qtbug18498_peek2)
        QSKIP("qtbug18498_peek2");
        
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif

    SslServer5 listener;
    QVERIFY(listener.listen(QHostAddress::Any));
    QScopedPointer<QSslSocket> client(new QSslSocket);
    client->connectToHost(QHostAddress::LocalHost, listener.serverPort());
    QVERIFY(client->waitForConnected(5000));
    QVERIFY(listener.waitForNewConnection(1000));

    QScopedPointer<QSslSocket> server(listener.socket);

    QVERIFY(server->write("HELLO\r\n", 7));
    QTRY_COMPARE(client->bytesAvailable(), 7);
    char c;
    QCOMPARE(client->peek(&c,1), 1);
    QCOMPARE(c, 'H');
    QCOMPARE(client->read(&c,1), 1);
    QCOMPARE(c, 'H');
    QByteArray b = client->peek(2);
    QCOMPARE(b, QByteArray("EL"));
    char a[3];
    QVERIFY(client->peek(a, 2) == 2);
    QCOMPARE(a[0], 'E');
    QCOMPARE(a[1], 'L');
    QCOMPARE(client->readAll(), QByteArray("ELLO\r\n"));

    //check data split between QIODevice and plain socket buffers.
    QByteArray bigblock;
    bigblock.fill('#', QIODEVICE_BUFFERSIZE + 1024);
    QVERIFY(client->write(QByteArray("head")));
    QVERIFY(client->write(bigblock));
    QTRY_COMPARE(server->bytesAvailable(), bigblock.length() + 4);
    QCOMPARE(server->read(4), QByteArray("head"));
    QCOMPARE(server->peek(bigblock.length()), bigblock);
    b.reserve(bigblock.length());
    b.resize(server->peek(b.data(), bigblock.length()));
    QCOMPARE(b, bigblock);

    //check oversized peek
    QCOMPARE(server->peek(bigblock.length() * 3), bigblock);
    b.reserve(bigblock.length() * 3);
    b.resize(server->peek(b.data(), bigblock.length() * 3));
    QCOMPARE(b, bigblock);

    QCOMPARE(server->readAll(), bigblock);

    QVERIFY(client->write("STARTTLS\r\n"));
    QTRY_COMPARE(server->bytesAvailable(), 10);
    QCOMPARE(server->peek(&c,1), 1);
    QCOMPARE(c, 'S');
    b = server->peek(3);
    QCOMPARE(b, QByteArray("STA"));
    QCOMPARE(server->read(5), QByteArray("START"));
    QVERIFY(server->peek(a, 3) == 3);
    QCOMPARE(a[0], 'T');
    QCOMPARE(a[1], 'L');
    QCOMPARE(a[2], 'S');
    QCOMPARE(server->readAll(), QByteArray("TLS\r\n"));

    QFile file(testDataDir + "certs/fluke.key");
    QVERIFY(file.open(QIODevice::ReadOnly));
    QSslKey key(file.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    QVERIFY(!key.isNull());
    server->setPrivateKey(key);

    QList<QSslCertificate> localCert = QSslCertificate::fromPath(testDataDir + "certs/fluke.cert");
    QVERIFY(!localCert.isEmpty());
    QVERIFY(!localCert.first().isNull());
    server->setLocalCertificate(localCert.first());

    server->setProtocol(QSsl::AnyProtocol);
    server->setPeerVerifyMode(QSslSocket::VerifyNone);

    server->ignoreSslErrors();
    client->ignoreSslErrors();

    server->startServerEncryption();
    client->startClientEncryption();

    QVERIFY(server->write("hello\r\n", 7));
    QTRY_COMPARE(client->bytesAvailable(), 7);
    QVERIFY(server->mode() == QSslSocket::SslServerMode && client->mode() == QSslSocket::SslClientMode);
    QCOMPARE(client->peek(&c,1), 1);
    QCOMPARE(c, 'h');
    QCOMPARE(client->read(&c,1), 1);
    QCOMPARE(c, 'h');
    b = client->peek(2);
    QCOMPARE(b, QByteArray("el"));
    QCOMPARE(client->readAll(), QByteArray("ello\r\n"));

    QVERIFY(client->write("goodbye\r\n"));
    QTRY_COMPARE(server->bytesAvailable(), 9);
    QCOMPARE(server->peek(&c,1), 1);
    QCOMPARE(c, 'g');
    QCOMPARE(server->readAll(), QByteArray("goodbye\r\n"));
    client->disconnectFromHost();
    /*QVERIFY(client->waitForDisconnected(5000));*/
}

void tst_QSslWolfSSL::resetProxy()
{
    if (skip_resetProxy)
        QSKIP("resetProxy");
        
#ifndef QT_NO_NETWORKPROXY

    // check fix for bug 199941

    QNetworkProxy goodProxy(QNetworkProxy::NoProxy);
    QNetworkProxy badProxy(QNetworkProxy::HttpProxy, "thisCannotWorkAbsolutelyNotForSure", 333);

    // make sure the connection works, and then set a nonsense proxy, and then
    // make sure it does not work anymore
    QSslSocket socket;
    auto config = socket.sslConfiguration();
    config.addCaCertificates(httpServerCertChainPath());
    socket.setSslConfiguration(config);
    socket.setProxy(goodProxy);
    /* launched openssl s_server -accept 11111 -key /wolf-path/certs/server-key.pem -cert /wolf-path/certs/server-cert.pem */
    socket.connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
    QVERIFY2(socket.waitForConnected(10000), qPrintable(socket.errorString()));
    socket.abort();
    socket.setProxy(badProxy);
    /* launched openssl s_server -accept 11111 -key /wolf-path/certs/server-key.pem -cert /wolf-path/certs/server-cert.pem */
    socket.connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
    QVERIFY(! socket.waitForConnected(10000));

    // don't forget to login
    QCOMPARE((int) socket.write("USER ftptest\r\n"), 14);
    QCOMPARE((int) socket.write("PASS password\r\n"), 15);

    enterLoop(10);

    // now the other way round:
    // set the nonsense proxy and make sure the connection does not work,
    // and then set the right proxy and make sure it works
    QSslSocket socket2;
    auto config2 = socket.sslConfiguration();
    config2.addCaCertificates(httpServerCertChainPath());
    socket2.setSslConfiguration(config2);
    socket2.setProxy(badProxy);
    socket2.connectToHostEncrypted(QtNetworkSettings::httpServerName(), 443);
    QVERIFY(! socket2.waitForConnected(10000));
    socket2.abort();
    socket2.setProxy(goodProxy);
    socket2.connectToHostEncrypted(QtNetworkSettings::httpServerName(), 443);
    //QVERIFY2(socket2.waitForConnected(10000), qPrintable(socket.errorString()));
#endif // QT_NO_NETWORKPROXY
}

void tst_QSslWolfSSL::ignoreSslErrorsList_data()
{

    QTest::addColumn<QList<QSslError> >("expectedSslErrors");
    QTest::addColumn<int>("expectedSslErrorSignalCount");

    // construct the list of errors that we will get with the SSL handshake and that we will ignore
    QList<QSslError> expectedSslErrors;
    // fromPath gives us a list of certs, but it actually only contains one
    QList<QSslCertificate> certs = QSslCertificate::fromPath(tst_QSslWolfSSL::testDataDir + QStringLiteral("certs/server-cert.pem"));
    QSslError rightError(FLUKE_CERTIFICATE_ERROR, certs.at(0));
    QSslError hostnamemismatch(QSslError::HostNameMismatch, certs.at(0));
    #if QT_CONFIG(openssl)
    QSslError anothererror(QSslError::UnableToVerifyFirstCertificate, certs.at(0));
    #else
    QSslError anothererror(QSslError::InvalidCaCertificate, certs.at(0));
    #endif
    QSslError wrongError(FLUKE_CERTIFICATE_ERROR);
    
    QTest::newRow("SSL-failure-empty-list") << expectedSslErrors << 1;
    expectedSslErrors.append(wrongError);
    QTest::newRow("SSL-failure-wrong-error") << expectedSslErrors << 1;
    expectedSslErrors.append(rightError);
    expectedSslErrors.append(hostnamemismatch);
    expectedSslErrors.append(anothererror);
    QTest::newRow("allErrorsInExpectedList1") << expectedSslErrors << 0;
    expectedSslErrors.removeAll(wrongError);
    QTest::newRow("allErrorsInExpectedList2") << expectedSslErrors << 0;
    expectedSslErrors.removeAll(hostnamemismatch);
    QTest::newRow("SSL-failure-empty-list-again") << expectedSslErrors << 1;
}

void tst_QSslWolfSSL::ignoreSslErrorsList()
{
    if (skip_ignoreSslErrorsList)
        QSKIP("ignoreSslErrorsList");
        
    QSslSocket socket;
    connect(&socket, SIGNAL(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)),
            this, SLOT(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)));

    QSslCertificate cert;

    QFETCH(QList<QSslError>, expectedSslErrors);
    socket.ignoreSslErrors(expectedSslErrors);

    QFETCH(int, expectedSslErrorSignalCount);
    QSignalSpy sslErrorsSpy(&socket, SIGNAL(errorOccurred(QAbstractSocket::SocketError)));
    
    /*connect(&socket, SIGNAL(sslErrors(QList<QSslError>)), this, 
                    SLOT(displayErrorSlot(QList<QSslError>)));
    const auto socketSslErrors = socket.sslHandshakeErrors();
    for (const QSslError &err : socketSslErrors)
        qDebug() << " error " << err.error();*/
        
    /* launched openssl s_server -accept 11111 -key /wolf-path/certs/server-key.pem -cert /wolf-path/certs/server-cert.pem */
    socket.connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);

    socket.waitForEncrypted(10000);
    /*const auto socketSslErrors = socket.sslHandshakeErrors();
    for (const QSslError &err : socketSslErrors)
        qDebug() << err.error();*/
    
    QCOMPARE(sslErrorsSpy.count(), expectedSslErrorSignalCount);
}

void tst_QSslWolfSSL::ignoreSslErrorsListWithSlot_data()
{
    ignoreSslErrorsList_data();
}

// this is not a test, just a slot called in the test below
void tst_QSslWolfSSL::ignoreErrorListSlot(const QList<QSslError> &)
{
    socket->ignoreSslErrors(storedExpectedSslErrors);
}

void tst_QSslWolfSSL::ignoreSslErrorsListWithSlot()
{
    if (skip_ignoreSslErrorsListWithSlot)
        QSKIP("ignoreSslErrorsListWithSlot");
        
    QSslSocket socket;
    this->socket = &socket;

    QFETCH(QList<QSslError>, expectedSslErrors);
    // store the errors to ignore them later in the slot connected below
    storedExpectedSslErrors = expectedSslErrors;
    connect(&socket, SIGNAL(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)),
            this, SLOT(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)));
    connect(&socket, SIGNAL(sslErrors(QList<QSslError>)),
            this, SLOT(ignoreErrorListSlot(QList<QSslError>)));
    /* launched openssl s_server -accept 11111 -key /wolf-path/certs/server-key.pem -cert /wolf-path/certs/server-cert.pem */
    socket.connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);

    QFETCH(int, expectedSslErrorSignalCount);
    bool expectEncryptionSuccess = (expectedSslErrorSignalCount == 0);
    
    if ((socket.waitForEncrypted(10000) != expectEncryptionSuccess))
        QSKIP("Skipping flaky test - See QTBUG-29941");
}

void tst_QSslWolfSSL::abortOnSslErrors()
{
    if (skip_abortOnSslErrors)
        QSKIP("abortOnSslErrors");
        
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif

    SslServer server;
    QVERIFY(server.listen());

    QSslSocket clientSocket;
    connect(&clientSocket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(abortOnErrorSlot()));
    clientSocket.connectToHostEncrypted("127.0.0.1", server.serverPort());
    clientSocket.ignoreSslErrors();

    QEventLoop loop;
    QTimer::singleShot(1000, &loop, SLOT(quit()));
    loop.exec();

    QCOMPARE(clientSocket.state(), QAbstractSocket::UnconnectedState);
}

// make sure a closed socket has no bytesAvailable()
// related to https://bugs.webkit.org/show_bug.cgi?id=28016
void tst_QSslWolfSSL::readFromClosedSocket()
{
    if (skip_readFromClosedSocket)
        QSKIP("readFromClosedSocket");
        
    QSslSocketPtr socket = newSocket();
#if QT_CONFIG(schannel) // old certificate not supported with TLS 1.2
    socket->setProtocol(QSsl::SslProtocol::TlsV1_1);
#endif
    socket->ignoreSslErrors();
    /* launched openssl s_server -accept 11111 -key /wolf-path/certs/server-key.pem -cert /wolf-path/certs/server-cert.pem -WWW */
    socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
    socket->ignoreSslErrors();
    socket->waitForConnected();
    socket->waitForEncrypted();
    // provoke a response by sending a request
    socket->write("GET /qtest/fluke.gif HTTP/1.1\n");
    socket->write("Host: ");
    socket->write(QtNetworkSettings::httpServerName().toLocal8Bit().constData());
    socket->write("\n");
    socket->write("\n");
    socket->waitForBytesWritten();
    socket->waitForReadyRead();
    
    if ((socket->state() != QAbstractSocket::ConnectedState))
        QSKIP("Skipping flaky test - See QTBUG-29941");
#if 1
    /* OpenSSL s_server doesn't return anything when not specified -WWW*/
    QVERIFY(socket->bytesAvailable());
#endif
    socket->close();
    QVERIFY(!socket->bytesAvailable());
    QVERIFY(!socket->bytesToWrite());
    QCOMPARE(socket->state(), QAbstractSocket::UnconnectedState);
}


void tst_QSslWolfSSL::writeBigChunk()
{
    if (skip_writeBigChunk)
        QSKIP("writeBigChunk");
        
    if (!QSslSocket::supportsSsl())
        return;

    QSslSocketPtr socket = newSocket();
    this->socket = socket.data();

    connect(this->socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
    /* launched openssl s_server -accept 11111 -key /wolf-path/certs/server-key.pem -cert /wolf-path/certs/server-cert.pem */
    socket->connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);

    QByteArray data;
    // Originally, the test had this: '1024*1024*10; // 10 MB'
    data.resize(1024 * 1024 * 10);
    // Init with garbage. Needed so TLS cannot compress it in an efficient way.
    QRandomGenerator::global()->fillRange(reinterpret_cast<quint32 *>(data.data()),
                                          data.size() / int(sizeof(quint32)));

    socket->waitForEncrypted(10000);
    //    QSKIP("Skipping flaky test - See QTBUG-29941");
    QString errorBefore = socket->errorString();

    int ret = socket->write(data.constData(), data.size());
    QCOMPARE(data.size(), ret);

    // spin the event loop once so QSslSocket::transmit() gets called
    QCoreApplication::processEvents();
    QString errorAfter = socket->errorString();

    // no better way to do this right now since the error is the same as the default error.
    if (socket->errorString().startsWith(QLatin1String("Unable to write data")))
    {
        qWarning() << socket->error() << socket->errorString();
        QFAIL("Error while writing! Check if the OpenSSL BIO size is limited?!");
    }
    // also check the error string. If another error (than UnknownError) occurred, it should be different than before
    QVERIFY2(errorBefore == errorAfter || socket->error() == QAbstractSocket::RemoteHostClosedError,
             QByteArray("unexpected error: ").append(qPrintable(errorAfter)));

    // check that everything has been written to OpenSSL
    QCOMPARE(socket->bytesToWrite(), 0);

    socket->close();
}

void tst_QSslWolfSSL::blacklistedCertificates()
{
    if (skip_blacklistedCertificates)
        QSKIP("blacklistedCertificates");
        
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif

    
    SslServer server(testDataDir + "certs/fake-login.live.com.key", testDataDir + "certs/fake-login.live.com.pem");
    QSslSocket *receiver = new QSslSocket(this);
    connect(receiver, SIGNAL(readyRead()), SLOT(exitLoop()));

    // connect two sockets to each other:
    QVERIFY(server.listen(QHostAddress::LocalHost));
    receiver->connectToHost("127.0.0.1", server.serverPort());
    QVERIFY(receiver->waitForConnected(5000));
    server.waitForNewConnection(0);
    
    QSslSocket *sender = server.socket;
    QVERIFY(sender);
    QCOMPARE(sender->state(), QAbstractSocket::ConnectedState);
    receiver->setObjectName("receiver");
    sender->setObjectName("sender");
    receiver->startClientEncryption();

    connect(receiver, SIGNAL(sslErrors(QList<QSslError>)), SLOT(exitLoop()));
    connect(receiver, SIGNAL(encrypted()), SLOT(exitLoop()));
    enterLoop(1);
    QList<QSslError> sslErrors = receiver->sslHandshakeErrors();
    QVERIFY(sslErrors.count() > 0);
    // there are more errors (self signed cert and hostname mismatch), but we only care about the blacklist error
    QCOMPARE(sslErrors.at(0).error(), QSslError::CertificateBlacklisted);
}

void tst_QSslWolfSSL::versionAccessors()
{
    if (skip_versionAccessors)
        QSKIP("versionAccessors");
        
    if (!QSslSocket::supportsSsl())
        return;

    qDebug() << QSslSocket::sslLibraryVersionString();
    qDebug() << QString::number(QSslSocket::sslLibraryVersionNumber(), 16);
}

#ifndef QT_NO_OPENSSL
void tst_QSslWolfSSL::sslOptions()
{
    if (skip_sslOptions)
        QSKIP("sslOptions");
        
    if (!QSslSocket::supportsSsl())
        return;

#ifdef SSL_OP_NO_COMPRESSION
    QCOMPARE(QSslSocketBackendPrivate::setupOpenSslOptions(QSsl::SecureProtocols,
                                                           QSslConfigurationPrivate::defaultSslOptions),
             long(SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_COMPRESSION|SSL_OP_CIPHER_SERVER_PREFERENCE));
#else
    QCOMPARE(QSslSocketBackendPrivate::setupOpenSslOptions(QSsl::SecureProtocols,
                                                           QSslConfigurationPrivate::defaultSslOptions),
             long(SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_CIPHER_SERVER_PREFERENCE));
#endif

    QCOMPARE(QSslSocketBackendPrivate::setupOpenSslOptions(QSsl::SecureProtocols,
                                                           QSsl::SslOptionDisableEmptyFragments
                                                           |QSsl::SslOptionDisableLegacyRenegotiation),
             long(SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_CIPHER_SERVER_PREFERENCE));

#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    QCOMPARE(QSslSocketBackendPrivate::setupOpenSslOptions(QSsl::SecureProtocols,
                                                           QSsl::SslOptionDisableEmptyFragments),
             long((SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION|SSL_OP_CIPHER_SERVER_PREFERENCE)));
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
    QCOMPARE(QSslSocketBackendPrivate::setupOpenSslOptions(QSsl::SecureProtocols,
                                                           QSsl::SslOptionDisableLegacyRenegotiation),
             long((SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_CIPHER_SERVER_PREFERENCE) & ~SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS));
#endif

#ifdef SSL_OP_NO_TICKET
    QCOMPARE(QSslSocketBackendPrivate::setupOpenSslOptions(QSsl::SecureProtocols,
                                                           QSsl::SslOptionDisableEmptyFragments
                                                           |QSsl::SslOptionDisableLegacyRenegotiation
                                                           |QSsl::SslOptionDisableSessionTickets),
             long((SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TICKET|SSL_OP_CIPHER_SERVER_PREFERENCE)));
#endif

#ifdef SSL_OP_NO_TICKET
#ifdef SSL_OP_NO_COMPRESSION
    QCOMPARE(QSslSocketBackendPrivate::setupOpenSslOptions(QSsl::SecureProtocols,
                                                           QSsl::SslOptionDisableEmptyFragments
                                                           |QSsl::SslOptionDisableLegacyRenegotiation
                                                           |QSsl::SslOptionDisableSessionTickets
                                                           |QSsl::SslOptionDisableCompression),
             long((SSL_OP_ALL|SSL_OP_NO_SSLv2|SSL_OP_NO_SSLv3|SSL_OP_NO_TICKET|SSL_OP_NO_COMPRESSION|SSL_OP_CIPHER_SERVER_PREFERENCE)));
#endif
#endif
}
#endif

void tst_QSslWolfSSL::encryptWithoutConnecting()
{
    if (skip_encryptWithoutConnecting)
        QSKIP("encryptWithoutConnecting");
        
    if (!QSslSocket::supportsSsl())
        return;

    QTest::ignoreMessage(QtWarningMsg,
                         "QSslSocket::startClientEncryption: cannot start handshake when not connected");

    QSslSocket sock;
    sock.startClientEncryption();
}

void tst_QSslWolfSSL::resume_data()
{
    QTest::addColumn<bool>("ignoreErrorsAfterPause");
    QTest::addColumn<QList<QSslError> >("errorsToIgnore");
    QTest::addColumn<bool>("expectSuccess");

    QList<QSslError> errorsList;
    QTest::newRow("DoNotIgnoreErrors") << false << QList<QSslError>() << false;
    QTest::newRow("ignoreAllErrors") << true << QList<QSslError>() << true;

    // Note, httpServerCertChainPath() it's ... because we use the same certificate on
    // different services. We'll be actually connecting to IMAP server.
    QList<QSslCertificate> certs = QSslCertificate::fromPath(tst_QSslWolfSSL::testDataDir + QStringLiteral("certs/server-cert.pem"));
    QSslError rightError(FLUKE_CERTIFICATE_ERROR, certs.at(0));
    QSslError wrongError(FLUKE_CERTIFICATE_ERROR);
    QSslError hostnamemismatch(QSslError::HostNameMismatch, certs.at(0));
    #if QT_CONFIG(openssl)
    QSslError anothererror(QSslError::UnableToVerifyFirstCertificate, certs.at(0));
    #else
    QSslError anothererror(QSslError::InvalidCaCertificate, certs.at(0));
    #endif
    
    errorsList.append(wrongError);
    QTest::newRow("ignoreSpecificErrors-Wrong") << true << errorsList << false;
    errorsList.clear();
    errorsList.append(rightError);
    errorsList.append(hostnamemismatch);
    errorsList.append(anothererror);
    QTest::newRow("ignoreSpecificErrors-Right") << true << errorsList << true;
}

void tst_QSslWolfSSL::resume()
{
    if (skip_resume)
        QSKIP("resume");
        
    // make sure the server certificate is not in the list of accepted certificates,
    // we want to trigger the sslErrors signal
    auto sslConfig = QSslConfiguration::defaultConfiguration();
    sslConfig.setCaCertificates(QSslConfiguration::systemCaCertificates());
    QSslConfiguration::setDefaultConfiguration(sslConfig);

    QFETCH(bool, ignoreErrorsAfterPause);
    QFETCH(QList<QSslError>, errorsToIgnore);
    QFETCH(bool, expectSuccess);

    QSslSocket socket;
    socket.setPauseMode(QAbstractSocket::PauseOnSslErrors);

    QSignalSpy sslErrorSpy(&socket, SIGNAL(sslErrors(QList<QSslError>)));
    QSignalSpy encryptedSpy(&socket, SIGNAL(encrypted()));
    QSignalSpy errorSpy(&socket, SIGNAL(errorOccurred(QAbstractSocket::SocketError)));

    connect(&socket, SIGNAL(sslErrors(QList<QSslError>)), &QTestEventLoop::instance(), SLOT(exitLoop()));
    connect(&socket, SIGNAL(encrypted()), &QTestEventLoop::instance(), SLOT(exitLoop()));
    connect(&socket, SIGNAL(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)),
            this, SLOT(proxyAuthenticationRequired(QNetworkProxy,QAuthenticator*)));
    connect(&socket, SIGNAL(errorOccurred(QAbstractSocket::SocketError)), &QTestEventLoop::instance(), SLOT(exitLoop()));

    /* launched openssl s_server -accept 11111 -key /wolf-path/certs/server-key.pem -cert /wolf-path/certs/server-cert.pem */
    socket.connectToHostEncrypted(tst_QSslWolfSSL::EXAMPLE_SERVER, tst_QSslWolfSSL::EXAMPLE_SERVER_PORT);
    QTestEventLoop::instance().enterLoop(10);
    QTestEventLoop::instance().timeout();
    //    QSKIP("Skipping flaky test - See QTBUG-29941");
    QCOMPARE(sslErrorSpy.count(), 1);
    QCOMPARE(errorSpy.count(), 0);
    QCOMPARE(encryptedSpy.count(), 0);
    QVERIFY(!socket.isEncrypted());
    if (ignoreErrorsAfterPause) {
        if (errorsToIgnore.empty())
            socket.ignoreSslErrors();
        else
            socket.ignoreSslErrors(errorsToIgnore);
    }
    socket.resume();
    QTestEventLoop::instance().enterLoop(10);
    QVERIFY(!QTestEventLoop::instance().timeout()); // quit by encrypted() or error() signal
    if (expectSuccess) {
        QCOMPARE(encryptedSpy.count(), 1);
        QVERIFY(socket.isEncrypted());
        QCOMPARE(errorSpy.count(), 0);
        socket.disconnectFromHost();
        QVERIFY(socket.waitForDisconnected(10000));
    } else {
        QCOMPARE(encryptedSpy.count(), 0);
        QVERIFY(!socket.isEncrypted());
        QCOMPARE(errorSpy.count(), 1);
        QCOMPARE(socket.error(), QAbstractSocket::SslHandshakeFailedError);
    }
}

void tst_QSslWolfSSL::ephemeralServerKey_data()
{
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif
    QTest::addColumn<QString>("cipher");
    QTest::addColumn<bool>("emptyKey");
    #if QT_CONFIG(openssl)
    QTest::newRow("ForwardSecrecyCipher") << "ECDHE-RSA-AES256-SHA" << (QSslSocket::sslLibraryVersionNumber() < 0x10002000L);
    #else
    /* wolfSSL doesn't keep this key info */
    QTest::newRow("ForwardSecrecyCipher") << "ECDHE-RSA-AES256-SHA" << true;
    #endif
}

void tst_QSslWolfSSL::ephemeralServerKey()
{
    if (skip_ephemeralServerKey)
        QSKIP("ephemeralServerKey");
        
    if (!QSslSocket::supportsSsl())
        return;

    QFETCH(QString, cipher);
    QFETCH(bool, emptyKey);
    SslServer server;
    server.config.setCiphers(QList<QSslCipher>() << QSslCipher(cipher));
    QVERIFY(server.listen());
    QSslSocketPtr client = newSocket();
    socket = client.data();
    connect(socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
    QSignalSpy spy(client.data(), &QSslSocket::encrypted);

    client->connectToHostEncrypted(QHostAddress(QHostAddress::LocalHost).toString(), server.serverPort());
    spy.wait();

    QCOMPARE(spy.count(), 1);
    QVERIFY(server.config.ephemeralServerKey().isNull());
    QCOMPARE(client->sslConfiguration().ephemeralServerKey().isNull(), emptyKey);
}

void tst_QSslWolfSSL::signatureAlgorithm_data()
{
    if (!QSslSocket::supportsSsl())
        QSKIP("Signature algorithms cannot be tested without SSL support");

    if (QSslSocket::sslLibraryVersionNumber() >= 0x10101000L) {
        // FIXME: investigate if this test makes any sense with TLS 1.3.
        QSKIP("Test is not valid for TLS 1.3/OpenSSL 1.1.1");
    }

    QTest::addColumn<QByteArrayList>("serverSigAlgPairs");
    QTest::addColumn<QSsl::SslProtocol>("serverProtocol");
    QTest::addColumn<QByteArrayList>("clientSigAlgPairs");
    QTest::addColumn<QSsl::SslProtocol>("clientProtocol");
    QTest::addColumn<QAbstractSocket::SocketState>("state");

    const QByteArray dsaSha1("DSA+SHA1");
    const QByteArray ecdsaSha1("ECDSA+SHA1");
    const QByteArray ecdsaSha512("ECDSA+SHA512");
    const QByteArray rsaSha256("RSA+SHA256");
    const QByteArray rsaSha384("RSA+SHA384");
    const QByteArray rsaSha512("RSA+SHA512");

    QTest::newRow("match_TlsV1_2")
        << QByteArrayList({rsaSha256})
        << QSsl::TlsV1_2
        << QByteArrayList({rsaSha256})
        << QSsl::AnyProtocol
        << QAbstractSocket::ConnectedState;
    QTest::newRow("no_hashalg_match_TlsV1_2")
        << QByteArrayList({rsaSha256})
        << QSsl::TlsV1_2
        << QByteArrayList({rsaSha512})
        << QSsl::AnyProtocol
        << QAbstractSocket::UnconnectedState;
    QTest::newRow("no_sigalg_match_TlsV1_2")
        << QByteArrayList({ecdsaSha512})
        << QSsl::TlsV1_2
        << QByteArrayList({rsaSha512})
        << QSsl::AnyProtocol
        << QAbstractSocket::UnconnectedState;
    QTest::newRow("no_cipher_match_AnyProtocol")
        << QByteArrayList({rsaSha512})
        << QSsl::AnyProtocol
        << QByteArrayList({ecdsaSha512})
        << QSsl::AnyProtocol
        << QAbstractSocket::UnconnectedState;
    QTest::newRow("match_multiple-choice")
        << QByteArrayList({dsaSha1, rsaSha256, rsaSha384, rsaSha512})
        << QSsl::AnyProtocol
        << QByteArrayList({ecdsaSha1, rsaSha384, rsaSha512, ecdsaSha512})
        << QSsl::AnyProtocol
        << QAbstractSocket::ConnectedState;
    QTest::newRow("match_client_longer")
        << QByteArrayList({dsaSha1, rsaSha256})
        << QSsl::AnyProtocol
        << QByteArrayList({ecdsaSha1, ecdsaSha512, rsaSha256})
        << QSsl::AnyProtocol
        << QAbstractSocket::ConnectedState;
    QTest::newRow("match_server_longer")
        << QByteArrayList({ecdsaSha1, ecdsaSha512, rsaSha256})
        << QSsl::AnyProtocol
        << QByteArrayList({dsaSha1, rsaSha256})
        << QSsl::AnyProtocol
        << QAbstractSocket::ConnectedState;

    // signature algorithms do not match, but are ignored because the tls version is not v1.2
    QTest::newRow("client_ignore_TlsV1_1")
        << QByteArrayList({rsaSha256})
        << QSsl::TlsV1_1
        << QByteArrayList({rsaSha512})
        << QSsl::AnyProtocol
        << QAbstractSocket::ConnectedState;
    QTest::newRow("server_ignore_TlsV1_1")
        << QByteArrayList({rsaSha256})
        << QSsl::AnyProtocol
        << QByteArrayList({rsaSha512})
        << QSsl::TlsV1_1
        << QAbstractSocket::ConnectedState;
    QTest::newRow("client_ignore_TlsV1_0")
        << QByteArrayList({rsaSha256})
        << QSsl::TlsV1_0
        << QByteArrayList({rsaSha512})
        << QSsl::AnyProtocol
        << QAbstractSocket::ConnectedState;
    QTest::newRow("server_ignore_TlsV1_0")
        << QByteArrayList({rsaSha256})
        << QSsl::AnyProtocol
        << QByteArrayList({rsaSha512})
        << QSsl::TlsV1_0
        << QAbstractSocket::ConnectedState;
}

void tst_QSslWolfSSL::signatureAlgorithm()
{
    if (skip_signatureAlgorithm)
        QSKIP("signatureAlgorithm");
        
    QFETCH(QByteArrayList, serverSigAlgPairs);
    QFETCH(QSsl::SslProtocol, serverProtocol);
    QFETCH(QByteArrayList, clientSigAlgPairs);
    QFETCH(QSsl::SslProtocol, clientProtocol);
    QFETCH(QAbstractSocket::SocketState, state);

    SslServer server;
    server.protocol = serverProtocol;
    server.config.setCiphers({QSslCipher("ECDHE-RSA-AES256-SHA")});
    server.config.setBackendConfigurationOption(QByteArrayLiteral("SignatureAlgorithms"), serverSigAlgPairs.join(':'));
    QVERIFY(server.listen());

    QSslConfiguration clientConfig = QSslConfiguration::defaultConfiguration();
    clientConfig.setProtocol(clientProtocol);
    clientConfig.setBackendConfigurationOption(QByteArrayLiteral("SignatureAlgorithms"), clientSigAlgPairs.join(':'));
    QSslSocket client;
    client.setSslConfiguration(clientConfig);
    socket = &client;

    QEventLoop loop;
    QTimer::singleShot(5000, &loop, &QEventLoop::quit);
    connect(socket, &QAbstractSocket::errorOccurred, &loop, &QEventLoop::quit);
    connect(socket, QOverload<const QList<QSslError> &>::of(&QSslSocket::sslErrors), this, &tst_QSslWolfSSL::ignoreErrorSlot);
    connect(socket, &QSslSocket::encrypted, &loop, &QEventLoop::quit);

    client.connectToHostEncrypted(QHostAddress(QHostAddress::LocalHost).toString(), server.serverPort());
    loop.exec();
    socket = nullptr;
    QCOMPARE(client.state(), state);
}

void tst_QSslWolfSSL::disabledProtocols_data()
{
    QTest::addColumn<QSsl::SslProtocol>("disabledProtocol");
    QTest::newRow("SslV2") << QSsl::SslV2;
    QTest::newRow("SslV3") << QSsl::SslV3;
}

void tst_QSslWolfSSL::disabledProtocols()
{

    if (skip_disabledProtocols)
        QSKIP("disabledProtocols");
    
    QFETCH(const QSsl::SslProtocol, disabledProtocol);
    const int timeoutMS = 500;
    // Test a client socket.
    {
        // 0. connectToHostEncrypted: client-side, non-blocking API, error is discovered
        // early, preventing any real connection from ever starting.
        QSslSocket socket;
        socket.setProtocol(disabledProtocol);
        QCOMPARE(socket.error(), QAbstractSocket::UnknownSocketError);
        socket.connectToHostEncrypted(QStringLiteral("doesnotmatter.org"), 1010);
        QCOMPARE(socket.error(), QAbstractSocket::SslInvalidUserDataError);
        QCOMPARE(socket.state(), QAbstractSocket::UnconnectedState);
    }
    {
        // 1. startClientEncryption: client-side, non blocking API, but wants a socket in
        // the 'connected' state (otherwise just returns false not setting any error code).
        SslServer server;
        QVERIFY(server.listen());

        QSslSocket socket;
        QCOMPARE(socket.error(), QAbstractSocket::UnknownSocketError);

        socket.connectToHost(QHostAddress::LocalHost, server.serverPort());
        QVERIFY(socket.waitForConnected(timeoutMS));

        socket.setProtocol(disabledProtocol);
        socket.startClientEncryption();
        QCOMPARE(socket.error(), QAbstractSocket::SslInvalidUserDataError);
    }
    {
        // 2. waitForEncrypted: client-side, blocking API plus requires from us
        // to call ... connectToHostEncrypted(), which will notice an error and
        // will prevent any connect at all. Nothing to test.
    }

    // Test a server side, relatively simple: server does not connect, it listens/accepts
    // and then calls startServerEncryption() (which must fall).
    {
        SslServer server;
        server.protocol = disabledProtocol;
        QVERIFY(server.listen());

        QTestEventLoop loop;
        connect(&server, &SslServer::socketError, [&loop](QAbstractSocket::SocketError)
                {loop.exitLoop();});

        QTcpSocket client;
        client.connectToHost(QHostAddress::LocalHost, server.serverPort());
        loop.enterLoopMSecs(timeoutMS);
        QVERIFY(!loop.timeout());
        QVERIFY(server.socket);
        QCOMPARE(server.socket->error(), QAbstractSocket::SslInvalidUserDataError);
    }
}

void tst_QSslWolfSSL::oldErrorsOnSocketReuse()
{

    if (skip_oldErrorsOnSocketReuse)
        QSKIP("oldErrorsOnSocketReuse");
        
    SslServer server;
    server.protocol = QSsl::TlsV1_1;
    server.m_certFile = testDataDir + "certs/fluke.cert";
    server.m_keyFile = testDataDir + "certs/fluke.key";
    QVERIFY(server.listen(QHostAddress::SpecialAddress::LocalHost));

    QSslSocket socket;
    socket.setProtocol(QSsl::TlsV1_1);
    QList<QSslError> errorList;
    auto connection = connect(&socket, QOverload<const QList<QSslError> &>::of(&QSslSocket::sslErrors),
        [&socket, &errorList](const QList<QSslError> &errors) {
            errorList += errors;
            socket.ignoreSslErrors(errors);
            socket.resume();
    });

    socket.connectToHostEncrypted(QString::fromLatin1("localhost"), server.serverPort());
    QVERIFY(QTest::qWaitFor([&socket](){ return socket.isEncrypted(); }));
    socket.disconnectFromHost();
    if (socket.state() != QAbstractSocket::UnconnectedState) {
        QVERIFY(QTest::qWaitFor(
            [&socket](){
                return socket.state() == QAbstractSocket::UnconnectedState;
        }));
    }

    auto oldList = errorList;
    errorList.clear();
    server.close();
    server.m_certFile = testDataDir + "certs/bogus-client.crt";
    server.m_keyFile = testDataDir + "certs/bogus-client.key";
    QVERIFY(server.listen(QHostAddress::SpecialAddress::LocalHost));

    socket.connectToHostEncrypted(QString::fromLatin1("localhost"), server.serverPort());
    QVERIFY(QTest::qWaitFor([&socket](){ return socket.isEncrypted(); }));

    for (const auto &error : oldList) {
        QVERIFY2(!errorList.contains(error),
            "The new errors should not contain any of the old ones");
    }
}

void tst_QSslWolfSSL::dhServer()
{
    if (skip_dhServer)
        QSKIP("dhServer");
        
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif
    if (!QSslSocket::supportsSsl())
        QSKIP("No SSL support");

    /*QFETCH_GLOBAL(bool, setProxy);
    if (setProxy)
        return;*/

    SslServer server;
    server.ciphers = {QSslCipher("DHE-RSA-AES256-SHA"), QSslCipher("DHE-DSS-AES256-SHA")};
    QVERIFY(server.listen());

    QEventLoop loop;
    QTimer::singleShot(5000, &loop, SLOT(quit()));

    QSslSocket client;
    socket = &client;
    connect(socket, SIGNAL(errorOccurred(QAbstractSocket::SocketError)), &loop, SLOT(quit()));
    connect(socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
    connect(socket, SIGNAL(encrypted()), &loop, SLOT(quit()));

    client.connectToHostEncrypted(QHostAddress(QHostAddress::LocalHost).toString(), server.serverPort());

    loop.exec();
    QCOMPARE(client.state(), QAbstractSocket::ConnectedState);
}

void tst_QSslWolfSSL::ecdhServer()
{
    if (skip_ecdhServer)
        QSKIP("skip_ecdhServer");
        
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif
    if (!QSslSocket::supportsSsl()) {
        qWarning("SSL not supported, skipping test");
        return;
    }


    SslServer server;
    server.ciphers = {QSslCipher("ECDHE-RSA-AES128-SHA")};
    QVERIFY(server.listen());

    QEventLoop loop;
    QTimer::singleShot(5000, &loop, SLOT(quit()));

    QSslSocket client;
    socket = &client;
    connect(socket, SIGNAL(errorOccurred(QAbstractSocket::SocketError)), &loop, SLOT(quit()));
    connect(socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
    connect(socket, SIGNAL(encrypted()), &loop, SLOT(quit()));

    client.connectToHostEncrypted(QHostAddress(QHostAddress::LocalHost).toString(), server.serverPort());

    loop.exec();
    QCOMPARE(client.state(), QAbstractSocket::ConnectedState);
}


void tst_QSslWolfSSL::verifyClientCertificate_data()
{
    QTest::addColumn<QSslSocket::PeerVerifyMode>("peerVerifyMode");
    QTest::addColumn<QList<QSslCertificate> >("clientCerts");
    QTest::addColumn<QSslKey>("clientKey");
    QTest::addColumn<bool>("works");

    // no certificate
    QList<QSslCertificate> noCerts;
    QSslKey noKey;

    QTest::newRow("NoCert:AutoVerifyPeer") << QSslSocket::AutoVerifyPeer << noCerts << noKey << true;
    QTest::newRow("NoCert:QueryPeer") << QSslSocket::QueryPeer << noCerts << noKey << true;
    QTest::newRow("NoCert:VerifyNone") << QSslSocket::VerifyNone << noCerts << noKey << true;
    QTest::newRow("NoCert:VerifyPeer") << QSslSocket::VerifyPeer << noCerts << noKey << false;

    // self-signed certificate
    QList<QSslCertificate> flukeCerts = QSslCertificate::fromPath(tst_QSslWolfSSL::testDataDir + "certs/fluke.cert");
    QCOMPARE(flukeCerts.size(), 1);

    QFile flukeFile(tst_QSslWolfSSL::testDataDir + "certs/fluke.key");
    QVERIFY(flukeFile.open(QIODevice::ReadOnly));
    QSslKey flukeKey(flukeFile.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    QVERIFY(!flukeKey.isNull());

    QTest::newRow("SelfSignedCert:AutoVerifyPeer") << QSslSocket::AutoVerifyPeer << flukeCerts << flukeKey << true;
    QTest::newRow("SelfSignedCert:QueryPeer") << QSslSocket::QueryPeer << flukeCerts << flukeKey << true;
    QTest::newRow("SelfSignedCert:VerifyNone") << QSslSocket::VerifyNone << flukeCerts << flukeKey << true;
    QTest::newRow("SelfSignedCert:VerifyPeer") << QSslSocket::VerifyPeer << flukeCerts << flukeKey << false;

    // valid certificate, but wrong usage (server certificate)
    QList<QSslCertificate> serverCerts = QSslCertificate::fromPath(tst_QSslWolfSSL::testDataDir + "certs/bogus-server.crt");
    QCOMPARE(serverCerts.size(), 1);

    QFile serverFile(tst_QSslWolfSSL::testDataDir + "certs/bogus-server.key");
    QVERIFY(serverFile.open(QIODevice::ReadOnly));
    QSslKey serverKey(serverFile.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    QVERIFY(!serverKey.isNull());

    QTest::newRow("ValidServerCert:AutoVerifyPeer") << QSslSocket::AutoVerifyPeer << serverCerts << serverKey << true;
    QTest::newRow("ValidServerCert:QueryPeer") << QSslSocket::QueryPeer << serverCerts << serverKey << true;
    QTest::newRow("ValidServerCert:VerifyNone") << QSslSocket::VerifyNone << serverCerts << serverKey << true;
    #if defined(QT_NO_WOLFSSL)
    QTest::newRow("ValidServerCert:VerifyPeer") << QSslSocket::VerifyPeer << serverCerts << serverKey << false;
    #else
    QWARN("wolfSSL does not currently support parsing Netscape Cert Type Extensions.");
    #endif

    // valid certificate, correct usage (client certificate)
    QList<QSslCertificate> validCerts = QSslCertificate::fromPath(testDataDir + "certs/bogus-client.crt");
    QCOMPARE(validCerts.size(), 1);

    QFile validFile(testDataDir + "certs/bogus-client.key");
    QVERIFY(validFile.open(QIODevice::ReadOnly));
    QSslKey validKey(validFile.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
    QVERIFY(!validKey.isNull());

    QTest::newRow("ValidClientCert:AutoVerifyPeer") << QSslSocket::AutoVerifyPeer << validCerts << validKey << true;
    QTest::newRow("ValidClientCert:QueryPeer") << QSslSocket::QueryPeer << validCerts << validKey << true;
    QTest::newRow("ValidClientCert:VerifyNone") << QSslSocket::VerifyNone << validCerts << validKey << true;
    QTest::newRow("ValidClientCert:VerifyPeer") << QSslSocket::VerifyPeer << validCerts << validKey << true;

    // valid certificate, correct usage (client certificate), with chain
    validCerts += QSslCertificate::fromPath(testDataDir + "certs/bogus-ca.crt");
    QCOMPARE(validCerts.size(), 2);

    QTest::newRow("ValidChainedClientCert:AutoVerifyPeer") << QSslSocket::AutoVerifyPeer << validCerts << validKey << true;
    QTest::newRow("ValidChainedClientCert:QueryPeer") << QSslSocket::QueryPeer << validCerts << validKey << true;
    QTest::newRow("ValidChainedClientCert:VerifyNone") << QSslSocket::VerifyNone << validCerts << validKey << true;
    QTest::newRow("ValidChainedClientCert:VerifyPeer") << QSslSocket::VerifyPeer << validCerts << validKey << true;
}

void tst_QSslWolfSSL::verifyClientCertificate()
{
    if (skip_verifyClientCertificate)
        QSKIP("verifyClientCertificate");
        
#if QT_CONFIG(securetransport)
    // We run both client and server on the same machine,
    // this means, client can update keychain with client's certificates,
    // and server later will use the same certificates from the same
    // keychain thus making tests fail (wrong number of certificates,
    // success instead of failure etc.).
    QSKIP("This test can not work with Secure Transport");
#endif // QT_CONFIG(securetransport)
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif
    if (!QSslSocket::supportsSsl()) {
        qWarning("SSL not supported, skipping test");
        return;
    }

    QFETCH(QSslSocket::PeerVerifyMode, peerVerifyMode);
#if QT_CONFIG(schannel)
    if (peerVerifyMode == QSslSocket::QueryPeer || peerVerifyMode == QSslSocket::AutoVerifyPeer)
        QSKIP("Schannel doesn't tackle requesting a certificate and not receiving one.");
#endif

    SslServer server;
    server.addCaCertificates = testDataDir + "certs/bogus-ca.crt";
    server.ignoreSslErrors = false;
    server.peerVerifyMode = peerVerifyMode;
    QVERIFY(server.listen());

    QEventLoop loop;
    QTimer::singleShot(5000, &loop, SLOT(quit()));

    QFETCH(QList<QSslCertificate>, clientCerts);
    QFETCH(QSslKey, clientKey);
    QSslSocket client;
    client.setLocalCertificateChain(clientCerts);
    client.setPrivateKey(clientKey);
    socket = &client;

    connect(socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
    connect(socket, SIGNAL(disconnected()), &loop, SLOT(quit()));
    connect(socket, SIGNAL(encrypted()), &loop, SLOT(quit()));

    
    client.connectToHostEncrypted(QHostAddress(QHostAddress::LocalHost).toString(), server.serverPort());
    
    loop.exec();
    //qDebug() << "server.socket->peerCertificateChain().size()" << server.socket->peerCertificateChain().size();
    
    QFETCH(bool, works);
    QAbstractSocket::SocketState expectedState = (works) ? QAbstractSocket::ConnectedState : QAbstractSocket::UnconnectedState;

    // check server socket
    QVERIFY(server.socket);

    QCOMPARE(server.socket->state(), expectedState);
    QCOMPARE(server.socket->isEncrypted(), works);

    if (peerVerifyMode == QSslSocket::VerifyNone || clientCerts.isEmpty()) {
        QVERIFY(server.socket->peerCertificate().isNull());
        QVERIFY(server.socket->peerCertificateChain().isEmpty());
    } else {
        QCOMPARE(server.socket->peerCertificate(), clientCerts.first());
#if QT_CONFIG(schannel)
        if (clientCerts.count() == 1 && server.socket->peerCertificateChain().count() == 2) {
            QEXPECT_FAIL("",
                         "Schannel includes the entire chain, not just the leaf and intermediates",
                         Continue);
        }
#endif
        /*for (const QSslCertificate &cert : server.socket->peerCertificateChain()){
//          qDebug() << cert.toText();
            qDebug() << cert.issuerDisplayName() << " " << cert.serialNumber();
        }*/
        QCOMPARE(server.socket->peerCertificateChain(), clientCerts);
    }

    // check client socket
    QCOMPARE(client.state(), expectedState);
    QCOMPARE(client.isEncrypted(), works);
}

void tst_QSslWolfSSL::readBufferMaxSize()
{

    
#if QT_CONFIG(securetransport) || QT_CONFIG(schannel)
    if (skip_readBufferMaxSize)
        QSKIP("readBufferMaxSize");
        
    // QTBUG-55170:
    // SecureTransport back-end was ignoring read-buffer
    // size limit, resulting (potentially) in a constantly
    // growing internal buffer.
    // The test's logic is: we set a small read buffer size on a client
    // socket (to some ridiculously small value), server sends us
    // a bunch of bytes , we ignore readReady signal so
    // that socket's internal buffer size stays
    // >= readBufferMaxSize, we wait for a quite long time
    // (which previously would be enough to read completely)
    // and we check socket's bytesAvaiable to be less than sent.
    QFETCH_GLOBAL(bool, setProxy);
    if (setProxy)
        return;

    SslServer server;
    QVERIFY(server.listen());

    QEventLoop loop;

    QSslSocketPtr client(new QSslSocket);
    socket = client.data();
    connect(socket, SIGNAL(errorOccurred(QAbstractSocket::SocketError)), &loop, SLOT(quit()));
    connect(socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
    connect(socket, SIGNAL(encrypted()), &loop, SLOT(quit()));

    client->connectToHostEncrypted(QHostAddress(QHostAddress::LocalHost).toString(),
                                   server.serverPort());

    // Wait for 'encrypted' first:
    QTimer::singleShot(5000, &loop, SLOT(quit()));
    loop.exec();

    QCOMPARE(client->state(), QAbstractSocket::ConnectedState);
    QCOMPARE(client->mode(), QSslSocket::SslClientMode);

    client->setReadBufferSize(10);
    const QByteArray message(int(0xffff), 'a');
    server.socket->write(message);

    QTimer::singleShot(5000, &loop, SLOT(quit()));
    loop.exec();

    int readSoFar = client->bytesAvailable();
    QVERIFY(readSoFar > 0 && readSoFar < message.size());
    // Now, let's check that we still can read the rest of it:
    QCOMPARE(client->readAll().size(), readSoFar);

    client->setReadBufferSize(0);

    QTimer::singleShot(1500, &loop, SLOT(quit()));
    loop.exec();

    QCOMPARE(client->bytesAvailable() + readSoFar, message.size());
#else
    // Not needed, QSslSocket works correctly with other back-ends.
#endif // QT_CONFIG(securetransport) || QT_CONFIG(schannel)
}

void tst_QSslWolfSSL::setEmptyDefaultConfiguration() // this test should be last, as it has some side effects
{
    if (skip_setEmptyDefaultConfiguration)
        QSKIP("setEmptyDefaultConfiguration");
        
    // used to produce a crash in QSslConfigurationPrivate::deepCopyDefaultConfiguration, QTBUG-13265

    if (!QSslSocket::supportsSsl())
        return;

    QSslConfiguration emptyConf;
    QSslConfiguration::setDefaultConfiguration(emptyConf);

    QSslSocketPtr client = newSocket();
    socket = client.data();

    connect(socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));
    socket->connectToHostEncrypted(QtNetworkSettings::httpServerName(), 443);
    //QFETCH_GLOBAL(bool, setProxy);
    socket->waitForEncrypted(4000);
    //    QSKIP("Skipping flaky test - See QTBUG-29941");
}

void tst_QSslWolfSSL::allowedProtocolNegotiation()
{
#ifndef ALPN_SUPPORTED
    QSKIP("ALPN is unsupported, skipping test");
#endif

#if QT_CONFIG(schannel)
    if (QOperatingSystemVersion::current() < QOperatingSystemVersion::Windows8_1)
        QSKIP("ALPN is not supported on this version of Windows using Schannel.");
#endif

    /*QFETCH_GLOBAL(bool, setProxy);
    if (setProxy)
        return;*/

    const QByteArray expectedNegotiated("cool-protocol");
    QList<QByteArray> serverProtos;
    serverProtos << expectedNegotiated << "not-so-cool-protocol";
    QList<QByteArray> clientProtos;
    clientProtos << "uber-cool-protocol" << expectedNegotiated << "not-so-cool-protocol";


    SslServer server;
    server.config.setAllowedNextProtocols(serverProtos);
    QVERIFY(server.listen());

    QSslSocket clientSocket;
    auto configuration = clientSocket.sslConfiguration();
    configuration.setAllowedNextProtocols(clientProtos);
    clientSocket.setSslConfiguration(configuration);

    clientSocket.connectToHostEncrypted("127.0.0.1", server.serverPort());
    clientSocket.ignoreSslErrors();

    QEventLoop loop;
    QTimer::singleShot(5000, &loop, SLOT(quit()));
    connect(&clientSocket, SIGNAL(encrypted()), &loop, SLOT(quit()));
    loop.exec();

    QVERIFY(server.socket->sslConfiguration().nextNegotiatedProtocol() ==
            clientSocket.sslConfiguration().nextNegotiatedProtocol());
    QVERIFY(server.socket->sslConfiguration().nextNegotiatedProtocol() == expectedNegotiated);
}

class PskProvider : public QObject
{
    Q_OBJECT

public:
    bool m_server;
    QByteArray m_identity;
    QByteArray m_psk;

    explicit PskProvider(QObject *parent = 0)
        : QObject(parent), m_server(false)
    {
    }

    void setIdentity(const QByteArray &identity)
    {
        m_identity = identity;
    }

    void setPreSharedKey(const QByteArray &psk)
    {
        m_psk = psk;
    }

public slots:
    void providePsk(QSslPreSharedKeyAuthenticator *authenticator)
    {
        QVERIFY(authenticator);
        QCOMPARE(authenticator->identityHint(), PSK_SERVER_IDENTITY_HINT);
        if (m_server)
            QCOMPARE(authenticator->maximumIdentityLength(), 0);
        else
            QVERIFY(authenticator->maximumIdentityLength() > 0);

        QVERIFY(authenticator->maximumPreSharedKeyLength() > 0);

        if (!m_identity.isEmpty()) {
            authenticator->setIdentity(m_identity);
            QCOMPARE(authenticator->identity(), m_identity);
        }

        if (!m_psk.isEmpty()) {
            authenticator->setPreSharedKey(m_psk);
            QCOMPARE(authenticator->preSharedKey(), m_psk);
        }
    }
};

class PskServer : public QTcpServer
{
    Q_OBJECT
public:
    PskServer()
        : socket(0),
          config(QSslConfiguration::defaultConfiguration()),
          ignoreSslErrors(true),
          peerVerifyMode(QSslSocket::AutoVerifyPeer),
          protocol(QSsl::TlsV1_0),
          m_pskProvider()
    {
        m_pskProvider.m_server = true;
    }
    QSslSocket *socket;
    QSslConfiguration config;
    bool ignoreSslErrors;
    QSslSocket::PeerVerifyMode peerVerifyMode;
    QSsl::SslProtocol protocol;
    QList<QSslCipher> ciphers;
    PskProvider m_pskProvider;

protected:
    void incomingConnection(qintptr socketDescriptor)
    {
        socket = new QSslSocket(this);
        socket->setSslConfiguration(config);
        socket->setPeerVerifyMode(peerVerifyMode);
        socket->setProtocol(protocol);
        if (ignoreSslErrors)
            connect(socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(ignoreErrorSlot()));

        if (!ciphers.isEmpty()) {
            auto sslConfig = socket->sslConfiguration();
            sslConfig.setCiphers(ciphers);
            socket->setSslConfiguration(sslConfig);
        }

        QVERIFY(socket->setSocketDescriptor(socketDescriptor, QAbstractSocket::ConnectedState));
        QVERIFY(!socket->peerAddress().isNull());
        QVERIFY(socket->peerPort() != 0);
        QVERIFY(!socket->localAddress().isNull());
        QVERIFY(socket->localPort() != 0);

        connect(socket, &QSslSocket::preSharedKeyAuthenticationRequired, &m_pskProvider, &PskProvider::providePsk);

        socket->startServerEncryption();
    }

protected slots:
    void ignoreErrorSlot()
    {
        socket->ignoreSslErrors();
    }
};

void tst_QSslWolfSSL::pskServer()
{
#ifdef Q_OS_WINRT
    QSKIP("Server-side encryption is not implemented on WinRT.");
#endif
#if QT_CONFIG(schannel)
    QSKIP("Schannel does not have PSK support implemented.");
#endif
    /*QFETCH_GLOBAL(bool, setProxy);
    if (!QSslSocket::supportsSsl() || setProxy)
        return;*/

    QSslSocket socket;
    this->socket = &socket;

    QSignalSpy connectedSpy(&socket, SIGNAL(connected()));
    QVERIFY(connectedSpy.isValid());

    QSignalSpy disconnectedSpy(&socket, SIGNAL(disconnected()));
    QVERIFY(disconnectedSpy.isValid());

    QSignalSpy connectionEncryptedSpy(&socket, SIGNAL(encrypted()));
    QVERIFY(connectionEncryptedSpy.isValid());

    QSignalSpy pskAuthenticationRequiredSpy(&socket, SIGNAL(preSharedKeyAuthenticationRequired(QSslPreSharedKeyAuthenticator*)));
    QVERIFY(pskAuthenticationRequiredSpy.isValid());

    connect(&socket, SIGNAL(connected()), this, SLOT(exitLoop()));
    connect(&socket, SIGNAL(disconnected()), this, SLOT(exitLoop()));
    connect(&socket, SIGNAL(modeChanged(QSslSocket::SslMode)), this, SLOT(exitLoop()));
    connect(&socket, SIGNAL(encrypted()), this, SLOT(exitLoop()));
    connect(&socket, SIGNAL(sslErrors(QList<QSslError>)), this, SLOT(exitLoop()));
    connect(&socket, SIGNAL(errorOccurred(QAbstractSocket::SocketError)), this, SLOT(exitLoop()));
    connect(&socket, SIGNAL(peerVerifyError(QSslError)), this, SLOT(exitLoop()));
    connect(&socket, SIGNAL(stateChanged(QAbstractSocket::SocketState)), this, SLOT(exitLoop()));

    // force a PSK cipher w/o auth
    auto sslConfig = socket.sslConfiguration();
    sslConfig.setCiphers({QSslCipher(PSK_CIPHER_WITHOUT_AUTH)});
    socket.setSslConfiguration(sslConfig);

    PskProvider provider;
    provider.setIdentity(PSK_CLIENT_IDENTITY);
    provider.setPreSharedKey(PSK_CLIENT_PRESHAREDKEY);
    connect(&socket, SIGNAL(preSharedKeyAuthenticationRequired(QSslPreSharedKeyAuthenticator*)), &provider, SLOT(providePsk(QSslPreSharedKeyAuthenticator*)));
    socket.setPeerVerifyMode(QSslSocket::VerifyNone);
    socket.setProtocol(QSsl::TlsV1_0);
    
    PskServer server;
    server.m_pskProvider.setIdentity(provider.m_identity);
    server.m_pskProvider.setPreSharedKey(provider.m_psk);
    server.config.setPreSharedKeyIdentityHint(PSK_SERVER_IDENTITY_HINT);
    QVERIFY(server.listen());

    // Start connecting
    socket.connectToHost(QHostAddress(QHostAddress::LocalHost).toString(), server.serverPort());
    enterLoop(5);

    // Entered connected state
    QCOMPARE(socket.state(), QAbstractSocket::ConnectedState);
    QCOMPARE(socket.mode(), QSslSocket::UnencryptedMode);
    QVERIFY(!socket.isEncrypted());
    QCOMPARE(connectedSpy.count(), 1);
    QCOMPARE(disconnectedSpy.count(), 0);

    // Enter encrypted mode
    socket.startClientEncryption();
    QCOMPARE(socket.mode(), QSslSocket::SslClientMode);
    QVERIFY(!socket.isEncrypted());
    QCOMPARE(connectionEncryptedSpy.count(), 0);

    // Start handshake.
    enterLoop(10);

    // We must get the PSK signal in all cases
    QCOMPARE(pskAuthenticationRequiredSpy.count(), 1);

    QCOMPARE(connectionEncryptedSpy.count(), 1);
    QVERIFY(socket.isEncrypted());
    QCOMPARE(socket.state(), QAbstractSocket::ConnectedState);

    // check writing
    socket.write("Hello from Qt TLS/PSK!");
    QVERIFY(socket.waitForBytesWritten());

    // disconnect
    socket.disconnectFromHost();
    enterLoop(10);

    QCOMPARE(socket.state(), QAbstractSocket::UnconnectedState);
    QCOMPARE(disconnectedSpy.count(), 1);
}

#endif // QT_NO_SSL

QTEST_MAIN(tst_QSslWolfSSL)
#include "tst_wolfssl.moc"
