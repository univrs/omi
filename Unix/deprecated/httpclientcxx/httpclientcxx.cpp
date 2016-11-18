/*
**==============================================================================
**
** Copyright (c) Microsoft Corporation. All rights reserved. See file LICENSE
** for license information.
**
**==============================================================================
*/

#include <iostream>
#include <memory>
#include <semaphore.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "httpclientcxx.h"
#include <common.h>
#include <pal/atomic.h>
#include <pal/sleep.h>
#include <http/httpclient.h>
#include <pal/thread.h>

#define ENABLE_TRACING 1
#define TRACING_LEVEL 5
#include <deprecated/logging/logging.h>

static sem_t            s_connectionSemaphore;
static bool             s_connectionSemaphoreInitialized = false;
static pthread_mutex_t  s_connectionSemaphoreLock;
static sem_t            s_sendSemaphore;
static pthread_mutex_t  s_sendLock;
static bool             s_notifySet = false;

using namespace std;

// callback for thread (run function)
BEGIN_EXTERNC

static MI_Uint32 MI_CALL _proc(void*);

// callback for user's functions executed in background thread
static void threadDelegation(void* self, Message* message);

// HTTP callbacks
static void httpClientCallbackOnStatus(
    ::HttpClient* http,
    void* callbackData,
    MI_Result result);

static MI_Boolean httpClientCallbackOnResponse(
    ::HttpClient* http,
    void* callbackData,
    const HttpClientResponseHeader* headers,
    MI_Sint64 contentSize,
    MI_Boolean lastChunk,
    Page** data);

END_EXTERNC

/*
 Convert a 4-bit binary value to its hexadecimal character representation, using uppercase
 A - F and leading zero, as needed, as per RFC 3986.

 @param[in]     n - the number to be converted

 @returns       the hexadecimal representation of n
*/
static unsigned int ToHexit(
    unsigned int n)
{
    if (n <= 9)
    {
        return n + '0';
    }
    if (n <= 15)
    {
        return n + 'A' - 10;
    }
    return '?';
}

/*
 Replace a hostname or URI string encoded using the UTF-8 character set with
 another string that specifies the same hostname or URI encoded using the
 escapes specified in RFC 3986.  For a URI, as specified in the RFC, escaping
 stops at the first '?' character after the last slash.

 The scheme, for example, "http:", and host name are not normalized to lower case
 as specified in RFC 3986; neither are path segments mormalized.

 This function does not check for correctly-formatted UTF-8 multibyte characters,
 it simply encodes the characters in the input string character-by-character.

 @param[in]     UriString - the unescaped URI string

 @returns       the escaped URI string
*/
static std::string EscapeUriString(const char* UriString, bool UriSyntax)
{
    std::string EscapedUriString;

    EscapedUriString.reserve(strlen(UriString) * 3);    // reserve space so the "+=" operator is more efficient
    for (const char* Uri = UriString; *Uri != '\0'; Uri++)
    {
        unsigned char c = (unsigned char)*Uri;
        if ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            strchr("-._~/,!'$&%:;*\\", (int)c) != NULL)
        {
            // an unreserved character or delimiter
            EscapedUriString += (char)c;
        }
        else if (c == '?')
        {
            // a '?': if a URI, check for '?' before or after the final '/'
            EscapedUriString += '?';
            if (UriSyntax && strchr(Uri, '/') == NULL)
            {
                // if a URI and there is no '/' after this, this finishes translation
                if (*(Uri + 1) != '\0')
                {
                    EscapedUriString += std::string(Uri + 1);
                }
                break;
            }
        }
        else
        {
            // a character that must be escaped
            EscapedUriString += '%';
            EscapedUriString += ToHexit((unsigned int)c >> 4);
            EscapedUriString += ToHexit((unsigned int)c & 0x0000000F);
        }
    }
    return EscapedUriString;
}

HTTPCLIENT_BEGIN

/* helper structure used to post messages from calling thread
    to background processing thread
*/
class NotifyItem
{
public:
    // data generic for all calls
    enum Type
    {
        CONNECT, START_REQUEST, DELETE_HTTP, SET_TIMEOUT
    } _type;
    class HttpClientRep* _rep;
    Message* _msg;

    // Connect-specific
    std::string _host;
    unsigned short _port;
    bool _secure;
    std::string _trustedCertsDir;
    std::string _certFile;
    std::string _privateKeyFile;
    sem_t      *_connectionSemaphore;
    bool       *_connectWorked;
    bool       *_connectComplete;

    // start-request- specific
    std::string _verb;
    std::string _uri;
    std::map< std::string, std::string > _extraHeaders;
    std::vector< unsigned char > _data;

    // timeout-specific
    MI_Uint64 _timeout;

    // connect request
    NotifyItem(
        class HttpClientRep* rep,
        const char* host,
        unsigned short port,
        bool secure,
        const char* trustedCertsDir,
        const char* certFile,
        const char* privateKeyFile,
        sem_t     * connectionSemaphore,
        bool      * connectWorked,
        bool      * connectComplete) :
        _type(CONNECT),
        _rep(rep),
        _host(host),
        _port(port),
        _secure(secure),
        _trustedCertsDir(trustedCertsDir == NULL ? "" : trustedCertsDir),
        _certFile(certFile == NULL ? "" : certFile),
        _privateKeyFile(privateKeyFile == NULL ? "" : privateKeyFile),
        _connectionSemaphore(connectionSemaphore),
        _connectWorked(connectWorked),
        _connectComplete(connectComplete)
    {
        _InitMsg();
    }

    // start-request
    NotifyItem(
        class HttpClientRep* rep,
        const char* verb,
        const char* uri,
        const std::map< std::string, std::string >& extraHeaders,
        const std::vector< unsigned char >& data):
        _type(START_REQUEST),
        _rep(rep),
        _port(0),
       _secure(false),
        _verb(verb),
        _uri(uri),
        _extraHeaders(extraHeaders),
        _data(data)
    {
        _InitMsg();
    }

    // delete-http item
    NotifyItem(
        class HttpClientRep* rep):
        _type(DELETE_HTTP),
        _rep(rep),
        _port(0),
       _secure(false)
    {
        _InitMsg();
    }

    // set Timeout item
    NotifyItem(
        class HttpClientRep* rep,
        MI_Uint64 timeout):
        _type(SET_TIMEOUT),
        _rep(rep),
        _port(0),
       _secure(false),
       _timeout(timeout)
    {
        _InitMsg();
    }

    ~NotifyItem()
    {
        Message_Release(_msg);
    }

private:
    NotifyItem(const NotifyItem&);
    void operator=(const NotifyItem&);

    void _InitMsg()
    {
        _msg =  __Message_New(NoOpReqTag, sizeof (NoOpReq), 0, 0, CALLSITE);
        _msg->argPtr = PtrToUint64(this);
        *((void**)&_msg->clientId) = this;
        fprintf(stderr, "NotifyItem::InitMsg - argument is this: %p --> 0x%lX\n", this, (unsigned long)_msg->argPtr);
    }
};

/* Helper class - background thread operations */
class IOThread
{
public:
    IOThread();
    ~IOThread();

    bool Start();

    /* delegate work to background thread */
    bool PostItem(NotifyItem* item);

//private:
    // not supported
    IOThread(const IOThread&);
    void operator = (const IOThread&);

    // impl

    // mirror functions for public API.
    // note: these functions are always called from the context of the background thread

    void ConnectTh(NotifyItem* item);
    void StartRequestTh(NotifyItem* item);
    void DeleteHttpTh(NotifyItem* item);
    void SetTimeoutTh(NotifyItem* item);

    // data
    Thread*     _th;
    Selector    _selector;
};

/* thread handle - used to store ref-counted pointer to IOThread */
class IOThreadHandle
{
    struct Item {
        ptrdiff_t   ref;
        IOThread    t;

        Item() :ref(0){}
    };

    Item* _p;

    void _AddRef()
    {
        if (_p != NULL)
            Atomic_Inc(&_p->ref);
    }

    void _Release()
    {
        if (_p != NULL && Atomic_Dec(&_p->ref) == 0)
        {
            delete _p;
        }
    }
public:

    // full set of ctors/dtors/assign operators
    ~IOThreadHandle() {_Release();}
    IOThreadHandle() : _p(0) {}
    IOThreadHandle(const IOThreadHandle& x) : _p(x._p) {_AddRef();}
    IOThreadHandle& operator =(const IOThreadHandle& x)
    {
        if (_p != x._p)
        {
            _Release();
            _p = x._p;
            _AddRef();
        }
        return *this;
    }

    // accessor
    IOThread* operator ->()
    {
        return &_p->t;
    }

    // allocator
    void Alloc()
    {
        _Release();
        _p = new Item;
        _AddRef();
    }
};

// forward declaration
static IOThreadHandle _GetThreadObj();

// impl class
class HttpClientRep
{
public:
    HttpClientRep(HttpClientCallback* callback) :
      _callback(callback),
      _timeoutMS(1000),
      _httpClient(NULL),
      _notify(false),
      _destroyed(false),
      _lastStatus(httpclient::OKAY)
    {
        _th = _GetThreadObj();
    }

    ~HttpClientRep()
    {
        if (_httpClient)
            HttpClient_Delete(_httpClient);
    }

    // data
    HttpClientCallback* _callback;
    IOThreadHandle      _th;
    int _timeoutMS;
    ::HttpClient* _httpClient;
    bool    _notify;
    bool    _destroyed;
    httpclient::Result _lastStatus;
};

/* ****************************************************** */

IOThread::IOThread()
{
    _th = new Thread;
}

IOThread::~IOThread()
{
    // notify about stopping!
    Selector_StopRunning(&_selector);

    Thread_Destroy(_th);
    delete _th;

    // clean up
    Selector_RemoveAllHandlers(&_selector);
    Selector_Destroy(&_selector);
}

bool IOThread::Start()
{
    fprintf(stderr, "IOThread::Start - Begin. Initializing selector\n");
    if (MI_RESULT_OK != Selector_Init(&_selector))
        return false;

    Selector_SetAllowEmptyFlag(&_selector, MI_TRUE);

    fprintf(stderr, "IOThread::Start - Creating Thread\n");
    if (Thread_CreateJoinable(_th, _proc, NULL, this) != MI_RESULT_OK)
    {
        fprintf(stderr, "IOThread::Start - Creation of thread failed\n");
        return false;
    }

    fprintf(stderr, "IOThread::Start - OK exit\n");
    return true;
}

bool IOThread::PostItem(NotifyItem* item)
{
#ifdef ENABLE_TRACING
    fprintf(stderr, "IoThread::PostItem - Posting item: %d (%s)\n", item->_type, notifyitemtypestr(item->_type));
    if (item->_type == NotifyItem::CONNECT)
    {
        fprintf(stderr, "PostItem - CONNECT. host: %s, port %d\n", item->_host.c_str(), item->_port);
    }
    if (item->_type == NotifyItem::START_REQUEST)
    {
        fprintf(stderr, "PostItem - START_REQUEST. verb: %s, URI: %s\n", item->_verb.c_str(), item->_uri.c_str());
    }
    if (item->_type == NotifyItem::SET_TIMEOUT)
    {
        fprintf(stderr, "PostItem - SET_TIMEOUT. timeout: %lu us\n", (unsigned long)item->_timeout);
    }
    if (item->_type == NotifyItem::DELETE_HTTP)
    {
        fprintf(stderr, "PostItem - DELETE_HTTP\n");
    }
#endif

    MI_Result res = Selector_CallInIOThread(&_selector, threadDelegation, this, item->_msg);

    return res == MI_RESULT_OK;
}

void IOThread::ConnectTh(NotifyItem* item)
{
    MI_Result res = HttpClient_New_Connector(
        &item->_rep->_httpClient,
        &_selector,
        item->_host.c_str(),
        item->_port,
        item->_secure,
        httpClientCallbackOnStatus,
        httpClientCallbackOnResponse,
        item->_rep,
        item->_trustedCertsDir.c_str(),
        item->_certFile.c_str(),
        item->_privateKeyFile.c_str());

    if (res != MI_RESULT_OK)
    {
        *item->_connectWorked = false;
        fprintf(stderr, "IOThread::ConnectTh - HTTP client connect failed with result: %d (%s)\n", (int)res, mistrerror(res));
        item->_rep->_callback->OnStatus(httpclient::FAILED);
        item->_rep->_notify = true;
    }
    else
    {
        // item->_rep->_callback->OnStatus(httpclient::OKAY);
        fprintf(stderr, "IOThread::ConnectTh - HTTP client connect succeeded\n");
        *item->_connectWorked = true;
    }

    *item->_connectComplete = true;
    HttpClient_SetTimeout(item->_rep->_httpClient, (MI_Uint64)item->_rep->_timeoutMS * 1000);
    sem_post(&s_connectionSemaphore);
    fprintf(stderr, "IOThread::ConnectTh - HttpClient_New_Connector returned result: %d (%s), timeout: %d ms\n", (int)res, mistrerror(res), item->_rep->_timeoutMS);
    *item->_connectComplete = true;
}

void IOThread::StartRequestTh(NotifyItem* item)
{
    Page* c_data = NULL;
    const char* c_verb = item->_verb.c_str();
    HttpClientRequestHeaders c_headers;
    std::vector< std::string > headers_strings;
    std::vector< const char* > headers_pointers;

    memset(&c_headers, 0, sizeof(c_headers));

    if (!item->_data.empty() > 0)
    {
        c_data = (Page*)PAL_Malloc(item->_data.size() + sizeof (Page));
        /* clear header */
        memset(c_data, 0, sizeof(Page));

        c_data->u.s.size = (unsigned int)item->_data.size();

        memcpy(c_data+1, &item->_data[0], item->_data.size());
    }

    if (!item->_extraHeaders.empty())
    {
        // create array of strings
        for (std::map< std::string, std::string >::const_iterator it = item->_extraHeaders.begin(); it != item->_extraHeaders.end(); it++)
        {
            std::string s = it->first;
            s += ": ";
            s += it->second;
            headers_strings.push_back(s);
        }

        // create array of pointers
        for (size_t i = 0; i < headers_strings.size(); i++)
        {
            headers_pointers.push_back(headers_strings[i].c_str());
        }

        // initialize c-struct:
        c_headers.size = headers_pointers.size();
        c_headers.data = &headers_pointers[0];
    }

    headers_pointers.push_back("Authorization: None");
    c_headers.size = headers_pointers.size();
    c_headers.data = &headers_pointers[0];

    MI_Result res = HttpClient_StartRequest(
        item->_rep->_httpClient,
        c_verb,
        item->_uri.c_str(),
        (c_headers.size != 0) ? &c_headers : NULL,
        &c_data);

    if (c_data != NULL)
    {
        PAL_Free(c_data);
        c_data = NULL;
    }

    if (res != MI_RESULT_OK)
    {
        fprintf(stderr, "IOThread::_StartRequestTh - HTTP client request failed with error: %d (%s)\n", (int)res, mistrerror(res));
        item->_rep->_callback->OnStatus(res == MI_RESULT_TIME_OUT ? httpclient::TIMEOUT : httpclient::FAILED);
    }
    else
    {
        fprintf(stderr, "IOThread::_StartRequestTh - HTTP client request succeeded\n");
        item->_rep->_callback->OnStatus(httpclient::OKAY);
    }
}

void IOThread::DeleteHttpTh(NotifyItem* item)
{
    fprintf(stderr, "_DeleteHttpTh - Deleting HTTP thread\n");

    // Clean up here as the first thread is not waiting for any signal for this to be completed.
    HttpClient_Delete(item->_rep->_httpClient);
    item->_rep->_httpClient = NULL;
    item->_rep->_destroyed = true;

    fprintf(stderr, "_DeleteHttpTh - Done\n");
}

void IOThread::SetTimeoutTh(NotifyItem* item)
{
    fprintf(stderr, "IOThread::SetTimeoutTh - Item: %p, rep: %p, timeout: %lu us\n", item, item->_rep, (unsigned long)item->_rep->_timeoutMS * 1000);
    HttpClient_SetTimeout(item->_rep->_httpClient, (MI_Uint64)item->_rep->_timeoutMS * 1000);
}

static IOThreadHandle _GetThreadObj()
{
    static IOThreadHandle s_obj;
    static int s_init = 0;
    static pthread_mutex_t s_mutex = PTHREAD_MUTEX_INITIALIZER;

    /* check if we may need to init */
    if (!s_init)
    {
        pthread_mutex_lock(&s_mutex);

        /* check if we really need to init or get here by race-condition */
        if (!s_init)
        {
            s_obj.Alloc();
            s_obj->Start();
            s_init = 1;
        }

        pthread_mutex_unlock(&s_mutex);

    }

    return s_obj;
}

/* ******************************************** */

HttpClient::~HttpClient()
{
    fprintf(stderr, "HttpClient::~HttpClient - Begin\n");

    pthread_mutex_lock(&m_httpClientLock);

    NotifyItem* item = new NotifyItem(_rep);
    fprintf(stderr, "~HttpClient NotifyItem\n");

    if (_rep != NULL)
    {
        if (_rep->_th->PostItem(item))
        {
            /* wait for thread to complete operation */
            while (!_rep->_destroyed)
                usleep(50);
        }
        delete _rep;
    }
    pthread_mutex_unlock(&m_httpClientLock);
    fprintf(stderr, "HttpClient::~HttpClient finished\n");
}

HttpClient::HttpClient(
    HttpClientCallback* callback)
{
    pthread_mutex_init(&m_httpClientLock, NULL);
    pthread_mutex_lock(&m_httpClientLock);

    _rep = new HttpClientRep(callback);
    pthread_mutex_unlock(&m_httpClientLock);
    fprintf(stderr, "HttpClient::HttpClient finished\n");
}

Result HttpClient::Connect(
    const char* host,
    unsigned short port,
    bool secure,
    const char* trustedCertsDir,
    const char* certFile,
    const char* privateKeyFile)
{
    if (!s_connectionSemaphoreInitialized)
    {
        s_connectionSemaphoreInitialized = true;
        sem_init(&s_connectionSemaphore, 0, 0);
        sem_init(&s_sendSemaphore, 0, 0);
        pthread_mutex_init(&s_connectionSemaphoreLock, NULL);
        pthread_mutex_init(&s_sendLock, NULL);
    }

    pthread_mutex_lock(&s_connectionSemaphoreLock);

    bool connectWorked = false;
    bool connectComplete = false;

    fprintf(stderr, "HttpClient::Connect - host: %s, port: %u\n", host, (unsigned int)port);
    if (secure)
    {
        fprintf(stderr, "HttpClient::Connect - trustedCertsDir: %s, certFile: %s, privateKeyFile: %s\n", trustedCertsDir, certFile, privateKeyFile);
    }

    std::string EncodedHost(EscapeUriString(host, false));

    fprintf(stderr, "HttpClient::Connect - Beginning connection\n");

    NotifyItem* item = new NotifyItem(_rep,
                                      EncodedHost.empty() ? "" : EncodedHost.c_str(),
                                      port,
                                      secure,
                                      trustedCertsDir,
                                      certFile,
                                      privateKeyFile,
                                      &s_connectionSemaphore,
                                      &connectWorked,
                                      &connectComplete);

    fprintf(stderr, "Connect NotifyItem\n");

    if (!_rep->_th->PostItem(item))
    {
        delete item;
        fprintf(stderr, "HttpClient::Connect - PostItem failed\n");
        return httpclient::FAILED;
    }

#if defined(__hpux) || defined(macos) || defined(__SunOS_5_9)   // these OSs don't have sem_timedwait
    // Yeah, sure, this is async.  You betcha.  That's why we're going to wait
    // here until the connect is complete.
    fprintf(stderr, "HttpClient::Connect - Beginning wait for connection complete semaphore\n");
    while (!connectComplete)
    {
        fprintf(stderr, "HttpClient::Connect - Waiting for connection complete semaphore\n");
        sem_wait(&s_connectionSemaphore);
        fprintf(stderr, "HttpClient::Connect - Connection complete semaphore received.  connectComplete was %s\n", connectComplete ? "True" : "False");
    }
#else
    // Wait 30 seconds until the connect is complete or there was an error.
    struct timespec timeout_time;
    time_t current_time = time(NULL);

    fprintf(stderr, "HttpClient::Connect - Waiting for connection complete semaphore\n");
    timeout_time.tv_sec = current_time + 31;   // 30 - 31 seconds, since we don't compute tv_nsec.
    timeout_time.tv_nsec = 0;
    if (sem_timedwait(&s_connectionSemaphore, &timeout_time) < 0)
    {                                   // in most cases, errno here will be ETIMEDOUT
        fprintf(stderr, "HttpClient::Connect - Connect process error: %d (%s)\n", errno, strerror(errno));
    }
#endif
    fprintf(stderr, "HttpClient::Connect - Connection request done. connectComplete was %d, connectWorked was: %d\n", connectComplete, connectComplete);
    // sem_destroy(&connectionSemaphore);

    pthread_mutex_unlock(&s_connectionSemaphoreLock);
    if (!connectWorked)
    {
        // failure
       fprintf(stderr, "HttpClient::Connect - connection failed\n");
        return httpclient::FAILED;
    }

    fprintf(stderr, "HttpClient::Connect - OK\n");
    return httpclient::OKAY;
}

Result HttpClient::StartRequest(
    const char* verb,
    const char* uri,
    const std::map< std::string, std::string >& extraHeaders,
    const std::vector< unsigned char >& data,
    bool blockUntilCompleted)
{
    pthread_mutex_lock(&s_sendLock);

    std::string EncodedUri(EscapeUriString(uri, true));

    fprintf(stderr, "HttpClient::StartRequest - verb: %s, URI: %s\n", verb, uri);
    NotifyItem* item = new NotifyItem(_rep, verb, EncodedUri.empty() ? "" : EncodedUri.c_str(), extraHeaders, data);

    fprintf(stderr, "StartRequest NotifyItem\n");
    _rep->_notify = false;
    s_notifySet = false;

    if (!_rep->_th->PostItem(item))
    {
        fprintf(stderr, "HttpClient::StartRequest - PostItem failed\n");
        pthread_mutex_unlock(&s_sendLock);
        delete item;
        return httpclient::FAILED;
    }

    /* wait for thread to complete operation */
    if (blockUntilCompleted)
    {
        httpclient::Result res;

#if defined(__hpux) || defined(macos) || defined(__SunOS_5_9)   // these OSs don't have sem_timedwait
        // Yeah, sure, this is async.  You betcha.  That's why we're going to wait
        // here until the send is complete.
        while (!s_notifySet)
        {
            sem_wait(&s_sendSemaphore);
        }
#else
        // Wait 30 seconds until the send is complete or there was an error
        struct timespec timeout_time;
        time_t current_time = time(NULL);
        int r;

        fprintf(stderr, "HttpClient::StartRequest - Waiting for send semaphore\n");
        timeout_time.tv_sec = current_time + 31;   // 30 - 31 seconds, since we don't compute tv_nsec.
        timeout_time.tv_nsec = 0;
        if ((r = sem_timedwait(&s_sendSemaphore, &timeout_time)) < 0)
        {                               // in most cases, errno here will be ETIMEDOUT
            fprintf(stderr, "HttpClient::StartRequest - status: %d, errno: %d (%s)\n", r, errno, strerror(errno));
        }
        else
        {
            fprintf(stderr, "HttpClient::StartRequest - sem_timedwait returned status: %d\n", r);
        }
#endif

        if (!_rep->_notify)
        {
            fprintf(stderr, "HttpClient::StartRequest - Timed out. rep: %p\n", _rep);
            res = httpclient::TIMEOUT;
        }
        else
            res = _rep->_lastStatus;

        _rep->_notify = false;
        pthread_mutex_unlock(&s_sendLock);
        return res;
    }

    pthread_mutex_unlock(&s_sendLock);
    return httpclient::OKAY;
}

void HttpClient::SetOperationTimeout(
    int timeoutMS)
{
    _rep->_timeoutMS = timeoutMS;

    NotifyItem* item = new NotifyItem(_rep, timeoutMS * 1000);

    fprintf(stderr, "SetOperationTimeout NotifyItem\n");

    if (!_rep->_th->PostItem(item))
    {
        fprintf(stderr, "HttpClient::SetOperationTimeout - PostItem failed\n");
        delete item;
    }
}

HTTPCLIENT_END

static MI_Uint32 _proc(
    void* self)
{
    httpclient::IOThread* pThis = (httpclient::IOThread*)self;
    // keep runnning until terminated
    fprintf(stderr, "_proc - Begin. Running selector thread\n");
    Selector_Run(&pThis->_selector, TIME_NEVER, MI_FALSE);

    fprintf(stderr, "_proc - OK exit\n");
    return 0;
}

static void threadDelegation(
    void* self,
    Message* message)
{
    httpclient::IOThread* pThis = (httpclient::IOThread*)self;
    httpclient::NotifyItem* item = (httpclient::NotifyItem*)Uint64ToPtr(message->argPtr);
    fprintf(stderr, "threadDelegation - item: %p, Argument: %lX\n", item, (unsigned long)item->_msg->argPtr);

    if (item != NULL)
    {
        switch (item->_type)
        {
        case httpclient::NotifyItem::CONNECT:
            pThis->ConnectTh(item);
            break;

        case httpclient::NotifyItem::START_REQUEST:
            pThis->StartRequestTh(item);
            break;

        case httpclient::NotifyItem::DELETE_HTTP:
            pThis->DeleteHttpTh(item);
//            delete item->_rep;
            break;

        case httpclient::NotifyItem::SET_TIMEOUT:
            pThis->SetTimeoutTh(item);
            break;

        default:
            assert(!"unexpected item type");
            break;
        }

        delete item;
    }
}

static void httpClientCallbackOnStatus(
    ::HttpClient* http,
    void* callbackData,
    MI_Result result)
{
    httpclient::HttpClientRep* rep = (httpclient::HttpClientRep*)callbackData;
    httpclient::Result user_res = httpclient::FAILED;

    fprintf(stderr, "httpClientCallbackOnStatus - Begin. MI result: %d (%s)\n", (int)result, mistrerror(result));
    if (result == MI_RESULT_OK)
        user_res = httpclient::OKAY;
    else if (result == MI_RESULT_TIME_OUT)
        user_res = httpclient::TIMEOUT;
    else if (result == MI_RESULT_NOT_FOUND)
        user_res = httpclient::NOTFOUND;
    else if (result == MI_RESULT_FAILED)
        user_res = httpclient::TIMEOUT;

    if (rep != NULL && rep->_callback != NULL)
    {
        fprintf(stderr, "httpClientCallbackOnStatus - Calling caller's callback. HTTP client status: %d (%s)\n", user_res, clientstatusstr(user_res));
        rep->_callback->OnStatus(user_res);
    }

    rep->_lastStatus = user_res;
    fprintf(stderr, "httpClientCallbackOnstatus - Notify was set. rep: %p\n", rep);
    s_notifySet = true;
    rep->_notify = true;
    sem_post(&s_sendSemaphore);
}

static MI_Boolean httpClientCallbackOnResponse(
    ::HttpClient* http,
    void* callbackData,
    const HttpClientResponseHeader* headers,
    MI_Sint64 contentSize,
    MI_Boolean lastChunk,
    Page** data)
{
    httpclient::HttpClientRep* rep = (httpclient::HttpClientRep*)callbackData;

    fprintf(stderr, "httpClientCallbackOnResponse - content size (-1 means use chunk size): %ld, lastChunk: %d\n", (long)contentSize, (int)lastChunk);

    if (headers != NULL)
    {
        std::map< std::string, std::string > user_headers;

        for (MI_Uint32 i = 0; i < headers->sizeHeaders; i++)
        {
            fprintf(stderr, "httpClientCallbackOnResponse - H: %s --> %s\n", headers->headers[i].name, headers->headers[i].value);
            user_headers[headers->headers[i].name] = headers->headers[i].value;
        }

        if (headers->httpError < 100 || headers->httpError > 999)
        {
            fprintf(stderr, "httpClientCallbackOnResponse - HTTP status < 100 or > 999 in callback: %d\n", headers->httpError);
        }
        fprintf(stderr, "httpClientCallbackOnResponse - Returning %ld bytes data. HTTP status: %d\n", (long)contentSize, headers->httpError);
        if (!rep->_callback->OnResponseHeader(headers->httpError, user_headers, (int)contentSize))
        {
            fprintf(stderr, "httpClientCallbackOnResponse - Error returning header\n");

            return MI_FALSE;
        }
    }

    if (data != NULL && *data != NULL)
    {
        std::vector< unsigned char > user_data(
            (unsigned char*)(*data + 1), (unsigned char*)(*data + 1) + (*data)->u.s.size);

        if (!rep->_callback->OnResponseData(user_data, lastChunk))
        {
            fprintf(stderr, "httpClientCallbackOnResponse - Error from OnResponseData\n");
            return MI_FALSE;
        }
        fprintf(stderr, "httpClientCallbackOnResponse - Returning %u bytes data\n", (unsigned int)(*data)->u.s.size);
    }

    fprintf(stderr, "httpClientCallbackOnStatusResponse - Returning OK (MI_TRUE)\n");
    return MI_TRUE;
}
