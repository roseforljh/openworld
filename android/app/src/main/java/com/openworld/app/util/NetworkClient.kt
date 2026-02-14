package com.openworld.app.util

import android.util.Log
import okhttp3.ConnectionPool
import okhttp3.Dispatcher
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Protocol
import java.io.IOException
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Global shared OkHttpClient singleton
 */
object NetworkClient {
    private const val TAG = "NetworkClient"

    // Timeout configuration (seconds)
    private const val CONNECT_TIMEOUT = 15L
    private const val READ_TIMEOUT = 20L
    private const val WRITE_TIMEOUT = 20L
    private const val CALL_TIMEOUT = 60L

    private val connectionPool = ConnectionPool(10, 5, TimeUnit.MINUTES)

    private val dispatcher = Dispatcher().apply {
        maxRequests = 64
        maxRequestsPerHost = 10
    }

    private val totalRequests = AtomicLong(0)
    private val failedRequests = AtomicLong(0)

    private val statsInterceptor = Interceptor { chain ->
        totalRequests.incrementAndGet()
        try {
            chain.proceed(chain.request())
        } catch (e: IOException) {
            failedRequests.incrementAndGet()
            throw e
        }
    }

    val client: OkHttpClient by lazy {
        OkHttpClient.Builder()
            .connectTimeout(CONNECT_TIMEOUT, TimeUnit.SECONDS)
            .readTimeout(READ_TIMEOUT, TimeUnit.SECONDS)
            .writeTimeout(WRITE_TIMEOUT, TimeUnit.SECONDS)
            .callTimeout(CALL_TIMEOUT, TimeUnit.SECONDS)
            .connectionPool(connectionPool)
            .dispatcher(dispatcher)
            .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
            .addInterceptor(statsInterceptor)
            .retryOnConnectionFailure(true)
            .followRedirects(true)
            .followSslRedirects(true)
            .build()
    }

    fun newBuilder(): OkHttpClient.Builder {
        return client.newBuilder()
    }

    fun createClientWithTimeout(
        connectTimeoutSeconds: Long,
        readTimeoutSeconds: Long,
        writeTimeoutSeconds: Long = readTimeoutSeconds
    ): OkHttpClient {
        return newBuilder()
            .connectTimeout(connectTimeoutSeconds, TimeUnit.SECONDS)
            .readTimeout(readTimeoutSeconds, TimeUnit.SECONDS)
            .writeTimeout(writeTimeoutSeconds, TimeUnit.SECONDS)
            .build()
    }

    fun createClientWithoutRetry(
        connectTimeoutSeconds: Long,
        readTimeoutSeconds: Long,
        writeTimeoutSeconds: Long = readTimeoutSeconds
    ): OkHttpClient {
        return OkHttpClient.Builder()
            .connectTimeout(connectTimeoutSeconds, TimeUnit.SECONDS)
            .readTimeout(readTimeoutSeconds, TimeUnit.SECONDS)
            .writeTimeout(writeTimeoutSeconds, TimeUnit.SECONDS)
            .connectionPool(connectionPool)
            .protocols(listOf(Protocol.HTTP_2, Protocol.HTTP_1_1))
            .retryOnConnectionFailure(false)
            .followRedirects(true)
            .followSslRedirects(true)
            .build()
    }

    fun createClientWithProxy(
        proxyPort: Int,
        connectTimeoutSeconds: Long,
        readTimeoutSeconds: Long,
        writeTimeoutSeconds: Long = readTimeoutSeconds
    ): OkHttpClient {
        val proxy = java.net.Proxy(
            java.net.Proxy.Type.HTTP,
            java.net.InetSocketAddress("127.0.0.1", proxyPort)
        )
        return OkHttpClient.Builder()
            .proxy(proxy)
            .connectTimeout(connectTimeoutSeconds, TimeUnit.SECONDS)
            .readTimeout(readTimeoutSeconds, TimeUnit.SECONDS)
            .writeTimeout(writeTimeoutSeconds, TimeUnit.SECONDS)
            .connectionPool(ConnectionPool(5, 2, TimeUnit.MINUTES))
            .protocols(listOf(Protocol.HTTP_1_1))
            .retryOnConnectionFailure(false)
            .followRedirects(true)
            .followSslRedirects(true)
            .build()
    }

    fun clearConnectionPool() {
        connectionPool.evictAll()
    }
}
