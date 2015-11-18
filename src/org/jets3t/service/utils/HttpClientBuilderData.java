package org.jets3t.service.utils;

import org.apache.http.client.HttpRequestRetryHandler;
import org.apache.http.conn.HttpClientConnectionManager;
import org.apache.http.impl.client.HttpClientBuilder;

/**
 * Container for request configuration objects used to build an HttpClient.
 * @author jmurty
 */
public class HttpClientBuilderData {
    public HttpClientBuilder httpClientBuilder;
    public HttpClientConnectionManager connectionManager;
    public HttpRequestRetryHandler retryHandler;

    public HttpClientBuilderData(HttpClientBuilder httpClientBuilder,
        HttpClientConnectionManager connectionManager,
        HttpRequestRetryHandler retryHandler)
    {
        this.connectionManager = connectionManager;
        this.httpClientBuilder = httpClientBuilder;
        this.retryHandler = retryHandler;
    }
}