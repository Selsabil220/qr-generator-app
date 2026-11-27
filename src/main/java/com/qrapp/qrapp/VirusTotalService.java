package com.qrapp.qrapp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;

/** Asks VirusTotal whether a URL is known to be malicious. The API key comes from configuration, never from code. */
@Service
public class VirusTotalService {

    public enum Verdict { SAFE, MALICIOUS, UNKNOWN }

    private static final ParameterizedTypeReference<Map<String, Object>> JSON_MAP =
            new ParameterizedTypeReference<>() { };

    private final RestClient client;
    private final String apiKey;
    private final int blockThreshold;

    @Autowired
    public VirusTotalService(
            @Value("${virustotal.api-key:}") String apiKey,
            @Value("${virustotal.base-url:https://www.virustotal.com/api/v3}") String baseUrl,
            @Value("${virustotal.block-threshold:1}") int blockThreshold) {
        this(buildClient(baseUrl), apiKey, blockThreshold);
    }

    // Used by the tests, so they can plug in a mocked server
    VirusTotalService(RestClient client, String apiKey, int blockThreshold) {
        this.client = client;
        this.apiKey = apiKey == null ? "" : apiKey.trim();
        this.blockThreshold = blockThreshold;
    }

    private static RestClient buildClient(String baseUrl) {
        HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(3))
                .build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(httpClient);
        factory.setReadTimeout(Duration.ofSeconds(5));
        return RestClient.builder().baseUrl(baseUrl).requestFactory(factory).build();
    }

    /**
     * SAFE: VirusTotal knows the URL and fewer engines than the threshold flag it.
     * MALICIOUS: at least {@code blockThreshold} engines say malicious or suspicious.
     * UNKNOWN: VirusTotal has no verdict yet for this URL.
     *
     * @throws VirusTotalUnavailableException if no usable answer could be obtained
     */
    public Verdict check(String url) {
        if (apiKey.isEmpty()) {
            throw new VirusTotalUnavailableException("VirusTotal API key is not configured");
        }
        String id = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(url.getBytes(StandardCharsets.UTF_8));
        try {
            Map<String, Object> body = client.get()
                    .uri("/urls/{id}", id)
                    .header("x-apikey", apiKey)
                    .retrieve()
                    .body(JSON_MAP);
            return evaluate(body);
        } catch (HttpClientErrorException.NotFound e) {
            return Verdict.UNKNOWN;
        } catch (RestClientException e) {
            throw new VirusTotalUnavailableException(
                    "VirusTotal request failed (" + e.getClass().getSimpleName() + ")", e);
        }
    }

    private Verdict evaluate(Map<String, Object> body) {
        if (body == null) {
            throw new VirusTotalUnavailableException("Empty response from VirusTotal");
        }
        Map<String, Object> data = asMap(body.get("data"));
        Map<String, Object> attributes = asMap(data.get("attributes"));
        Map<String, Object> stats = asMap(attributes.get("last_analysis_stats"));
        if (stats.isEmpty()) {
            return Verdict.UNKNOWN;
        }
        int flagged = asInt(stats.get("malicious")) + asInt(stats.get("suspicious"));
        return flagged >= blockThreshold ? Verdict.MALICIOUS : Verdict.SAFE;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> asMap(Object value) {
        return value instanceof Map<?, ?> map ? (Map<String, Object>) map : Map.of();
    }

    private static int asInt(Object value) {
        return value instanceof Number number ? number.intValue() : 0;
    }
}
