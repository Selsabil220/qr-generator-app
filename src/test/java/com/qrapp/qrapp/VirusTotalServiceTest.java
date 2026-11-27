package com.qrapp.qrapp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

class VirusTotalServiceTest {

    private static final String BASE = "https://vt.test/api/v3";
    private static final String URL = "https://example.com/page";
    private static final String KEY = "dummy-key";

    private MockRestServiceServer server;
    private RestClient client;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder().baseUrl(BASE);
        server = MockRestServiceServer.bindTo(builder).build();
        client = builder.build();
    }

    private static String expectedUri() {
        String id = Base64.getUrlEncoder().withoutPadding()
                .encodeToString(URL.getBytes(StandardCharsets.UTF_8));
        return BASE + "/urls/" + id;
    }

    private static String statsJson(int malicious, int suspicious) {
        return "{\"data\":{\"attributes\":{\"last_analysis_stats\":{\"malicious\":" + malicious
                + ",\"suspicious\":" + suspicious + ",\"harmless\":60,\"undetected\":20}}}}";
    }

    @Test
    void flaggedUrlIsMalicious() {
        server.expect(requestTo(expectedUri()))
                .andExpect(header("x-apikey", KEY))
                .andRespond(withSuccess(statsJson(3, 0), MediaType.APPLICATION_JSON));

        assertThat(new VirusTotalService(client, KEY, 1).check(URL))
                .isEqualTo(VirusTotalService.Verdict.MALICIOUS);
        server.verify();
    }

    @Test
    void suspiciousCountsToo() {
        server.expect(requestTo(expectedUri()))
                .andRespond(withSuccess(statsJson(0, 2), MediaType.APPLICATION_JSON));

        assertThat(new VirusTotalService(client, KEY, 1).check(URL))
                .isEqualTo(VirusTotalService.Verdict.MALICIOUS);
    }

    @Test
    void cleanUrlIsSafe() {
        server.expect(requestTo(expectedUri()))
                .andRespond(withSuccess(statsJson(0, 0), MediaType.APPLICATION_JSON));

        assertThat(new VirusTotalService(client, KEY, 1).check(URL))
                .isEqualTo(VirusTotalService.Verdict.SAFE);
    }

    @Test
    void unseenUrlIsUnknown() {
        server.expect(requestTo(expectedUri()))
                .andRespond(withStatus(HttpStatus.NOT_FOUND));

        assertThat(new VirusTotalService(client, KEY, 1).check(URL))
                .isEqualTo(VirusTotalService.Verdict.UNKNOWN);
    }

    @Test
    void wrongKeyIsReportedAsUnavailable() {
        server.expect(requestTo(expectedUri()))
                .andRespond(withStatus(HttpStatus.UNAUTHORIZED));

        assertThatThrownBy(() -> new VirusTotalService(client, KEY, 1).check(URL))
                .isInstanceOf(VirusTotalUnavailableException.class);
    }

    @Test
    void quotaExceededIsReportedAsUnavailable() {
        server.expect(requestTo(expectedUri()))
                .andRespond(withStatus(HttpStatus.TOO_MANY_REQUESTS));

        assertThatThrownBy(() -> new VirusTotalService(client, KEY, 1).check(URL))
                .isInstanceOf(VirusTotalUnavailableException.class);
    }

    @Test
    void missingKeyFailsWithoutCallingVirusTotal() {
        assertThatThrownBy(() -> new VirusTotalService(client, "", 1).check(URL))
                .isInstanceOf(VirusTotalUnavailableException.class);
        server.verify();
    }
}