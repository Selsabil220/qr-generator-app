package com.qrapp.qrapp;

import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class QrControllerTest {

    private static final String URL = "https://example.com/page";

    private VirusTotalService virusTotal;
    private SimpleMeterRegistry registry;

    @BeforeEach
    void setUp() {
        virusTotal = mock(VirusTotalService.class);
        registry = new SimpleMeterRegistry();
    }

    private QrController controller(boolean failOpen) {
        return new QrController(virusTotal, registry, failOpen);
    }

    private static void assertStatus(Throwable error, int expected) {
        assertThat(error).isInstanceOf(ResponseStatusException.class);
        assertThat(((ResponseStatusException) error).getStatusCode().value()).isEqualTo(expected);
    }

    @Test
    void rejectsNonHttpUrls() {
        assertThatThrownBy(() -> controller(false).generateQrCode("javascript:alert(1)"))
                .satisfies(e -> assertStatus(e, 400));
        assertThatThrownBy(() -> controller(false).generateQrCode("httpfoo"))
                .satisfies(e -> assertStatus(e, 400));
    }

    @Test
    void safeUrlProducesPng() throws Exception {
        when(virusTotal.check(URL)).thenReturn(VirusTotalService.Verdict.SAFE);

        byte[] png = controller(false).generateQrCode(URL);

        assertThat(png).startsWith((byte) 0x89, (byte) 'P', (byte) 'N', (byte) 'G');
    }

    @Test
    void unknownUrlIsAllowed() throws Exception {
        when(virusTotal.check(URL)).thenReturn(VirusTotalService.Verdict.UNKNOWN);

        assertThat(controller(false).generateQrCode(URL)).isNotEmpty();
    }

    @Test
    void maliciousUrlIsBlockedAndCounted() {
        when(virusTotal.check(URL)).thenReturn(VirusTotalService.Verdict.MALICIOUS);

        assertThatThrownBy(() -> controller(false).generateQrCode(URL))
                .satisfies(e -> assertStatus(e, 403));
        assertThat(registry.counter("qr.urls.blocked", "reason", "malicious").count()).isEqualTo(1.0);
    }

    @Test
    void failsClosedWhenVirusTotalIsUnavailable() {
        when(virusTotal.check(URL)).thenThrow(new VirusTotalUnavailableException("down"));

        assertThatThrownBy(() -> controller(false).generateQrCode(URL))
                .satisfies(e -> assertStatus(e, 503));
    }

    @Test
    void failsOpenWhenConfiguredTo() throws Exception {
        when(virusTotal.check(URL)).thenThrow(new VirusTotalUnavailableException("down"));

        assertThat(controller(true).generateQrCode(URL)).isNotEmpty();
    }
}
