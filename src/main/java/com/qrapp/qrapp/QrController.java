package com.qrapp.qrapp;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;
import com.google.zxing.qrcode.QRCodeWriter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Locale;

@RestController
@RequestMapping("/api/qr")
public class QrController {

    private static final Logger log = LoggerFactory.getLogger(QrController.class);
    private static final int MAX_URL_LENGTH = 2048;

    private final VirusTotalService virusTotal;
    private final MeterRegistry registry;
    private final boolean failOpen;

    public QrController(VirusTotalService virusTotal,
                        MeterRegistry registry,
                        @Value("${virustotal.fail-open:false}") boolean failOpen) {
        this.virusTotal = virusTotal;
        this.registry = registry;
        this.failOpen = failOpen;
    }

    @GetMapping(value = "/generate", produces = MediaType.IMAGE_PNG_VALUE)
    public byte[] generateQrCode(@RequestParam String text) throws Exception {
        validateUrl(text);
        checkWithVirusTotal(text);
        return renderQr(text);
    }

    private static void validateUrl(String text) {
        if (text == null || text.isBlank() || text.length() > MAX_URL_LENGTH) {
            throw invalidUrl();
        }
        try {
            URI uri = new URI(text);
            String scheme = uri.getScheme();
            boolean http = "http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme);
            if (!http || uri.getHost() == null) {
                throw invalidUrl();
            }
        } catch (URISyntaxException e) {
            throw invalidUrl();
        }
    }

    private static ResponseStatusException invalidUrl() {
        return new ResponseStatusException(HttpStatus.BAD_REQUEST,
                "Invalid URL. Must be a valid http or https address.");
    }

    private void checkWithVirusTotal(String url) {
        try {
            VirusTotalService.Verdict verdict = virusTotal.check(url);
            registry.counter("qr.urls.checked", "result", verdict.name().toLowerCase(Locale.ROOT)).increment();
            if (verdict == VirusTotalService.Verdict.MALICIOUS) {
                registry.counter("qr.urls.blocked", "reason", "malicious").increment();
                throw new ResponseStatusException(HttpStatus.FORBIDDEN,
                        "Security block: this URL is flagged as malicious by VirusTotal. QR generation refused.");
            }
        } catch (VirusTotalUnavailableException e) {
            log.warn("VirusTotal check unavailable: {}", e.getMessage());
            registry.counter("qr.urls.checked", "result", "unavailable").increment();
            if (!failOpen) {
                registry.counter("qr.urls.blocked", "reason", "unavailable").increment();
                throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                        "URL safety check unavailable. QR generation refused.");
            }
        }
    }

    private static byte[] renderQr(String text) throws Exception {
        QRCodeWriter writer = new QRCodeWriter();
        BitMatrix matrix = writer.encode(text, BarcodeFormat.QR_CODE, 300, 300);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        MatrixToImageWriter.writeToStream(matrix, "PNG", out);
        return out.toByteArray();
    }
}