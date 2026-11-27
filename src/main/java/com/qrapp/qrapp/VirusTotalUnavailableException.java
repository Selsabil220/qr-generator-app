package com.qrapp.qrapp;

/** Thrown when VirusTotal cannot give a usable answer (no key, quota, network error, 5xx...). */
public class VirusTotalUnavailableException extends RuntimeException {

    public VirusTotalUnavailableException(String message) {
        super(message);
    }

    public VirusTotalUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
