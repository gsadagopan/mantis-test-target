package com.sample.maven;


import com.fasterxml.jackson.databind.ObjectMapper;

public class VulnerableApp {
    public static void main(String[] args) {
        System.out.println("Mantis Test Target Initialized.");
        ObjectMapper mapper = new ObjectMapper();
        // Basic usage to ensure type attribution hooks into Jackson
        boolean isConfigured = (mapper != null);
        System.out.println("Jackson ObjectMapper active: " + isConfigured);
    }
}