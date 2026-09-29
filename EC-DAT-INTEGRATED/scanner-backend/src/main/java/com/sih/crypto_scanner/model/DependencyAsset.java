package com.sih.crypto_scanner.model;

public class DependencyAsset {

    private String name;
    private String version;
    private String ecosystem;
    private String filePath;
    private String detectionMethod;

    public DependencyAsset() {
    }

    public DependencyAsset(
            String name,
            String version,
            String ecosystem,
            String filePath,
            String detectionMethod) {

        this.name = name;
        this.version = version;
        this.ecosystem = ecosystem;
        this.filePath = filePath;
        this.detectionMethod = detectionMethod;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getEcosystem() {
        return ecosystem;
    }

    public void setEcosystem(String ecosystem) {
        this.ecosystem = ecosystem;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getDetectionMethod() {
        return detectionMethod;
    }

    public void setDetectionMethod(String detectionMethod) {
        this.detectionMethod = detectionMethod;
    }
}
