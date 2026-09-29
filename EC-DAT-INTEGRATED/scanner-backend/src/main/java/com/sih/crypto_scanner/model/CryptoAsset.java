package com.sih.crypto_scanner.model;

public class CryptoAsset {

    private String name;
    private String type;
    private String algorithm;
    private Integer keyLength;
    private String language;
    private String filePath;
    private String version;
    private String detectionMethod;
    private String primitive;
    private Integer lineNumber;

    public CryptoAsset() {
    }

    public CryptoAsset(
            String name,
            String type,
            String algorithm,
            Integer keyLength,
            String language,
            String filePath,
            String version,
            String detectionMethod,
            String primitive,
            Integer lineNumber) {

        this.name = name;
        this.type = type;
        this.algorithm = algorithm;
        this.keyLength = keyLength;
        this.language = language;
        this.filePath = filePath;
        this.version = version;
        this.detectionMethod = detectionMethod;
        this.primitive = primitive;
        this.lineNumber = lineNumber;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public Integer getKeyLength() {
        return keyLength;
    }

    public void setKeyLength(Integer keyLength) {
        this.keyLength = keyLength;
    }

    public String getLanguage() {
        return language;
    }

    public void setLanguage(String language) {
        this.language = language;
    }

    public String getFilePath() {
        return filePath;
    }

    public void setFilePath(String filePath) {
        this.filePath = filePath;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getDetectionMethod() {
        return detectionMethod;
    }

    public void setDetectionMethod(String detectionMethod) {
        this.detectionMethod = detectionMethod;
    }

    public String getPrimitive() {
        return primitive;
    }

    public void setPrimitive(String primitive) {
        this.primitive = primitive;
    }

    public Integer getLineNumber() {
        return lineNumber;
    }

    public void setLineNumber(Integer lineNumber) {
        this.lineNumber = lineNumber;
    }
}