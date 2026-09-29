package com.sih.crypto_scanner.scanner;

import com.sih.crypto_scanner.model.CryptoAsset;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class SourceCryptoScanner {

    private static final List<String> SUPPORTED_EXTENSIONS = List.of(
            ".java",
            ".py",
            ".c",
            ".h",
            ".cpp",
            ".cc",
            ".cxx",
            ".hpp",
            ".go"
    );

    private static final List<String> ALGORITHMS = List.of(
            "RSA",
            "ECDSA",
            "ECDH",
            "ECC",
            "X25519",
            "DH",
            "AES",
            "DES",
            "3DES",
            "SHA-256",
            "SHA-384",
            "SHA-512",
            "SHA1",
            "HMAC",
            "MD5",
            "ML-KEM",
            "Kyber",
            "ML-DSA",
            "Dilithium",
            "SLH-DSA",
            "SPHINCS"
    );

    public List<CryptoAsset> scanDirectory(String directoryPath)
            throws IOException {

        List<CryptoAsset> assets = new ArrayList<>();

        Path root = Path.of(directoryPath);

        if (!Files.exists(root)) {
            throw new IllegalArgumentException(
                    "Directory does not exist: " + directoryPath
            );
        }

        Files.walk(root)
                .filter(Files::isRegularFile)
                .filter(this::isSupportedSourceFile)
                .forEach(file -> {

                    try {
                        String content = Files.readString(file);

                        assets.addAll(
                                scanFile(file, content)
                        );

                    } catch (IOException e) {
                        // Ignore unreadable files for now
                    }
                });

        return assets;
    }

    private List<CryptoAsset> scanFile(
            Path file,
            String content) {

        List<CryptoAsset> assets = new ArrayList<>();

        String language = detectLanguage(file);

        for (String algorithm : ALGORITHMS) {

            Pattern pattern = Pattern.compile(
                    "\\b" + Pattern.quote(algorithm) + "\\b",
                    Pattern.CASE_INSENSITIVE
            );

            Matcher matcher = pattern.matcher(content);

            if (matcher.find()) {

                Integer keyLength =
                        detectKeyLength(content, algorithm);

                String primitive =
                        detectPrimitive(algorithm);

                int lineNumber = 1;

                for (int i = 0; i < matcher.start(); i++) {

                    if (content.charAt(i) == '\n') {
                        lineNumber++;
                    }
                }

                CryptoAsset asset = new CryptoAsset(
                        algorithm + " usage",
                        "cryptographic-asset",
                        algorithm,
                        keyLength,
                        language,
                        file.toString(),
                        null,
                        "REGEX",
                        primitive,
                        lineNumber
                );

                assets.add(asset);
            }
        }

        return assets;
    }

    private String detectPrimitive(String algorithm) {

        if (algorithm == null) {
            return "unknown";
        }

        String alg = algorithm.toUpperCase();

        if (alg.equals("ECC")
                || alg.equals("ECDH")
                || alg.equals("X25519")
                || alg.equals("DH")) {
            return "key-agreement";
        }

        if (alg.equals("RSA")) {
            return "unknown";
        }

        if (alg.equals("ECDSA")
                || alg.equals("ML-DSA")
                || alg.equals("DILITHIUM")
                || alg.equals("SLH-DSA")
                || alg.equals("SPHINCS")) {
            return "signature";
        }

        if (alg.equals("AES")
                || alg.equals("DES")
                || alg.equals("3DES")) {
            return "block-cipher";
        }

        if (alg.equals("SHA-256")
                || alg.equals("SHA-384")
                || alg.equals("SHA-512")
                || alg.equals("SHA1")
                || alg.equals("MD5")) {
            return "hash";
        }

        if (alg.equals("HMAC")) {
            return "mac";
        }

        if (alg.equals("ML-KEM")
                || alg.equals("KYBER")) {
            return "kem";
        }

        return "unknown";
    }

    private Integer detectKeyLength(
            String content,
            String algorithm) {

        if (algorithm.equalsIgnoreCase("RSA")) {

            Pattern pattern = Pattern.compile(
                    "(1024|2048|3072|4096)",
                    Pattern.CASE_INSENSITIVE
            );

            Matcher matcher = pattern.matcher(content);

            if (matcher.find()) {
                return Integer.parseInt(matcher.group(1));
            }
        }

        if (algorithm.equalsIgnoreCase("AES")) {

            Pattern pattern = Pattern.compile(
                    "AES[-_/]?(128|192|256)",
                    Pattern.CASE_INSENSITIVE
            );

            Matcher matcher = pattern.matcher(content);

            if (matcher.find()) {
                return Integer.parseInt(matcher.group(1));
            }
        }

        return null;
    }

    private boolean isSupportedSourceFile(Path file) {

        String fileName =
                file.getFileName()
                        .toString()
                        .toLowerCase();

        return SUPPORTED_EXTENSIONS.stream()
                .anyMatch(fileName::endsWith);
    }

    private String detectLanguage(Path file) {

        String fileName =
                file.getFileName()
                        .toString()
                        .toLowerCase();

        if (fileName.endsWith(".java")) {
            return "Java";
        }

        if (fileName.endsWith(".py")) {
            return "Python";
        }

        if (fileName.endsWith(".c")
                || fileName.endsWith(".h")
                || fileName.endsWith(".cpp")
                || fileName.endsWith(".cc")
                || fileName.endsWith(".cxx")
                || fileName.endsWith(".hpp")) {
            return "C/C++";
        }

        if (fileName.endsWith(".go")) {
            return "Go";
        }

        return "Unknown";
    }
}