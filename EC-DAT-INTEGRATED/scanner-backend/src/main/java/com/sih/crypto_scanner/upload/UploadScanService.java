package com.sih.crypto_scanner.upload;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.sih.crypto_scanner.generator.CycloneDxGenerator;
import com.sih.crypto_scanner.model.CryptoAsset;
import com.sih.crypto_scanner.model.DependencyAsset;
import com.sih.crypto_scanner.scanner.DependencyScanner;
import com.sih.crypto_scanner.scanner.SourceCryptoScanner;

import tools.jackson.databind.node.ObjectNode;

@Service
public class UploadScanService {

    private static final long MAX_TOTAL_SIZE = 50L * 1024 * 1024;

    private final SourceCryptoScanner sourceCryptoScanner;
    private final DependencyScanner dependencyScanner;
    private final CycloneDxGenerator cycloneDxGenerator;

    public UploadScanService(
            SourceCryptoScanner sourceCryptoScanner,
            DependencyScanner dependencyScanner,
            CycloneDxGenerator cycloneDxGenerator) {

        this.sourceCryptoScanner = sourceCryptoScanner;
        this.dependencyScanner = dependencyScanner;
        this.cycloneDxGenerator = cycloneDxGenerator;
    }

    public ObjectNode scanUploadedFiles(
            MultipartFile[] files) throws IOException {

        if (files == null || files.length == 0) {
            throw new IllegalArgumentException(
                    "No files were uploaded."
            );
        }

        long totalSize = 0;

        for (MultipartFile file : files) {

            if (file == null || file.isEmpty()) {
                continue;
            }

            totalSize += file.getSize();

            if (totalSize > MAX_TOTAL_SIZE) {
                throw new IllegalArgumentException(
                        "Total upload size cannot exceed 50 MB."
                );
            }
        }

        Path temporaryDirectory =
                Files.createTempDirectory("ecdat-upload-");

        try {

            saveUploadedFiles(
                    files,
                    temporaryDirectory
            );

            List<CryptoAsset> cryptoAssets =
                    sourceCryptoScanner.scanDirectory(
                            temporaryDirectory.toString()
                    );

            List<DependencyAsset> dependencies =
                    dependencyScanner.scanDirectory(
                            temporaryDirectory.toString()
                    );

            return cycloneDxGenerator.generate(
                    cryptoAssets,
                    dependencies
            );

        } finally {

            deleteDirectory(temporaryDirectory);
        }
    }

    private List<Path> saveUploadedFiles(
            MultipartFile[] files,
            Path temporaryDirectory)
            throws IOException {

        List<Path> savedFiles = new ArrayList<>();

        for (MultipartFile file : files) {

            if (file == null || file.isEmpty()) {
                continue;
            }

            String originalName =
                    file.getOriginalFilename();

            if (originalName == null
                    || originalName.isBlank()) {
                continue;
            }

            String safeName =
                    Path.of(originalName)
                            .getFileName()
                            .toString();

            Path target =
                    temporaryDirectory
                            .resolve(safeName)
                            .normalize();

            if (!target.startsWith(
                    temporaryDirectory.normalize())) {

                throw new IllegalArgumentException(
                        "Invalid file path."
                );
            }

            try (InputStream inputStream =
                         file.getInputStream()) {

                Files.copy(
                        inputStream,
                        target
                );
            }

            savedFiles.add(target);
        }

        return savedFiles;
    }

    private void deleteDirectory(
            Path directory) {

        if (directory == null
                || !Files.exists(directory)) {
            return;
        }

        try {

            Files.walk(directory)
                    .sorted(
                            (a, b) -> b.compareTo(a)
                    )
                    .forEach(path -> {

                        try {
                            Files.deleteIfExists(path);
                        } catch (IOException ignored) {
                            // Best effort cleanup
                        }
                    });

        } catch (IOException ignored) {
            // Best effort cleanup
        }
    }
}