package com.sih.crypto_scanner.controller;

import com.sih.crypto_scanner.generator.CycloneDxGenerator;
import com.sih.crypto_scanner.model.CryptoAsset;
import com.sih.crypto_scanner.model.DependencyAsset;
import com.sih.crypto_scanner.scanner.DependencyScanner;
import com.sih.crypto_scanner.scanner.SourceCryptoScanner;
import org.springframework.web.bind.annotation.*;
import tools.jackson.databind.node.ObjectNode;
import org.springframework.web.bind.annotation.CrossOrigin;

import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api/v1/scan")
@CrossOrigin(origins = "http://localhost:5173")
public class ScanController {

    private final SourceCryptoScanner sourceCryptoScanner;
    private final DependencyScanner dependencyScanner;
    private final CycloneDxGenerator cycloneDxGenerator;

    public ScanController(
            SourceCryptoScanner sourceCryptoScanner,
            DependencyScanner dependencyScanner,
            CycloneDxGenerator cycloneDxGenerator) {

        this.sourceCryptoScanner = sourceCryptoScanner;
        this.dependencyScanner = dependencyScanner;
        this.cycloneDxGenerator = cycloneDxGenerator;
    }

    @PostMapping
    public ObjectNode scan(
            @RequestParam String directoryPath) throws IOException {

        // 1. Scan source code
        List<CryptoAsset> cryptoAssets =
                sourceCryptoScanner.scanDirectory(directoryPath);

        // 2. Scan dependency/manifests
        List<DependencyAsset> dependencies =
                dependencyScanner.scanDirectory(directoryPath);

        // 3. Generate CycloneDX CBOM
        return cycloneDxGenerator.generate(
                cryptoAssets,
                dependencies
        );
    }
}