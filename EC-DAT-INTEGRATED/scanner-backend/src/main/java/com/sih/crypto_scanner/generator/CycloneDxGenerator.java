package com.sih.crypto_scanner.generator;

import com.sih.crypto_scanner.model.CryptoAsset;
import com.sih.crypto_scanner.model.DependencyAsset;
import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ArrayNode;
import tools.jackson.databind.node.ObjectNode;

import java.util.List;
import java.util.UUID;

@Service
public class CycloneDxGenerator {

    private final ObjectMapper objectMapper;

    public CycloneDxGenerator(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public ObjectNode generate(
            List<CryptoAsset> cryptoAssets,
            List<DependencyAsset> dependencies) {

        ObjectNode bom =
                objectMapper.createObjectNode();

        bom.put("bomFormat", "CycloneDX");
        bom.put("specVersion", "1.6");
        bom.put(
                "serialNumber",
                "urn:uuid:" + UUID.randomUUID()
        );
        bom.put("version", 1);

        ArrayNode components =
                objectMapper.createArrayNode();

        // Crypto assets
        for (CryptoAsset asset : cryptoAssets) {

            ObjectNode component =
                    objectMapper.createObjectNode();

            component.put(
                    "type",
                    "cryptographic-asset"
            );

            component.put(
                    "name",
                    asset.getName()
            );

            ObjectNode cryptoProperties =
                    objectMapper.createObjectNode();

            cryptoProperties.put(
                    "assetType",
                    "algorithm"
            );

            ObjectNode algorithmProperties =
                    objectMapper.createObjectNode();

            // Explicit algorithm name
            algorithmProperties.put(
                    "algorithm",
                    asset.getAlgorithm()
            );

            if (asset.getPrimitive() != null
                    && !asset.getPrimitive().isBlank()) {

                algorithmProperties.put(
                        "primitive",
                        asset.getPrimitive()
                );
            }

            if (asset.getKeyLength() != null) {

                algorithmProperties.put(
                        "parameterSetIdentifier",
                        asset.getKeyLength().toString()
                );
            }

            cryptoProperties.set(
                    "algorithmProperties",
                    algorithmProperties
            );

            component.set(
                    "cryptoProperties",
                    cryptoProperties
            );

            ArrayNode properties =
                    objectMapper.createArrayNode();

            addProperty(
                    properties,
                    "language",
                    asset.getLanguage()
            );

            addProperty(
                    properties,
                    "filePath",
                    asset.getFilePath()
            );

            addProperty(
                    properties,
                    "lineNumber",
                    asset.getLineNumber() != null
                            ? asset.getLineNumber().toString()
                            : null
            );

            addProperty(
                    properties,
                    "detectionMethod",
                    asset.getDetectionMethod()
            );

            component.set(
                    "properties",
                    properties
            );

            components.add(component);
        }

        // Dependencies
        for (DependencyAsset dependency : dependencies) {

            ObjectNode component =
                    objectMapper.createObjectNode();

            component.put(
                    "type",
                    "library"
            );

            component.put(
                    "name",
                    dependency.getName()
            );

            if (dependency.getVersion() != null) {

                component.put(
                        "version",
                        dependency.getVersion()
                );
            }

            ArrayNode properties =
                    objectMapper.createArrayNode();

            addProperty(
                    properties,
                    "ecosystem",
                    dependency.getEcosystem()
            );

            addProperty(
                    properties,
                    "filePath",
                    dependency.getFilePath()
            );

            addProperty(
                    properties,
                    "detectionMethod",
                    dependency.getDetectionMethod()
            );

            component.set(
                    "properties",
                    properties
            );

            components.add(component);
        }

        bom.set(
                "components",
                components
        );

        return bom;
    }

    private void addProperty(
            ArrayNode properties,
            String name,
            String value) {

        if (value == null) {
            return;
        }

        ObjectNode property =
                objectMapper.createObjectNode();

        property.put(
                "name",
                name
        );

        property.put(
                "value",
                value
        );

        properties.add(property);
    }
}