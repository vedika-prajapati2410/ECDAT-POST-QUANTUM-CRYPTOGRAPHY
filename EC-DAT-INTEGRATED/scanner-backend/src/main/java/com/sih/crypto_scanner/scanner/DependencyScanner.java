package com.sih.crypto_scanner.scanner;

import com.sih.crypto_scanner.model.DependencyAsset;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class DependencyScanner {

    public List<DependencyAsset> scanDirectory(
            String directoryPath) throws IOException {

        List<DependencyAsset> dependencies = new ArrayList<>();

        Path root = Path.of(directoryPath);

        if (!Files.exists(root)) {
            throw new IllegalArgumentException(
                    "Directory does not exist: " + directoryPath
            );
        }

        Files.walk(root)
                .filter(Files::isRegularFile)
                .forEach(file -> {

                    try {
                        String fileName =
                                file.getFileName()
                                        .toString()
                                        .toLowerCase();

                        String content =
                                Files.readString(file);

                        if (fileName.equals("pom.xml")) {
                            dependencies.addAll(
                                    scanMaven(file, content)
                            );
                        }

                        if (fileName.equals("requirements.txt")) {
                            dependencies.addAll(
                                    scanPythonRequirements(file, content)
                            );
                        }

                        if (fileName.equals("go.mod")) {
                            dependencies.addAll(
                                    scanGoMod(file, content)
                            );
                        }

                    } catch (IOException ignored) {
                        // Ignore unreadable files
                    }
                });

        return dependencies;
    }

    private List<DependencyAsset> scanMaven(
            Path file,
            String content) {

        List<DependencyAsset> results =
                new ArrayList<>();

        /*
         * Find each Maven dependency block.
         */
        Pattern dependencyPattern = Pattern.compile(
                "<dependency>(.*?)</dependency>",
                Pattern.DOTALL
        );

        Matcher dependencyMatcher =
                dependencyPattern.matcher(content);

        while (dependencyMatcher.find()) {

            String dependencyBlock =
                    dependencyMatcher.group(1);

            String groupId =
                    extractXmlValue(
                            dependencyBlock,
                            "groupId"
                    );

            String artifactId =
                    extractXmlValue(
                            dependencyBlock,
                            "artifactId"
                    );

            String version =
                    extractXmlValue(
                            dependencyBlock,
                            "version"
                    );

            if (artifactId != null
                    && isCryptoRelated(
                    artifactId
            )) {

                results.add(
                        new DependencyAsset(
                                artifactId,
                                version,
                                "Maven",
                                file.toString(),
                                "MANIFEST"
                        )
                );
            }
        }

        return results;
    }

    private String extractXmlValue(
            String content,
            String tagName) {

        Pattern pattern = Pattern.compile(
                "<" + tagName + ">\\s*(.*?)\\s*</"
                        + tagName + ">",
                Pattern.DOTALL
        );

        Matcher matcher =
                pattern.matcher(content);

        if (matcher.find()) {
            return matcher.group(1).trim();
        }

        return null;
    }

    private List<DependencyAsset> scanPythonRequirements(
            Path file,
            String content) {

        List<DependencyAsset> results =
                new ArrayList<>();

        String[] lines =
                content.split("\\R");

        for (String line : lines) {

            line = line.trim();

            if (line.isEmpty()
                    || line.startsWith("#")) {
                continue;
            }

            String name = line;
            String version = null;

            if (line.contains("==")) {

                String[] parts =
                        line.split("==", 2);

                name = parts[0].trim();
                version = parts[1].trim();
            }

            if (isCryptoRelated(name)) {

                results.add(
                        new DependencyAsset(
                                name,
                                version,
                                "Python",
                                file.toString(),
                                "MANIFEST"
                        )
                );
            }
        }

        return results;
    }

    private List<DependencyAsset> scanGoMod(
            Path file,
            String content) {

        List<DependencyAsset> results =
                new ArrayList<>();

        Pattern pattern = Pattern.compile(
                "^\\s*([^\\s]+)\\s+(v[^\\s]+)",
                Pattern.MULTILINE
        );

        Matcher matcher =
                pattern.matcher(content);

        while (matcher.find()) {

            String name =
                    matcher.group(1).trim();

            String version =
                    matcher.group(2).trim();

            if (isCryptoRelated(name)) {

                results.add(
                        new DependencyAsset(
                                name,
                                version,
                                "Go",
                                file.toString(),
                                "MANIFEST"
                        )
                );
            }
        }

        return results;
    }

    private boolean isCryptoRelated(String name) {

        String value =
                name.toLowerCase();

        return value.contains("crypto")
                || value.contains("openssl")
                || value.contains("bouncycastle")
                || value.contains("bouncy")
                || value.contains("bcprov")
                || value.contains("cryptography")
                || value.contains("pycryptodome")
                || value.contains("nacl");
    }
}