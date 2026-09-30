package com.sih.crypto_scanner.upload;

import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import tools.jackson.databind.node.ObjectNode;

@RestController
@RequestMapping("/api/v1/upload-scan")
@CrossOrigin(origins = "http://localhost:5173")
public class UploadScanController {

    private final UploadScanService uploadScanService;

    public UploadScanController(
            UploadScanService uploadScanService) {

        this.uploadScanService = uploadScanService;
    }

    @PostMapping
    public ObjectNode uploadAndScan(
            @RequestParam("files") MultipartFile[] files)
            throws Exception {

        return uploadScanService.scanUploadedFiles(files);
    }
}