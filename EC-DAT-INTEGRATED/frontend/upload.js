// ============================================================
// ECDAT - File / Folder Upload
// This file is separate from the existing demo scan logic.
// ============================================================

(function () {

    // ------------------------------------------------------------
    // 1. Create the hidden file/folder picker
    // ------------------------------------------------------------

    const fileInput = document.createElement('input');

    fileInput.type = 'file';
    fileInput.multiple = true;

    // Allows folder selection in Chrome/Edge
    fileInput.setAttribute('webkitdirectory', '');
    fileInput.setAttribute('directory', '');

    fileInput.style.display = 'none';

    document.body.appendChild(fileInput);


    // ------------------------------------------------------------
    // 2. Create the Upload button
    // ------------------------------------------------------------

    const uploadBtn = document.createElement('button');

    uploadBtn.className = 'scan-btn';
    uploadBtn.textContent = 'Upload File / Folder';

    uploadBtn.style.marginLeft = '8px';

    const repoRow = document.querySelector('.repo-row');

    if (repoRow) {
        repoRow.appendChild(uploadBtn);
    }


    // ------------------------------------------------------------
    // 3. When Upload button is clicked
    // ------------------------------------------------------------

    uploadBtn.addEventListener('click', function () {
        fileInput.click();
    });


    // ------------------------------------------------------------
    // 4. When user selects files/folder
    // ------------------------------------------------------------

    fileInput.addEventListener('change', async function () {

        const files = Array.from(fileInput.files || []);

        if (files.length === 0) {
            return;
        }

        const scanLine = document.getElementById('scanLine');
        const scanFill = document.getElementById('scanFill');

        uploadBtn.disabled = true;

        scanFill.style.width = '10%';
        scanLine.textContent = `Preparing ${files.length} file(s)...`;


        try {

            // ----------------------------------------------------
            // File size protection
            // ----------------------------------------------------

            const MAX_FILE_SIZE = 50 * 1024 * 1024; // 50 MB per file
            const MAX_TOTAL_SIZE = 200 * 1024 * 1024; // 200 MB total

            let totalSize = 0;

            for (const file of files) {

                if (file.size > MAX_FILE_SIZE) {
                    throw new Error(
                        `File "${file.name}" is larger than 50 MB.`
                    );
                }

                totalSize += file.size;
            }

            if (totalSize > MAX_TOTAL_SIZE) {
                throw new Error(
                    'The selected files are larger than the 200 MB total upload limit.'
                );
            }


            // ----------------------------------------------------
            // 5. Prepare multipart/form-data
            // ----------------------------------------------------

            const formData = new FormData();

            files.forEach(file => {
                formData.append('files', file, file.name);
            });


            // ----------------------------------------------------
            // 6. Send files to Java upload backend
            // ----------------------------------------------------

            scanLine.textContent = 'Uploading files...';
            scanFill.style.width = '30%';

            const uploadResponse = await fetch(
                'http://localhost:8080/api/v1/upload-scan',
                {
                    method: 'POST',
                    body: formData
                }
            );


            if (!uploadResponse.ok) {

                const errorText = await uploadResponse.text();

                throw new Error(
                    `File upload failed: ${uploadResponse.status} ${errorText}`
                );
            }


            // ----------------------------------------------------
            // 7. Receive CycloneDX CBOM
            // ----------------------------------------------------

            scanLine.textContent = 'Upload complete. Analyzing cryptographic risk...';
            scanFill.style.width = '50%';

            const cbom = await uploadResponse.json();


            // ----------------------------------------------------
            // 8. Send CBOM to Flask risk engine
            // ----------------------------------------------------

            const riskResponse = await fetch(
                'http://localhost:5000/api/scans',
                {
                    method: 'POST',

                    headers: {
                        'Content-Type': 'application/json',
                        'X-API-Key': 'ecdat-dev-key-change-me'
                    },

                    body: JSON.stringify({
                        cbom: cbom,
                        years_to_crqc: 12.0
                    })
                }
            );


            if (!riskResponse.ok) {

                const errorText = await riskResponse.text();

                throw new Error(
                    `Risk analysis failed: ${riskResponse.status} ${errorText}`
                );
            }


            const report = await riskResponse.json();

            window.latestReport = report;

            console.log('Uploaded CBOM:', cbom);
            console.log('Risk Report:', report);


            // ----------------------------------------------------
            // 9. Convert risk report to dashboard artefacts
            // ----------------------------------------------------

            const realArtefacts =
                report.artefacts ||
                report.artifacts ||
                report.results ||
                report.risks ||
                [];


            // Clear existing dashboard data

            ARTEFACTS.length = 0;


            realArtefacts.forEach((item, index) => {

                const cbomItem =
                    report.cbom?.[index] || {};

                const recommendationItem =
                    report.recommendations?.[index] || {};


                // -----------------------------
                // Risk classification
                // -----------------------------

                const riskValue =
                    item.risk_tier ||
                    item.risk ||
                    item.classification ||
                    'Safe';


                let risk =
                    String(riskValue).toLowerCase();


                if (
                    risk.includes('critical') ||
                    risk.includes('high') ||
                    risk.includes('shor_breakable') ||
                    risk.includes('vulnerable')
                ) {

                    risk = 'risk';

                } else if (
                    risk.includes('medium') ||
                    risk.includes('warn') ||
                    risk.includes('at_risk')
                ) {

                    risk = 'warn';

                } else {

                    risk = 'safe';
                }


                // -----------------------------
                // CBOM information
                // -----------------------------

                const cryptoProperties =
                    cbomItem.cryptoProperties || {};

                const algorithmProperties =
                    cryptoProperties.algorithmProperties || {};


                const properties =
                    Array.isArray(cbomItem.properties)
                        ? cbomItem.properties
                        : [];


                const propertyMap = {};


                properties.forEach(property => {

                    if (property && property.name) {
                        propertyMap[property.name] =
                            property.value;
                    }

                });


                // -----------------------------
                // Dashboard artefact
                // -----------------------------

                ARTEFACTS.push({

                    id: index + 1,

                    name:
                        cbomItem.name ||
                        item.algorithm ||
                        `Crypto Asset ${index + 1}`,

                    type:
                        cbomItem.type === 'library'
                            ? 'library'
                            : 'algorithm',

                    path:
                        propertyMap.filePath ||
                        item.location ||
                        'uploaded file',

                    risk: risk,

                    criticality:
                        item.criticality ||
                        item.priority ||
                        3,

                    lifetime:
                        item.lifetime ||
                        report.years_to_crqc_assumption ||
                        12,

                    rec:
                        recommendationItem.recommendation ||
                        recommendationItem.action ||
                        recommendationItem.description ||
                        'Review migration requirements.',

                    algorithm:
                        algorithmProperties.algorithm ||
                        item.algorithm ||
                        cbomItem.name ||
                        'Unknown',

                    key_length:
                        item.key_length ||
                        algorithmProperties.parameterSetIdentifier ||
                        null,

                    crit:
                        Math.min(
                            1,
                            Math.max(
                                0,
                                (Number(item.criticality) || 3) / 5
                            )
                        ),

                    vuln:
                        getVulnerabilityScore(report, index)
                });

            });


            // ----------------------------------------------------
            // 10. Refresh existing dashboard
            // ----------------------------------------------------

            scanLine.textContent =
                `Upload scan complete — ${files.length} file(s) analyzed.`;

            scanFill.style.width = '100%';

            renderStats();
            renderTable();
            renderMatrix();
            renderRecs();


        } catch (error) {

            console.error('Upload scan error:', error);

            scanLine.textContent = 'Upload scan failed.';
            scanFill.style.width = '0%';

            alert(
                'Upload scan failed.\n\n' +
                error.message +
                '\n\nMake sure Backend 1 (8080) and Backend 2 (5000) are running.'
            );

        } finally {

            uploadBtn.disabled = false;

            // Allows selecting the same file again
            fileInput.value = '';

        }

    });


    // ------------------------------------------------------------
    // Vulnerability score helper
    // ------------------------------------------------------------

    function getVulnerabilityScore(report, index) {

        const classification =
            String(
                report.classifications?.[index]?.vulnerability_tier ||
                ''
            ).toLowerCase();


        if (classification === 'shor_breakable') {
            return 1.0;
        }


        if (
            classification.includes('weak') ||
            classification.includes('medium')
        ) {
            return 0.6;
        }


        if (
            classification.includes('quantum_safe') ||
            classification.includes('safe')
        ) {
            return 0.1;
        }


        return 0.3;
    }

})();