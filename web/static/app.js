document.addEventListener('DOMContentLoaded', () => {
    const fileUpload = document.getElementById('file-upload');
    const codeInput = document.getElementById('code-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const btnText = analyzeBtn.querySelector('.btn-text');
    const spinner = analyzeBtn.querySelector('.spinner');
    
    const resultsSection = document.getElementById('results-section');
    const errorMessage = document.getElementById('error-message');
    
    // File upload handling
    fileUpload.addEventListener('change', (e) => {
        const file = e.target.files[0];
        if (!file) return;
        
        const reader = new FileReader();
        reader.onload = (e) => {
            codeInput.value = e.target.result;
            document.getElementById('target-filename').textContent = file.name;
        };
        reader.readAsText(file);
    });

    // Drag and drop support
    codeInput.addEventListener('dragover', (e) => {
        e.preventDefault();
        codeInput.style.borderColor = 'var(--accent-blue)';
    });
    
    codeInput.addEventListener('dragleave', (e) => {
        e.preventDefault();
        codeInput.style.borderColor = '';
    });
    
    codeInput.addEventListener('drop', (e) => {
        codeInput.style.borderColor = '';

        const file = e.dataTransfer.files[0];
        if (!file) return; // no file dropped (e.g. plain text drag) -- let the browser's native drop-to-insert behavior run
        e.preventDefault();

        if (!file.name.endsWith('.py')) return;

        const reader = new FileReader();
        reader.onload = (event) => {
            codeInput.value = event.target.result;
            document.getElementById('target-filename').textContent = file.name;
        };
        reader.readAsText(file);
    });

    // Analyze button click
    analyzeBtn.addEventListener('click', async () => {
        const code = codeInput.value.trim();
        if (!code) {
            showError("Please enter or upload some Python code.");
            return;
        }

        const filename = document.getElementById('target-filename').textContent;
        
        // UI Loading state
        hideError();
        resultsSection.style.display = 'none';
        btnText.style.display = 'none';
        spinner.style.display = 'inline-block';
        analyzeBtn.disabled = true;

        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ code, filename })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || `HTTP Error ${response.status}`);
            }

            renderResults(code, data);
        } catch (error) {
            showError(error.message);
        } finally {
            // Reset UI Loading state
            btnText.style.display = 'inline';
            spinner.style.display = 'none';
            analyzeBtn.disabled = false;
        }
    });

    function showError(msg) {
        errorMessage.textContent = msg;
        errorMessage.style.display = 'block';
        resultsSection.style.display = 'none';
    }

    function hideError() {
        errorMessage.style.display = 'none';
    }

    function renderResults(code, data) {
        // Render Summary
        document.getElementById('summary-vulnerable').textContent = data.summary.vulnerable || 0;
        document.getElementById('summary-safe').textContent = data.summary.safe || 0;
        document.getElementById('summary-unknown').textContent = data.summary.unknown || 0;

        // Build Line Severity Map with precedence: high > unknown > safe
        const lineSeverityMap = new Map();
        
        // Priority map for precedence
        const severityPriority = {
            'high': 3,
            'unknown': 2,
            'safe': 1,
            'info': 0
        };

        const normalFindings = [];
        const infoNotes = [];

        data.findings.forEach(finding => {
            // Split findings based on severity
            if (finding.severity === 'info') {
                infoNotes.push(finding);
            } else {
                normalFindings.push(finding);
                
                // Track line severity for highlighting
                if (finding.line) {
                    const currentSeverity = lineSeverityMap.get(finding.line);
                    const newPriority = severityPriority[finding.severity] || 0;
                    const currentPriority = currentSeverity ? severityPriority[currentSeverity] : -1;
                    
                    if (newPriority > currentPriority) {
                        lineSeverityMap.set(finding.line, finding.severity);
                    }
                }
            }
        });

        // Render Code Viewer
        const codeViewer = document.getElementById('code-viewer');
        codeViewer.innerHTML = ''; // Clear previous
        
        const lines = code.split('\n');
        lines.forEach((line, index) => {
            const lineNum = index + 1;
            const severity = lineSeverityMap.get(lineNum);
            
            const lineContainer = document.createElement('div');
            lineContainer.className = 'code-line';
            if (severity) {
                lineContainer.classList.add(`line-${severity}`);
            }

            const lineNumEl = document.createElement('div');
            lineNumEl.className = 'line-number';
            lineNumEl.textContent = lineNum;

            const lineContentEl = document.createElement('div');
            lineContentEl.className = 'line-content';
            // CRITICAL: Use textContent to prevent XSS
            lineContentEl.textContent = line;

            lineContainer.appendChild(lineNumEl);
            lineContainer.appendChild(lineContentEl);
            codeViewer.appendChild(lineContainer);
        });

        // Render Findings List
        const findingsList = document.getElementById('findings-list');
        findingsList.innerHTML = '';
        
        if (normalFindings.length === 0) {
            findingsList.innerHTML = '<p class="finding-detail" style="padding: 1rem;">No vulnerabilities or safety proofs found.</p>';
        } else {
            normalFindings.forEach(finding => {
                const card = document.createElement('div');
                card.className = `finding-card severity-${finding.severity}`;
                
                // Safe construction of HTML, escaping text dynamically
                
                const header = document.createElement('div');
                header.className = 'finding-header';
                
                const title = document.createElement('div');
                title.className = 'finding-title';
                // E.g. "OS Command Injection"
                title.textContent = finding.vuln_type;
                header.appendChild(title);
                
                const location = document.createElement('div');
                location.className = 'finding-location';
                location.textContent = finding.location;
                header.appendChild(location);
                
                card.appendChild(header);

                // Add details
                const addDetail = (label, text) => {
                    if (!text) return;
                    const detail = document.createElement('div');
                    detail.className = 'finding-detail';
                    
                    const strStrong = document.createElement('strong');
                    strStrong.textContent = `${label}: `;
                    
                    const textNode = document.createTextNode(text);
                    
                    detail.appendChild(strStrong);
                    detail.appendChild(textNode);
                    card.appendChild(detail);
                };

                addDetail("Verdict", finding.verdict);
                addDetail("Source", finding.tainted_source);
                addDetail("Path Condition", finding.path_condition);
                
                // Add Z3 Counterexample block if it exists
                if (finding.z3_counterexample) {
                    const cxContainer = document.createElement('div');
                    cxContainer.className = 'counterexample-block';
                    
                    const cxLabel = document.createElement('span');
                    cxLabel.className = 'counterexample-label';
                    cxLabel.textContent = 'Z3 Counterexample (Proof of Exploitability):';
                    cxContainer.appendChild(cxLabel);
                    
                    const cxCode = document.createElement('div');
                    // CRITICAL: Use textContent to prevent XSS
                    cxCode.textContent = finding.z3_counterexample;
                    cxContainer.appendChild(cxCode);
                    
                    card.appendChild(cxContainer);
                }

                findingsList.appendChild(card);
            });
        }

        // Render Info Notes
        const infoContainer = document.getElementById('info-notes-container');
        const infoList = document.getElementById('info-notes-list');
        infoList.innerHTML = '';
        
        if (infoNotes.length > 0) {
            infoContainer.style.display = 'block';
            infoNotes.forEach(note => {
                const li = document.createElement('li');
                li.className = 'info-note-item';
                
                const strong = document.createElement('strong');
                strong.textContent = note.location ? `[${note.location}] ` : '';
                
                const text = document.createTextNode(note.vuln_type + (note.path_condition ? ` (${note.path_condition})` : ''));
                
                if (strong.textContent) li.appendChild(strong);
                li.appendChild(text);
                
                infoList.appendChild(li);
            });
        } else {
            infoContainer.style.display = 'none';
        }

        // Show Results
        resultsSection.style.display = 'flex';
    }
});
