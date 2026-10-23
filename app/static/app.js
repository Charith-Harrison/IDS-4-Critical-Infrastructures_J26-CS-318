/**
 * Protocol-Aware Replay Attack Detection for Modbus/TCP
 * Client-Side Application Logic (app.js)
 * 
 * Provides interactive UI handlers, drag-and-drop file upload with progress tracking,
 * session processing, data cleaning and transaction reconstruction inspection,
 * openpyxl Excel exports, configurable time-window re-extraction,
 * dual protocol feature tables with server-side pagination/search/sorting,
 * XGBoost training loss progress SVG chart, feature importance visualization,
 * ROC curve chart, prediction probability distribution histogram, and
 * full test transaction predictions inspection with 4-way filtering.
 */

// ==============================================================================
// 1. GLOBAL NOTIFICATION & UI UTILITIES
// ==============================================================================

function showAlert(message, type) {
    const alertBox = document.getElementById("statusAlert");
    if (!alertBox) return;

    alertBox.className = "alert-box";
    if (type === "success") {
        alertBox.classList.add("alert-success");
    } else if (type === "error") {
        alertBox.classList.add("alert-error");
    } else if (type === "loading") {
        alertBox.classList.add("alert-loading");
    }

    alertBox.innerHTML = message;
    alertBox.style.display = "block";
}

function setButtonLoading(btnId, isLoading, originalText, loadingText) {
    const btn = document.getElementById(btnId);
    if (!btn) return;
    if (isLoading) {
        btn.disabled = true;
        btn.dataset.originalText = btn.innerHTML;
        btn.innerHTML = `<span class="spinner">⏳</span> ${loadingText}`;
    } else {
        btn.disabled = false;
        btn.innerHTML = btn.dataset.originalText || originalText;
    }
}


// ==============================================================================
// 2. DATASET UPLOAD & PROCESSING (MAX 200 MB, CSV / PCAP, SESSION GENERATION)
// ==============================================================================

const MAX_FILE_SIZE_BYTES = 200 * 1024 * 1024; // 200 MB

function handleDragOver(event) {
    event.preventDefault();
    event.stopPropagation();
    event.currentTarget.classList.add("dragover");
}

function handleDragLeave(event) {
    event.preventDefault();
    event.stopPropagation();
    event.currentTarget.classList.remove("dragover");
}

function handleDrop(event, category) {
    event.preventDefault();
    event.stopPropagation();
    event.currentTarget.classList.remove("dragover");

    if (event.dataTransfer && event.dataTransfer.files.length > 0) {
        const file = event.dataTransfer.files[0];
        executeUpload(file, category);
    }
}

function handleFileSelect(event, category) {
    const file = event.target.files[0];
    if (file) {
        executeUpload(file, category);
    }
}

function executeUpload(file, category) {
    const isNormal = (category === "normal_traffic");
    const prefix = isNormal ? "Normal" : "Replay";

    const progressContainer = document.getElementById(`progressContainer${prefix}`);
    const progressFill = document.getElementById(`progressFill${prefix}`);
    const progressPercent = document.getElementById(`progressPercent${prefix}`);
    const progressLabel = document.getElementById(`progressLabel${prefix}`);
    const feedbackBox = document.getElementById(`uploadMsg${prefix}`);

    // Client-side size limit validation
    if (file.size > MAX_FILE_SIZE_BYTES) {
        const sizeMb = (file.size / (1024 * 1024)).toFixed(2);
        showAlert(`File ${file.name} (${sizeMb} MB) exceeds maximum 200 MB limit.`, "error");
        return;
    }

    // Client-side extension validation
    const validExts = [".csv", ".pcap", ".pcapng"];
    const ext = file.name.substring(file.name.lastIndexOf(".")).toLowerCase();
    if (!validExts.includes(ext)) {
        showAlert(`Unsupported file type '${ext}'. Please upload a .csv, .pcap, or .pcapng dataset.`, "error");
        return;
    }

    // Prepare FormData
    const formData = new FormData();
    formData.append("file", file);
    formData.append("category", category);

    // Initialize progress indicators
    progressContainer.style.display = "block";
    progressFill.style.width = "0%";
    progressPercent.textContent = "0%";
    progressLabel.textContent = `Uploading ${file.name}...`;
    if (feedbackBox) feedbackBox.style.display = "none";

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/upload_dataset", true);

    xhr.upload.onprogress = function(e) {
        if (e.lengthComputable) {
            const percentComplete = Math.round((e.loaded / e.total) * 100);
            progressFill.style.width = percentComplete + "%";
            progressPercent.textContent = percentComplete + "%";
        }
    };

    xhr.onload = function() {
        progressContainer.style.display = "none";
        try {
            const result = JSON.parse(xhr.responseText);
            if (xhr.status === 200 && result.success) {
                showAlert(result.message, "success");
                document.getElementById(`name${prefix}`).textContent = result.filename;
                document.getElementById(`size${prefix}`).textContent = result.size_formatted;
                document.getElementById(`type${prefix}`).textContent = result.format.toUpperCase();

                if (feedbackBox) {
                    feedbackBox.className = "alert-box alert-success";
                    feedbackBox.innerHTML = `&check; ${result.filename} uploaded and validated successfully (${result.size_formatted}).`;
                    feedbackBox.style.display = "block";
                }
            } else {
                showAlert(`Upload failed: ${result.error || 'Server error'}`, "error");
                if (feedbackBox) {
                    feedbackBox.className = "alert-box alert-error";
                    feedbackBox.innerHTML = `&cross; ${result.error || 'Upload rejected by server.'}`;
                    feedbackBox.style.display = "block";
                }
            }
        } catch (err) {
            showAlert(`Failed to parse server upload response: ${err.message}`, "error");
        }
    };

    xhr.onerror = function() {
        progressContainer.style.display = "none";
        showAlert(`Network error during dataset upload for ${file.name}.`, "error");
    };

    xhr.send(formData);
}

async function removeDataset(category) {
    const isNormal = (category === "normal_traffic");
    const prefix = isNormal ? "Normal" : "Replay";

    try {
        const resp = await fetch("/api/remove_dataset", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ category: category })
        });
        const res = await resp.json();
        if (res.success) {
            showAlert(res.message, "success");
            const active = res.active_datasets;
            if (isNormal) {
                document.getElementById(`name${prefix}`).textContent = active.normal_filename;
                document.getElementById(`size${prefix}`).textContent = (active.normal_size / (1024*1024)).toFixed(2) + " MB";
                document.getElementById(`type${prefix}`).textContent = (active.normal_type || "csv").toUpperCase();
            } else {
                document.getElementById(`name${prefix}`).textContent = active.replay_filename;
                document.getElementById(`size${prefix}`).textContent = (active.replay_size / (1024*1024)).toFixed(2) + " MB";
                document.getElementById(`type${prefix}`).textContent = (active.replay_type || "csv").toUpperCase();
            }
            setTimeout(() => window.location.reload(), 600);
        } else {
            showAlert(res.error, "error");
        }
    } catch (e) {
        showAlert("Error resetting dataset: " + e.message, "error");
    }
}

async function uploadAndProcessDatasets() {
    showAlert("Validating datasets, verifying protocol fields & timestamps, and creating session... Please wait.", "loading");
    setButtonLoading("btnUploadAndProcess", true, "", "Processing Datasets...");

    try {
        const response = await fetch("/api/upload_and_process", { method: "POST" });
        const result = await response.json();

        if (result.success && result.session) {
            const sess = result.session;
            showAlert(`&check; Datasets verified (${sess.normal_rows.toLocaleString()} Normal rows, ${sess.replay_rows.toLocaleString()} Replay rows). Ready for Stage A.`, "success");

            // Update session card
            const cardSession = document.getElementById("cardSessionSummary");
            if (cardSession) {
                cardSession.style.display = "block";
                const elSessionId = document.getElementById("valSessionId");
                if (elSessionId) elSessionId.textContent = sess.session_id;
                const elNorm = document.getElementById("valSessionNormalRows");
                if (elNorm) elNorm.textContent = sess.normal_rows.toLocaleString();
                const elRep = document.getElementById("valSessionReplayRows");
                if (elRep) elRep.textContent = sess.replay_rows.toLocaleString();
                const elTime = document.getElementById("valSessionTimestamps");
                if (elTime) elTime.textContent = sess.timestamps_valid ? "Valid & Verified" : "Verification Warning";

                const badgeContainer = document.getElementById("sessionFieldBadges");
                if (badgeContainer && sess.protocol_fields_detected) {
                    badgeContainer.innerHTML = sess.protocol_fields_detected.map(f => `<span class="badge badge-secondary" style="font-family: monospace;">${f}</span>`).join(" ");
                }
            }

            setButtonLoading("btnUploadAndProcess", false);
        } else {
            showAlert(`Dataset processing failed: ${result.error || 'Unknown error'}`, "error");
            setButtonLoading("btnUploadAndProcess", false);
        }
    } catch (err) {
        showAlert(`Network or server error during processing: ${err.message}`, "error");
        setButtonLoading("btnUploadAndProcess", false);
    }
}


// ==============================================================================
// 3. STAGE A: DATA INTEGRITY AUDIT, CLEANING & RECONSTRUCTED TRANSACTIONS
// ==============================================================================

async function triggerAudit() {
    showAlert("Executing Data & Label Integrity Audit and generating publication-quality PDF report... Please wait.", "loading");
    setButtonLoading("btnRunAudit", true, "", "Auditing Datasets...");

    try {
        const response = await fetch("/api/run_audit", { method: "POST" });
        const result = await response.json();

        if (result.success) {
            showAlert("Audit completed! PDF report generated at artifacts/audits/RP4_Data_Audit_Report.pdf. Reloading...", "success");
            setTimeout(() => window.location.reload(), 900);
        } else {
            showAlert(`Audit failed: ${result.error}`, "error");
            setButtonLoading("btnRunAudit", false);
        }
    } catch (err) {
        showAlert(`Network or server error: ${err.message}`, "error");
        setButtonLoading("btnRunAudit", false);
    }
}

async function applyDataCleaning() {
    const opts = {
        remove_duplicates: document.getElementById("cleanDuplicates") ? document.getElementById("cleanDuplicates").checked : true,
        handle_missing: document.getElementById("cleanMissing") ? document.getElementById("cleanMissing").checked : true,
        validate_timestamps: document.getElementById("cleanTimestamps") ? document.getElementById("cleanTimestamps").checked : true,
        exclude_invalid: document.getElementById("cleanInvalid") ? document.getElementById("cleanInvalid").checked : true,
        inspect_inconsistent_labels: document.getElementById("cleanInconsistentLabels") ? document.getElementById("cleanInconsistentLabels").checked : true
    };

    showAlert("Applying data cleaning rules and re-running transaction pairing coverage... Downstream stages invalidated.", "loading");
    setButtonLoading("btnApplyCleaning", true, "", "Cleaning Datasets...");

    try {
        const response = await fetch("/api/apply_cleaning", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(opts)
        });
        const result = await response.json();

        if (result.success && result.cleaning_summary) {
            const summary = result.cleaning_summary;
            const audit = result.audit_report;

            showAlert(`&check; Data cleaning applied successfully! Removed ${summary.transformations.duplicates_removed} duplicates, handled ${summary.transformations.missing_records_handled} missing values. Final usable records: ${summary.cleaned_records.total}.`, "success");

            // Update cleaning summary box
            const box = document.getElementById("cleaningSummaryBox");
            if (box) {
                box.style.display = "block";
                document.getElementById("cleanSummaryDups").textContent = summary.transformations.duplicates_removed;
                document.getElementById("cleanSummaryMissing").textContent = summary.transformations.missing_records_handled;
                document.getElementById("cleanSummaryInvalid").textContent = summary.transformations.invalid_frames_excluded;
                document.getElementById("cleanSummaryFinal").textContent = summary.cleaned_records.total.toLocaleString();
            }

            // Update top metrics
            if (audit) {
                if (document.getElementById("metricNormalRows")) document.getElementById("metricNormalRows").textContent = audit.row_counts.normal_rows;
                if (document.getElementById("metricReplayRows")) document.getElementById("metricReplayRows").textContent = audit.row_counts.replay_rows;
                if (document.getElementById("metricMissingCount")) {
                    const miss = audit.missing_values.normal_missing_total + audit.missing_values.replay_missing_total;
                    document.getElementById("metricMissingCount").textContent = miss;
                }
                if (document.getElementById("metricDuplicateCount") && audit.duplicate_records) {
                    document.getElementById("metricDuplicateCount").textContent = audit.duplicate_records.total_duplicates;
                }
                if (document.getElementById("metricConflictCount") && audit.reconstruction_coverage) {
                    document.getElementById("metricConflictCount").textContent = audit.reconstruction_coverage.label_conflicts_flagged;
                }
                if (document.getElementById("metricMatchedTx") && audit.reconstruction_coverage) {
                    document.getElementById("metricMatchedTx").textContent = audit.reconstruction_coverage.total_requests_processed;
                }
            }

            // Reload reconstructed transactions preview
            loadReconstructedTxPage(1);

            setButtonLoading("btnApplyCleaning", false);
        } else {
            showAlert(`Cleaning failed: ${result.error || 'Server error'}`, "error");
            setButtonLoading("btnApplyCleaning", false);
        }
    } catch (err) {
        showAlert(`Network or server error during cleaning: ${err.message}`, "error");
        setButtonLoading("btnApplyCleaning", false);
    }
}

// Reconstructed transactions table state
const reconstructedTxState = {
    page: 1,
    limit: 20,
    totalPages: 1,
    sortBy: "transaction_id",
    sortOrder: "asc",
    search: "",
    statusFilter: "all"
};

let txSearchTimer = null;
function handleTxSearch(e) {
    clearTimeout(txSearchTimer);
    txSearchTimer = setTimeout(() => {
        reconstructedTxState.search = e.target.value;
        loadReconstructedTxPage(1);
    }, 300);
}

function changeReconstructedTxPage(delta) {
    const newPage = reconstructedTxState.page + delta;
    if (newPage >= 1 && newPage <= reconstructedTxState.totalPages) {
        loadReconstructedTxPage(newPage);
    }
}

function sortReconstructedTx(column) {
    if (reconstructedTxState.sortBy === column) {
        reconstructedTxState.sortOrder = (reconstructedTxState.sortOrder === "asc") ? "desc" : "asc";
    } else {
        reconstructedTxState.sortBy = column;
        reconstructedTxState.sortOrder = "asc";
    }
    loadReconstructedTxPage(1);
}

async function loadReconstructedTxPage(page) {
    const tbody = document.getElementById("tbodyReconstructedTx");
    const pageInfo = document.getElementById("pageInfoTx");
    const btnPrev = document.getElementById("btnPrevTx");
    const btnNext = document.getElementById("btnNextTx");
    const statusSelect = document.getElementById("filterTxStatus");
    const limitSelect = document.getElementById("limitReconstructedTx");
    const totalCountEl = document.getElementById("totalReconstructedCount");

    if (!tbody) return;

    reconstructedTxState.page = page;
    reconstructedTxState.limit = limitSelect ? parseInt(limitSelect.value) : 20;
    reconstructedTxState.statusFilter = statusSelect ? statusSelect.value : "all";

    const params = new URLSearchParams({
        page: reconstructedTxState.page,
        limit: reconstructedTxState.limit,
        search: reconstructedTxState.search,
        status_filter: reconstructedTxState.statusFilter,
        sort_by: reconstructedTxState.sortBy,
        sort_order: reconstructedTxState.sortOrder
    });

    tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="padding: 2rem;">Loading reconstructed transactions...</td></tr>`;

    try {
        const resp = await fetch(`/api/reconstructed_transactions?${params.toString()}`);
        const res = await resp.json();

        if (res.success && res.data) {
            reconstructedTxState.totalPages = res.total_pages;

            if (totalCountEl) totalCountEl.textContent = res.total.toLocaleString();

            if (res.data.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" class="text-center" style="padding: 2rem;">No reconstructed transactions found matching criteria.</td></tr>`;
            } else {
                tbody.innerHTML = res.data.map(row => {
                    let statusBadge = `<span class="badge badge-success">Matched</span>`;
                    if (row.match_status.includes("timeout")) {
                        statusBadge = `<span class="badge badge-attack">Timeout</span>`;
                    } else if (row.match_status.includes("ambiguous")) {
                        statusBadge = `<span class="badge badge-secondary">Ambiguous</span>`;
                    }

                    const conflictBadge = (row.label_conflict === "Yes")
                        ? `<span class="badge badge-attack">Yes</span>`
                        : `<span class="badge badge-normal">No</span>`;

                    const latencyStr = (row.latency_ms !== null && row.latency_ms !== undefined)
                        ? `${row.latency_ms} ms`
                        : `<span class="text-muted">-</span>`;

                    return `
                        <tr>
                            <td><small><code>${row.transaction_id || '-'}</code></small></td>
                            <td><small>${row.timestamp ? Number(row.timestamp).toFixed(4) : '-'}</small></td>
                            <td><small>${row.client_ip || '-'}</small></td>
                            <td><small>${row.server_ip || '-'}</small></td>
                            <td>${row.modbus_func_code !== null ? row.modbus_func_code : '-'}</td>
                            <td>${statusBadge}</td>
                            <td>${latencyStr}</td>
                            <td>${conflictBadge}</td>
                        </tr>
                    `;
                }).join("");
            }

            if (pageInfo) pageInfo.textContent = `Page ${res.page} of ${res.total_pages} (${res.total} total)`;
            if (btnPrev) btnPrev.disabled = (res.page <= 1);
            if (btnNext) btnNext.disabled = (res.page >= res.total_pages);
        } else {
            tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger" style="padding: 2rem;">Error: ${res.error || 'Failed to load transactions'}</td></tr>`;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="8" class="text-center text-danger" style="padding: 2rem;">Network error: ${err.message}</td></tr>`;
    }
}


// ==============================================================================
// 4. STAGE B: FEATURES, TIME WINDOW & DUAL FEATURE TABLES
// ==============================================================================

async function triggerFeatures() {
    const timeWindowInput = document.getElementById("inputTimeWindow");
    const timeWindow = timeWindowInput ? parseFloat(timeWindowInput.value) || 60.0 : 60.0;
    
    showAlert(`Partitioning transactions (70/30) and extracting protocol consistency features with time window = ${timeWindow}s... Please wait.`, "loading");
    setButtonLoading("btnRunFeatures", true, "", "Extracting Features...");

    try {
        const response = await fetch("/api/run_features", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ time_window_seconds: timeWindow })
        });
        const result = await response.json();

        if (result.success) {
            showAlert("Features extracted and split manifest generated! Reloading...", "success");
            setTimeout(() => window.location.reload(), 800);
        } else {
            showAlert(`Feature extraction failed: ${result.error}`, "error");
            setButtonLoading("btnRunFeatures", false);
        }
    } catch (err) {
        showAlert(`Network or server error: ${err.message}`, "error");
        setButtonLoading("btnRunFeatures", false);
    }
}

async function applyTimeWindow() {
    const timeWindowInput = document.getElementById("inputTimeWindow");
    const timeWindow = timeWindowInput ? parseFloat(timeWindowInput.value) || 60.0 : 60.0;
    
    if (timeWindow <= 0) {
        showAlert("Time window duration must be greater than 0 seconds.", "error");
        return;
    }

    showAlert(`Applying ${timeWindow}s trailing window and re-extracting protocol features... Downstream models invalidated.`, "loading");
    setButtonLoading("btnApplyWindow", true, "", "Applying Window...");

    try {
        const response = await fetch("/api/run_features", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ time_window_seconds: timeWindow })
        });
        const result = await response.json();

        if (result.success) {
            showAlert(`Time window updated to ${timeWindow}s. Protocol features recalculated successfully.`, "success");
            setTimeout(() => window.location.reload(), 800);
        } else {
            showAlert(`Failed to apply time window: ${result.error}`, "error");
            setButtonLoading("btnApplyWindow", false);
        }
    } catch (err) {
        showAlert(`Network or server error: ${err.message}`, "error");
        setButtonLoading("btnApplyWindow", false);
    }
}

const featureTableState = {
    normal: { page: 1, limit: 20, totalPages: 1, sortBy: "transaction_id", sortOrder: "asc", search: "" },
    replay: { page: 1, limit: 20, totalPages: 1, sortBy: "transaction_id", sortOrder: "asc", search: "" }
};

let normalSearchTimer = null;
function handleNormalSearch(e) {
    clearTimeout(normalSearchTimer);
    normalSearchTimer = setTimeout(() => {
        featureTableState.normal.search = e.target.value;
        loadFeaturesPage("normal", 1);
    }, 300);
}

let replaySearchTimer = null;
function handleReplaySearch(e) {
    clearTimeout(replaySearchTimer);
    replaySearchTimer = setTimeout(() => {
        featureTableState.replay.search = e.target.value;
        loadFeaturesPage("replay", 1);
    }, 300);
}

function changeFeaturesPage(source, delta) {
    const st = featureTableState[source];
    const newPage = st.page + delta;
    if (newPage >= 1 && newPage <= st.totalPages) {
        loadFeaturesPage(source, newPage);
    }
}

function sortFeaturesTable(source, column) {
    const st = featureTableState[source];
    if (st.sortBy === column) {
        st.sortOrder = (st.sortOrder === "asc") ? "desc" : "asc";
    } else {
        st.sortBy = column;
        st.sortOrder = "asc";
    }
    loadFeaturesPage(source, 1);
}

async function loadFeaturesPage(source, page) {
    const isNormal = (source === "normal");
    const prefix = isNormal ? "Normal" : "Replay";
    const tbody = document.getElementById(`tbody${prefix}Features`);
    const pageInfo = document.getElementById(`pageInfo${prefix}`);
    const btnPrev = document.getElementById(`btnPrev${prefix}`);
    const btnNext = document.getElementById(`btnNext${prefix}`);
    const limitSelect = document.getElementById(`limit${prefix}`);

    if (!tbody) return;

    const st = featureTableState[source];
    st.page = page;
    st.limit = limitSelect ? parseInt(limitSelect.value) : 20;

    const params = new URLSearchParams({
        source: source,
        page: st.page,
        limit: st.limit,
        search: st.search,
        sort_by: st.sortBy,
        sort_order: st.sortOrder
    });

    tbody.innerHTML = `<tr><td colspan="14" class="text-center" style="padding: 2rem;">Loading ${source} traffic features...</td></tr>`;

    try {
        const resp = await fetch(`/api/features_data?${params.toString()}`);
        const res = await resp.json();

        if (res.success && res.data) {
            st.totalPages = res.total_pages;

            if (res.data.length === 0) {
                tbody.innerHTML = `<tr><td colspan="14" class="text-center" style="padding: 2rem;">No matching transactions found.</td></tr>`;
            } else {
                tbody.innerHTML = res.data.map(row => {
                    const isAttack = (row.target_is_attack === 1);
                    const labelBadge = isAttack 
                        ? `<span class="badge badge-attack">Replay (1)</span>` 
                        : `<span class="badge badge-normal">Normal (0)</span>`;
                    
                    const partBadge = row.partition === "train" 
                        ? `<span class="badge badge-secondary">Train (70%)</span>`
                        : (row.partition === "test" ? `<span class="badge badge-primary">Test (30%)</span>` : `<span class="badge badge-unknown">Gap</span>`);

                    return `
                        <tr>
                            <td><small><code>${row.transaction_id || '-'}</code></small></td>
                            <td><small>${row.request_timestamp ? Number(row.request_timestamp).toFixed(2) : '-'}</small></td>
                            <td><small>${row.client_ip || '-'}</small></td>
                            <td><small>${row.server_ip || '-'}</small></td>
                            <td>${row.modbus_func_code !== undefined ? row.modbus_func_code : '-'}</td>
                            <td>${row.request_len !== undefined ? row.request_len : '-'}</td>
                            <td>${row.response_len !== undefined ? row.response_len : '-'}</td>
                            <td>${row.response_latency !== undefined && row.response_latency !== null ? Number(row.response_latency).toFixed(4) : '-'}</td>
                            <td>${row.request_iat !== undefined && row.request_iat !== null ? Number(row.request_iat).toFixed(4) : '-'}</td>
                            <td>${row.trans_id_delta !== undefined ? row.trans_id_delta : '-'}</td>
                            <td>${row.tid_previously_seen !== undefined ? (row.tid_previously_seen ? 'Yes' : 'No') : '-'}</td>
                            <td>${row.rolling_cmd_freq_10s !== undefined ? Number(row.rolling_cmd_freq_10s).toFixed(2) : '-'}</td>
                            <td>${partBadge}</td>
                            <td>${labelBadge}</td>
                        </tr>
                    `;
                }).join("");
            }

            if (pageInfo) pageInfo.textContent = `Page ${res.page} of ${res.total_pages} (${res.total} records)`;
            if (btnPrev) btnPrev.disabled = (res.page <= 1);
            if (btnNext) btnNext.disabled = (res.page >= res.total_pages);
        } else {
            tbody.innerHTML = `<tr><td colspan="14" class="text-center text-danger" style="padding: 2rem;">Error: ${res.error || 'Failed to load records'}</td></tr>`;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="14" class="text-center text-danger" style="padding: 2rem;">Network error: ${err.message}</td></tr>`;
    }
}


// ==============================================================================
// 5. STAGE C: MODEL TRAINING, LOSS PROGRESS & FEATURE IMPORTANCE
// ==============================================================================

async function triggerTraining() {
    showAlert("Training XGBoost binary classifier on 70% partition with class weight balancing... Please wait.", "loading");
    setButtonLoading("btnTrainModel", true, "", "Training Model...");

    try {
        const response = await fetch("/api/train_model", { method: "POST" });
        const result = await response.json();

        if (result.success) {
            showAlert("Model successfully trained and serialized! Boosting round history recorded.", "success");
            if (result.training_history) {
                renderTrainingChart(result.training_history);
            }
            if (result.feature_importance) {
                renderFeatureImportance(result.feature_importance);
            }
            updateModelMetaCards(result.metadata);
            setTimeout(() => window.location.reload(), 900);
        } else {
            showAlert(`Training failed: ${result.error}`, "error");
            setButtonLoading("btnTrainModel", false);
        }
    } catch (err) {
        showAlert(`Network or server error: ${err.message}`, "error");
        setButtonLoading("btnTrainModel", false);
    }
}

async function triggerLoadModel() {
    showAlert("Verifying and loading saved model artifact from disk...", "loading");
    setButtonLoading("btnLoadModel", true, "", "Loading Artifacts...");

    try {
        const response = await fetch("/api/load_saved_model", { method: "POST" });
        const result = await response.json();

        if (result.success) {
            showAlert(`Model loaded! Features: ${result.feature_count}. scale_pos_weight: ${result.scale_pos_weight}`, "success");
            if (result.training_history) {
                renderTrainingChart(result.training_history);
            }
            if (result.feature_importance) {
                renderFeatureImportance(result.feature_importance);
            }
            updateModelMetaCards(result);
            setTimeout(() => window.location.reload(), 800);
        } else {
            showAlert(`Failed to load model: ${result.error}`, "error");
            setButtonLoading("btnLoadModel", false);
        }
    } catch (err) {
        showAlert(`Network or server error: ${err.message}`, "error");
        setButtonLoading("btnLoadModel", false);
    }
}

function updateModelMetaCards(data) {
    if (!data) return;
    const emptyState = document.getElementById("emptyModelState");
    const dynGrid = document.getElementById("dynamicModelMetaGrid");
    if (emptyState) emptyState.style.display = "none";
    if (dynGrid) dynGrid.style.display = "grid";

    if (document.getElementById("metaModelName")) document.getElementById("metaModelName").textContent = data.model_name || "XGBClassifier";
    if (document.getElementById("metaStatus")) document.getElementById("metaStatus").textContent = data.status || "Serialized & Ready";
    if (document.getElementById("metaSampleCount")) document.getElementById("metaSampleCount").textContent = data.sample_count || (data.train_samples ? data.train_samples.total : "-");
    if (document.getElementById("metaFeatureCount")) document.getElementById("metaFeatureCount").textContent = data.feature_count || 10;
    if (document.getElementById("metaDuration")) document.getElementById("metaDuration").textContent = (data.duration_seconds || data.training_duration_seconds || 0.1) + " s";
    if (document.getElementById("metaRounds")) document.getElementById("metaRounds").textContent = data.boosting_rounds || 100;
    if (document.getElementById("metaVersion")) document.getElementById("metaVersion").textContent = data.version || "v1.0";
    if (document.getElementById("metaScaleWeight")) document.getElementById("metaScaleWeight").textContent = data.scale_pos_weight || 1.0;
}

function renderTrainingChart(history) {
    const emptyState = document.getElementById("chartEmptyState");
    const canvasWrapper = document.getElementById("chartCanvasWrapper");
    const svg = document.getElementById("trainingLossSvg");
    const finalLossEl = document.getElementById("chartFinalLoss");

    const losses = history ? (history.eval_metric_history || history.training_logloss || []) : [];

    if (!svg || losses.length === 0) {
        if (emptyState) emptyState.style.display = "block";
        if (canvasWrapper) canvasWrapper.style.display = "none";
        return;
    }

    if (emptyState) emptyState.style.display = "none";
    if (canvasWrapper) canvasWrapper.style.display = "block";

    const n = losses.length;
    const finalLoss = losses[n - 1];

    if (finalLossEl) {
        finalLossEl.innerHTML = `Final Loss: <strong>${finalLoss.toFixed(5)}</strong> (Round ${n})`;
    }

    const width = 800;
    const height = 240;
    const padding = { top: 20, right: 35, bottom: 40, left: 65 };
    const chartW = width - padding.left - padding.right;
    const chartH = height - padding.top - padding.bottom;

    const minLoss = Math.min(...losses) * 0.95;
    const maxLoss = Math.max(...losses) * 1.05;
    const lossRange = (maxLoss - minLoss) || 1.0;

    const getX = (idx) => padding.left + (idx / Math.max(1, n - 1)) * chartW;
    const getY = (val) => padding.top + chartH - ((val - minLoss) / lossRange) * chartH;

    let svgContent = "";

    // Gridlines & Y-axis labels (5 ticks)
    const numTicks = 5;
    for (let i = 0; i <= numTicks; i++) {
        const tickVal = minLoss + (i / numTicks) * lossRange;
        const tickY = getY(tickVal);
        svgContent += `
            <line class="chart-grid-line" x1="${padding.left}" y1="${tickY}" x2="${width - padding.right}" y2="${tickY}" />
            <text class="chart-axis-text" x="${padding.left - 10}" y="${tickY + 4}" text-anchor="end">${tickVal.toFixed(4)}</text>
        `;
    }

    // X-axis ticks
    const xStep = Math.max(1, Math.floor(n / 6));
    for (let r = 0; r < n; r += xStep) {
        const tickX = getX(r);
        svgContent += `
            <line class="chart-grid-line" x1="${tickX}" y1="${padding.top}" x2="${tickX}" y2="${height - padding.bottom}" />
            <text class="chart-axis-text" x="${tickX}" y="${height - padding.bottom + 20}" text-anchor="middle">R${r + 1}</text>
        `;
    }
    if ((n - 1) % xStep !== 0) {
        const lastX = getX(n - 1);
        svgContent += `
            <text class="chart-axis-text" x="${lastX}" y="${height - padding.bottom + 20}" text-anchor="middle">R${n}</text>
        `;
    }

    svgContent += `
        <line class="chart-axis-line" x1="${padding.left}" y1="${padding.top}" x2="${padding.left}" y2="${height - padding.bottom}" />
        <line class="chart-axis-line" x1="${padding.left}" y1="${height - padding.bottom}" x2="${width - padding.right}" y2="${height - padding.bottom}" />
    `;

    const points = losses.map((loss, idx) => `${getX(idx).toFixed(1)},${getY(loss).toFixed(1)}`);
    const pathD = "M " + points.join(" L ");
    svgContent += `<path class="chart-data-line" d="${pathD}" />`;

    losses.forEach((loss, idx) => {
        const cx = getX(idx).toFixed(1);
        const cy = getY(loss).toFixed(1);
        svgContent += `
            <circle class="chart-point" cx="${cx}" cy="${cy}" r="3.5"
                    data-round="${idx + 1}" data-loss="${loss.toFixed(6)}"
                    onmouseover="showChartTooltip(evt)" onmouseout="hideChartTooltip()" />
        `;
    });

    svg.innerHTML = svgContent;
}

function showChartTooltip(evt) {
    const tooltip = document.getElementById("chartTooltip");
    if (!tooltip) return;
    const target = evt.target;
    const round = target.getAttribute("data-round");
    const loss = target.getAttribute("data-loss");

    tooltip.innerHTML = `Round ${round}: <strong>${loss}</strong> logloss`;
    tooltip.style.left = (evt.pageX + 10) + "px";
    tooltip.style.top = (evt.pageY - 25) + "px";
    tooltip.style.display = "block";
}

function hideChartTooltip() {
    const tooltip = document.getElementById("chartTooltip");
    if (tooltip) tooltip.style.display = "none";
}

function renderFeatureImportance(importanceList) {
    const emptyState = document.getElementById("importanceEmptyState");
    const content = document.getElementById("importanceContent");
    const barsContainer = document.getElementById("featureImportanceBars");

    if (!importanceList || importanceList.length === 0) {
        if (emptyState) emptyState.style.display = "block";
        if (content) content.style.display = "none";
        return;
    }

    if (emptyState) emptyState.style.display = "none";
    if (content) content.style.display = "block";

    if (barsContainer) {
        barsContainer.innerHTML = importanceList.map(item => {
            const pct = (item.importance * 100).toFixed(2);
            return `
                <div class="feature-bar-row" style="display: flex; align-items: center; gap: 1rem;">
                    <div style="width: 220px; font-size: 0.85rem; font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis;" title="${item.feature}">
                        ${item.feature}
                    </div>
                    <div style="flex: 1; background: #e2e8f0; height: 18px; border-radius: 4px; overflow: hidden;">
                        <div style="width: ${pct}%; background: #0f4c81; height: 100%; border-radius: 4px; transition: width 0.3s ease;"></div>
                    </div>
                    <div style="width: 70px; text-align: right; font-size: 0.85rem; font-weight: 600; color: var(--text-main);">
                        ${pct}%
                    </div>
                </div>
            `;
        }).join("");
    }
}


// ==============================================================================
// 6. STAGE D: EVALUATION CHARTS & TEST PREDICTIONS TABLE
// ==============================================================================

async function triggerEvaluation() {
    showAlert("Evaluating Rule Baseline and XGBoost on the held-out 30% test partition... Please wait.", "loading");
    setButtonLoading("btnRunEval", true, "", "Evaluating Models...");

    try {
        const response = await fetch("/api/run_evaluation", { method: "POST" });
        const result = await response.json();

        if (result.success) {
            showAlert("Evaluation completed successfully! Reloading comparative metrics...", "success");
            setTimeout(() => window.location.reload(), 800);
        } else {
            showAlert(`Evaluation failed: ${result.error}`, "error");
            setButtonLoading("btnRunEval", false);
        }
    } catch (err) {
        showAlert(`Network or server error: ${err.message}`, "error");
        setButtonLoading("btnRunEval", false);
    }
}

function renderRocCurveChart(rocData) {
    const svg = document.getElementById("rocCurveSvg");
    if (!svg || !rocData || !rocData.fpr || !rocData.tpr) return;

    const width = 340;
    const height = 260;
    const padding = { top: 20, right: 20, bottom: 40, left: 50 };
    const chartW = width - padding.left - padding.right;
    const chartH = height - padding.top - padding.bottom;

    const getX = (fpr) => padding.left + fpr * chartW;
    const getY = (tpr) => padding.top + chartH - tpr * chartH;

    let svgContent = "";

    // Gridlines and axis labels (0.0 to 1.0)
    for (let i = 0; i <= 5; i++) {
        const v = i / 5;
        const y = getY(v);
        const x = getX(v);
        svgContent += `
            <line class="chart-grid-line" x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}" />
            <text class="chart-axis-text" x="${padding.left - 8}" y="${y + 4}" text-anchor="end">${v.toFixed(1)}</text>
            <line class="chart-grid-line" x1="${x}" y1="${padding.top}" x2="${x}" y2="${height - padding.bottom}" />
            <text class="chart-axis-text" x="${x}" y="${height - padding.bottom + 18}" text-anchor="middle">${v.toFixed(1)}</text>
        `;
    }

    // Axes
    svgContent += `
        <line class="chart-axis-line" x1="${padding.left}" y1="${padding.top}" x2="${padding.left}" y2="${height - padding.bottom}" />
        <line class="chart-axis-line" x1="${padding.left}" y1="${height - padding.bottom}" x2="${width - padding.right}" y2="${height - padding.bottom}" />
    `;

    // Diagonal random baseline
    svgContent += `
        <line x1="${padding.left}" y1="${height - padding.bottom}" x2="${width - padding.right}" y2="${padding.top}"
              stroke="#94a3b8" stroke-width="1.5" stroke-dasharray="4,4" />
    `;

    // ROC Line Path
    const points = rocData.fpr.map((fpr, i) => `${getX(fpr).toFixed(1)},${getY(rocData.tpr[i]).toFixed(1)}`);
    const pathD = "M " + points.join(" L ");
    svgContent += `<path d="${pathD}" fill="none" stroke="#0f4c81" stroke-width="2.5" />`;

    // Dots
    rocData.fpr.forEach((fpr, i) => {
        const tpr = rocData.tpr[i];
        svgContent += `
            <circle cx="${getX(fpr).toFixed(1)}" cy="${getY(tpr).toFixed(1)}" r="3" fill="#0f4c81"
                    data-fpr="${fpr}" data-tpr="${tpr}"
                    onmouseover="showRocTooltip(evt)" onmouseout="hideRocTooltip()" />
        `;
    });

    svg.innerHTML = svgContent;
}

function showRocTooltip(evt) {
    const tooltip = document.getElementById("rocTooltip");
    if (!tooltip) return;
    const target = evt.target;
    const fpr = target.getAttribute("data-fpr");
    const tpr = target.getAttribute("data-tpr");
    tooltip.innerHTML = `FPR: <strong>${fpr}</strong> | TPR: <strong>${tpr}</strong>`;
    tooltip.style.left = (evt.pageX + 10) + "px";
    tooltip.style.top = (evt.pageY - 25) + "px";
    tooltip.style.display = "block";
}

function hideRocTooltip() {
    const tooltip = document.getElementById("rocTooltip");
    if (tooltip) tooltip.style.display = "none";
}

function renderPredictionDistChart(distData) {
    const svg = document.getElementById("predDistSvg");
    if (!svg || !distData || !distData.normal_counts || !distData.replay_counts) return;

    const width = 340;
    const height = 260;
    const padding = { top: 20, right: 20, bottom: 40, left: 45 };
    const chartW = width - padding.left - padding.right;
    const chartH = height - padding.top - padding.bottom;

    const normCounts = distData.normal_counts;
    const repCounts = distData.replay_counts;
    const numBins = normCounts.length;

    const maxCount = Math.max(...normCounts, ...repCounts, 1);

    let svgContent = "";

    // Y ticks
    for (let i = 0; i <= 4; i++) {
        const val = Math.round((i / 4) * maxCount);
        const y = padding.top + chartH - (i / 4) * chartH;
        svgContent += `
            <line class="chart-grid-line" x1="${padding.left}" y1="${y}" x2="${width - padding.right}" y2="${y}" />
            <text class="chart-axis-text" x="${padding.left - 6}" y="${y + 4}" text-anchor="end">${val}</text>
        `;
    }

    // Axes
    svgContent += `
        <line class="chart-axis-line" x1="${padding.left}" y1="${padding.top}" x2="${padding.left}" y2="${height - padding.bottom}" />
        <line class="chart-axis-line" x1="${padding.left}" y1="${height - padding.bottom}" x2="${width - padding.right}" y2="${height - padding.bottom}" />
    `;

    // Bars
    const binW = chartW / numBins;
    for (let i = 0; i < numBins; i++) {
        const x = padding.left + i * binW;
        const normH = (normCounts[i] / maxCount) * chartH;
        const repH = (repCounts[i] / maxCount) * chartH;
        const subW = (binW - 4) / 2;

        // Normal bar (Green)
        svgContent += `
            <rect x="${x + 2}" y="${height - padding.bottom - normH}" width="${subW}" height="${normH}"
                  fill="#10b981" rx="1" data-label="Normal" data-count="${normCounts[i]}" data-bin="${(i*0.1).toFixed(1)}-${((i+1)*0.1).toFixed(1)}"
                  onmouseover="showDistTooltip(evt)" onmouseout="hideDistTooltip()" />
        `;

        // Replay bar (Red)
        svgContent += `
            <rect x="${x + 2 + subW}" y="${height - padding.bottom - repH}" width="${subW}" height="${repH}"
                  fill="#e11d48" rx="1" data-label="Replay" data-count="${repCounts[i]}" data-bin="${(i*0.1).toFixed(1)}-${((i+1)*0.1).toFixed(1)}"
                  onmouseover="showDistTooltip(evt)" onmouseout="hideDistTooltip()" />
        `;

        // X tick label (0.0, 0.5, 1.0)
        if (i === 0 || i === 5 || i === 9) {
            const labelX = x + binW / 2;
            const labelText = (i * 0.1).toFixed(1);
            svgContent += `
                <text class="chart-axis-text" x="${labelX}" y="${height - padding.bottom + 16}" text-anchor="middle">${labelText}</text>
            `;
        }
    }

    svg.innerHTML = svgContent;
}

function showDistTooltip(evt) {
    const tooltip = document.getElementById("distTooltip");
    if (!tooltip) return;
    const target = evt.target;
    const label = target.getAttribute("data-label");
    const count = target.getAttribute("data-count");
    const bin = target.getAttribute("data-bin");
    tooltip.innerHTML = `<strong>${label}</strong> [Prob ${bin}]: <strong>${count}</strong> tx`;
    tooltip.style.left = (evt.pageX + 10) + "px";
    tooltip.style.top = (evt.pageY - 25) + "px";
    tooltip.style.display = "block";
}

function hideDistTooltip() {
    const tooltip = document.getElementById("distTooltip");
    if (tooltip) tooltip.style.display = "none";
}

// Prediction table filter and pagination state
const predTableState = {
    page: 1,
    limit: 20,
    totalPages: 1,
    sortBy: "transaction_id",
    sortOrder: "asc",
    search: ""
};

let predSearchTimer = null;
function handlePredictionSearch(e) {
    clearTimeout(predSearchTimer);
    predSearchTimer = setTimeout(() => {
        predTableState.search = e.target.value;
        loadPredictionsPage(1);
    }, 300);
}

function changePredictionsPage(delta) {
    const newPage = predTableState.page + delta;
    if (newPage >= 1 && newPage <= predTableState.totalPages) {
        loadPredictionsPage(newPage);
    }
}

function sortPredictionsTable(column) {
    if (predTableState.sortBy === column) {
        predTableState.sortOrder = (predTableState.sortOrder === "asc") ? "desc" : "asc";
    } else {
        predTableState.sortBy = column;
        predTableState.sortOrder = "asc";
    }
    loadPredictionsPage(1);
}

async function loadPredictionsPage(page) {
    const tbody = document.getElementById("tbodyPredictions");
    const pageInfo = document.getElementById("pageInfoPred");
    const btnPrev = document.getElementById("btnPrevPred");
    const btnNext = document.getElementById("btnNextPred");

    const predFilter = document.getElementById("filterPredLabel");
    const actualFilter = document.getElementById("filterActualLabel");
    const statusFilter = document.getElementById("filterStatus");
    const datasetFilter = document.getElementById("filterDataset");
    const limitSelect = document.getElementById("limitPredictions");

    if (!tbody) return;

    predTableState.page = page;
    predTableState.limit = limitSelect ? parseInt(limitSelect.value) : 20;

    const params = new URLSearchParams({
        page: predTableState.page,
        limit: predTableState.limit,
        search: predTableState.search,
        sort_by: predTableState.sortBy,
        sort_order: predTableState.sortOrder,
        pred_filter: predFilter ? predFilter.value : "all",
        actual_filter: actualFilter ? actualFilter.value : "all",
        status_filter: statusFilter ? statusFilter.value : "all",
        dataset_filter: datasetFilter ? datasetFilter.value : "all"
    });

    tbody.innerHTML = `<tr><td colspan="11" class="text-center" style="padding: 2rem;">Loading test transaction predictions...</td></tr>`;

    try {
        const resp = await fetch(`/api/predictions_data?${params.toString()}`);
        const res = await resp.json();

        if (res.success && res.data) {
            predTableState.totalPages = res.total_pages;

            if (res.data.length === 0) {
                tbody.innerHTML = `<tr><td colspan="11" class="text-center" style="padding: 2rem;">No test predictions matching filter criteria.</td></tr>`;
            } else {
                tbody.innerHTML = res.data.map(row => {
                    // Predicted label badge
                    const predBadge = (row.xgb_pred === 1)
                        ? `<span class="badge badge-attack">Replay (1)</span>`
                        : `<span class="badge badge-normal">Normal (0)</span>`;

                    // Actual label badge
                    let actualBadge = `<span class="badge badge-unknown">Unknown</span>`;
                    if (row.target_is_attack === 1) {
                        actualBadge = `<span class="badge badge-attack">Replay (1)</span>`;
                    } else if (row.target_is_attack === 0) {
                        actualBadge = `<span class="badge badge-normal">Normal (0)</span>`;
                    }

                    // Prediction status badge with color coding
                    let statusBadgeClass = "badge-unknown";
                    const statusStr = row.prediction_status || "Not Evaluated";
                    if (statusStr.includes("TN") || statusStr.includes("True Negative")) {
                        statusBadgeClass = "badge-tn"; // Green
                    } else if (statusStr.includes("TP") || statusStr.includes("True Positive")) {
                        statusBadgeClass = "badge-tp"; // Red
                    } else if (statusStr.includes("FP") || statusStr.includes("False Positive")) {
                        statusBadgeClass = "badge-fp"; // Orange
                    } else if (statusStr.includes("FN") || statusStr.includes("False Negative")) {
                        statusBadgeClass = "badge-fn"; // Purple
                    }

                    const statusBadge = `<span class="${statusBadgeClass}">${statusStr}</span>`;

                    const probPercent = (row.replay_probability !== undefined && row.replay_probability !== null)
                        ? Number(row.replay_probability).toFixed(4)
                        : "-";

                    const confPercent = (row.confidence !== undefined && row.confidence !== null)
                        ? (Number(row.confidence)).toFixed(1) + "%"
                        : "-";

                    return `
                        <tr>
                            <td><small><code>${row.transaction_id || '-'}</code></small></td>
                            <td><small>${row.request_timestamp ? Number(row.request_timestamp).toFixed(2) : '-'}</small></td>
                            <td><small class="text-muted">${row.source_dataset || '-'}</small></td>
                            <td><small>${row.client_ip || '-'}</small></td>
                            <td><small>${row.server_ip || '-'}</small></td>
                            <td>${row.modbus_func_code !== undefined ? row.modbus_func_code : '-'}</td>
                            <td>${actualBadge}</td>
                            <td>${predBadge}</td>
                            <td><strong>${probPercent}</strong></td>
                            <td>${confPercent}</td>
                            <td>${statusBadge}</td>
                        </tr>
                    `;
                }).join("");
            }

            if (pageInfo) pageInfo.textContent = `Page ${res.page} of ${res.total_pages} (${res.total_filtered} filtered)`;
            if (btnPrev) btnPrev.disabled = (res.page <= 1);
            if (btnNext) btnNext.disabled = (res.page >= res.total_pages);
        } else {
            tbody.innerHTML = `<tr><td colspan="11" class="text-center text-danger" style="padding: 2rem;">Error: ${res.error || 'Failed to load test predictions'}</td></tr>`;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="11" class="text-center text-danger" style="padding: 2rem;">Network error: ${err.message}</td></tr>`;
    }
}


// ==============================================================================
// 7. AUTOMATIC PAGE INITIALIZATION
// ==============================================================================

document.addEventListener("DOMContentLoaded", function() {
    // Stage A: Initialize reconstructed transactions preview table if present
    if (document.getElementById("tbodyReconstructedTx")) {
        loadReconstructedTxPage(1);
    }

    // Stage B: Initialize feature tables if present
    if (document.getElementById("tbodyNormalFeatures")) {
        loadFeaturesPage("normal", 1);
    }
    if (document.getElementById("tbodyReplayFeatures")) {
        loadFeaturesPage("replay", 1);
    }

    // Stage C: Initialize training progress chart & feature importance if present
    if (document.getElementById("trainingLossSvg")) {
        const histScript = document.getElementById("initialTrainingHistory");
        if (histScript && histScript.textContent.trim()) {
            try {
                const historyData = JSON.parse(histScript.textContent);
                if (historyData) {
                    renderTrainingChart(historyData);
                }
            } catch (e) {
                console.warn("Could not parse initial training history JSON:", e);
            }
        }
    }
    if (document.getElementById("featureImportanceBars")) {
        const impScript = document.getElementById("initialFeatureImportance");
        if (impScript && impScript.textContent.trim()) {
            try {
                const impData = JSON.parse(impScript.textContent);
                if (impData) {
                    renderFeatureImportance(impData);
                }
            } catch (e) {
                console.warn("Could not parse initial feature importance JSON:", e);
            }
        }
    }

    // Stage D: Initialize evaluation charts & test predictions table if present
    if (document.getElementById("rocCurveSvg") || document.getElementById("predDistSvg")) {
        const evalScript = document.getElementById("initialEvalData");
        if (evalScript && evalScript.textContent.trim()) {
            try {
                const evalData = JSON.parse(evalScript.textContent);
                if (evalData) {
                    if (evalData.roc_curve) renderRocCurveChart(evalData.roc_curve);
                    if (evalData.prediction_distribution) renderPredictionDistChart(evalData.prediction_distribution);
                }
            } catch (e) {
                console.warn("Could not parse initial evaluation data JSON:", e);
            }
        }
    }

    if (document.getElementById("tbodyPredictions")) {
        loadPredictionsPage(1);
    }
});
