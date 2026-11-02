/* ==================================================================
   week4_optimization/static/app.js
   ------------------------------------------------------------------
   The client half of the async job queue.

   TWO DIFFERENT BROWSER APIS, AND WHY
     XMLHttpRequest  -> upload progress. fetch() still cannot report
                        how many bytes of a request body have been sent.
     fetch()         -> polling. It is promise-based and much nicer for
                        small repeated JSON requests.

   FLOW
     submit -> XHR POST /analyze -> { job_id } -> poll /api/jobs/<id>
            -> status "done"  -> location.href = /report/<id>
            -> status "error" -> show the message
   ================================================================== */

// ------------------------------------------------------------------
// Element handles
// ------------------------------------------------------------------
const form = document.getElementById("upload-form");
const submitButton = document.getElementById("submit-btn");
const demoButton = document.getElementById("demo-btn");
const progressPanel = document.getElementById("progress-panel");
const progressBar = document.getElementById("progress-bar");
const progressPercent = document.getElementById("progress-percent");
const progressStatus = document.getElementById("progress-status");
const progressHint = document.getElementById("progress-hint");
const errorPanel = document.getElementById("error-panel");

// ------------------------------------------------------------------
// UI helpers
// ------------------------------------------------------------------
let pollTimer = null;

function showProgress(percent, message) {
  progressPanel.hidden = false;
  errorPanel.hidden = true;
  progressBar.style.width = percent + "%";
  progressPercent.textContent = percent + "%";
  progressStatus.textContent = message;
}

function showError(message) {
  errorPanel.hidden = false;
  errorPanel.textContent = message;
  progressPanel.hidden = true;

  // Re-enable the buttons so the user can try again.
  submitButton.disabled = false;
  demoButton.disabled = false;
}

// setTimeout wrapped in a Promise so we can `await` a pause.
function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

// ------------------------------------------------------------------
// Poll the job until it finishes
// ------------------------------------------------------------------
async function pollJob(jobId) {
  let lastProgress = 0;

  while (true) {
    let response;

    try {
      response = await fetch("/api/jobs/" + jobId);
    } catch (networkError) {
      // The server may be restarting; one failed poll is not fatal.
      await sleep(1000);
      continue;
    }

    if (response.status === 404) {
      throw new Error("This job no longer exists (the server was restarted).");
    }

    const job = await response.json();

    // The server is the single source of truth for progress. We never
    // let the bar move backwards, which can happen if two responses
    // arrive out of order.
    lastProgress = Math.max(lastProgress, job.progress || 0);
    showProgress(lastProgress, job.message || job.status);

    if (job.status === "done") {
      progressHint.textContent = "Opening report…";
      // Small delay so the user actually sees 100%.
      await sleep(300);
      window.location.href = "/report/" + jobId;
      return;
    }

    if (job.status === "error") {
      throw new Error(job.error || "Analysis failed.");
    }

    await sleep(500);   // twice per second
  }
}

// ------------------------------------------------------------------
// Upload with real progress
// ------------------------------------------------------------------
function uploadFile(file, threshold) {
  return new Promise((resolve, reject) => {
    const body = new FormData();
    body.append("logfile", file);
    if (threshold) body.append("threshold", threshold);

    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/analyze");

    // upload.onprogress fires as bytes leave the browser.
    // total can be 0 for some proxies; guard before dividing.
    xhr.upload.onprogress = (event) => {
      if (!event.lengthComputable) return;
      const uploadPercent = Math.round((event.loaded / event.total) * 100);
      // Upload is only the first 10% of the perceived job.
      showProgress(Math.round(uploadPercent * 0.1), "Uploading… " + uploadPercent + "%");
    };

    xhr.onload = () => {
      let payload = {};
      try {
        payload = JSON.parse(xhr.responseText);
      } catch (parseError) {
        reject(new Error("Server sent an unexpected response."));
        return;
      }

      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(payload);
      } else {
        reject(new Error(payload.error || "Upload failed (" + xhr.status + ")."));
      }
    };

    xhr.onerror = () => reject(new Error("Network error during upload."));
    xhr.send(body);
  });
}

// ------------------------------------------------------------------
// Submit handler
// ------------------------------------------------------------------
form.addEventListener("submit", async (event) => {
  event.preventDefault();               // stop the browser's own submit

  const fileInput = document.getElementById("logfile");
  const file = fileInput.files[0];

  if (!file) {
    showError("Choose a .log file first.");
    return;
  }

  submitButton.disabled = true;
  demoButton.disabled = true;
  showProgress(0, "Uploading…");

  try {
    const threshold = form.querySelector('[name="threshold"]').value;
    const accepted = await uploadFile(file, threshold);

    showProgress(10, "Queued — waiting for a worker…");
    await pollJob(accepted.job_id);
  } catch (error) {
    showError(error.message);
  }
});

// ------------------------------------------------------------------
// Demo button - same flow, no upload
// ------------------------------------------------------------------
demoButton.addEventListener("click", async () => {
  submitButton.disabled = true;
  demoButton.disabled = true;
  showProgress(5, "Queuing demo log…");

  try {
    const response = await fetch(form.dataset.demoUrl, { method: "POST" });
    const payload = await response.json();

    if (!response.ok) throw new Error(payload.error || "Could not queue the demo.");

    await pollJob(payload.job_id);
  } catch (error) {
    showError(error.message);
  }
});

// ------------------------------------------------------------------
// Drag and drop (nice touch, ~6 lines)
// ------------------------------------------------------------------
const dropZone = document.querySelector(".drop");

["dragenter", "dragover"].forEach((name) => {
  dropZone.addEventListener(name, (event) => {
    event.preventDefault();
    dropZone.classList.add("dragging");
  });
});

["dragleave", "drop"].forEach((name) => {
  dropZone.addEventListener(name, () => dropZone.classList.remove("dragging"));
});

dropZone.addEventListener("drop", (event) => {
  event.preventDefault();
  const dropped = event.dataTransfer.files;
  if (dropped.length > 0) {
    document.getElementById("logfile").files = dropped;
    document.querySelector(".drop-text").textContent = dropped[0].name;
  }
});
