const form = document.querySelector("#file-form");
const input = document.querySelector("#input-file");
const keyFile = document.querySelector("#key-file");
const keyId = document.querySelector("#key-id");
const outputName = document.querySelector("#output-name");
const processButton = document.querySelector("#process-button");
const operationStatus = document.querySelector("#operation-status");
const inputModeField = document.querySelector("#input-mode");
const textInput = document.querySelector("#input-text");
const keyText = document.querySelector("#key-text");
const keyModeField = document.querySelector("#key-mode");
let mode = "encrypt";
let inputMode = "file";
let keyMode = "file";

function showStatus(element, message, type) {
  element.hidden = false;
  element.className = `status ${type}`;
  element.innerHTML = message;
}
function setMode(nextMode) {
  mode = nextMode;
  document.querySelectorAll(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.mode === mode));
  document.querySelector("#verb").textContent = mode;
  processButton.textContent = `${mode[0].toUpperCase()}${mode.slice(1)} file`;
  keyFile.name = mode === "encrypt" ? "public_key" : "private_key";
  keyFile.required = !keyId.value && keyMode === "file";
  document.querySelector("#key-help").textContent = mode === "encrypt" ? "Use the public key for encryption." : "Use the private key for decryption.";
  outputName.placeholder = mode === "encrypt" ? "file.enc" : "decrypted-file";
  document.querySelector("#text-verb").textContent = mode;
  document.querySelector("#text-help").textContent = mode === "encrypt"
    ? "Encrypted output is shown as Base64 text that can be copied."
    : "Paste the Base64 ciphertext produced by Encrypt text.";
}
document.querySelectorAll(".tab").forEach((tab) => tab.addEventListener("click", () => setMode(tab.dataset.mode)));
document.querySelectorAll(".input-tab").forEach((tab) => tab.addEventListener("click", () => {
  inputMode = tab.dataset.inputMode;
  inputModeField.value = inputMode;
  document.querySelectorAll(".input-tab").forEach((item) => item.classList.toggle("active", item === tab));
  document.querySelector("#file-input-panel").hidden = inputMode !== "file";
  document.querySelector("#text-input-panel").hidden = inputMode !== "text";
  input.required = inputMode === "file";
  textInput.required = inputMode === "text";
  keyFile.required = !keyId.value && keyMode === "file";
}));
document.querySelectorAll(".key-input-tab").forEach((tab) => tab.addEventListener("click", () => {
  keyMode = tab.dataset.keyMode;
  keyModeField.value = keyMode;
  document.querySelectorAll(".key-input-tab").forEach((item) => item.classList.toggle("active", item === tab));
  document.querySelector("#key-file-panel").hidden = keyMode !== "file";
  document.querySelector("#key-text-panel").hidden = keyMode !== "text";
  keyFile.required = !keyId.value && keyMode === "file";
}));
input.addEventListener("change", () => {
  const file = input.files[0];
  document.querySelector("#file-title").textContent = file ? file.name : "Choose a file";
  document.querySelector("#file-meta").textContent = file ? `${(file.size / 1024).toFixed(1)} KB selected` : "The selected file will stay in the app's private workspace.";
});
form.addEventListener("submit", async (event) => {
  event.preventDefault();
  if ((inputMode === "file" && !input.files.length) || (inputMode === "text" && !textInput.value.trim()) || (keyMode === "file" && !keyFile.files.length && !keyId.value) || (keyMode === "text" && !keyText.value.trim())) return showStatus(operationStatus, "Choose an input and a matching key.", "error");
  processButton.disabled = true; processButton.textContent = "Working...";
  const data = new FormData(form);
  data.set("output_name", outputName.value);
  if (keyMode === "text") data.set(mode === "encrypt" ? "public_key_text" : "private_key_text", keyText.value);
  const response = await fetch(`/api/${mode}`, { method: "POST", body: data });
  const result = await response.json();
  processButton.disabled = false; setMode(mode);
  if (!response.ok || !result.ok) return showStatus(operationStatus, result.error || "Operation failed.", "error");
  const textResult = result.text_output
    ? `<textarea class="result-text" readonly>${result.text_output}</textarea><button type="button" class="copy-button">Copy text</button>`
    : "";
  showStatus(operationStatus, `Completed: <strong>${result.output_name}</strong> &middot; <a href="${result.download_url}">Download result</a>${textResult}`, "success");
  const copyButton = operationStatus.querySelector(".copy-button");
  if (copyButton) copyButton.addEventListener("click", async () => {
    await navigator.clipboard.writeText(operationStatus.querySelector(".result-text").value);
    copyButton.textContent = "Copied";
  });
});
document.querySelector("#key-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const button = event.target.querySelector("button"); button.disabled = true; button.textContent = "Generating...";
  const response = await fetch("/api/keys", { method: "POST", body: new FormData(event.target) });
  const result = await response.json(); button.disabled = false; button.textContent = "Generate RSA key pair";
  if (!response.ok || !result.ok) return showStatus(document.querySelector("#key-status"), result.error || "Could not generate keys.", "error");
  keyId.value = result.key_id; keyFile.required = false;
  document.querySelector("#key-links").hidden = false;
  document.querySelector("#key-links").innerHTML = `
    <a href="${result.public_key.url}">Download public.key</a>
    <button type="button" class="copy-button key-copy" data-copy="${result.public_key.text}">Copy public key text</button>
    <a href="${result.private_key.url}">Download private.key</a>
    <button type="button" class="copy-button key-copy" data-copy="${result.private_key.text}">Copy private key text</button>
    <small>Key pair selected. Private key text is shown only for this local academic tool.</small>`;
  document.querySelectorAll(".key-copy").forEach((copy) => copy.addEventListener("click", async () => {
    await navigator.clipboard.writeText(copy.dataset.copy);
    copy.textContent = "Copied";
  }));
  showStatus(document.querySelector("#key-status"), "Key pair generated successfully.", "success");
});
