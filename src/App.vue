<script setup lang="ts">
import { ref } from "vue";

const seed = ref("");
const password = ref("");
const encrypted = ref("");
const decrypted = ref("");
const error = ref("");

// Шифрование
async function encrypt() {
  error.value = "";
  if (!seed.value.trim() || !password.value) {
    error.value = "Введите seed-фразу и пароль";
    return;
  }

  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const key = await deriveKey(password.value, salt);
    const encoded = new TextEncoder().encode(seed.value);
    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encoded
    );

    const payload = {
      salt: arrayBufferToBase64(salt),
      iv: arrayBufferToBase64(iv),
      ciphertext: arrayBufferToBase64(ciphertext),
    };

    encrypted.value = JSON.stringify(payload, null, 2);
    seed.value = "";
    password.value = "";
  } catch (err: any) {
    error.value = `Ошибка шифрования: ${err.message}`;
  }
}

// Расшифровка
async function decrypt() {
  error.value = "";
  if (!encrypted.value.trim() || !password.value) {
    error.value = "Введите зашифрованные данные и пароль";
    return;
  }

  try {
    const payload = JSON.parse(encrypted.value);
    const salt = base64ToArrayBuffer(payload.salt);
    const iv = base64ToArrayBuffer(payload.iv);
    const ciphertext = base64ToArrayBuffer(payload.ciphertext);

    const key = await deriveKey(password.value, salt);
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );

    decrypted.value = new TextDecoder().decode(decryptedBuffer);
    password.value = "";
  } catch (err: any) {
    error.value = "Неверный пароль или данные повреждены";
    decrypted.value = "";
  }
}

// Получение ключа из пароля (PBKDF2)
async function deriveKey(password: string, salt: Uint8Array) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 600000, // OWASP рекомендует 600k+ для 2024
      hash: "SHA-256",
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// Хелперы base64
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function clear() {
  seed.value = "";
  password.value = "";
  encrypted.value = "";
  decrypted.value = "";
  error.value = "";
}

function copyEncrypted() {
  navigator.clipboard.writeText(encrypted.value);
}

function copyDecrypted() {
  navigator.clipboard.writeText(decrypted.value);
}
</script>

<template>
  <div class="container">
    <header>
      <h1>🔐 Crypto Vault</h1>
      <p class="subtitle">
        Офлайн-шифрование seed-фраз (AES-256-GCM + PBKDF2)
      </p>
    </header>

    <div v-if="error" class="alert error">⚠️ {{ error }}</div>

    <section class="card">
      <h2>🔒 Зашифровать</h2>
      <textarea
        v-model="seed"
        placeholder="Введите seed-фразу (12/24 слова)"
        rows="3"
      ></textarea>
      <input
        v-model="password"
        type="password"
        placeholder="Сильный пароль"
      />
      <button @click="encrypt" class="btn primary">Зашифровать</button>

      <div v-if="encrypted" class="result">
        <div class="result-header">
          <strong>Зашифрованные данные (сохрани в файл):</strong>
          <button @click="copyEncrypted" class="btn-copy">📋 Копировать</button>
        </div>
        <pre>{{ encrypted }}</pre>
      </div>
    </section>

    <section class="card">
      <h2>🔓 Расшифровать</h2>
      <textarea
        v-model="encrypted"
        placeholder='{"salt":"...","iv":"...","ciphertext":"..."}'
        rows="6"
      ></textarea>
      <input
        v-model="password"
        type="password"
        placeholder="Пароль"
      />
      <button @click="decrypt" class="btn success">Расшифровать</button>

      <div v-if="decrypted" class="result success">
        <div class="result-header">
          <strong>Seed-фраза:</strong>
          <button @click="copyDecrypted" class="btn-copy">📋 Копировать</button>
        </div>
        <pre>{{ decrypted }}</pre>
      </div>
    </section>

    <button @click="clear" class="btn secondary clear-btn">🗑️ Очистить всё</button>

    <footer>
      <p>⚠️ Всё работает локально в браузере. Никакие данные не отправляются.</p>
      <p>💾 Сохрани зашифрованный JSON в надёжное место.</p>
      <p>🔑 Используй длинный пароль (5–7+ слов).</p>
    </footer>
  </div>
</template>

<style scoped>
* {
  box-sizing: border-box;
}

.container {
  max-width: 700px;
  margin: 0 auto;
  padding: 24px;
  font-family: system-ui, -apple-system, sans-serif;
}

header {
  text-align: center;
  margin-bottom: 32px;
}

h1 {
  font-size: 2.5rem;
  margin: 0;
  color: #1a1a1a;
}

.subtitle {
  color: #666;
  margin-top: 8px;
}

.card {
  background: #f9f9f9;
  border: 1px solid #ddd;
  border-radius: 12px;
  padding: 24px;
  margin-bottom: 24px;
}

h2 {
  margin-top: 0;
  font-size: 1.5rem;
}

textarea,
input {
  width: 100%;
  padding: 12px;
  margin-bottom: 12px;
  border: 1px solid #ccc;
  border-radius: 8px;
  font-family: monospace;
  font-size: 14px;
  resize: vertical;
}

textarea {
  min-height: 80px;
}

.btn {
  width: 100%;
  padding: 14px;
  border: none;
  border-radius: 8px;
  font-size: 16px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
}

.btn.primary {
  background: #3b82f6;
  color: white;
}

.btn.primary:hover {
  background: #2563eb;
}

.btn.success {
  background: #10b981;
  color: white;
}

.btn.success:hover {
  background: #059669;
}

.btn.secondary {
  background: #6b7280;
  color: white;
}

.btn.secondary:hover {
  background: #4b5563;
}

.btn-copy {
  padding: 6px 12px;
  background: #e5e7eb;
  border: none;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
}

.btn-copy:hover {
  background: #d1d5db;
}

.clear-btn {
  margin-bottom: 24px;
}

.result {
  margin-top: 16px;
  padding: 16px;
  background: white;
  border: 1px solid #e5e7eb;
  border-radius: 8px;
}

.result.success {
  border-color: #10b981;
  background: #f0fdf4;
}

.result-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 8px;
}

pre {
  margin: 0;
  white-space: pre-wrap;
  word-break: break-all;
  font-size: 13px;
  color: #1f2937;
}

.alert {
  padding: 16px;
  border-radius: 8px;
  margin-bottom: 24px;
  font-weight: 500;
}

.alert.error {
  background: #fef2f2;
  border: 1px solid #fca5a5;
  color: #991b1b;
}

footer {
  text-align: center;
  color: #6b7280;
  font-size: 14px;
  margin-top: 32px;
  padding-top: 24px;
  border-top: 1px solid #e5e7eb;
}

footer p {
  margin: 8px 0;
}
</style>