const DEFAULT_BACKEND_URL = 'http://127.0.0.1:3000';

const input = document.getElementById('backend-url');
const status = document.getElementById('status');

chrome.storage.sync.get(['backendUrl'], (result) => {
    input.value = result.backendUrl || DEFAULT_BACKEND_URL;
});

document.getElementById('save-btn').addEventListener('click', () => {
    const value = input.value.trim().replace(/\/$/, '') || DEFAULT_BACKEND_URL;
    chrome.storage.sync.set({ backendUrl: value }, () => {
        status.textContent = 'Saved';
        setTimeout(() => { status.textContent = ''; }, 2000);
    });
});
