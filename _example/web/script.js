document.getElementById('registerButton').addEventListener('click', register);
document.getElementById('loginButton').addEventListener('click', login);


function showMessage(message, isError = false) {
    const messageElement = document.getElementById('message');
    messageElement.textContent = message;
    messageElement.style.color = isError ? 'red' : 'green';
}

async function register() {
    // Retrieve the username from the input field
    const username = document.getElementById('username').value;

    try {
        // Get registration options from your server. Here, we also receive the challenge.
        const response = await fetch('/api/passkey/registerBegin', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: username})
        });

        // Check if the registration options are ok.
        if (!response.ok) {
            const msg = await response.json();
            throw new Error('User already exists or failed to get registration options from server: ' + msg);
        }

        // Convert the registration options to JSON.
        const options = await response.json();

        // This triggers the browser to display the passkey / WebAuthn modal (e.g. Face ID, Touch ID, Windows Hello).
        // A new attestation is created. This also means a new public-private-key pair is created.
        const attestationResponse = await SimpleWebAuthnBrowser.startRegistration({optionsJSON: options.publicKey});

        // Send attestationResponse back to server for verification and storage.
        const verificationResponse = await fetch('/api/passkey/registerFinish', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(attestationResponse)
        });

        const msg = await verificationResponse.json();
        if (verificationResponse.ok) {
            showMessage(msg, false);
        } else {
            showMessage(msg, true);
        }
    } catch
        (error) {
        showMessage('Error: ' + error.message, true);
    }
}

async function login() {
    // Retrieve the username from the input field
    const username = document.getElementById('username').value;

    try {
        // Get login options from your server. Here, we also receive the challenge.
        const response = await fetch('/api/passkey/loginBegin', {
            method: 'POST', headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: username})
        });
        // Check if the login options are ok.
        if (!response.ok) {
            const msg = await response.json();
            throw new Error('Failed to get login options from server: ' + msg);
        }
        // Convert the login options to JSON.
        const options = await response.json();

        // This triggers the browser to display the passkey / WebAuthn modal (e.g. Face ID, Touch ID, Windows Hello).
        // A new assertionResponse is created. This also means that the challenge has been signed.
        const assertionResponse = await SimpleWebAuthnBrowser.startAuthentication({optionsJSON: options.publicKey});

        // Send assertionResponse back to server for verification.
        const verificationResponse = await fetch('/api/passkey/loginFinish', {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(assertionResponse)
        });

        const msg = await verificationResponse.json();
        if (verificationResponse.ok) {
            showMessage(msg, false);
        } else {
            showMessage(msg, true);
        }
    } catch (error) {
        showMessage('Error: ' + error.message, true);
    }
}