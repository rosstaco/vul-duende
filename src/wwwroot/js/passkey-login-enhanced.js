// Enhanced Passkey Authentication JavaScript for Modern Login Page
class ModernPasskeyManager {
    constructor() {
        this.baseUrl = '/api/webauthn';
        this.returnUrl = document.querySelector('input[name="Input.ReturnUrl"]')?.value || '';
        this.autoDetectionEnabled = true;
        this.statusMessage = document.getElementById('statusMessage');
        this.passkeyAutoSection = document.getElementById('passkeyAutoSection');
        this.abortController = null; // For canceling pending operations

        // Setup progressive disclosure for compact layout
        this.setupProgressiveDisclosure();

        // Initialize automatic passkey detection
        this.initializePasskeyDetection();

        // Check if we should show additional options
        setTimeout(() => this.showAdditionalOptionsIfNeeded(), 500);
    }

    // Convert ArrayBuffer to Base64
    arrayBufferToBase64(buffer) {
        return btoa(String.fromCharCode(...new Uint8Array(buffer)));
    }

    // Convert Base64 to ArrayBuffer
    base64ToArrayBuffer(base64) {
        const binaryString = atob(base64);
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return bytes.buffer;
    }

    // Show status message
    showMessage(message, type = 'info') {
        if (this.statusMessage) {
            this.statusMessage.className = `status-message ${type} visible`;
            this.statusMessage.textContent = message;

            // Auto-hide after 5 seconds for non-error messages
            if (type !== 'error') {
                setTimeout(() => {
                    this.statusMessage.classList.remove('visible');
                    this.statusMessage.classList.add('hidden');
                }, 5000);
            }
        }
    }

    // Initialize automatic passkey detection
    async initializePasskeyDetection() {
        if (!window.PublicKeyCredential) {
            this.showMessage('WebAuthn is not supported in this browser', 'warning');
            this.disablePasskeyButtons();
            return;
        }

        try {
            // Check if conditional UI is supported (automatic passkey detection)
            const conditionalUISupported = await PublicKeyCredential.isConditionalMediationAvailable();

            if (conditionalUISupported) {
                await this.startConditionalMediation();
            } else {
                // Fallback: Check for available passkeys
                await this.checkForAvailablePasskeys();
            }
        } catch (error) {
            console.error('Passkey detection error:', error);
            // Continue without automatic detection
        }
    }

    // Start conditional mediation (automatic passkey detection)
    async startConditionalMediation() {
        try {
            // Get authentication options for conditional UI
            const response = await fetch(`${this.baseUrl}/authenticate/begin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: null, conditionalUI: true })
            });

            if (!response.ok) {
                throw new Error('Failed to begin conditional authentication');
            }

            const { options } = await response.json();

            // Convert server options for WebAuthn API
            const publicKeyCredentialRequestOptions = {
                challenge: this.base64ToArrayBuffer(options.challenge),
                timeout: options.timeout,
                rpId: options.rpId,
                allowCredentials: options.allowCredentials?.map(cred => ({
                    id: this.base64ToArrayBuffer(cred.id),
                    type: cred.type,
                    transports: cred.transports
                })),
                userVerification: options.userVerification
            };

            // Create abort signal for this operation
            const signal = this.createAbortController();

            // Start conditional mediation
            const credential = await navigator.credentials.get({
                publicKey: publicKeyCredentialRequestOptions,
                mediation: 'conditional',
                signal: signal
            });

            if (credential) {
                await this.completeAuthentication(credential, response.sessionId);
            }

        } catch (error) {
            if (error.name !== 'AbortError') {
                console.error('Conditional mediation error:', error);
            }
        }
    }

    // Check for available passkeys and show auto-detection UI
    async checkForAvailablePasskeys() {
        try {
            // Try to get available passkeys without showing UI
            const response = await fetch(`${this.baseUrl}/authenticate/begin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username: null })
            });

            if (response.ok) {
                const { options } = await response.json();

                if (options.allowCredentials && options.allowCredentials.length > 0) {
                    this.showAutoPasskeySection();
                }
            }
        } catch (error) {
            console.error('Passkey availability check error:', error);
        }
    }

    // Show automatic passkey detection section
    showAutoPasskeySection() {
        if (this.passkeyAutoSection) {
            this.passkeyAutoSection.classList.remove('hidden');
            this.passkeyAutoSection.classList.add('visible');
        }
    }

    // Disable passkey buttons when not supported
    disablePasskeyButtons() {
        const buttons = [
            'signInWithPasskey',
            'signInWithPasskeySpecific',
            'autoSignInPasskey',
            'registerPasskey'
        ];

        buttons.forEach(id => {
            const button = document.getElementById(id);
            if (button) {
                button.disabled = true;
                button.title = 'WebAuthn not supported';
            }
        });
    }

    // Set button loading state
    setButtonLoading(buttonId, loading = true) {
        const button = document.getElementById(buttonId);
        if (button) {
            if (loading) {
                button.classList.add('loading');
                button.disabled = true;
            } else {
                button.classList.remove('loading');
                button.disabled = false;
            }
        }
    }

    // Register a new passkey
    async registerPasskey() {
        const registerBtn = 'registerPasskey';

        try {
            const username = document.getElementById('registerUsername')?.value.trim();
            const email = document.getElementById('registerEmail')?.value.trim();
            const displayName = document.getElementById('registerDisplayName')?.value.trim() || username;

            if (!username || !email) {
                this.showMessage('Username and email are required', 'error');
                return;
            }

            // Cancel any pending WebAuthn operations
            this.cancelPendingOperations();

            this.setButtonLoading(registerBtn);
            this.showMessage('Starting passkey registration...', 'info');

            // Step 1: Get registration options from server
            const beginResponse = await fetch(`${this.baseUrl}/register/begin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, email, displayName })
            });

            if (!beginResponse.ok) {
                throw new Error('Failed to begin registration');
            }

            const { options, sessionId } = await beginResponse.json();

            // Step 2: Convert server options for WebAuthn API
            const publicKeyCredentialCreationOptions = {
                challenge: this.base64ToArrayBuffer(options.challenge),
                rp: options.rp,
                user: {
                    id: this.base64ToArrayBuffer(options.user.id),
                    name: options.user.name,
                    displayName: options.user.displayName
                },
                pubKeyCredParams: options.pubKeyCredParams,
                authenticatorSelection: options.authenticatorSelection,
                timeout: options.timeout,
                attestation: options.attestation
            };

            // Step 3: Create credential using WebAuthn API
            this.showMessage('Please complete the authentication on your device...', 'warning');

            // Create abort signal for this operation
            const signal = this.createAbortController();

            const credential = await navigator.credentials.create({
                publicKey: publicKeyCredentialCreationOptions,
                signal: signal
            });

            if (!credential) {
                throw new Error('Failed to create credential');
            }

            // Step 4: Prepare response for server
            const attestationResponse = {
                id: credential.id,
                rawId: this.arrayBufferToBase64(credential.rawId),
                response: {
                    attestationObject: this.arrayBufferToBase64(credential.response.attestationObject),
                    clientDataJSON: this.arrayBufferToBase64(credential.response.clientDataJSON)
                },
                type: credential.type
            };

            // Step 5: Complete registration on server
            const completeResponse = await fetch(`${this.baseUrl}/register/complete`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    username,
                    attestationResponse: JSON.stringify(attestationResponse),
                    sessionId
                })
            });

            if (!completeResponse.ok) {
                throw new Error('Failed to complete registration');
            }

            const result = await completeResponse.json();

            if (result.success) {
                this.showMessage('Passkey registered successfully! You can now use it to sign in.', 'success');
                // Clear form
                ['registerUsername', 'registerEmail', 'registerDisplayName'].forEach(id => {
                    const input = document.getElementById(id);
                    if (input) input.value = '';
                });

                // Hide registration form and show main options
                const passkeyRegistrationForm = document.getElementById('passkeyRegistration');
                if (passkeyRegistrationForm) {
                    passkeyRegistrationForm.classList.remove('visible');
                    passkeyRegistrationForm.classList.add('hidden');
                }
                this.showMainAuthOptions();

                // Show auto passkey section since we now have a passkey
                this.showAutoPasskeySection();
            } else {
                throw new Error('Registration failed');
            }

        } catch (error) {
            console.error('Registration error:', error);
            if (error.name === 'AbortError') {
                this.showMessage('Registration was cancelled', 'warning');
            } else {
                this.showMessage(`Registration failed: ${error.message}`, 'error');
            }
        } finally {
            this.setButtonLoading(registerBtn, false);
        }
    }

    // Authenticate with passkey
    async signInWithPasskey(username = null, buttonId = 'signInWithPasskey') {
        try {
            // Cancel any pending WebAuthn operations
            this.cancelPendingOperations();

            this.setButtonLoading(buttonId);
            this.showMessage('Checking for available passkeys...', 'info');

            // Step 1: Get authentication options from server
            const beginResponse = await fetch(`${this.baseUrl}/authenticate/begin`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username })
            });

            if (!beginResponse.ok) {
                throw new Error('Failed to begin authentication');
            }

            const { options, sessionId } = await beginResponse.json();

            // Check if there are any passkeys available
            if (!options.allowCredentials || options.allowCredentials.length === 0) {
                this.setButtonLoading(buttonId, false);
                this.showMessage('No passkeys found. Would you like to register one?', 'warning');
                // Show registration form instead
                this.showPasskeyRegistrationForm();
                return;
            }

            // Step 2: Convert server options for WebAuthn API
            const publicKeyCredentialRequestOptions = {
                challenge: this.base64ToArrayBuffer(options.challenge),
                timeout: options.timeout,
                rpId: options.rpId,
                allowCredentials: options.allowCredentials?.map(cred => ({
                    id: this.base64ToArrayBuffer(cred.id),
                    type: cred.type,
                    transports: cred.transports
                })),
                userVerification: options.userVerification
            };

            // Step 3: Get assertion using WebAuthn API
            this.showMessage('Please authenticate with your passkey...', 'warning');

            // Create abort signal for this operation
            const signal = this.createAbortController();

            const assertion = await navigator.credentials.get({
                publicKey: publicKeyCredentialRequestOptions,
                signal: signal
            });

            if (!assertion) {
                throw new Error('Failed to get assertion');
            }

            await this.completeAuthentication(assertion, sessionId);

        } catch (error) {
            console.error('Authentication error:', error);
            if (error.name === 'AbortError') {
                this.showMessage('Authentication was cancelled', 'warning');
            } else {
                this.showMessage(`Authentication failed: ${error.message}`, 'error');
            }
        } finally {
            this.setButtonLoading(buttonId, false);
        }
    }

    // Show passkey registration form
    showPasskeyRegistrationForm() {
        // Cancel any pending WebAuthn operations
        this.cancelPendingOperations();

        const passkeyRegistrationForm = document.getElementById('passkeyRegistration');
        const additionalOptions = document.querySelector('.additional-options');

        if (passkeyRegistrationForm) {
            passkeyRegistrationForm.classList.remove('hidden');
            passkeyRegistrationForm.classList.add('visible');
        }

        // Hide main authentication options
        this.hideMainAuthOptions();

        if (additionalOptions) {
            additionalOptions.classList.remove('visible');
            additionalOptions.classList.add('hidden');
        }

        // Focus username field
        const usernameField = passkeyRegistrationForm?.querySelector('#registerUsername');
        if (usernameField) {
            setTimeout(() => usernameField.focus(), 100);
        }
    }

    // Complete authentication and redirect
    async completeAuthentication(assertion, sessionId) {
        // Prepare response for server
        const assertionResponse = {
            id: assertion.id,
            rawId: this.arrayBufferToBase64(assertion.rawId),
            response: {
                authenticatorData: this.arrayBufferToBase64(assertion.response.authenticatorData),
                clientDataJSON: this.arrayBufferToBase64(assertion.response.clientDataJSON),
                signature: this.arrayBufferToBase64(assertion.response.signature),
                userHandle: assertion.response.userHandle ? this.arrayBufferToBase64(assertion.response.userHandle) : null
            },
            type: assertion.type
        };

        // Complete authentication on server
        const completeResponse = await fetch(`${this.baseUrl}/authenticate/complete`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                assertionResponse: JSON.stringify(assertionResponse),
                sessionId
            })
        });

        if (!completeResponse.ok) {
            throw new Error('Failed to complete authentication');
        }

        const result = await completeResponse.json();

        if (result.success) {
            this.showMessage('Authentication successful! Redirecting...', 'success');

            // Create a form to simulate successful login and redirect
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = window.location.pathname;

            // Add antiforgery token
            const antiforgeryToken = document.querySelector('input[name="__RequestVerificationToken"]');
            if (antiforgeryToken) {
                const tokenInput = document.createElement('input');
                tokenInput.type = 'hidden';
                tokenInput.name = '__RequestVerificationToken';
                tokenInput.value = antiforgeryToken.value;
                form.appendChild(tokenInput);
            }

            // Add return URL
            const returnUrlInput = document.createElement('input');
            returnUrlInput.type = 'hidden';
            returnUrlInput.name = 'Input.ReturnUrl';
            returnUrlInput.value = this.returnUrl || '/';
            form.appendChild(returnUrlInput);

            // Add passkey user info
            const userInput = document.createElement('input');
            userInput.type = 'hidden';
            userInput.name = 'Input.PasskeyUser';
            userInput.value = JSON.stringify(result.user);
            form.appendChild(userInput);

            // Add button value to indicate passkey login
            const buttonInput = document.createElement('input');
            buttonInput.type = 'hidden';
            buttonInput.name = 'Input.Button';
            buttonInput.value = 'passkey';
            form.appendChild(buttonInput);

            document.body.appendChild(form);
            form.submit();
        } else {
            throw new Error('Authentication failed');
        }
    }

    // Toggle passkey options visibility
    togglePasskeyOptions() {
        const options = document.getElementById('passkeyOptions');
        const button = document.getElementById('togglePasskeyOptions');

        if (options && button) {
            const isVisible = options.classList.contains('visible');
            if (isVisible) {
                options.classList.remove('visible');
                options.classList.add('hidden');
                button.textContent = 'More passkey options';
            } else {
                options.classList.remove('hidden');
                options.classList.add('visible');
                button.textContent = 'Fewer passkey options';
            }
        }
    }

    // Progressive disclosure event handlers for compact layout
    setupProgressiveDisclosure() {
        // Show local login form
        const showLocalLoginBtn = document.getElementById('showLocalLogin');
        const localLoginForm = document.getElementById('localLoginForm');
        const cancelLocalLoginBtn = document.getElementById('cancelLocalLogin');

        if (showLocalLoginBtn && localLoginForm) {
            showLocalLoginBtn.addEventListener('click', () => {
                localLoginForm.classList.remove('hidden');
                localLoginForm.classList.add('visible');
                // Hide all main auth options
                this.hideMainAuthOptions();
                // Hide additional options if visible
                const additionalOptions = document.querySelector('.additional-options');
                if (additionalOptions) {
                    additionalOptions.classList.remove('visible');
                    additionalOptions.classList.add('hidden');
                }
                // Focus username field
                const usernameField = localLoginForm.querySelector('input[name="Input.Username"]');
                if (usernameField) {
                    setTimeout(() => usernameField.focus(), 100);
                }
            });
        }

        if (cancelLocalLoginBtn && localLoginForm && showLocalLoginBtn) {
            cancelLocalLoginBtn.addEventListener('click', () => {
                localLoginForm.classList.remove('visible');
                localLoginForm.classList.add('hidden');
                // Show all main auth options again
                this.showMainAuthOptions();
                // Show additional options again
                this.showAdditionalOptionsIfNeeded();
            });
        }

        // Show passkey registration form
        const showPasskeyRegistrationBtn = document.getElementById('showPasskeyRegistration');
        const passkeyRegistrationForm = document.getElementById('passkeyRegistration');
        const cancelPasskeyRegistrationBtn = document.getElementById('cancelPasskeyRegistration');

        if (showPasskeyRegistrationBtn && passkeyRegistrationForm) {
            showPasskeyRegistrationBtn.addEventListener('click', () => {
                passkeyRegistrationForm.classList.remove('hidden');
                passkeyRegistrationForm.classList.add('visible');
                // Hide all main auth options
                this.hideMainAuthOptions();
                // Hide additional options
                const additionalOptions = document.querySelector('.additional-options');
                if (additionalOptions) {
                    additionalOptions.classList.remove('visible');
                    additionalOptions.classList.add('hidden');
                }
                // Focus username field
                const usernameField = passkeyRegistrationForm.querySelector('#registerUsername');
                if (usernameField) {
                    setTimeout(() => usernameField.focus(), 100);
                }
            });
        }

        if (cancelPasskeyRegistrationBtn && passkeyRegistrationForm && showPasskeyRegistrationBtn) {
            cancelPasskeyRegistrationBtn.addEventListener('click', () => {
                passkeyRegistrationForm.classList.remove('visible');
                passkeyRegistrationForm.classList.add('hidden');
                // Show all main auth options again
                this.showMainAuthOptions();
                // Clear form
                ['registerUsername', 'registerEmail', 'registerDisplayName'].forEach(id => {
                    const input = document.getElementById(id);
                    if (input) input.value = '';
                });
                // Show additional options again
                this.showAdditionalOptionsIfNeeded();
            });
        }
    }

    // Cancel any pending WebAuthn operations
    cancelPendingOperations() {
        if (this.abortController) {
            this.abortController.abort();
            this.abortController = null;
        }
    }

    // Create a new abort controller for WebAuthn operations
    createAbortController() {
        this.cancelPendingOperations();
        this.abortController = new AbortController();
        return this.abortController.signal;
    }

    // Hide main authentication options
    hideMainAuthOptions() {
        const authOptions = document.querySelector('.auth-options');
        if (authOptions) {
            authOptions.classList.add('hidden');
        }
    }

    // Show main authentication options
    showMainAuthOptions() {
        const authOptions = document.querySelector('.auth-options');
        if (authOptions) {
            authOptions.classList.remove('hidden');
        }
    }

    // Show additional options if no passkey is detected
    showAdditionalOptionsIfNeeded() {
        const additionalOptions = document.querySelector('.additional-options');
        if (additionalOptions) {
            // Only show if no passkey auto-detection is active
            const passkeyAutoSection = document.getElementById('passkeyAutoSection');
            if (!passkeyAutoSection || passkeyAutoSection.classList.contains('hidden')) {
                additionalOptions.classList.remove('hidden');
                additionalOptions.classList.add('visible');
            }
        }
    }
}

// Initialize when page loads
document.addEventListener('DOMContentLoaded', function() {
    const passkeyManager = new ModernPasskeyManager();

    // Event listeners for all passkey buttons
    const buttonMappings = {
        'signInWithPasskey': () => passkeyManager.signInWithPasskey(),
        'signInWithPasskeySpecific': () => {
            const username = document.getElementById('passkeyUsername')?.value.trim() || null;
            passkeyManager.signInWithPasskey(username, 'signInWithPasskeySpecific');
        },
        'autoSignInPasskey': () => passkeyManager.signInWithPasskey(null, 'autoSignInPasskey'),
        'registerPasskey': () => passkeyManager.registerPasskey(),
        'togglePasskeyOptions': () => passkeyManager.togglePasskeyOptions()
    };

    // Attach event listeners
    Object.entries(buttonMappings).forEach(([buttonId, handler]) => {
        const button = document.getElementById(buttonId);
        if (button) {
            button.addEventListener('click', handler);
        }
    });

    // Enter key support for passkey username field
    const usernameField = document.getElementById('passkeyUsername');
    if (usernameField) {
        usernameField.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                const username = e.target.value.trim() || null;
                passkeyManager.signInWithPasskey(username, 'signInWithPasskeySpecific');
            }
        });
    }

    // Auto-focus username field when traditional login form is shown
    const usernameInput = document.querySelector('input[name="Input.Username"]');
    if (usernameInput && !document.querySelector('#passkeyAutoSection[style*="block"]')) {
        // Only auto-focus if passkey auto-section is not visible
        setTimeout(() => {
            if (usernameInput.value === '') {
                usernameInput.focus();
            }
        }, 100);
    }
});
