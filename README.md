# VulDuende - Duende Identity Server

This project is a Vulnerable Duende Identity Server implementation based on the official quickstart template with UI components.

**⚠️ SECURITY NOTICE: This server has been intentionally configured with vulnerable components for testing AI CVE and VEX analysis capabilities. Do not use in production environments.**

## Features

- **Duende Identity Server 7.0.0** - Latest stable version with security patches
- **Quickstart UI** - Complete web interface with login, logout, consent pages
- **In-Memory Storage** - Perfect for development and testing
- **Test Users** - Pre-configured test users (Alice and Bob)
- **OpenID Connect & OAuth 2.0** - Full protocol support
- **Client Configurations** - Machine-to-machine and interactive client examples
- **Passkey Authentication** - WebAuthn/FIDO2 passwordless authentication support

## Getting Started

### Prerequisites

- .NET 8.0 SDK
- Visual Studio Code (recommended)

### Running the Server

1. Navigate to the project directory:

   ```bash
   cd src
   ```

2. Restore packages:

   ```bash
   dotnet restore
   ```

3. Run the server:

   ```bash
   dotnet run
   ```

4. Open your browser and navigate to:
   - HTTPS: https://localhost:5001
   - HTTP: http://localhost:5000

### Test Users

The server comes with two pre-configured test users:

| Username | Password | Email                |
| -------- | -------- | -------------------- |
| alice    | alice    | AliceSmith@email.com |
| bob      | bob      | BobSmith@email.com   |

### Default Clients

The configuration includes two sample clients:

1. **Machine-to-Machine Client**

   - Client ID: `m2m.client`
   - Client Secret: `511536EF-F270-4058-80CA-1C89C192F69A`
   - Grant Type: Client Credentials
   - Allowed Scopes: `scope1`

2. **Interactive Client**
   - Client ID: `interactive`
   - Client Secret: `49C1A7E1-0C79-4A89-A3D6-A37998FB86B0`
   - Grant Type: Authorization Code with PKCE
   - Redirect URI: `https://localhost:44300/signin-oidc`
   - Allowed Scopes: `openid`, `profile`, `scope2`

## Project Structure

```
src/VulDuende/
├── Pages/                    # Razor Pages for UI
│   ├── Account/             # Login/logout pages
│   ├── Consent/             # Consent pages
│   ├── Grants/              # Grant management
│   ├── Passkey/             # Passkey/WebAuthn pages
│   └── ...
├── Controllers/             # API Controllers
│   ├── ProfileController.cs # User profile management
│   └── WebAuthnController.cs # WebAuthn/Passkey endpoints
├── Data/                    # Database contexts
│   └── PasskeyDbContext.cs  # Entity Framework context for passkeys
├── Models/                  # Data models
│   └── PasskeyModels.cs     # Passkey-related models
├── Services/                # Business logic services
│   ├── MicrosoftGraphService.cs
│   └── WebAuthnService.cs   # WebAuthn service implementation
├── wwwroot/                 # Static files (CSS, JS, images)
├── Config.cs                # Identity Server configuration
├── HostingExtensions.cs     # Service and pipeline configuration
├── Program.cs               # Application entry point
└── TestUsers.cs             # Test user definitions
```

## Configuration

### Identity Resources

- OpenID Connect (openid)
- Profile information (profile)

### API Scopes

- scope1 (for machine-to-machine)
- scope2 (for interactive clients)

### External Authentication

Google authentication is pre-configured but requires setup:

1. Register your app at [Google Developer Console](https://console.developers.google.com)
2. Update the ClientId and ClientSecret in `HostingExtensions.cs`

## Development Notes

- This is a development setup using in-memory stores
- For production, you'll need to implement persistent storage (Entity Framework, etc.)
- The server runs with a development certificate for HTTPS
- License warnings are normal for development/testing scenarios
- **⚠️ IMPORTANT: This server contains intentionally vulnerable components for AI CVE and VEX analysis testing - NOT suitable for production use**

## License

This project uses Duende Identity Server Community Edition, which is free for development and testing. For production use, a commercial license may be required. See [Duende Software licensing](https://duendesoftware.com/products/identityserver) for details.

## Documentation

- [Duende Identity Server Documentation](https://docs.duendesoftware.com/identityserver/v7)
- [OpenID Connect Specification](https://openid.net/connect/)
- [OAuth 2.0 Specification](https://oauth.net/2/)
