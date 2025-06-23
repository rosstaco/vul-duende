using Microsoft.AspNetCore.Mvc.RazorPages;
using VulDuende.Services;

namespace VulDuende.Pages.Passkey;

public class IndexModel : PageModel
{
    private readonly IWebAuthnService _webAuthnService;

    public IndexModel(IWebAuthnService webAuthnService)
    {
        _webAuthnService = webAuthnService;
    }

    public string? Message { get; set; }
    public bool IsRegistered { get; set; }

    public void OnGet()
    {
        // Check if user has any passkeys registered
        // This is a simple example - in practice you'd check based on current user
        Message = "Manage your passkeys for secure, passwordless authentication.";
    }
}
