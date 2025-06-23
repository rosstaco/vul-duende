using Duende.IdentityServer;
using VulDuende;
using VulDuende.Services;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;
using Fido2NetLib;
using Serilog;

namespace VulDuende;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        builder.Services.AddRazorPages();
        builder.Services.AddControllers();

        // Register Microsoft Graph Service
        builder.Services.AddScoped<IMicrosoftGraphService, MicrosoftGraphService>();
        builder.Services.AddHttpClient();

        // Configure WebAuthn/Passkey support
        builder.Services.AddDbContext<VulDuende.Data.PasskeyDbContext>(options =>
            options.UseInMemoryDatabase("PasskeyDb"));

        builder.Services.AddScoped<IWebAuthnService, WebAuthnService>();
        builder.Services.AddMemoryCache();

        // Configure session for WebAuthn
        builder.Services.AddSession(options =>
        {
            options.IdleTimeout = TimeSpan.FromMinutes(30);
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.None;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        });        // Configure Fido2 - Register the service manually if AddFido2 extension is not available
        builder.Services.AddSingleton<IFido2>(provider =>
        {
            var configuration = provider.GetRequiredService<IConfiguration>();
            var fido2Configuration = new Fido2NetLib.Fido2Configuration
            {
                ServerDomain = configuration["Fido2:ServerDomain"] ?? "localhost",
                ServerName = configuration["Fido2:ServerName"] ?? "VulDuende Identity Server",
                Origins = configuration.GetSection("Fido2:Origins").Get<string[]>()?.ToHashSet() ??
                         new HashSet<string> { "https://localhost:5001" },
                TimestampDriftTolerance = 300000 // 5 minutes
            };
            return new Fido2NetLib.Fido2(fido2Configuration);
        });

        var isBuilder = builder.Services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;

                // see https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/
                options.EmitStaticAudienceClaim = true;
            })
            .AddTestUsers(TestUsers.Users);

        // in-memory, code config
        isBuilder.AddInMemoryIdentityResources(Config.IdentityResources);
        isBuilder.AddInMemoryApiScopes(Config.ApiScopes);
        isBuilder.AddInMemoryClients(Config.Clients);


        // if you want to use server-side sessions: https://blog.duendesoftware.com/posts/20220406_session_management/
        // then enable it
        //isBuilder.AddServerSideSessions();
        //
        // and put some authorization on the admin/management pages
        //builder.Services.AddAuthorization(options =>
        //       options.AddPolicy("admin",
        //           policy => policy.RequireClaim("sub", "1"))
        //   );        //builder.Services.Configure<RazorPagesOptions>(options =>
        //    options.Conventions.AuthorizeFolder("/ServerSideSessions", "admin"));

        builder.Services.AddAuthentication()
            .AddLocalApi("Bearer", options =>
            {
                options.RequireDpop = true;
            })
            .AddGoogle(options =>
            {
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

                // register your IdentityServer with Google at https://console.developers.google.com
                // enable the Google+ API
                // set the redirect URI to https://localhost:5001/signin-google
                options.ClientId = "copy client ID from Google here";
                options.ClientSecret = "copy client secret from Google here";
            })
            .AddMicrosoftAccount(options =>
            {
                options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;

                // Register your app in Azure AD at https://portal.azure.com
                // Navigate to Azure Active Directory > App registrations > New registration
                // Set redirect URI to https://localhost:5001/signin-microsoft
                options.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"] ?? "your-azure-ad-client-id";
                options.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"] ?? "your-azure-ad-client-secret";

                // Request additional scopes for profile picture access
                options.Scope.Add("https://graph.microsoft.com/User.Read");
                options.Scope.Add("https://graph.microsoft.com/User.ReadBasic.All");
                // Save the access token for later use with Microsoft Graph
                options.SaveTokens = true;

                options.Events.OnCreatingTicket = async context =>
                {
                    // Get the access token
                    var accessToken = context.AccessToken;

                    if (!string.IsNullOrEmpty(accessToken))
                    {
                        var graphService = context.HttpContext.RequestServices
                            .GetRequiredService<IMicrosoftGraphService>();

                        // Get user profile information
                        var userProfile = await graphService.GetUserProfileAsync(accessToken);
                        if (userProfile != null)
                        {
                            // Add additional claims
                            if (!string.IsNullOrEmpty(userProfile.DisplayName))
                                context.Identity?.AddClaim(new System.Security.Claims.Claim("name", userProfile.DisplayName));

                            if (!string.IsNullOrEmpty(userProfile.Mail))
                                context.Identity?.AddClaim(new System.Security.Claims.Claim("email", userProfile.Mail));

                            if (!string.IsNullOrEmpty(userProfile.JobTitle))
                                context.Identity?.AddClaim(new System.Security.Claims.Claim("job_title", userProfile.JobTitle));
                        }

                        // Get profile picture
                        var profilePicture = await graphService.GetUserProfilePictureAsync(accessToken);
                        if (!string.IsNullOrEmpty(profilePicture))
                        {
                            context.Identity?.AddClaim(new System.Security.Claims.Claim("picture", profilePicture));
                        }

                        // Store the access token as a claim for later use
                        context.Identity?.AddClaim(new System.Security.Claims.Claim("ms_access_token", accessToken));
                    }
                };
            });

        return builder.Build();
    }
    public static WebApplication ConfigurePipeline(this WebApplication app)
    {
        app.UseSerilogRequestLogging();

        if (app.Environment.IsDevelopment())
        {
            app.UseDeveloperExceptionPage();
        }

        // Initialize the database
        using (var scope = app.Services.CreateScope())
        {
            var context = scope.ServiceProvider.GetRequiredService<VulDuende.Data.PasskeyDbContext>();
            context.Database.EnsureCreated();
        }

        app.UseStaticFiles();
        app.UseRouting();
        app.UseSession();
        app.UseIdentityServer();
        app.UseAuthorization();

        app.MapControllers();
        app.MapRazorPages()
            .RequireAuthorization();

        return app;
    }
}
