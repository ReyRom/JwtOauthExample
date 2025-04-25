using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Security.Claims;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = "GitHub";
})
.AddCookie()
.AddOAuth("GitHub", options =>
{
    options.ClientId = builder.Configuration["GitHub:ClientId"];
    options.ClientSecret = builder.Configuration["GitHub:ClientSecret"];
    options.CallbackPath = "/signin-github";

    options.AuthorizationEndpoint = "https://github.com/login/oauth/authorize";
    options.TokenEndpoint = "https://github.com/login/oauth/access_token";
    options.UserInformationEndpoint = "https://api.github.com/user";

    options.SaveTokens = true;

    options.ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "id");
    options.ClaimActions.MapJsonKey(ClaimTypes.Name, "login");

    options.Events = new OAuthEvents
    {
        OnCreatingTicket = async context =>
        {
            var request = new HttpRequestMessage(HttpMethod.Get, context.Options.UserInformationEndpoint);
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", context.AccessToken);
            request.Headers.UserAgent.ParseAdd("OauthExample");

            var response = await context.Backchannel.SendAsync(request);
            response.EnsureSuccessStatusCode();

            using var user = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
            context.RunClaimActions(user.RootElement);
        }
    };
});


var app = builder.Build();

app.UseAuthentication();

app.MapGet("/", async context =>
{
    if (context.User.Identity?.IsAuthenticated == true)
    {
        var name = context.User.Identity.Name;
        await context.Response.WriteAsync($"Hello, {name}!");
    }
    else
    {
        context.Response.Redirect("/login");
    }
})
.WithName("Main")
.WithOpenApi();

app.MapGet("/login", async context =>
{
    await context.ChallengeAsync("GitHub", new AuthenticationProperties { RedirectUri = "/" });
})
.WithName("Login")
.WithOpenApi();

app.MapGet("/logout", async context =>
{
    await context.SignOutAsync();
    context.Response.Redirect("/");
})
.WithName("Logout")
.WithOpenApi();


app.Run();
