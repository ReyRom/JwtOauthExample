using System.Security.Claims;
using System;
using System.Collections.Generic;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite("Data Source=app.db"));

builder.Services.Configure<JwtSettings>(
    builder.Configuration.GetSection("JwtSettings"));

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    var jwtSettings = builder.Configuration.GetSection("JwtSettings").Get<JwtSettings>()!;
    var key = Encoding.ASCII.GetBytes(jwtSettings.Key);
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = jwtSettings.Issuer,
        ValidateAudience = true,
        ValidAudience = jwtSettings.Audience,
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ClockSkew = TimeSpan.Zero
    };
});

builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/", () => "Hello JWT + GitHub OAuth!");

app.MapGet("/me", async (ClaimsPrincipal user, AppDbContext db) =>
{
    var githubId = user.FindFirst(ClaimTypes.NameIdentifier)?.Value;
    var dbUser = await db.Users.FirstOrDefaultAsync(u => u.GitHubId == githubId);
    return dbUser is not null ? Results.Ok(dbUser) : Results.NotFound();
}).RequireAuthorization();

app.MapPost("/refresh", async (HttpRequest request, AppDbContext db, IConfiguration config) =>
{
    var refreshToken = request.Headers["x-refresh-token"].ToString();
    var user = await db.Users.FirstOrDefaultAsync(u => u.RefreshToken == refreshToken);
    if (user == null || user.RefreshTokenExpiryTime < DateTime.UtcNow)
        return Results.Unauthorized();

    var jwtSettings = config.GetSection("JwtSettings").Get<JwtSettings>()!;
    var tokenHandler = new JwtSecurityTokenHandler();
    var key = Encoding.ASCII.GetBytes(jwtSettings.Key);

    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity(new[] {
            new Claim(ClaimTypes.NameIdentifier, user.GitHubId),
            new Claim(ClaimTypes.Name, user.Username)
        }),
        Expires = DateTime.UtcNow.AddMinutes(jwtSettings.AccessTokenExpirationMinutes),
        Issuer = jwtSettings.Issuer,
        Audience = jwtSettings.Audience,
        SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
    };

    var token = tokenHandler.CreateToken(tokenDescriptor);
    var tokenString = tokenHandler.WriteToken(token);

    return Results.Ok(new { access_token = tokenString });
});


app.Run();



// Helpers/JwtSettings.cs
public class JwtSettings
{
    public string Key { get; set; } = default!;
    public string Issuer { get; set; } = default!;
    public string Audience { get; set; } = default!;
    public int AccessTokenExpirationMinutes { get; set; }
    public int RefreshTokenExpirationDays { get; set; }
}


public class User
{
    public int Id { get; set; }
    public string GitHubId { get; set; }
    public string Username { get; set; }
    public string RefreshToken { get; set; }
    public DateTime RefreshTokenExpiryTime { get; set; }
}

public class AppDbContext : DbContext
{
    public DbSet<User> Users => Set<User>();

    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
}