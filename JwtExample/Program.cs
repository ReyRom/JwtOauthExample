using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.Security.Claims;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();


builder.Services.AddAuthorization();
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
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
        };
    });

builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "JWTToken_Auth_API",
        Version = "v1"
    });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.Http,
        Scheme = "bearer"
    });


    c.AddSecurityRequirement(new OpenApiSecurityRequirement {
        {
            new OpenApiSecurityScheme {
                Reference = new OpenApiReference {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});




var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();


if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}



app.MapPost("/token", (string username, string password, HttpContext context) =>
{
    var jwtSettings = context.RequestServices.GetRequiredService<IConfiguration>()
        .GetSection("JwtSettings").Get<JwtSettings>()!;
    var creditionals = UserCreditionals.ValidateCreditionals(username, password);
    if (creditionals != null)
    {
        var tokenHandler = new JsonWebTokenHandler();
        var key = Encoding.ASCII.GetBytes(jwtSettings.Key);
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(
            [
                new Claim(ClaimTypes.Name, creditionals.Username),
                new Claim(ClaimTypes.Role, creditionals.Role),
            ]),
            Expires = DateTime.UtcNow.AddDays(jwtSettings.AccessTokenExpirationMinutes),
            Issuer = jwtSettings.Issuer,
            Audience = jwtSettings.Audience,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
        };
        var token = tokenHandler.CreateToken(tokenDescriptor);

        return Results.Ok(new { Token = token });
    }
    return Results.Unauthorized();
})
.WithName("Token")
.WithOpenApi();




app.MapGet("/helloadmin", [Authorize(Roles ="Admin")] (HttpContext context) =>
{
    return Results.Ok($"Hello {context.User.Identity?.Name}");
})
.WithName("Hello Admin")
.WithOpenApi();

app.MapGet("/hellouser", [Authorize(Roles ="User")] () =>
{
    return Results.Ok("Hello");
})
.WithName("Hello User")
.WithOpenApi();

app.Run();


public class JwtSettings
{
    public string Key { get; set; } = default!;
    public string Issuer { get; set; } = default!;
    public string Audience { get; set; } = default!;
    public int AccessTokenExpirationMinutes { get; set; }
    public int RefreshTokenExpirationDays { get; set; }
}

public class UserCreditionals
{
    public string Username { get; set; } = default!;
    public string Password { get; set; } = default!;
    public string Role { get; set; } = default!;


    public static UserCreditionals? ValidateCreditionals(string username, string password)
    {
        List<UserCreditionals> users = new List<UserCreditionals>
        {
            new UserCreditionals
            {
                Username = "test",
                Password = "password",
                Role = "Admin"
            },
            new UserCreditionals
            {
                Username = "test2",
                Password = "password2",
                Role = "User"
            }
        };


        return users.FirstOrDefault(x => x.Username == username && x.Password == password) ?? null;
    }
}