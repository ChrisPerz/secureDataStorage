using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using secureDataStorage.Models;

public class JwtGeneratorService
{
    private readonly string _secret;
    private readonly int _expirationInMinutes;

    public JwtGeneratorService(IConfiguration config)
    {
        _secret = config.GetValue<string>("JwtConfiguration:Secret");
        _expirationInMinutes = config.GetValue<int>("JwtConfiguration:ExpirationInMinutes");
    }

    public string GenerateToken(string username, string role, string claim)
    {
        var securityKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(_secret));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, username)
        };

        // Should use service to assign claims and roles
        var roleClaim = AsignRole(role);
        var userClaim = AsignClaim(claim);
        if (roleClaim != null)
        {
            claims.Add(roleClaim);
        } 
        if (userClaim != null)
        {
            claims.Add(userClaim);
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(_expirationInMinutes),
            SigningCredentials = credentials
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private Claim? AsignRole(string? role)
    {
        if (string.IsNullOrEmpty(role))
        {
            return null;
        }

        if (role != UserRoles.Admin && role != UserRoles.User && role != UserRoles.Guest)
        {
            throw new ArgumentException("Invalid role specified.");
        }
        return role switch
        {
            UserRoles.Admin => new Claim(ClaimTypes.Role, UserRoles.Admin),
            UserRoles.User => new Claim(ClaimTypes.Role, UserRoles.User),
            UserRoles.Guest => new Claim(ClaimTypes.Role, UserRoles.Guest),
            _ => throw new ArgumentException("Invalid role specified.")
        };
    }

    private Claim? AsignClaim(string claim)
    {
        if (string.IsNullOrEmpty(claim))
        {
            return null;
        }

        return claim switch
        {
            UserClaims.Username => new Claim(UserClaims.Username, "exampleUsername"),
            UserClaims.HasPaidService => new Claim(UserClaims.HasPaidService, "true"),
            UserClaims.IsActive => new Claim(UserClaims.IsActive, "true"),
            UserClaims.Department => new Claim(UserClaims.Department, "IT"),
            _ => throw new ArgumentException("Invalid claim specified.")
        };
    }
}