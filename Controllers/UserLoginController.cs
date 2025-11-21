using Microsoft.AspNetCore.Mvc;

[ApiController]
public class UserLoginController : ControllerBase
{
    private readonly EncryptionService _encryptionService;
    private readonly JwtGeneratorService _jwtGeneratorService;

    public UserLoginController(EncryptionService encryptionService, JwtGeneratorService jwtGeneratorService)
    {
        _encryptionService = encryptionService;
        _jwtGeneratorService = jwtGeneratorService;
    }

    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        // TODO: Validate user credentials (this is just a placeholder)
        // validate claims and roles
        if (request.Username == "user" && request.Password == "password")
        {
            var token = _jwtGeneratorService.GenerateToken(request.Username);
            var encryptedToken = _encryptionService.Encrypt(token);
            return Ok(new { Token = encryptedToken });
        }
        return Unauthorized();
    }

   
}