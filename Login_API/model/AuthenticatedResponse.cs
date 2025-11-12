using System.ComponentModel.DataAnnotations;

public class TokenModel
{

    [Required]
    public string? AccessToken { get; set; }
    [Required]
    public string? RefreshToken { get; set; }
}