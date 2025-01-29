namespace PraxisWebApi.Models
{
    public class ResetPasswordResponse
    {
        public bool Success { get; set; } = false;
        public string? Message { get; set; } = string.Empty;
    }
}
