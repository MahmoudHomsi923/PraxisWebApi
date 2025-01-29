namespace PraxisWebApi.Models
{
    public class ForgetPasswordResponse
    {
        public bool Success { get; set; } = false;
        public string? Message { get; set; } = string.Empty;
    }
}
