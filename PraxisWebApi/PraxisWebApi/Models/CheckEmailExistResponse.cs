namespace PraxisWebApi.Models
{
    public class CheckEmailExistResponse
    {
        public bool Success { get; set; } = false;
        public string? Message { get; set; } = string.Empty;
    }
}
