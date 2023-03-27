namespace FS.TechDemo.BuyerBFF.Options;

public class IdentityProviderOptions
{
    public const string IdentityProvider = "IdentityProvider";

    public string Authority { get; set; } = "";
    public string Audience { get; set; } = "";
    public string UserInvitationRedirectUri { get; set; } = "";
    public string UserInvitationClientId { get; set; } = "";
    public List<string> ValidAudiences { get; set; } = new();
}
