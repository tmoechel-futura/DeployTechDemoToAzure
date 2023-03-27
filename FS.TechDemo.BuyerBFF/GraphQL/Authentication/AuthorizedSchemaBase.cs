using FS.BFF.Common.IdentityProvider.Policies;

namespace FS.TechDemo.BuyerBFF.GraphQL.Authentication;

public abstract class AuthorizedObjectTypeBase : ObjectType
{
    protected override void Configure(IObjectTypeDescriptor descriptor) => descriptor.Authorize();
}
