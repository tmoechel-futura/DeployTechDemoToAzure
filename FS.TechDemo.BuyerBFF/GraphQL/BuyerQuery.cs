using FS.TechDemo.BuyerBFF.GraphQL.Authentication;
using FS.TechDemo.BuyerBFF.GraphQL.Extensions;
using FS.TechDemo.BuyerBFF.GraphQL.RequestHandler;
using FS.TechDemo.BuyerBFF.GraphQL.Types.Order;
using FS.TechDemo.BuyerBFF.GraphQL.Types.User;
using MediatR;

namespace FS.TechDemo.BuyerBFF.GraphQL;

public class BuyerQuery  : AuthorizedObjectTypeBase
{
    private readonly IMediator _mediator;
    private readonly ILoggerFactory _loggerFactory;
    
    public BuyerQuery(IMediator mediator, ILoggerFactory loggerFactory)
    {
        _mediator = mediator;
        _loggerFactory = loggerFactory;
    }
    
    protected override void Configure(IObjectTypeDescriptor descriptor)
    {
        base.Configure(descriptor);
        descriptor.Field("OrderList").Type<ListType<OrderType>>()
            .Resolve(_mediator.GetResolverFunc<OrderTypeResolvableRequest>(_loggerFactory))
            .Authorize();
        
        descriptor.Field("UserList").Type<ListType<UserType>>()
            .Resolve(_mediator.GetResolverFunc<UserTypeResolvableRequest>(_loggerFactory));
            
    }
}