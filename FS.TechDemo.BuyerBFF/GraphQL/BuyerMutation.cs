using FS.TechDemo.BuyerBFF.GraphQL.Authentication;
using FS.TechDemo.BuyerBFF.GraphQL.Extensions;
using FS.TechDemo.BuyerBFF.GraphQL.RequestHandler;
using FS.TechDemo.BuyerBFF.GraphQL.Types.Order;
using Google.Protobuf.WellKnownTypes;
using MediatR;

namespace FS.TechDemo.BuyerBFF.GraphQL;

public class BuyerMutation: AuthorizedObjectTypeBase
{
    private readonly IMediator _mediator;
    private readonly ILoggerFactory _loggerFactory;

    public BuyerMutation(IMediator mediator, ILoggerFactory loggerFactory)
    {
        _mediator = mediator;
        _loggerFactory = loggerFactory;
    }
    
    
    protected override void Configure(IObjectTypeDescriptor descriptor)
    {
        base.Configure(descriptor);
        descriptor.Field("CreateOrder").Type<IntType>()
            .Argument("CreateOrderInput", argument => argument.Type<NonNullType<OrderTypeInput>>())
            .Resolve(_mediator.GetResolverFunc<CreateOrderResolvableRequest>(_loggerFactory));
    }
}