namespace ProtocolTransport
{
    public abstract class CommandRequest : Command
    {
        public abstract void ExecuteCommand(Transport transport, ref ClientInfo clientInfo);
    }
}
