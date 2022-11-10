namespace ProtocolTransport
{
    public interface IParser
    {
        public Command Parse(byte[] buffer);
    }
}
