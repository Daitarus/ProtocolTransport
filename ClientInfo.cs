using System.Net;
using CryptL;

namespace ProtocolTransport
{
    public class ClientInfo
    {
        public readonly IPEndPoint endPoint;
        public readonly DateTime timeConnection;
        public readonly CryptAES aes;
        public readonly byte[] sessionId;

        public DateTime timeDisconnection;
        public bool authentication;
        public uint clientId;

        public ClientInfo(IPEndPoint endPoint, DateTime timeConnection, CryptAES aes, byte[] sessionId)
        {
            this.endPoint = endPoint;
            this.timeConnection = timeConnection;
            this.aes = aes;
            this.sessionId = sessionId;
        }
    }
}
