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
        public readonly List<uint> allClientsId;

        public DateTime timeDisconnection;

        private bool authentication;
        private uint clientId;

        public bool Authentication { get { return authentication; } }
        public uint ClientId { get { return clientId; } }

        public ClientInfo(IPEndPoint endPoint, DateTime timeConnection, CryptAES aes, byte[] sessionId, List<uint> allClientsId)
        {
            this.endPoint = endPoint;
            this.timeConnection = timeConnection;
            this.aes = aes;
            this.sessionId = sessionId;
            this.allClientsId = allClientsId;
        }

        public bool AddId(uint clientId)
        {
            bool isIdInList = false;
            lock (allClientsId)
            {
                foreach (uint clientIdinList in allClientsId)
                {
                    if (clientId == clientIdinList)
                    {
                        isIdInList = true;
                        break;
                    }
                }

                if (!isIdInList)
                {
                    authentication = true;
                    allClientsId.Add(clientId);
                    this.clientId = clientId;
                }
            }

            return authentication;
        }
        public void RecallId()
        {
            if(authentication)
            {
                lock (allClientsId)
                {
                    authentication = false;
                    allClientsId.Remove(clientId);
                    clientId = 0;
                }
            }
        }
    }
}
