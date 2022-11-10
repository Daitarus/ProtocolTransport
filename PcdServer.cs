using CryptL;
using System.Net;
using System.Net.Sockets;
using System.Text;
using NLog;

namespace ProtocolTransport
{
    public class PcdServer
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private IPEndPoint serverEndPoint;
        private CryptRSA rsa;
        private IParser parser;
        //private List<uint> clientsId = new List<uint>();

        public PcdServer(IPEndPoint serverEndPoint, IParser parser)
        {
            rsa = new CryptRSA();
            this.serverEndPoint = serverEndPoint;
            this.parser = parser;
        }
        public PcdServer(IPEndPoint serverEndPoint, CryptRSA rsa, IParser parser)
        {
            this.serverEndPoint = serverEndPoint;
            this.rsa = rsa;
            this.parser = parser;
        }

        public void Start()
        {
            try
            {
                while (true)
                {
                    Socket listenSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    listenSocket.Bind(serverEndPoint);
                    listenSocket.Listen(1);
                    Socket acceptSocket = listenSocket.Accept();
                    Task clientWork = new Task(() => ClientWork(acceptSocket));
                    clientWork.Start();
                    listenSocket.Close();
                }
            }
            catch (Exception e)
            {
                LogException(e);
            }
        }

        private void ClientWork(Socket socket)
        {
            DateTime timeConnection = DateTime.Now;
            IPEndPoint clientEndPoint = (IPEndPoint)socket.RemoteEndPoint;
            Transport transport = new Transport(socket);
            bool getCommand = true;

            try
            {
                //send publicKey RSA
                RsaPkeyCom rsaPkeyCom = new RsaPkeyCom(rsa.PublicKey);
                transport.SendData(rsaPkeyCom.ConvertToBytes());

                //get AES key
                AesKeyCom aesCom;
                if (AesKeyCom.ParseToCom(rsa.Decrypt(transport.GetData()), out aesCom))
                {
                    ClientInfo clientInfo = new ClientInfo(clientEndPoint, timeConnection, new CryptAES(aesCom.unionKeyIV), GenerateSessionId(clientEndPoint, timeConnection));

                    //send hash(SessionId)
                    SessionIdCom sessionIdCom = new SessionIdCom(clientInfo.sessionId);
                    transport.SendData(clientInfo.aes.Encrypt(sessionIdCom.ConvertToBytes()));

                    //client cycle
                    while(getCommand)
                    {
                        Command com = parser.Parse(clientInfo.aes.Decrypt(transport.GetData()));
                        CommandRequest? comRequest = com as CommandRequest;

                        if(comRequest != null)
                        {
                            comRequest.ExecuteCommand(transport, ref clientInfo);
                        }
                    }
                }
            }
            catch (Exception e)
            {
                LogException(e);
            }
            finally
            {
                Disconnect(socket);
            }
        }

        private void Disconnect(Socket socket)
        {
            try
            {
                socket.Disconnect(false);
                socket.Close();
            }
            catch (Exception e)
            {
                LogException(e);
            }
        }

        private void LogException(Exception e)
        {
            logger.Error(String.Format("{0}\n{1}\n\n", e.Message, e.StackTrace));
        }

        private byte[] GenerateSessionId(IPEndPoint clientEndPoint, DateTime dateConnection)
        {
            StringBuilder sessionIpStr = new StringBuilder(clientEndPoint.ToString());
            sessionIpStr.Append(':');
            sessionIpStr.Append(dateConnection.Ticks);
            return HashSHA256.GetHash(Encoding.UTF8.GetBytes(sessionIpStr.ToString()));
        }
    }
}
