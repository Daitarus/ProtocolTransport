using CryptL;
using System.Net;
using System.Net.Sockets;
using NLog;

namespace ProtocolTransport
{
    public class PcdClient
    {
        private static readonly Logger logger = LogManager.GetCurrentClassLogger();

        private IPEndPoint serverEndPoint;
        private Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        private IParser parser;
        private CryptAES aes = new CryptAES();
        private Transport? transport;
        public byte[] sessionId = new byte[0];

        public PcdClient(IPEndPoint serverEndPoint, IParser parser)
        {
            this.serverEndPoint = serverEndPoint;         
            this.parser = parser;
        }

        public bool Connect()
        {
            try
            {
                socket.Connect(serverEndPoint);
                transport = new Transport(socket);

                //get PublicKey RSA
                RsaPkeyCom rsaCom;
                if (RsaPkeyCom.ParseToCom(transport.GetData(), out rsaCom))
                {
                    CryptRSA rsa = new CryptRSA(rsaCom.publicKey, false);

                    //send aes key
                    AesKeyCom aesKeyCom = new AesKeyCom(aes.UnionKeyIV());
                    transport.SendData(rsa.Encrypt(aesKeyCom.ConvertToBytes()));

                    //get sessionId
                    SessionIdCom sessionIdCom;
                    if (SessionIdCom.ParseToCom(aes.Decrypt(transport.GetData()), out sessionIdCom))
                    {
                        sessionId = sessionIdCom.sessionId;
                        return true;
                    }
                }
            }
            catch (SocketException e)
            {
                //An existing connection was forcibly closed by the remote host
                if (e.NativeErrorCode != 10054)
                {
                    Disconnect();
                    LogException(e);
                }
            }
            catch (Exception e)
            {
                Disconnect();
                LogException(e);
            }

            return false;
        }

        public bool ServeCommand(CommandRequest comRequest)
        {
            try
            {
                if (transport == null)
                    throw new Exception("PcdClient is not connection");

                transport.SendData(aes.Encrypt(comRequest.ToBytes()));               
                Command com = parser.Parse(aes.Decrypt(transport.GetData()));
                if (com is CommandAnswer)
                {
                    CommandAnswer comAnswer = (CommandAnswer)com;
                    return comAnswer.ExecuteCommand();
                }
            }
            catch (SocketException e)
            {
                //An existing connection was forcibly closed by the remote host
                if (e.NativeErrorCode != 10054)
                {
                    Disconnect();
                    LogException(e);
                }
            }
            catch (Exception e)
            {
                Disconnect();
                LogException(e);
            }

            return false;
        }
        public bool ServeCommands(CommandRequest comRequest)
        {

            try
            {
                if (transport == null)
                    throw new Exception("PcdClient is not connection");

                transport.SendData(aes.Encrypt(comRequest.ToBytes()));

                bool repeater = true;
                while (repeater)
                {
                    Command com = parser.Parse(aes.Decrypt(transport.GetData()));
                    if (com is CommandAnswer)
                    {
                        CommandAnswer comAnswer = (CommandAnswer)com;
                        repeater = comAnswer.ExecuteCommand();
                    }
                }

                return true;
            }
            catch (SocketException e)
            {
                //An existing connection was forcibly closed by the remote host
                if (e.NativeErrorCode != 10054)
                {
                    Disconnect();
                    LogException(e);
                }
            }
            catch (Exception e)
            {
                Disconnect();
                LogException(e);
            }

            return false;
        }

        public void Disconnect()
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
            logger.Error(String.Format("{0}\n\n{1}\n\n", e.Message, e.StackTrace));
        }
    }
}
