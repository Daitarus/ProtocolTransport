using System.Net.Sockets;

namespace ProtocolTransport
{
    public class Transport
    {
        private long maxLengthPack = Command.MaxLengthData + 1;
        private const int lengthArrayLengthPayload = 3;

        private Socket socket;

        public Transport(Socket socket)
        {
            this.socket = socket;
        }

        public void SendData(byte[] payLoad)
        {
            payLoad = AddLength(payLoad);
            socket.Send(payLoad);
        }
        public byte[] GetData()
        {
            byte[] lengthPayLoadBuffer = new byte[lengthArrayLengthPayload];
            if(socket.Available==0)
            { }
            socket.Receive(lengthPayLoadBuffer, lengthArrayLengthPayload, SocketFlags.None);

            int lengthPayLoad = GetLength(lengthPayLoadBuffer);

            if(lengthPayLoad==0)
            { }
            
            byte[] payLoad = new byte[lengthPayLoad];

            if (lengthPayLoad > maxLengthPack)
                throw new ArgumentException($"{nameof(payLoad)} size greater than {maxLengthPack}", nameof(lengthPayLoad));

            int byteCounter = 0, byteCounterOld = 0;
            while (byteCounter < lengthPayLoad)
            {
                byteCounter += socket.Receive(payLoad, byteCounterOld, lengthPayLoad - byteCounterOld, SocketFlags.None);
                byteCounterOld = byteCounter;
            }

            return payLoad;
        }

        private byte[] AddLength(byte[] payLoad)
        {
            if(payLoad == null)
                throw new ArgumentNullException(nameof(payLoad));

            if(payLoad.Length > maxLengthPack)
                throw new ArgumentException($"{nameof(payLoad)} size greater than {maxLengthPack}", nameof(payLoad));

            byte[] lengthPayLoad = new byte[lengthArrayLengthPayload];
            byte[] lengthPayLoadBuffer = BitConverter.GetBytes(payLoad.Length);
            Array.Copy(lengthPayLoadBuffer, lengthPayLoad, lengthArrayLengthPayload);

            byte[] newPayLoad = new byte[lengthPayLoad.Length + payLoad.Length];
            Array.Copy(lengthPayLoad, newPayLoad, lengthPayLoad.Length);
            Array.Copy(payLoad, 0, newPayLoad, lengthPayLoad.Length, payLoad.Length);

            return newPayLoad;
        }
        private int GetLength(byte[] lengthPayLoad)
        {
            if (lengthPayLoad == null)
                throw new ArgumentNullException(nameof(lengthPayLoad));

            byte[] lengthPayLoadBuffer = new byte[lengthPayLoad.Length + 1];
            Array.Copy(lengthPayLoad, lengthPayLoadBuffer, lengthPayLoad.Length);

            return BitConverter.ToInt32(lengthPayLoadBuffer);
        }
    }
}