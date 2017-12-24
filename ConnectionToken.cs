using ProtocolFramework;

namespace WebsocketProtocol
{
    // For websocket.
    public class ConnectionToken
    {
        public ConnectionToken()
        {
            this.PendingData = new Buffer(1024 * 1024);
        }

        public Buffer PendingData;
        public bool IsNegociationEnded;
        public WebsocketProtocol.WebSocketOpCode LastReceivedOpCode;
    }
}