using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using ProtocolFramework;

namespace WebsocketProtocol
{
    public class WebsocketProtocol : Protocol
    {
        public enum WebSocketOpCode
        {
            ContinuationFrame = 0,
            TextFrame = 1,
            BinaryFrame = 2,
            ConnectionClose = 8,
            Ping = 9,
            Pong = 10
        }

        public static bool IsControlFrame(WebSocketOpCode opCode)
        {
            return opCode == WebSocketOpCode.ConnectionClose ||
                opCode == WebSocketOpCode.Ping ||
                opCode == WebSocketOpCode.Pong;
        }

        public static bool IsValidCode(WebSocketOpCode opCode)
        {
            return opCode == WebSocketOpCode.ContinuationFrame ||
                opCode == WebSocketOpCode.TextFrame ||
                opCode == WebSocketOpCode.BinaryFrame ||
                opCode == WebSocketOpCode.ConnectionClose ||
                opCode == WebSocketOpCode.Ping ||
                opCode == WebSocketOpCode.Pong;
        }
        
        public WebsocketProtocol(bool isServerSide)
        {
            this.IsServerSide = isServerSide;
        }

        public bool IsBinaryMode
        {
            get;
            set;
        }  

        public bool IsServerSide
        {
            get;
            set;
        }

        public override string Name
        {
            get
            {
                return "Websocket Protocol";
            }
        }

        public override object CreateConnectionToken()
        {
            return new ConnectionToken();
        }

        public override void StartProtocolNegociation(object connectionToken, out ProtocolFramework.Buffer outputBytes)
        {
            ConnectionToken token = (ConnectionToken)connectionToken;

            if (this.IsServerSide)
            {
                // We should just for client.
                outputBytes = null;
                return;
            }
            else
            {
                string handshakeRequest = "HTTP/1.1 101 Switching Protocols\r\n";
                handshakeRequest += "Sec-WebSocket-Version: 13\r\n";
                handshakeRequest += "Sec-WebSocket-Key: uikmSAU+xlcxDKO4grfBRA==\r\n";
                handshakeRequest += "Upgrade: websocket\r\n";
                handshakeRequest += "\r\n";

                byte[] buffer = System.Text.Encoding.UTF8.GetBytes(handshakeRequest);

                outputBytes = new ProtocolFramework.Buffer(buffer, buffer.Length);
            }            
        }  

        public override bool ReadBytes(ProtocolFramework.Buffer incomingBytes, object connectionToken)
        {
            ConnectionToken token = (ConnectionToken)connectionToken;

            // TODO. Improve.
            if (token.PendingData.RemainingCapacity < incomingBytes.Size)
            {
                Console.WriteLine("buffered data exceeded 64 KB");
                return false;
            }

            token.PendingData.Append(incomingBytes);
            return true;
        }


        private DecodeResult TryDecodeHandshakeData(ConnectionToken token, out ProtocolFramework.Buffer decodedBytes, out ProtocolFramework.Buffer outputBytes)
        {
            decodedBytes = null;
            outputBytes = null;

            char endChar = (char)token.PendingData.Data[token.PendingData.Size - 1];
            if (endChar != '\n')
            {
                return DecodeResult.WantMoreData;
            }

            if (this.IsServerSide)
            {
                string header = Encoding.UTF8.GetString(token.PendingData.Data, 0, token.PendingData.Size);
                Regex webSocketKeyRegex = new Regex("Sec-WebSocket-Key: (.*)");
                Regex webSocketVersionRegex = new Regex("Sec-WebSocket-Version: (.*)");

                // check the version. Support version 13 and above
                const int WebSocketVersion = 13;
                int secWebSocketVersion = Convert.ToInt32(webSocketVersionRegex.Match(header).Groups[1].Value.Trim());
                if (secWebSocketVersion < WebSocketVersion)
                {
                    return DecodeResult.Failure;
                }

                string secWebSocketKey = webSocketKeyRegex.Match(header).Groups[1].Value.Trim();
                string setWebSocketAccept = this.ComputeSocketAcceptString(secWebSocketKey);
                string response = ("HTTP/1.1 101 Switching Protocols" + Environment.NewLine
                                   + "Connection: Upgrade" + Environment.NewLine
                                   + "Upgrade: websocket" + Environment.NewLine
                                   + "Sec-WebSocket-Accept: " + setWebSocketAccept)
                                   + "\r\n"
                                   + "\r\n";

                /* + Environment.NewLine
                + Environment.NewLine;*/

                byte[] encodedResponse = Encoding.UTF8.GetBytes(response);
                outputBytes = new ProtocolFramework.Buffer(encodedResponse, encodedResponse.Length);

                token.PendingData.Clear();
                token.IsNegociationEnded = true;
                return DecodeResult.Success;
            }
            else
            {
                //Make sure the server has accepted the handshake request.
                token.PendingData.Clear();
                token.IsNegociationEnded = true;
                return DecodeResult.Success;
            }
        }
        public override DecodeResult TryDecode(object connectionToken, out ProtocolFramework.Buffer decodedBytes, out ProtocolFramework.Buffer outputBytes)
        {
            decodedBytes = null;
            outputBytes = null;
            ConnectionToken token = (ConnectionToken)connectionToken;

            if(token.PendingData.Empty())
            {
                return DecodeResult.WantMoreData;
            }

            if (!token.IsNegociationEnded)
            {
                return this.TryDecodeHandshakeData(token, out decodedBytes, out outputBytes);
            }            
            
            // We start interpreting two bytes.
            int headerSize = 2;
            if (token.PendingData.Size < headerSize)
            {
                return DecodeResult.WantMoreData;
            }

            // First byte = Fin (1 bit) + Flags (3 bits) + opcodes (4 bits):
            byte byte1 = token.PendingData.Data[0];
            const byte finBitFlag = 0x80;
            const byte opCodeFlag = 0x0F;
            const byte reservedBitsFlag = 0x70;
            
            bool isFinBitSet = (byte1 & finBitFlag) == finBitFlag;
            int reservedBits = (byte1 & reservedBitsFlag);

            if (reservedBits != 0)
            {
                Console.WriteLine("Reserved bits not zeros");
                return DecodeResult.Failure;
            } 

            WebSocketOpCode opCode = (WebSocketOpCode)(byte1 & opCodeFlag);
            if (!WebsocketProtocol.IsValidCode(opCode))
            {
                Console.WriteLine("Invalid opCode: " + opCode);
                return DecodeResult.Failure;
            }
                       

            // Second byte is Mask (1 bit) + Payload Size (7 bits)
            byte byte2 = token.PendingData.Data[1];
            const byte maskFlag = 0x80;
            bool isMaskBitSet = (byte2 & maskFlag) == maskFlag;
            const byte payloadLenFlag = 0x7F;
            uint len = (uint)(byte2 & payloadLenFlag);

            int payloadSize = 0;
            if (len <= 125)
            {
                payloadSize = (int)len;
            }
            if (len == 126)
            {
                headerSize += 2;
                if (token.PendingData.Size < headerSize)
                    return DecodeResult.WantMoreData;

                byte[] lenBuffer = new byte[2];
                Array.Copy(token.PendingData.Data, 2, lenBuffer, 0, 2);
                Array.Reverse(lenBuffer); // big endian
                payloadSize = (int)BitConverter.ToUInt16(lenBuffer, 0);
            }
            else if (len == 127)
            {
                headerSize += 8;
                if (token.PendingData.Size < headerSize)
                    return DecodeResult.WantMoreData;

                byte[] lenBuffer = new byte[8];
                Array.Copy(token.PendingData.Data, 2, lenBuffer, 0, 8);
                Array.Reverse(lenBuffer); // big endian
                payloadSize = (int)BitConverter.ToUInt64(lenBuffer, 0);
            }

            if (WebsocketProtocol.IsControlFrame(opCode) && payloadSize > 125)
            {
                Console.WriteLine("Large control frame payload");
                return DecodeResult.Failure;
            }

            int totalSize = headerSize + (isMaskBitSet ? 4 : 0) + (int)payloadSize;

            if (token.PendingData.Size < totalSize)
                return DecodeResult.WantMoreData;

            ProtocolFramework.Buffer payloadBuffer = new ProtocolFramework.Buffer(payloadSize);
            int payloadOffset = headerSize + (isMaskBitSet ? 4 : 0);
            payloadBuffer.Append(token.PendingData.Data, payloadOffset, (int)payloadSize);

            if (isMaskBitSet)
            {
                const int maskKeyLen = 4;
                byte[] maskKey = new byte[4];
                Array.Copy(token.PendingData.Data, headerSize, maskKey, 0, 4);
                // apply the mask key
                for (int i = 0; i < payloadBuffer.Size; i++)
                {
                    payloadBuffer.Data[i] = (Byte)(payloadBuffer.Data[i] ^ maskKey[i % maskKeyLen]);
                }
            }

            token.PendingData.PopAndAdjust(payloadOffset + (int)payloadSize);

            if (opCode == WebSocketOpCode.ConnectionClose)
            {
                this.EncodeFrame(null, out outputBytes, WebSocketOpCode.ConnectionClose);
                return DecodeResult.Failure; // TODO.
            }
            else if (opCode == WebSocketOpCode.Pong)
            {
                return DecodeResult.Success;
            }
            else if (opCode == WebSocketOpCode.Ping)
            {
                this.EncodeFrame(payloadBuffer, out outputBytes, WebSocketOpCode.Pong);
                return DecodeResult.Success;
            }
            else
            {
                token.LastReceivedOpCode = opCode;
                decodedBytes = payloadBuffer;
                return DecodeResult.Success;
            }         
        }

        public override bool IsNegociationEnded(object connectionToken)
        {
            ConnectionToken token = (ConnectionToken)connectionToken;
            return token.IsNegociationEnded;
        }

        public override EncodeResult Encode(object connectionToken, ProtocolFramework.Buffer inputBuffer, out ProtocolFramework.Buffer output)
        {
            ConnectionToken token = (ConnectionToken)connectionToken;

            return this.EncodeFrame(inputBuffer, out output, token.LastReceivedOpCode);
        }

        private EncodeResult EncodeFrame(ProtocolFramework.Buffer data, out ProtocolFramework.Buffer encoded, WebSocketOpCode opCode)
        {
            int size = data == null ? 0 : data.Size;
            encoded = new ProtocolFramework.Buffer(2 + 8 + size); // max possible length of header

            const bool isLastFrame = true;

            byte finBitSetAsByte = isLastFrame ? (byte) 0x80 : (byte) 0x00;
            byte byte1 = (byte) (finBitSetAsByte | (byte) opCode);

            encoded.Append(byte1);

            if (size < 126)
            {
                encoded.Append((byte)size);
            }
            else if (size <= ushort.MaxValue)
            {
                encoded.Append(126);

                byte[] buffer = BitConverter.GetBytes((ushort)size);
                Array.Reverse(buffer);
                encoded.Append(buffer, 0, buffer.Length);
            }
            else
            {
                encoded.Append(127);

                byte[] buffer = BitConverter.GetBytes((ulong)size);
                Array.Reverse(buffer);
                encoded.Append(buffer, 0, buffer.Length);
            }

            if (data != null)
            {
                encoded.Append(data);
            }
            
            return EncodeResult.Success;
        }

        /// <summary>
        /// Combines the key supplied by the client with a guid and returns the sha1 hash of the combination
        /// </summary>
        protected string ComputeSocketAcceptString(string secWebSocketKey)
        {
            // this is a guid as per the web socket spec
            const string webSocketGuid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

            string concatenated = secWebSocketKey + webSocketGuid;
            byte[] concatenatedAsBytes = Encoding.UTF8.GetBytes(concatenated);
            byte[] sha1Hash = SHA1.Create().ComputeHash(concatenatedAsBytes);
            string secWebSocketAccept = Convert.ToBase64String(sha1Hash);
            return secWebSocketAccept;
        }
    }
}