import socket
import ssl
import select
from ldap3.core.exceptions import LDAPException
from ldap3.protocol.rfc4511 import (
    LDAPMessage,
    ExtendedResponse,
    ProtocolOp,
    MessageID,
    ResultCode,
    ResponseName,
    LDAPString,
    LDAPDN,
)
from pyasn1.codec.ber import decoder, encoder
from pyasn1.error import PyAsn1Error

class LDAPServer:
    def __init__(self):
        # Create TCP socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Bind to a random port
        self.server_socket.bind(("127.0.0.1", 0))
        # Get the port number
        self.port = self.server_socket.getsockname()[1]
        # Listen for incoming connections
        self.server_socket.listen(5)
        self.server_socket.setblocking(False)  # Set non-blocking mode
        print(f"Server listening on port {self.port}...")

        # Store client sockets and their SSL objects
        self.connections = []
        self.requested_data = b""
        self.running = True

    def get_port(self):
        return self.port

    def stop(self):
        self.running = False
        self.server_socket.close()
        for sock in self.connections:
            sock.close()

    def start(self):
        try:
            times = 0
            while self.running:
                # Use select to wait for connections and readable events
                readable, _, _ = select.select(
                    [self.server_socket] + self.connections,
                    [self.server_socket] + self.connections,
                    [self.server_socket] + self.connections,
                    1,
                )
                connection_num = 0
                length = None
                for sock in readable:
                    if sock is self.server_socket:
                        # Handle new connection
                        connection_num += 1
                        client_socket, addr = self.server_socket.accept()
                        client_socket.setblocking(False)
                        print(f"New connection from {addr}: {client_socket}")
                        self.connections.append(client_socket)
                    else:
                        # Handle data from existing connection
                        times = times + 1
                        if times >= 2:
                            continue
                        received_data, remaining_len = self.recv_ldap_message(sock, length)
                        length = remaining_len
                        if received_data is not None and len(received_data) > 0:
                            self.requested_data += received_data
                        print(
                            f"received_data length = {len(received_data)}, remaining data length = {remaining_len}, \
requested_data length = {len(self.requested_data)}"
                        )
                        if remaining_len == 0 and len(self.requested_data) > 0:
                            print(f"start decode: {self.requested_data}")
                            try:
                                ldap_message, _ = decoder.decode(
                                    self.requested_data, asn1Spec=LDAPMessage()
                                )
                                print(ldap_message.prettyPrint())
                                # Check if it is a StartTLS request
                                message_id = int(ldap_message.getComponentByName("messageID"))
                                protocol_op = ldap_message.getComponentByName("protocolOp")
                                extended_req = protocol_op.getComponentByName("extendedReq")
                                request_name = extended_req.getComponentByName("requestName")
                                if request_name is not None:
                                    request_name_str = str(request_name)
                                    print(f"requestName: {request_name_str}")

                                    if request_name_str == "1.3.6.1.4.1.1466.20037":
                                        print("Received start_tls request.")
                                        self.handle_start_tls(sock, message_id)
                                    else:
                                        print("Received other LDAP message.")
                                else:
                                    print("Received invalid LDAP message.")
                                    # Handle other LDAP messages

                            except LDAPException as e:
                                print(f"LDAP Exception: {e}")

                            except PyAsn1Error as e:
                                print(f"Failed to decode LDAP message: {e}")
                        else:
                            # Close connection
                            print(f"No data received from {sock}")
                            sock.close()
                            self.connections.remove(sock)

        finally:
            self.stop()

    def construct_extended_response(self, message_id, result_code, response_name=None, response_value=None):
        # Create LDAPMessage object
        ldap_message = LDAPMessage()

        # Set messageID
        ldap_message["messageID"] = MessageID(message_id)

        # Create ExtendedResponse object
        ext_response = ExtendedResponse()

        # Set result code
        ext_response["resultCode"] = ResultCode(result_code)
        ext_response["matchedDN"] = LDAPDN("")
        ext_response["diagnosticMessage"] = LDAPString("")

        # Set optional responseName (OID of the extended operation)
        if response_name:
            ext_response["responseName"] = ResponseName(response_name)

        # Set optional responseValue (return value of the extended operation)
        if response_value:
            ext_response["responseValue"] = ResponseName(response_value)

        print(ext_response.prettyPrint())

        protocol_op = ProtocolOp()
        protocol_op["extendedResp"] = ext_response

        print(protocol_op.prettyPrint())

        ldap_message["protocolOp"] = protocol_op

        print(ldap_message.prettyPrint())
        encoded_message = encoder.encode(ldap_message)
        return encoded_message

    def handle_start_tls(self, sock, message_id):
        # Construct StartTLS extended response
        response_name = "1.3.6.1.4.1.1466.20037"

        response_data = self.construct_extended_response(message_id, 0, response_name)
        # Send response message
        sock.sendall(response_data)

        print("LDAP extended op start_tls response sent.")

        # Start TLS session
        # context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        # tls_sock = context.wrap_socket(sock, server_side=True)

        # return tls_sock

    def recv_ldap_message(self, sock: socket.socket, length=None):
        message_length = 0
        tlv_data = b""

        if length is None:
            # Step 1: Read the first byte (Tag)
            tag = sock.recv(1)
            if not tag:
                raise Exception("Connection closed or no data")

            # Add Tag to tlv_data
            tlv_data += tag

            # Step 2: Read the second byte (Length)
            first_length_byte = sock.recv(1)
            if not first_length_byte:
                raise Exception("Connection closed or no data")

            # Convert the first length byte to an integer
            first_length_byte = ord(first_length_byte)

            # Add the first length byte to tlv_data
            tlv_data += bytes([first_length_byte])

            # Step 3: Parse the length
            if first_length_byte & 0x80 == 0:  # Short form
                message_length = first_length_byte
            else:  # Long form
                num_length_bytes = first_length_byte & 0x7F  # Get the number of bytes representing the length
                length_bytes = sock.recv(num_length_bytes)  # Read the length bytes
                if not length_bytes or len(length_bytes) != num_length_bytes:
                    raise Exception("Invalid length encoding or connection closed")

                # Parse multi-byte length
                for b in length_bytes:
                    message_length = (message_length << 8) | ord(b)

                # Add the multi-byte length field to tlv_data
                tlv_data += length_bytes

            if message_length == 0:
                return None, 0
        else:
            if length <= 0:
                return None, 0
            message_length = length

        print(f"To recv {message_length} bytes data from {sock}")
        # Step 4: Read the complete message body
        message_data = b""
        try:
            message_data = sock.recv(message_length)
        except socket.error as e:
            print(f"Error receiving data: {e}")
            if message_data is None:
                return b"", message_length
            return tlv_data + message_data, message_length - len(message_data)
        if message_data is None:
            return b"", message_length
        print(f"message_data = {message_data}")
        if len(message_data) == 0:
            return tlv_data + message_data, message_length
        if len(message_data) != message_length:
            # Return the number of unread bytes and the data received so far
            return tlv_data + message_data, message_length - len(message_data)

        # Return the complete Tag + Length + Value
        return tlv_data + message_data, 0

if __name__ == "__main__":
    # Example usage
    server = LDAPServer()
    print(f"Bound to port: {server.get_port()}")
    server.start()
