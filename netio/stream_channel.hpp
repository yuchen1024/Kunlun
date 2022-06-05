/*
** Modified from the following project
** 1. https://github.com/emp-ot/
*/

#ifndef KUNLUN_NET_IO_STREAM_CHANNEL
#define KUNLUN_NET_IO_STREAM_CHANNEL

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h> // Include this header file for using socket feature

#include "../include/kunlun.hpp"

class NetIO{ 
public:
	bool IS_SERVER;
	int server_master_socket = -1; 
	int connect_socket = -1;
	FILE *stream = nullptr; 
	char *buffer = nullptr; 

	std::string address;
	int port;

	NetIO(std::string party, std::string address, int port); 

	void SetNodelay();
	void SetDelay();

	void SendDataInternal(const void *data, size_t LEN); 
	void ReceiveDataInternal(const void *data, size_t LEN); 

	void SendBytes(const void *data, size_t LEN);  
	void ReceiveBytes(void *data, size_t LEN); 

	void SendBlocks(const block* data, size_t LEN);
	void ReceiveBlocks(block* data, size_t LEN);  

	void SendBlock(const block &a);
	void ReceiveBlock(block &a);  

	void SendECPoints(const ECPoint* vec_A, size_t LEN); 
	void ReceiveECPoints(ECPoint* vec_A, size_t LEN); 

	void SendECPoint(const ECPoint &A);
	void ReceiveECPoint(ECPoint &A);

	void SendBits(uint8_t *data, size_t LEN);
	void ReceiveBits(uint8_t *data, size_t LEN); 

	void SendString(char *data, size_t LEN);
	void ReceiveString(char *data, size_t LEN); 

	void SendString(std::string &str);
	void ReceiveString(std::string &str); 

	template <typename T>
	void SendInteger(const T &n);

	template <typename T>
	void ReceiveInteger(T &n);

	~NetIO() {
		close(this->connect_socket); 
		if(IS_SERVER == true){
			close(this->server_master_socket); 
		}
		fflush(stream);
		fclose(stream);
		delete[] buffer;
	}
};

NetIO::NetIO(std::string party, std::string address, int port)
{
	this->port = port & 0xFFFF; 

	if(party == "server")
	{
		// create server master socket: socket descriptor is an integer (like a file-handle)
		this->server_master_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	
		// set sockaddr_in with IP and port
		struct sockaddr_in server_address; 
		memset(&server_address, 0, sizeof(server_address)); // fill each byte with 0
		socklen_t server_address_size = sizeof(server_address);

		server_address.sin_family = AF_INET; // use IPV4
		if(address==""){
			server_address.sin_addr.s_addr = htonl(INADDR_ANY); // set our address to any interface
		}
		else{
			server_address.sin_addr.s_addr = inet_addr(address.c_str());
		} 
		server_address.sin_port = htons(port);           // set the server port number  

		// set the server master socket
		int reuse = 1;
		if (setsockopt(this->server_master_socket, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0) {
			perror("error: setsockopt");
			exit(EXIT_FAILURE);
		}
	
		// bind the server master socket with IP and port
		if(bind(this->server_master_socket, (struct sockaddr *)&server_address, sizeof(struct sockaddr)) < 0) {
			perror("error: fail to bind server master socket");
			exit(EXIT_FAILURE);
		}

		// begin to listen
		if(listen(this->server_master_socket, 1) < 0) {
			perror("error: server master socket fail to listen");
			exit(EXIT_FAILURE);
		}
		else{
			std::cout << "server is listening connection request from client >>>" << std::endl;
		}	
		// accept request from the client
		struct sockaddr_in client_address; // structure that holds ip and port
		socklen_t client_address_size = sizeof(client_address); 
		// successful return of non-negative descriptor, error return-1
	
		connect_socket = accept(server_master_socket, (struct sockaddr*)&client_address, &client_address_size);
		if (connect_socket < 0) {
			perror("error: fail to accept client socket");
			exit(EXIT_FAILURE);	
		}
	}

	else{
		IS_SERVER = false;  

		// set the server address that the client socket is going to connect
		struct sockaddr_in server_address;
		memset(&server_address, 0, sizeof(server_address));
		server_address.sin_family = AF_INET; 
		server_address.sin_addr.s_addr = inet_addr(address.c_str());
		server_address.sin_port = htons(port);

		// create client socket
		this->connect_socket = socket(AF_INET, SOCK_STREAM, 0);


		if (connect(this->connect_socket, (struct sockaddr *)&server_address, sizeof(struct sockaddr_in)) < 0){
			perror("error: connect");
			exit(EXIT_FAILURE);	
		}
		else{
			std::cout << "client connects to server successfully >>>" << std::endl;
		}
	}
	
	SetNodelay(); 
	// very impprotant: bind the socket to a file stream
	stream = fdopen(this->connect_socket, "wb+"); 
	buffer = new char[NETWORK_BUFFER_SIZE];
	memset(buffer, 0, NETWORK_BUFFER_SIZE);
	setvbuf(stream, buffer, _IOFBF, NETWORK_BUFFER_SIZE); // Specifies a buffer for stream
}


void NetIO::SetNodelay() 
{
	const int one=1;
	setsockopt(this->connect_socket, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

void NetIO::SetDelay() 
{
	const int zero = 0;
	setsockopt(this->connect_socket, IPPROTO_TCP, TCP_NODELAY, &zero, sizeof(zero));
}

/*
** first define basic send/receive functions
** if we directly use the send/receive socket function
** the buffer will be overflowed when the data is massive
** it is important to buffer the data to the stream, which is binded with the socket
** the underlying mechanism will thus do the slice automatically to ensure the server/client will not crash
** then implement functions send/receiver bytes and more advanced types of data 
*/

// the very basic send function 
void NetIO::SendDataInternal(const void *data, size_t LEN)
{
	size_t HAVE_SENT_LEN = 0; 
	// continue write data to stream until all reach the desired LEN
	while(HAVE_SENT_LEN < LEN) {
		size_t SENT_LEN = fwrite((char*)data+HAVE_SENT_LEN, 1, LEN-HAVE_SENT_LEN, stream);
		if (SENT_LEN >= 0) HAVE_SENT_LEN+=SENT_LEN;
		else fprintf(stderr,"error: fail to send data %zu\n", SENT_LEN);
	}
	/* 
	** very important: 
	** if stream is not explicitly flushed, the data will not be sent
	*/
	fflush(stream); 
}

// the very basic receive function
void NetIO::ReceiveDataInternal(const void *data, size_t LEN)
{
	size_t HAVE_RECEIVE_LEN = 0;
	// continue receive data to stream until all reach the desired LEN
	while(HAVE_RECEIVE_LEN < LEN) {
		size_t RECEIVE_LEN = fread((char*)data+HAVE_RECEIVE_LEN, 1, LEN-HAVE_RECEIVE_LEN, stream);
		if (RECEIVE_LEN >= 0) HAVE_RECEIVE_LEN+=RECEIVE_LEN;
		else fprintf(stderr,"error: fail to receive data %zu\n", RECEIVE_LEN);
	}
}


void NetIO::SendBytes(const void* data, size_t LEN) 
{
	SendDataInternal(data, LEN); 
}

void NetIO::ReceiveBytes(void* data, size_t LEN) 
{
	ReceiveDataInternal(data, LEN); 
}

void NetIO::SendBlocks(const block* data, size_t LEN) 
{
	SendBytes(data, LEN*sizeof(block));
}

void NetIO::ReceiveBlocks(block* data, size_t LEN) 
{
	ReceiveBytes(data, LEN*sizeof(block));
}

void NetIO::SendBits(uint8_t *data, size_t LEN) 
{
	SendBytes(data, LEN);
}

void NetIO::ReceiveBits(uint8_t *data, size_t LEN) 
{
	ReceiveBytes(data, LEN);
}

void NetIO::SendString(char *data, size_t LEN) 
{
	SendBytes(data, LEN);
}

void NetIO::ReceiveString(char *data, size_t LEN) 
{
	ReceiveBytes(data, LEN);  
}

void NetIO::SendString(std::string &str) 
{
	SendBytes(&str[0], str.size());
}

void NetIO::ReceiveString(std::string &str) 
{
	ReceiveBytes(&str[0], str.size()); 
}

void NetIO::SendECPoints(const ECPoint* A, size_t LEN) 
{
	#ifdef ECPOINT_COMPRESSED
		unsigned char* buffer = new unsigned char[LEN*POINT_COMPRESSED_BYTE_LEN];
		for(auto i = 0; i < LEN; i++) {
    		EC_POINT_point2oct(group, A[i].point_ptr, POINT_CONVERSION_COMPRESSED, 
				               buffer + i*POINT_COMPRESSED_BYTE_LEN, POINT_COMPRESSED_BYTE_LEN, bn_ctx);
    	}
		SendBytes(buffer, LEN*POINT_COMPRESSED_BYTE_LEN);
	#else
		unsigned char* buffer = new unsigned char[LEN*POINT_BYTE_LEN];
		for(auto i = 0; i < LEN; i++) {
    		EC_POINT_point2oct(group, A[i].point_ptr, POINT_CONVERSION_UNCOMPRESSED, 
				               buffer + i*POINT_BYTE_LEN, POINT_BYTE_LEN, bn_ctx);
    	}
		SendBytes(buffer, LEN*POINT_BYTE_LEN);
	#endif
	
	delete[] buffer; 
}

void NetIO::ReceiveECPoints(ECPoint* A, size_t LEN) 
{
	#ifdef ECPOINT_COMPRESSED
		unsigned char* buffer = new unsigned char[LEN*POINT_COMPRESSED_BYTE_LEN];
		ReceiveBytes(buffer, LEN*POINT_COMPRESSED_BYTE_LEN); 
		for(auto i = 0; i < LEN; i++) {
			EC_POINT_oct2point(group, A[i].point_ptr, buffer+i*POINT_COMPRESSED_BYTE_LEN, 
			                   POINT_COMPRESSED_BYTE_LEN, bn_ctx);
		}
	#else
		unsigned char* buffer = new unsigned char[LEN*POINT_BYTE_LEN];
		ReceiveBytes(buffer, LEN*POINT_BYTE_LEN); 
		for(auto i = 0; i < LEN; i++) {
			EC_POINT_oct2point(group, A[i].point_ptr, buffer+i*POINT_BYTE_LEN, POINT_BYTE_LEN, bn_ctx);
		}
	#endif

	delete[] buffer; 
}

void NetIO::SendECPoint(const ECPoint &A) 
{
	#ifdef ECPOINT_COMPRESSED
		unsigned char buffer[POINT_COMPRESSED_BYTE_LEN];
		EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_COMPRESSED, buffer, POINT_COMPRESSED_BYTE_LEN, bn_ctx);
		SendBytes(buffer, POINT_COMPRESSED_BYTE_LEN);
	#else
		unsigned char buffer[POINT_BYTE_LEN];
		EC_POINT_point2oct(group, A.point_ptr, POINT_CONVERSION_UNCOMPRESSED, buffer, POINT_BYTE_LEN, bn_ctx);
		SendBytes(buffer, POINT_BYTE_LEN);
	#endif
}

void NetIO::ReceiveECPoint(ECPoint &A) 
{
	#ifdef ECPOINT_COMPRESSED
		unsigned char buffer[POINT_COMPRESSED_BYTE_LEN];
		ReceiveBytes(buffer, POINT_COMPRESSED_BYTE_LEN); 
		EC_POINT_oct2point(group, A.point_ptr, buffer, POINT_COMPRESSED_BYTE_LEN, bn_ctx);
	#else
		unsigned char buffer[POINT_BYTE_LEN];
		ReceiveBytes(buffer, POINT_BYTE_LEN); 
		EC_POINT_oct2point(group, A.point_ptr, buffer, POINT_BYTE_LEN, bn_ctx);
	#endif
}

// T could be any built-in data type, such as block or int
template <typename T>
void NetIO::SendInteger(const T &n)
{
	SendBytes(&n, sizeof(T));
}
template <typename T>
void NetIO::ReceiveInteger(T &n)
{
	ReceiveBytes(&n, sizeof(T));
}


void NetIO::SendBlock(const block &a) 
{
	SendBytes(&a, sizeof(block));
}

void NetIO::ReceiveBlock(block &a) 
{
	ReceiveBytes(&a, sizeof(block));
}



#endif  //NETWORK_IO_CHANNEL
